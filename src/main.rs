// Based on tlsnotary/tlsn examples basic.rs + attestation/present.rs (v0.1.0-alpha.15), MIT/Apache-2.0.

use std::{env, future::IntoFuture, net::SocketAddr, ops::Range};

use anyhow::{Context, Result};
use http_body_util::Empty;
use hyper::{Request, StatusCode, Uri, body::Bytes};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::instrument;

use tlsn::{
    Session,
    config::{
        prove::ProveConfig, prover::ProverConfig, tls::TlsClientConfig,
        tls_commit::mpc::MpcTlsConfig, verifier::VerifierConfig,
    },
    connection::ServerName,
    transcript::PartialTranscript,
    verifier::{VerifierCommitStart, VerifierOutput},
    webpki::RootCertStore,
};
use tlsn_formats::http::HttpTranscript;

const SERVER_DOMAIN: &str = "x.com";
const SERVER_PORT: u16 = 443;

/// Request headers whose VALUES must stay hidden from the verifier (only the
/// header names are revealed).
const SECRET_HEADERS: [&str; 3] = ["authorization", "cookie", "x-csrf-token"];

// Maximum number of bytes that can be sent from prover to server.
const MAX_SENT_DATA: usize = 2048;
const MAX_RECV_DATA: usize = 8192;

/// Default x.com GraphQL endpoint for fetching a single tweet.
///
/// The `queryId` and `features` rotate when x.com changes its GraphQL API;
/// a stale set gives HTTP 400/404. If it breaks, copy the fresh request URL
/// from devtools, swap the tweet id for `{tweet_id}`, and set it as `TWEET_URL`.
const DEFAULT_TWEET_URL: &str = "https://x.com/i/api/graphql/-4_LMahNlI4MuLJ-EAFEog/TweetResultByRestId?variables=%7B%22tweetId%22%3A%22{tweet_id}%22%2C%22withCommunity%22%3Afalse%2C%22includePromotedContent%22%3Afalse%2C%22withVoice%22%3Afalse%7D&features=%7B%22creator_subscriptions_tweet_preview_api_enabled%22%3Atrue%2C%22longform_notetweets_consumption_enabled%22%3Atrue%2C%22responsive_web_graphql_timeline_navigation_enabled%22%3Atrue%2C%22rweb_cashtags_enabled%22%3Atrue%2C%22freedom_of_speech_not_reach_fetch_enabled%22%3Atrue%7D";

fn build_tweet_url(tweet_id: &str) -> String {
    let template = env::var("TWEET_URL").unwrap_or_else(|_| DEFAULT_TWEET_URL.to_string());
    template.replace("{tweet_id}", tweet_id)
}

struct XCredentials {
    tweet_id: String,
    cookie: String,
    authorization: String,
    csrf_token: String,
}

/// Read a required env var, treating an unset OR empty value as an error.
fn required_env(key: &str) -> Result<String> {
    let value = env::var(key).ok().filter(|v| !v.trim().is_empty());
    value.with_context(|| format!("{key} is not set or empty"))
}

impl XCredentials {
    fn from_env() -> Result<Self> {
        Ok(Self {
            tweet_id: required_env("TWEET_ID")?,
            cookie: required_env("X_COOKIE")?,
            authorization: required_env("X_AUTHORIZATION")?,
            csrf_token: required_env("X_CSRF_TOKEN")?,
        })
    }
}

#[tokio::main]
async fn main() {
    let _ = dotenvy::dotenv();
    tracing_subscriber::fmt::init();

    let creds = XCredentials::from_env().expect("failed to read X credentials from env");

    let server_addr: SocketAddr = tokio::net::lookup_host(format!("{}:{}", SERVER_DOMAIN, SERVER_PORT))
        .await
        .unwrap()
        .next()
        .unwrap();

    println!("Connecting to {} at {}", SERVER_DOMAIN, server_addr);

    let (prover_socket, verifier_socket) = tokio::io::duplex(1 << 23);
    let prover = prover(prover_socket, &server_addr, &creds);
    let verifier = verifier(verifier_socket);
    let (_, transcript) = tokio::try_join!(prover, verifier).unwrap();

    // Regression test: no secret value should appear in what the verifier saw.
    let revealed_sent = transcript.sent_unsafe();
    for (name, secret) in [
        ("authorization", creds.authorization.as_bytes()),
        ("cookie", creds.cookie.as_bytes()),
        ("x-csrf-token", creds.csrf_token.as_bytes()),
    ] {
        assert!(
            find_all_ranges(revealed_sent, secret).is_empty(),
            "LEAK: {name} value appears in the transcript revealed to the verifier"
        );
    }
    println!("🔒 No secrets leaked into the revealed transcript");

    println!("\n✅ Successfully verified {}", build_tweet_url(&creds.tweet_id));
}

#[instrument(skip(verifier_socket, creds))]
async fn prover<T: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
    verifier_socket: T,
    server_addr: &SocketAddr,
    creds: &XCredentials,
) -> Result<()> {
    let url = build_tweet_url(&creds.tweet_id);
    let uri = url.parse::<Uri>().unwrap();

    // Create a session with the verifier.
    let session = Session::new(verifier_socket.compat());
    let (driver, mut handle) = session.split();

    // Spawn the session driver to run in the background.
    let driver_task = tokio::spawn(driver);

    // Create a new prover and perform necessary setup.
    let prover = handle
        .new_prover(ProverConfig::builder().build()?)?
        .commit(
            // We must configure the amount of data we expect to exchange beforehand,
            // which will be preprocessed prior to the
            // connection. Reducing these limits will improve
            // performance.
            MpcTlsConfig::builder()
                .max_sent_data(MAX_SENT_DATA)
                .max_recv_data(MAX_RECV_DATA)
                .build()?,
        )
        .await?;

    // Open a TCP connection to the server.
    let client_socket = tokio::net::TcpStream::connect(server_addr).await?;

    // Bind the prover to the server connection.
    let (tls_connection, prover) = prover.connect(
        TlsClientConfig::builder()
            .server_name(ServerName::Dns(SERVER_DOMAIN.try_into()?))
            .root_store(RootCertStore::mozilla())
            .build()?,
        client_socket.compat(),
    )?;
    let tls_connection = TokioIo::new(tls_connection.compat());

    // Spawn the Prover to run in the background.
    let prover_task = tokio::spawn(prover.into_future());

    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(tls_connection).await?;

    // Spawn the connection to run in the background.
    tokio::spawn(connection);

    // Send Request and wait for Response.
    let request = Request::builder()
        .uri(uri.clone())
        .method("GET")
        .header("Host", SERVER_DOMAIN)
        .header("Connection", "close")
        .header("Accept-Encoding", "identity")
        .header("authorization", &creds.authorization)
        .header("cookie", &creds.cookie)
        .header("x-csrf-token", &creds.csrf_token)
        .body(Empty::<Bytes>::new())?;

    let response = request_sender.send_request(request).await?;
    let status = response.status();
    println!("Response status: {}", status);
    assert!(status == StatusCode::OK, "Error: status {}", status);

    // Create proof for the Verifier.
    let mut prover = prover_task.await??;
    let mut builder = ProveConfig::builder(prover.transcript());

    // Reveal the DNS name.
    builder.server_identity();

    // Parse the request into its HTTP structure to enable redaction by header
    // name, rather than by locating each secret's value within the raw bytes.
    let http = HttpTranscript::parse(prover.transcript())?;

    // Request: reveal its structure and target, plus every header — but for the
    // secret ones reveal only the NAME, keeping the value hidden.
    let request = &http.requests[0];
    builder.reveal_sent(request.without_data())?;
    builder.reveal_sent(&request.request.target)?;
    for header in &request.headers {
        let is_secret = SECRET_HEADERS
            .iter()
            .any(|name| header.name.as_str().eq_ignore_ascii_case(name));
        if is_secret {
            builder.reveal_sent(header.without_value())?;
        } else {
            builder.reveal_sent(header)?;
        }
    }

    // Response: reveal only the body (the tweet JSON); status line and headers
    // (Set-Cookie, rate-limit, Cloudflare) stay hidden.
    let response = &http.responses[0];
    let body = response.body.as_ref().context("response has no body")?;
    builder.reveal_recv(body)?;

    let config = builder.build()?;

    prover.prove(&config).await?;
    prover.close().await?;

    // Close the session and wait for the driver to complete.
    handle.close();
    driver_task.await??;

    Ok(())
}

#[instrument(skip(socket))]
async fn verifier<T: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static>(
    socket: T,
) -> Result<PartialTranscript> {
    // Create a session with the prover.
    let session = Session::new(socket.compat());
    let (driver, mut handle) = session.split();

    // Spawn the session driver to run in the background.
    let driver_task = tokio::spawn(driver);

    let verifier_config = VerifierConfig::builder()
        .root_store(RootCertStore::mozilla())
        .build()?;
    let verifier = handle.new_verifier(verifier_config)?;

    // Validate the proposed configuration and then run the TLS commitment protocol.
    // This is the opportunity to ensure the prover does not attempt to overload the
    // verifier.
    let verifier = match verifier.commit().await? {
        VerifierCommitStart::Mpc(verifier) => {
            let cfg = verifier.config();
            let reject = if cfg.max_sent_data() > MAX_SENT_DATA {
                Some("max_sent_data is too large")
            } else if cfg.max_recv_data() > MAX_RECV_DATA {
                Some("max_recv_data is too large")
            } else {
                None
            };

            if let Some(msg) = reject {
                verifier.reject(Some(msg)).await?;
                return Err(anyhow::anyhow!("protocol configuration rejected: {}", msg));
            }

            verifier.accept().await?.run().await?
        }
        VerifierCommitStart::Proxy(verifier) => {
            verifier.reject(Some("expecting to use MPC-TLS")).await?;
            return Err(anyhow::anyhow!("protocol configuration rejected"));
        }
    };

    // Validate the proving request and then verify.
    let verifier = verifier.verify().await?;

    let (VerifierOutput { server_name, transcript, .. }, verifier) = verifier.accept().await?;
    if let Some(t) = &transcript {
        let recv = t.received_unsafe();
        let json = match (recv.iter().position(|&b| b == b'{'), recv.iter().rposition(|&b| b == b'}')) {
            (Some(start), Some(end)) => String::from_utf8_lossy(&recv[start..=end]).to_string(),
            _ => String::new(),
        };
        println!("\n📄 Verified tweet JSON:\n{json}");
    }

    verifier.close().await?;

    // Close the session and wait for the driver to complete.
    handle.close();
    driver_task.await??;

    let server_name = server_name.expect("prover should have revealed server name");
    let transcript = transcript.expect("prover should have revealed transcript data");

    // Check received data.
    let received = transcript.received_unsafe().to_vec();
    let response = String::from_utf8_lossy(&received);
    assert!(
        response.contains("tweetResult"),
        "Expected tweet data in response"
    );

    // Check Session info: server name
    let ServerName::Dns(server_name) = server_name;
    assert_eq!(server_name.as_str(), SERVER_DOMAIN);

    println!("✅ Verifier confirmed tweet data is present");

    Ok(transcript)
}

/// All non-overlapping occurrences of `needle` in `haystack`.
fn find_all_ranges(haystack: &[u8], needle: &[u8]) -> Vec<Range<usize>> {
    let mut ranges = Vec::new();
    if needle.is_empty() || needle.len() > haystack.len() {
        return ranges;
    }
    let mut start = 0;
    while start + needle.len() <= haystack.len() {
        if &haystack[start..start + needle.len()] == needle {
            ranges.push(start..start + needle.len());
            start += needle.len();
        } else {
            start += 1;
        }
    }
    ranges
}
