# TLSNotary tweet endpoint test

Minimal test of whether TLSNotary's MPC-TLS works against the x.com tweet
endpoint at all: the handshake, an authenticated request, and a verified response.
MPC-TLS only supports TLS 1.2 (not 1.3), so it also confirms the endpoint
works over TLS 1.2. Prover and Verifier run in one process, with no external notary.

## What it does

1. The Prover and Verifier open an MPC-TLS session with each other (in one
   process, over an in-memory channel).
2. The Prover connects to `x.com` and sends an authenticated GraphQL request
   (`TweetResultByRestId`) for the tweet.
3. The tweet JSON from the response is revealed to the Verifier, while the
   session credentials (`cookie`, `authorization`, `x-csrf-token`) are redacted
   by header name — the Verifier never sees them.
4. The Verifier confirms the response came from `x.com` and contains the tweet.

This verification is interactive: the Verifier checks it live, in-process. It
produces no portable proof.

## Run

1. Fill in credentials:
   ```bash
   cp .env.example .env
   ```
   Set `TWEET_ID`, `X_COOKIE`, `X_AUTHORIZATION`, `X_CSRF_TOKEN` — from the
   browser: DevTools → Network → `TweetResultByRestId` → request headers.

2. Build and run (in a normal terminal):
   ```bash
   cargo run --release
   ```

## License

Based on the official [tlsnotary/tlsn](https://github.com/tlsnotary/tlsn)
examples (tag `v0.1.0-alpha.15`). Dual-licensed under **MIT OR Apache-2.0**,
inherited from tlsn.
