# Privacy-wallet TVC application

Holds the wallet's privacy roles (nullifier key and viewing key, expanded from a
Turnkey-derived seed) out of browser JavaScript. Replica-stateless: the client
carries the seed sealed to the QOS Quorum key and presents it on every call.

Routes:

- `GET /health`: `{"status":"Healthy"}` once runtime keys are loaded.
- `GET /v1/info`: untrusted discovery the client binds to a signed release policy.
- `POST /v1/ping`: QOS connection challenge.
- `POST /v1/operations`: `Bootstrap`, `Decrypt`, `Derive`, `TransactionKeys`,
  `Prove`.

Module map: `operations/` (request validation, `bootstrap.rs`, `keys.rs` for
the three derivation operations, `prove.rs` for completing and forwarding a
prover request, `sealed.rs` for the sealed key state), `custody.rs` (Turnkey
signing of the derivation message behind one trait), `turnkey.rs` (HTTP
client), `local_dev.rs` (testkit, `local-dev` feature only).

Every network origin is compiled in: Turnkey and the devnet prover. The prover
receives the plaintext witness, including the nullifier secret, so this
application must not hold production funds.

## Build

```sh
just check lint test        # from the repository root
just image-privacy-wallet   # linux/amd64 image; prints the /tvc_app SHA-256
```

## Local testkit

Unattested. Real handlers, pinned local QOS keys instead of Nitro, a local
Ed25519 key instead of Turnkey. `just headless-e2e` runs it end to end; to run
the image directly:

```sh
just image-privacy-wallet-local
docker run --rm -p 127.0.0.1:44020:44020 \
  -v "/path/to/disposable-keypair.json:/wallet.json:ro" \
  zolana-tvc-privacy-wallet-local:dev --host 0.0.0.0 --wallet-keypair /wallet.json
```

The `local-dev` feature is never enabled in the enclave binary.
