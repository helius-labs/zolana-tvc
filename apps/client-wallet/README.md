# Zolana Lightweight TVC Service

This development profile makes the authenticated wallet client the privacy
boundary and keeps TVC as a small attested bootstrap/authorization service.
See [`ARCHITECTURE.md`](ARCHITECTURE.md) for the complete boundary and its
trade-offs.

The service exposes:

- `GET /health` with exact body `{"status":"Healthy"}`;
- `GET /v1/info` as untrusted discovery;
- `POST /v1/ping` for the QOS Quorum-encryption/Ephemeral-signing challenge;
- `POST /v1/operations` for only `BootstrapClientEd25519` and
  `AuthorizeDefaultRingTransfer`.

It does not link or call the Zolana indexer, Solana RPC, prover, transaction
builder, or wallet-sync crates. The client runs those components and stores its
own encrypted derivation seed and wallet state. The Rust SDK reconstructs the
local privacy boundary with `ClientEd25519WalletAuthority`; that type cannot
sign a Solana transaction.

`BootstrapClientEd25519` returns secret derivation material only inside the
QOS-encrypted response addressed to the authenticated client's one-time key.
`AuthorizeDefaultRingTransfer` accepts only a bounded compute-budget prefix and
one final Zolana `TRANSACT` instruction for the descriptor-bound sole signer.
That bounded shape covers both confidential transfers and public withdrawals;
clients domain-separate their authenticated intents. It is not a generic
signing endpoint.

This is not compatible with the previously deployed full-wallet TVC release.
It requires a new image, manifest, signed release policy, wallet descriptor,
and client implementation. It must not be used with production funds.

The binary links QOS 0.12.1, which is AGPL-3.0-only. This application crate is
therefore AGPL-3.0-only and is not published as a reusable library.

Run tests from the repository root:

```sh
cargo test --manifest-path apps/client-wallet/Cargo.toml --all-features --locked
```

Build the enclave image:

```sh
docker build \
  --platform linux/amd64 \
  --provenance=false \
  -f apps/client-wallet/Dockerfile \
  ..
```

The build prints the SHA-256 digest of `/tvc_app`. The deployment must pin both
that pivot digest and a single-platform OCI `@sha256:` manifest.

## Local bootstrap harness

`Dockerfile.local` remains an explicitly unattested bootstrap smoke test. It
uses a disposable in-process mock signer and returns public address material
only. It does not call Turnkey, produce a Boot Proof, or exercise the encrypted
client-material operation.

```sh
docker build \
  --platform linux/amd64 \
  --provenance=false \
  -f apps/client-wallet/Dockerfile.local \
  -t zolana-tvc-client-wallet-local:dev \
  ..

docker run --rm \
  --name zolana-tvc-client-wallet-local \
  -p 127.0.0.1:44020:44020 \
  zolana-tvc-client-wallet-local:dev
```
