# Zolana Keyholder TVC Service

This development profile keeps the shielded seed, viewing key, and nullifier
key inside the attested enclave while leaving indexer, prover, Solana RPC,
wallet sync, and transaction construction in the authenticated client. The
complete trust model is in [`../../docs/keyholder-profile.md`](../../docs/keyholder-profile.md).

The service exposes:

- `GET /health` with exact body `{"status":"Healthy"}`;
- `GET /v1/info` as untrusted discovery;
- `POST /v1/ping` for the QOS Quorum-encryption/Ephemeral-signing challenge;
- `POST /v1/operations` for `BootstrapKeyholder`, `DeriveViewTags`,
  `DecryptUtxos`, and `AuthorizeDefaultRingTransfer` only.

`BootstrapKeyholder` obtains the fixed deterministic Ed25519 derivation
signature from Turnkey, derives the public shielded identity, and returns the
seed sealed to the QOS Quorum key. The seed is never returned to the client.
The sealed blob is a recoverable cache: after a release or Quorum-key rotation,
the client verifies the new release, bootstraps again, and refuses to adopt it
unless the public identity matches the identity it already knows.

`DeriveViewTags` and `DecryptUtxos` unseal that state for one request and make no
network calls. Tag windows are capped at 512 and decryption batches at 256.
The client fetches ciphertexts from the indexer and must deserialize each
plaintext and verify its owner; the unauthenticated shielded transport cipher
cannot itself distinguish another wallet's payload from garbage.

`AuthorizeDefaultRingTransfer` is the existing narrow signing rail. It accepts
only a bounded compute-budget prefix and one final Zolana `TRANSACT`
instruction for the descriptor-bound sole signer. It is not a generic message
or transaction signing API.

Only bootstrap and transaction authorization use egress, and they reach
Turnkey only. The source has no indexer, prover, Solana RPC, or wallet-sync
transport. Spending still needs a settled proof-request design before the
keyholder profile is complete; the current demo exercises verified connection,
sealed bootstrap, and relayed sync.

This application is a separate TVC identity from the client-owned and full
enclave profiles. It needs its own image, app ID, Quorum key, manifest, signed
release policy, descriptor, and review line. It must not be used with
production funds.

The binary links QOS 0.12.1, which is AGPL-3.0-only. This application crate is
therefore AGPL-3.0-only and is not published as a reusable library.

Run its gate from the repository root:

```sh
cargo fmt --manifest-path apps/keyholder-wallet/Cargo.toml --all -- --check
cargo clippy --manifest-path apps/keyholder-wallet/Cargo.toml --all-targets --all-features --locked -- -D warnings
cargo test --manifest-path apps/keyholder-wallet/Cargo.toml --all-targets --all-features --locked
```

Build the production-shaped image with:

```sh
just image-keyholder-wallet
```

The build is single-platform `linux/amd64` and prints the SHA-256 digest of
`/tvc_app`. A deployment must pin both that pivot digest and the OCI manifest by
`@sha256:`.

## Local harness

The local image is explicitly unattested. It uses a disposable in-process mock
signer, has no Boot Proof, and is only a protocol smoke test:

```sh
just image-keyholder-wallet-local
docker run --rm \
  --name zolana-tvc-keyholder-wallet-local \
  -p 127.0.0.1:44020:44020 \
  zolana-tvc-keyholder-wallet-local:dev
```

Its `POST /dev/v1/bootstrap-ed25519` route is not compiled into `/tvc_app` and
must never be treated as the deployed keyholder API.
