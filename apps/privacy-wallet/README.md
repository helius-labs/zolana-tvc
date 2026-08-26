# Privacy-wallet TVC application

The application keeps the shielded seed, viewing key, and nullifier key out of
browser JavaScript. It is replica-stateless: the browser carries opaque key
state sealed to the QOS Quorum key, and TVC opens it only while executing a
typed request.

Routes:

- `GET /health` returns exactly `{"status":"Healthy"}` when ready.
- `GET /v1/info` returns untrusted discovery bound by the client to a signed
  release policy.
- `POST /v1/ping` completes the QOS connection challenge.
- `POST /v1/operations` accepts only the six privacy-wallet operations.

`BootstrapKeyholder` is also the recovery and Quorum-rotation flow. Turnkey
deterministically signs a fixed derivation message, TVC derives the same public
shielded identity, and the client accepts a replacement checkpoint only when
that identity matches the one already recorded.

Read synchronization is relayed through the browser. Private transfers and SOL
withdrawals are built inside TVC against compile-time-pinned services. The
current development prover receives the complete plaintext witness, including
`nullifier_secret`; this app must not hold production funds.

Run the app gate from the repository root:

```sh
cargo fmt --manifest-path apps/privacy-wallet/Cargo.toml --all -- --check
cargo clippy --manifest-path apps/privacy-wallet/Cargo.toml --all-targets --all-features --locked -- -D warnings
cargo test --manifest-path apps/privacy-wallet/Cargo.toml --all-targets --all-features --locked
```

Build the production-shaped `linux/amd64` image:

```sh
just image-privacy-wallet
```

The local harness is explicitly unattested and exists only for protocol smoke
tests:

```sh
just image-privacy-wallet-local
docker run --rm \
  --name zolana-tvc-privacy-wallet-local \
  -p 127.0.0.1:44020:44020 \
  zolana-tvc-privacy-wallet-local:dev
```

Its `/dev/v1/bootstrap-ed25519` route is not compiled into `/tvc_app`.

See [Architecture](ARCHITECTURE.md) and the detailed
[profile](../../docs/privacy-wallet.md).
