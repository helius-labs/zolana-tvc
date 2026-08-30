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
- `POST /v1/operations` accepts only the four privacy-wallet operations.

`BootstrapKeyholder` is also the recovery and Quorum-rotation flow. Turnkey
deterministically signs a fixed derivation message, TVC derives the same public
shielded identity, and the client accepts a replacement checkpoint only when
that identity matches the one already recorded.

Ciphertext discovery is relayed through the browser. When asked for spendable
balances, TVC validates the pool's classic SPL registry and reconciles owned
nullifiers against compile-time-pinned services. Direct transitions are built
inside TVC. For an ecosystem program, TVC proves the common SPP transition and
then validates the complete program transaction against the sealed
authorization capsule. The current development prover receives the complete
plaintext witness, including `nullifier_secret`; this app must not hold
production funds.

Run the app gate from the repository root:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --all-features --locked
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
