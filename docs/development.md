# Development

Requirements: Rust stable, Node.js 24+, Docker with `linux/amd64` support, and
pnpm 9. The repository pins dependencies through Cargo and pnpm lockfiles.

```sh
just setup
just fmt-check
just lint
just test
```

Focused commands:

```sh
cargo test -p zolana-tvc-protocol
cargo test --manifest-path apps/privacy-wallet/Cargo.toml --all-targets --all-features --locked
cargo test --manifest-path crates/keypair-turnkey/Cargo.toml --locked
cargo test --manifest-path crates/proof-verifier/Cargo.toml --locked
npx --yes pnpm@9.15.0 --filter @zolana/tvc-wallet test
npx --yes pnpm@9.15.0 --filter @zolana/tvc-wallet typecheck
npx --yes pnpm@9.15.0 --filter @zolana/tvc-wallet build
```

Build images with `just image-privacy-wallet` or the explicitly unattested
`just image-privacy-wallet-local`. The local harness is a protocol smoke test,
not an enclave verifier.

Generated protocol fixtures are committed under `crates/protocol/fixtures`.
Running the protocol conformance test refreshes them; review fixture and
manifest diffs together.

Never commit Turnkey operator files, API private keys, `.env.local`, sealed
wallet state, or Docker pull credentials.
