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
cargo test --workspace --all-targets --all-features --locked
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

Rust intentionally uses three lock domains: the root workspace contains the
protocol and TVC application; `keypair-turnkey` isolates the full Zolana RPC
test graph from QOS's pinned runtime; and `proof-verifier` isolates the
operator-side Nitro/Turnkey verification graph from enclave code.

Never commit Turnkey operator files, API private keys, `.env.local`, sealed
wallet state, or Docker pull credentials.
