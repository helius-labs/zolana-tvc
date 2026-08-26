# Development

## Prerequisites

- Rust `1.97` for repository development (pinned by `rust-toolchain.toml`)
- Node.js `24` and pnpm `9.15.0` for `@zolana/tvc-wallet`
- [just](https://just.systems/)
- Docker with `linux/amd64` support for image builds

The product demo remains in the separate `wallet-kit` repository and consumes
the TypeScript package from this repository. Zolana Rust crates and the
TypeScript SDK are pinned to the same immutable upstream commit.

The application manifests declare Rust `1.94` as their minimum version and the
deployment Dockerfiles build with the pinned StageX Rust `1.94` image. The
newer repository toolchain is used for formatting, linting, and local checks.

## Standard commands

Run `just --list` for the complete command surface. The common workflows are:

```sh
just doctor       # verify the Rust and Node.js toolchains
just fmt-check    # check formatting in all five Cargo workspaces
just check        # cargo check every workspace with its lockfile
just lint         # clippy every workspace with warnings denied
just test         # run all hermetic tests
just install-ts   # install the pinned pnpm workspace
just ci-ts        # lint, typecheck, test, and build the TypeScript package
just ci           # complete Rust and TypeScript gate
```

Each profile and shared crate also has an individual recipe, for example
`just test-client-wallet` or `just test-keypair-turnkey`.

## Independent workspaces

The root workspace contains only `crates/protocol`. The Turnkey keypair backend,
each deployable application, and the proof verifier are nested Cargo workspaces
with their own `Cargo.lock`. Always use the checked-in lockfiles. Do not merge
the workspaces to deduplicate build output: that would let one release change
another release's resolved dependency graph and would conflict with the exact
Turnkey, Solana, and QOS versions.

Current QOS pins are:

- application runtime and protocol interop: `0.12.1`;
- official host-side proof verifier: `0.12.2`.

## Fixtures and protocol changes

The protocol conformance tests generate and verify the content-addressed files
under `crates/protocol/fixtures`. A wire-format change must update the English
specification, Rust tests, fixtures and manifest, and TypeScript conformance
tests together. The TypeScript tests read the canonical Rust fixtures directly;
there is no second copy to synchronize. The English specification wins for
field and byte formats.

## Images

The application manifests use immutable Zolana Git dependencies, so each image
build uses this repository alone as its context:

```sh
just image-client-wallet
just image-enclave-wallet
```

Local unattested harness images are available as
`just image-client-wallet-local` and `just image-enclave-wallet-local`. They use
disposable mock custody, produce no Boot Proof, and must never be deployed or
funded.

## Before publishing the repository

Rerun `just ci`, configure the final Git remote, and add that source URL to
Cargo package metadata and OCI labels.
