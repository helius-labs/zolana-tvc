# Development

## Prerequisites

- Rust `1.97` for repository development (pinned by `rust-toolchain.toml`)
- [just](https://just.systems/)
- Docker with `linux/amd64` support for image builds
- the Zolana repository checked out as the sibling `../zolana`

The TypeScript client and demo are developed separately in sibling
`../wallet-kit`.

The application manifests declare Rust `1.94` as their minimum version and the
deployment Dockerfiles build with the pinned StageX Rust `1.94` image. The
newer repository toolchain is used for formatting, linting, and local checks.

## Standard commands

Run `just --list` for the complete command surface. The common workflows are:

```sh
just doctor       # verify the toolchain and sibling checkout
just fmt-check    # check formatting in all five Cargo workspaces
just check        # cargo check every workspace with its lockfile
just lint         # clippy every workspace with warnings denied
just test         # run all hermetic tests
just ci           # formatting, lint, and tests
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
specification, Rust tests, fixtures and manifest, and the corresponding fixture
copy in the TypeScript client together. The English specification wins for
field and byte formats.

## Images

The application manifests use sibling Zolana path dependencies, so Docker must
build with the parent directory as its context. The recipes do this for you:

```sh
just image-client-wallet
just image-enclave-wallet
```

Local unattested harness images are available as
`just image-client-wallet-local` and `just image-enclave-wallet-local`. They use
disposable mock custody, produce no Boot Proof, and must never be deployed or
funded.

## Before publishing the repository

Replace sibling path dependencies with released Zolana crates or immutable Git
revisions, rerun `just ci`, configure the final Git remote, and add that source
URL to Cargo package metadata and OCI labels.
