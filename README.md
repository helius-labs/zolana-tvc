# Zolana TVC

Attested Turnkey Verifiable Cloud components for Zolana private wallets. This
repository contains two explicit deployment applications on one `main` branch;
they are separate binaries and images, not Cargo features or long-lived source
branches.

| Application | Privacy boundary | TVC responsibilities | Status |
| --- | --- | --- | --- |
| [`client-wallet`](apps/client-wallet) | Authenticated wallet client | Deterministic bootstrap and bounded default-ring authorization | Preferred development profile |
| [`enclave-wallet`](apps/enclave-wallet) | TVC enclave | Bootstrap, wallet sync, proving, transaction construction, and bounded signing | Full reference profile |

Both applications share [`zolana-tvc-protocol`](crates/protocol), Boot/App Proof
verification, and operator tooling. They must use different TVC applications,
Quorum keys, manifests, release policies, and OCI images. Never deploy one
profile over the other profile's application.

The repository is development-only: production descriptors and production
funds remain unsupported. Turnkey policy evidence is
`CryptographicallyValidButUnbound` because Turnkey does not currently bind its
decision-context digest to the exact activity.

## Repository layout

- `crates/protocol`: canonical wire types, JCS, digests, P-256 authorization,
  QOS envelopes, fixtures, and release-policy verification.
- `crates/proof-verifier`: host-side Boot/App Proof verifier, provisioner, and
  full-profile E2E harness.
- `apps/client-wallet`: small attested backend for the client-owned wallet
  architecture used by `@zolana/tvc-wallet`.
- `apps/enclave-wallet`: enclave-owned wallet reference implementation retained
  as a separately buildable deployment profile.
- `spec`: normative English specification and its Russian translation. English
  wins for byte and field formats.

The TypeScript client and product demo stay in the sibling `wallet-kit`
repository. This repository owns the attested applications, wire protocol, and
operator-side proof/provisioning tools; it does not duplicate the UI SDK.

Each deployable application is an independently locked Cargo workspace. This is
intentional: a change to one image cannot silently alter the other image's
dependency graph. The shared protocol remains the small root workspace, while
`crates/proof-verifier` is also independent because Turnkey's official verifier
uses QOS `0.12.2` and the applications use QOS `0.12.1`.

## Local Zolana dependency

This initial local extraction is pinned by provenance to Zolana commit
`865ed56a` and expects the sibling checkout at `../zolana`. Before publishing
this repository, replace those path dependencies with released crates or an
immutable Git revision and run the same compatibility suite.

No Git remote is configured by this extraction. Add the final source URL to the
Cargo metadata and OCI labels when the repository is published.

```sh
cargo test -p zolana-tvc-protocol
cargo test --manifest-path apps/client-wallet/Cargo.toml --all-features --locked
cargo test --manifest-path apps/enclave-wallet/Cargo.toml --all-features --locked
cargo check --manifest-path crates/proof-verifier/Cargo.toml --all-targets --locked
```

The protocol and verifier are Apache-2.0. The QOS-linked application binaries
are AGPL-3.0-only; see `LICENSE` and `LICENSE-AGPL`.
