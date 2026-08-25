# Zolana TVC

Attested Turnkey Verifiable Cloud applications for Zolana private wallets.
The repository keeps two privacy boundaries explicit and independently
deployable while sharing one canonical wire protocol and proof-verification
toolchain.

> [!WARNING]
> This is a development proof of concept. Production descriptors, mainnet, and
> production funds are intentionally unsupported.

## Choose a profile

| Profile | Privacy boundary | Runs in TVC | Use when |
| --- | --- | --- | --- |
| [`client-wallet`](apps/client-wallet) | Authenticated wallet client | Bootstrap and bounded default-ring transaction authorization | You want the smaller, preferred development profile and accept that the client sees private wallet state. |
| [`enclave-wallet`](apps/enclave-wallet) | TVC enclave | Bootstrap, wallet sync, proving, transaction construction, and bounded signing | You need the full enclave-owned reference design and its larger operational surface. |

These are separate applications, OCI images, dependency locks, TVC app IDs,
Quorum keys, manifests, and release policies. They are not feature modes and
do not live on long-running alternative branches.

## Quick start

With the pinned Rust toolchain, Node.js 24, and
[just](https://just.systems/) installed:

```sh
just doctor
just test
```

Run the complete local gate with:

```sh
just ci
```

`just --list` shows the individual profile, formatting, lint, and image
recipes.

## Repository map

```text
apps/
  client-wallet/       lightweight, client-owned privacy profile
  enclave-wallet/      full, enclave-owned privacy profile
crates/
  keypair-turnkey/     Turnkey-backed ShieldedKeypairTrait implementation
  protocol/            strict wire types, JCS, digests, auth, QOS envelopes
  proof-verifier/      official Boot/App Proof verification and operator tools
packages/
  tvc-wallet/          TypeScript protocol, browser, shielded-wallet, and React client
docs/                   architecture, security, development, and deployment
spec/                   normative English spec and Russian translation
```

The TypeScript client lives with the protocol and attested applications. The
product demo remains in `wallet-kit` as a downstream integration consumer; the
generic wallet kit does not own TVC protocol or verification internals.

## Documentation

- [Documentation index](docs/README.md)
- [Architecture and profile selection](docs/architecture.md)
- [Security model and known gaps](docs/security.md)
- [Development and verification](docs/development.md)
- [Deployment model](docs/deployment.md)
- [Normative TVC specification](spec/TVC_SPEC.md)
- [Russian specification](spec/TVC_SPEC_RU.md)

The English specification is authoritative for byte and field formats. The
shorter documents explain the implementation; they do not redefine the
protocol.

## Dependency and release isolation

Each deployable application has its own Cargo workspace and `Cargo.lock`, so a
dependency update for one image cannot silently change the other. The protocol
uses the small root workspace. The Turnkey keypair backend and proof verifier
are independently locked, keeping their Turnkey and operator dependency graphs
out of the protocol lock. The official verifier uses QOS `0.12.2`, while both
TVC applications currently use QOS `0.12.1`.

The Rust applications and TypeScript package depend on immutable Zolana commit
`17e97dd72fd0831a5a743d0f86a9185ad7109849`. Cargo lockfiles and the pnpm
lockfile preserve the resolved dependency graphs independently of a moving
branch.

## License

The protocol and proof verifier are Apache-2.0. The QOS-linked application
binaries are AGPL-3.0-only. See [LICENSE](LICENSE) and
[LICENSE-AGPL](LICENSE-AGPL).
