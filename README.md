# Zolana TVC privacy wallet

An attested privacy-wallet backend for Zolana, built on Turnkey Verifiable
Compute. The TVC application holds the shielded seed, viewing key, and
nullifier key; the browser holds only public identity, an opaque sealed
checkpoint, and transaction bookkeeping.

This repository is a pre-production implementation for disposable devnet
funds. Its external prover currently receives a plaintext witness containing
the long-lived nullifier secret. See [Security](docs/security.md) before using
the code.

## Components

| Path | Purpose |
| --- | --- |
| [`apps/privacy-wallet`](apps/privacy-wallet) | The HTTP/1 TVC application and an explicitly unattested local harness. |
| [`packages/tvc-wallet`](packages/tvc-wallet) | Typed TypeScript client, release/Boot Proof verification, browser persistence, and React bindings. |
| [`crates/protocol`](crates/protocol) | Strict wire types, RFC 8785/JCS, digests, P-256 client auth, QOS envelopes, and release policies. |
| [`crates/keypair-turnkey`](crates/keypair-turnkey) | Narrow Turnkey-backed `ShieldedKeypairTrait` implementation. |
| [`crates/proof-verifier`](crates/proof-verifier) | Operator-side Turnkey and Nitro evidence inspection tools. |

The service exposes four closed operations: `BootstrapKeyholder`,
`DeriveViewTags`, `DecryptUtxos`, and `AuthorizeSpend`. `AuthorizeSpend` has a
built-in adapter for transfer/unshield and a program-neutral, private-only SPP
path for ecosystem programs. The generic path is exercised by canonical Zolana
swap `make`, order discovery, `take`, and `cancel` flows on devnet. The service does not expose a generic message
signer, wallet export, or raw privacy key.

Default- and custom-ring spends are built inside TVC. The existing Turnkey
Ed25519 wallet is both shielded owner and fee payer, so one Turnkey signature
authorizes both roles without exporting the derivation seed.

## Architecture

The browser verifies an independently signed release policy and AWS Nitro Boot
Proof before operations become available. Requests and results use the QOS
P-256 envelope and are bound to the exact release, wallet descriptor, client
key, operation, and sealed-state digest.

Read synchronization is client-relayed: TVC derives view tags, the browser
queries the indexer, and TVC decrypts returned ciphertexts. For a built-in
spend, TVC returns an unsigned transaction with a short-lived sealed capsule;
finalize accepts only that exact transaction. For an ecosystem spend, TVC
returns a proved SPP transition; the ecosystem SDK binds one target-program
instruction to its `private_tx_hash`, and finalize permits no executable
account except the shielded pool and the read-only System Program required by
the SPP account ABI. Both paths ask Turnkey to sign once only during finalize.
The selected ecosystem program is part of the user's trust decision: like any
Solana program receiving a wallet signer, TVC cannot prove arbitrary outer CPI
behavior from instruction bytes alone.

A custom-ring boundary transition uses the same `AuthorizeSpend` operation as
a default-ring spend. `Exit` consumes ring-bound inputs and emits into the
default pool; `Enter` consumes caller-named default-pool commitments and emits
into the target ring. A ring-to-ring move composes those two transitions through
an exact self-owned default note. Each custom-ring transaction travels as a v0
message over a lookup table that the application verifies against the accounts
the instruction needs.

Read [Architecture](docs/architecture.md), [Wallet flows](docs/wallet-flows.md),
the detailed [privacy-wallet profile](docs/privacy-wallet.md), and the
[open-ecosystem refactor](docs/open-ecosystem-refactor.md). The exact outbound
network boundary and current production gap are documented in
[TVC egress](docs/egress.md).

## Development

The repository uses Cargo, pnpm 9, and `just`:

```sh
just setup
just check
just test
```

Build the production-shaped `linux/amd64` image with:

```sh
just image-privacy-wallet
```

Deployment requires a dedicated TVC app, Quorum key, pinned single-platform OCI
digest, independently signed release policy, and wallet descriptor. See
[Deployment](docs/deployment.md).

## License

Reusable protocol, client, and keypair code is Apache-2.0. The TVC application
links AGPL QOS crates and is AGPL-3.0-only; see the individual manifests.
