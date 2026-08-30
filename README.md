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
| [`examples/private-swap`](examples/private-swap) | TVC integration for the canonical Zolana confidential swap SDK and prover. |

The service exposes four closed operations: `BootstrapKeyholder`,
`DeriveViewTags`, `DecryptUtxos`, and `AuthorizeSpend`. `AuthorizeSpend` has a
direct path for transfer/unshield and a program-neutral SPP path for ecosystem
programs. Both use the same prepare/finalize handshake. The program path is
exercised by canonical Zolana swap `make`, order discovery, `take`, and
`cancel` flows on devnet. The service does not expose a generic message signer,
wallet export, or raw privacy key.

Default- and custom-ring spends are built inside TVC. The existing Turnkey
Ed25519 wallet is both shielded owner and fee payer, so one Turnkey signature
authorizes both roles without exporting the derivation seed.

## Architecture

The browser verifies an independently signed release policy and AWS Nitro Boot
Proof before operations become available. Requests and results use the QOS
P-256 envelope and are bound to the exact release, wallet descriptor, client
key, operation, and sealed-state digest.

Read synchronization is split: the browser relays ciphertext discovery, TVC
decrypts candidates, then TVC loads and validates the shielded pool's classic
SPL registry and uses its nullifier role against pinned services to return the
currently spendable commitments and balances. For a direct spend, TVC returns
an unsigned transaction with a short-lived sealed capsule; finalize accepts
only that exact transaction. For an ecosystem spend, TVC returns a proved SPP
transition. The ecosystem SDK builds a complete Solana transaction whose
target-program instruction contains the prepared `private_tx_hash`. Finalize
verifies that private binding while allowing normal user-approved Solana
composition, refreshes the program transaction's blockhash, and asks Turnkey
to sign once. TVC fixes the private economic effects; the selected ecosystem
program and any additional public behavior remain the same user trust decision
as in a conventional Solana wallet.

A direct spend names source and destination domains. `Ring(A) -> Ring(A)` stays
in A, `Ring(A) -> Default` moves to the default pool, and `Default -> Ring(A)`
moves into A. A ring-to-ring move composes two transitions through an exact
self-owned default UTXO. Each custom-ring transaction travels as a v0 message
over a lookup table that the application verifies against the accounts the
instruction needs.

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
