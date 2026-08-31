# Zolana TVC privacy wallet

An attested privacy-wallet backend for Zolana, built on Turnkey Verifiable
Compute. The TVC application holds the shielded seed, viewing key, and
nullifier key. The browser holds only the public identity, an opaque sealed
checkpoint, and transaction bookkeeping.

This repository is a pre-production implementation for disposable devnet
funds. Its external prover currently receives a plaintext witness containing
the long-lived nullifier secret. Read [Network boundary](#network-boundary)
before using the code.

## Components

| Path | Purpose |
| --- | --- |
| [`apps/privacy-wallet`](apps/privacy-wallet) | The HTTP/1 TVC application and an explicitly unattested local harness. |
| [`packages/tvc-wallet`](packages/tvc-wallet) | Typed TypeScript client, release/Boot Proof verification, browser persistence, and React bindings. |
| [`crates/protocol`](crates/protocol) | Strict wire types, RFC 8785/JCS, digests, P-256 client auth, QOS envelopes, and release policies. |
| [`crates/keypair-turnkey`](crates/keypair-turnkey) | Narrow Turnkey-backed `ShieldedKeypairTrait` implementation. |
| [`crates/proof-verifier`](crates/proof-verifier) | Operator-side Turnkey and Nitro evidence inspection tools. |
| [`examples/private-swap`](examples/private-swap) | TVC integration for the canonical Zolana confidential swap SDK and prover. |
| [`examples/headless-wallet`](examples/headless-wallet) | Minimal Node client exercising the full verified flow. |

The normative wire contract is [`docs/spec.md`](docs/spec.md).

## Trust model

HTTPS does not establish enclave identity. The client connects in four steps
and refuses wallet calls until all of them pass.

1. Verify an independently distributed, threshold-signed `ReleasePolicyV1`
   against pinned release authorities. The verifier also compares the policy's
   Turnkey trust-root id with a client constant and its revocation epoch with
   an independently pinned minimum, so authorities can revoke a signed,
   unexpired policy.
2. Fetch `GET /v1/info` as untrusted discovery and bind every security-relevant
   field to that policy.
3. Complete the QOS ping: a Quorum-encrypted challenge answered with an App
   Proof signed by the replica's Ephemeral key.
4. Fetch and verify the matching AWS Nitro Boot Proof against pinned PCRs and
   the accepted manifest digests.

The result is an opaque `VerifiedConnection`. No wallet operation accepts a raw
URL or an unverified discovery object.

## Operations

The service exposes four closed operations over one encrypted endpoint. It
does not expose a generic message signer, wallet export, or raw privacy key.

- `BootstrapKeyholder` derives the stable shielded identity from a fixed,
  deterministic Turnkey signature and returns the public identity plus a seed
  sealed to the QOS Quorum key.
- `DeriveViewTags` returns the wallet's stable recipient tags, one per viewing
  key held.
- `DecryptUtxos` decrypts browser-relayed ciphertexts in bounded batches and
  optionally returns the spendable-output snapshot the enclave reconciled
  against pinned services.
- `AuthorizeSpend` is a two-phase protocol. Prepare proves and seals an exact
  transition. Finalize revalidates the sealed capsule against one complete
  transaction and asks Turnkey for a single signature.

The application is replica-stateless. The browser persists the sealed blob as
its checkpoint and presents it on key-dependent calls. Every result is
encrypted to a one-time client response key, and its App Proof binds the
request digest, encrypted-result digest, operation, and the digest of the
exact sealed state answered against.

The existing Turnkey Ed25519 wallet is both shielded owner and fee payer, so
one Turnkey signature authorizes both roles without exporting the derivation
seed.

## Spend rails

### Direct transitions

A direct plan names source and destination domains, either `Default` or
`Ring { program_id, lookup_table }`. The route is derived from the pair.

| Source | Destination | Meaning |
| --- | --- | --- |
| Default | Default | Default-pool private transfer |
| Ring(A) | Ring(A) | Private transfer remaining in A |
| Ring(A) | Default | Move privately from A to the default pool |
| Default | Ring(A) | Move into A using exact named bridge UTXOs |
| Ring(A) or Default | Public | Withdraw to SOL or a derived classic SPL token account |

Prepare returns one complete unsigned transaction and a short-lived sealed
capsule committing to its exact bytes. Finalize accepts only those bytes. The
ring named in a spend is caller input on every request, so a new ring needs no
re-provisioning. The rail's gates are the deployed ring circuit and the ring
program's own on-chain policy.

### Consolidation

Ordinary transact circuits accept at most five inputs. When a default-domain
balance is too fragmented, the wallet runs `Consolidate { asset }` through the
same prepare/finalize protocol. Zolana's fixed `merge_8_1` rail replaces up to
eight plain same-asset UTXOs with one same-owner UTXO. Consolidation is
balance-neutral and valid only in the default domain.

### Ring-to-ring movement

Direct Ring(A) to Ring(B) is deliberately invalid, a wallet composes it. Leg
one moves the exact amount from the source ring to a self-owned default UTXO.
After the indexer exposes that commitment, leg two spends exactly that bridge
UTXO into the destination ring. The exact-sum rule keeps any other default
balance from becoming ring-bound as change. The browser persists each phase,
so a reload resumes the pending leg instead of losing it.

### Ecosystem programs

A `Program` plan declares a program-neutral SPP transition: target program,
input tree, circuit shape, wallet and program-PDA-owned inputs, declared
program-authority seeds, shielded outputs, messages, and a short expiry. TVC
rediscovers the inputs, verifies openings and exact per-asset conservation,
proves the common transition, locally verifies the proof, and seals the exact
serialized transact behind `private_tx_hash`.

The ecosystem SDK then builds its own program proof and a complete Solana
transaction in which exactly one target instruction carries that hash.
Finalize checks the capsule, target, hash binding, sole wallet signer, lookup
tables, tree, pool interface, and declared program authorities, refreshes the
blockhash, and signs once through Turnkey.

TVC fixes the private economic effects. The selected program and any
additional user-approved instructions receive the same trust as in a
conventional Solana wallet transaction. An integrating program needs the
Zolana SPP `transact` interface, an authorization rule bound to
`private_tx_hash`, and an SDK that declares the transition and assembles the
final transaction. It does not need a new TVC operation, an adapter registry,
a caller-selected prover, or an enclave release. The canonical Zolana swap
`make`, order discovery, `take`, and `cancel` flows exercise this path on
devnet through [`examples/private-swap`](examples/private-swap).

## Wallet lifecycle

**Bootstrap and recovery.** The sealed blob is a cache, the Turnkey wallet is
the recovery root. The bootstrap input is a fixed message and Ed25519
signatures are deterministic, so the same Turnkey wallet always reproduces the
same seed. After blob loss or Quorum rotation the client verifies the
replacement release, bootstraps without old state, and accepts the new blob
only when every public identity field matches the identity it already knows.
Losing the underlying Turnkey wallet requires Turnkey custody recovery.

**Synchronization.** Reads are split. TVC derives tags, the browser queries
the indexer, and TVC decrypts the returned ciphertexts. The spendable-output
snapshot is enclave-owned because it needs the nullifier role: TVC validates
the pool's classic SPL registry, reconstructs owned UTXOs, and reconciles
nullifiers against the pinned index. The client keeps a decrypted opening only
when its owner matches the wallet identity and its commitment appears in the
snapshot, because the transport cipher is unauthenticated.

**Submission.** Registration and deposits need no privacy secret, so the
browser builds and submits them with the ordinary Turnkey wallet session.
Signed private transactions are journaled before submission. A timeout is an
unknown outcome, not a failure. The journal entry is cleared only on a
definitive chain failure or proven blockhash expiry, and a confirmed spend
cannot land twice because its nullifier is unique. Token-2022 is unsupported.

## Network boundary

Callers cannot select a network origin. Every destination is compiled into the
measured executable, so changing one changes the executable digest and needs a
new reviewed release. QOS currently provides a transparent outbound bridge,
not a per-host allowlist, so the application binary is the only destination
boundary today.

| Destination | Transport | Used by |
| --- | --- | --- |
| `api.turnkey.com` | HTTPS | Bootstrap signing and finalize signing |
| `api.devnet.solana.com` | HTTPS-only client | Chain reads during snapshots, prepare, and generic finalize |
| `zolnet-devnet-*.elb.amazonaws.com` | Plain HTTP | Indexer sync and default/generic prover witnesses |
| `d30sgubc9yxiri.cloudfront.net` | HTTPS | Custom-ring prover witnesses |

Sensitive disclosures inside that boundary: Turnkey can reproduce the
deterministic bootstrap seed, the indexer can link the tags and commitments an
enclave-owned spend queries, and the current prover receives a plaintext
witness containing private inputs, amounts, and the long-lived
`nullifier_secret`. Local Groth16 verification prevents an invalid prover
response from authorizing a different transition, but nothing makes the
witness confidential.

Production therefore requires, before real funds: proving inside the enclave
or an independently attested prover over a channel bound to that attestation,
replacement of the plain-HTTP development origin, an external
VPC/firewall/proxy enforcing the same destination set, and production release
governance with monitoring, rotation, and revocation procedures. Adding TLS
alone is insufficient because the prover process still reads the secret.

## Security properties

- Unknown and duplicate JSON fields are rejected. Wire integers and binary
  encodings are canonical.
- The release policy is verified before discovery, and discovery, App Proof,
  and Boot Proof must describe the same release and boot.
- Requests are signed with a non-exportable browser P-256 key and bound to
  release, descriptor, operation, expiration, response key, and checkpoint.
- The derivation seed never leaves the enclave. State is sealed to the wallet
  descriptor and Quorum epoch.
- Signing is limited to the fixed bootstrap message and the exact
  capsule-validated transaction. Production descriptors and mainnet are
  rejected.
- Turnkey policy evidence stays `CryptographicallyValidButUnbound`: the
  available proof does not bind `decisionContextDigest`, so the code never
  labels it `Verified`.

## Development

Rust (pinned by `rust-toolchain.toml`), Node.js 24+, pnpm 9, Docker with
`linux/amd64`, and `just`:

```sh
just setup
just ci
```

`just ci` runs formatting, clippy, every Rust suite, the committed-fixture
check, the private-swap example, and the TypeScript chain. The swap example
path-depends on a sibling `zolana` checkout next to this repository.
Regenerate protocol fixtures with `just regenerate-protocol-fixtures` and
review fixture and manifest diffs together, the TypeScript conformance suite
reads the committed files.

Rust intentionally uses three lock domains: the root workspace holds the
protocol and TVC application, `keypair-turnkey` isolates the full Zolana RPC
test graph from QOS's pinned runtime, and `proof-verifier` isolates the
operator-side verification graph from enclave code.

Never commit Turnkey operator files, API private keys, `.env.local`, sealed
wallet state, or Docker pull credentials.

## Deployment

Each deployment needs its own Turnkey TVC app, Quorum key, single-platform
`linux/amd64` OCI image pinned by `@sha256:`, signed release policy, and
wallet descriptor. Build with `just image-privacy-wallet` and record both the
OCI manifest digest and the printed `/tvc_app` SHA-256, the latter becomes
`expectedPivotDigest`. Never deploy the local harness image.

Validate a deployment descriptor before submitting it:

```sh
just deploy-preflight apps/privacy-wallet/deploy/<release>.deployment.json
```

The committed descriptors under `apps/privacy-wallet/deploy/` are the release
ledger. The preflight checks release-id and pivot-digest uniqueness against
them, so removing one silently disables that check. A release ID is immutable
signed deployment data, use a new one for every executable or protocol change.

Sign the release policy after the deployment answers `/v1/info`, because the
accepted manifest digest is only readable from a live deployment:

```sh
cargo run -p zolana-tvc-protocol --example sign-release-policy \
    -- policy.json <release-id>-<yyyy-mm>
```

The authority private key is generated, used once, and discarded. A policy
cannot be quietly re-signed later, re-signing requires a new authority set
every client must be updated to accept.

The relying party holds two Turnkey credentials on different rotation clocks.
`TVC_PROVISIONING_KEY_JSON` signs wallet descriptors and its public half is
pinned in the image, treat it as release material. `TVC_TURNKEY_API_KEY_JSON`
only reads Turnkey and can rotate freely. Deployment is complete when a client
verifies the release, ping, Boot Proof, and a descriptor-bound bootstrap
without bypass flags.

## License

Reusable protocol, client, and keypair code is Apache-2.0. The TVC application
links AGPL QOS crates and is AGPL-3.0-only, see the individual manifests.
