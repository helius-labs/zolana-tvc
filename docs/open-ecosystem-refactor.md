# Open-ecosystem refactor

Plan for a wallet that supports the pseudonymous default ring and anonymous
custom rings, keeps four TVC operations, and needs no TVC release per
third-party ZK program.

## The fact that drives it

ZK programs CPI the shielded pool's `transact`. In `zolana-examples`, both
`swap-program` and `escrow-program` import
`zolana_interface::instruction::tag::TRANSACT`, store no state, own no accounts,
and register no ring. `transact` accepts `ConfidentialEddsa` only, so
authorization is the pool's signer-account check and the owner signs the Solana
transaction. There is no shielded signature on that rail, and `sign_prepared` in
the Zolana wallet SDK signs nothing.

Turnkey signs that transaction, and a Turnkey policy can only name a transaction
structure. Every ZK program the wallet supports is therefore enumerated when the
wallet is provisioned. That is the ceiling.

`RingP256` avoids it. The owner signature is proven in-circuit,
`owner_signer_pubkeys` skips `Curve::P256`, and Turnkey signs a 32-byte digest
under one policy. It is reachable only through `ring_transact`, which needs a
ring's `ring_config` to sign, so it serves custom rings and not ZK programs.

## Rails

| | Default ring | Custom rings |
| --- | --- | --- |
| Owner | Ed25519, identity D | P-256, identity R |
| Instruction | `transact`, `ConfidentialEddsa` | `ring_transact`, `RingP256` |
| Authorization | on-chain signer | in-circuit digest |
| Privacy | pseudonymous | anonymous |
| Hosts | any ZK program, permissionless | ring programs, curated |

One seed, two owner identities, shared roles. `expand_roles` gives one nullifier
key and one viewing key, and both identities take them as supplied roles, which
is the three-key custody pattern the Zolana spec defines for devices that cannot
run key agreement. `owner_hash` is
`poseidon(owner_proof_input_hash(signing_pk), nullifier_pk)`, so the identities
are distinct owners over the same roles. One scan serves both, and the wallet
publishes two receive addresses.

Shielding is a proofless deposit on either rail, so the browser builds and signs
it with no privacy secret.

A ZK program can also be written as a ring program, which puts it on the P-256
rail and inside `SignRingSpend` today. Its value is then captive to that ring,
or it transits the default ring and publishes the owner tag on the leg that
spends a default-ring input.

## Phase 1, devnet

No key leaves the enclave. TVC syncs from its pinned endpoints, selects inputs,
builds the witness, calls the pinned prover, and signs. The client assembles the
transaction and submits it, which needs nothing secret.

| Operation | Bound to a transaction shape |
| --- | --- |
| `BootstrapKeyholder` | no |
| `DeriveViewTags` | no |
| `DecryptUtxos` | no |
| `SignRingSpend` | no |

`SignRingSpend` takes the intent `BuildCustomRingTransfer` takes today and
returns the proof, the encrypted output payloads, and the signature over
`private_tx_hash`.

The enclave keeps sync because `private_tx_hash` chains each input's
`utxo_hash`, `nullifier`, and tree roots with the output hashes, and because a
hash alone does not say whose UTXO it is. An enclave signing a chain the client
assembled would bind structure and not ownership. Reading the chain itself is
what makes the signature mean the wallet authorized its own inputs.

Turnkey no longer inspects a ring spend. The descriptor grants and the release
attestation are the gate on identity R.

The pinned indexer, RPC, and prover egress stays. The prover still receives the
plaintext witness, so this stays devnet for the same reason it is today.

A default-ring spend needs nothing from the enclave. The browser's own Turnkey
session signs the `transact`, as it already does for registration and deposits.

The cost is that session's policy. It has to allow any transaction with the
wallet account, because the invoked program is the ZK program and the pool is
reached only by CPI, so a policy naming the pool blocks every ZK program. A
compromised session can move the wallet's public balance, so keep that balance
small. The shielded balance is already exposed while the browser holds the
nullifier key. The enclave credential is untouched and keeps one digest policy.

Devnet only.

## Phase 2, target

`ConfidentialP256` lands in Zolana and puts digest authorization on `transact`.
Identity D collapses into one P-256 identity, the loose session policy retires,
and one enclave digest policy covers every ZK program.

`SignRingSpend` becomes `AuthorizeSpend`. It takes a spend description, never a
digest, recomputes `private_tx_hash` from the description it validated, and
returns the encrypted payloads, the proof, and the owner signature. Still four
operations.

`AuthorizeSpend` refuses a non-zero `data_hash` unless the descriptor grants
that program. `data_hash` is committed into `utxo_hash` unchecked and the owner
signature authorizes it, so program state is opaque to the enclave. The swap
program's order terms live there.

## Next steps

Nothing below waits on an open question.

1. **Add the P-256 identity.** Put it in `BootstrapKeyholderResult` and the
   sealed state in `crates/protocol`. In the app, `bootstrap_keyholder` builds a
   `TurnkeyP256ShieldedKeypair` with roles from `expand_roles`. Add a second
   Turnkey signing target to the descriptor. Pure addition.
2. **Add `SignRingSpend`.** A new `OperationKind` with its request and result
   types. In the app, reuse the spend path's sync and witness construction, sign
   `private_tx_hash` with identity R instead of asking Turnkey to sign a
   transaction, and return the proof, the encrypted payloads, and the signature.
3. **Move assembly to the client.** Delete `BuildCustomRingTransfer`,
   `BuildCustomRingSolWithdrawal`, and `AuthorizeDefaultRingTransfer`.
   `packages/tvc-wallet` assembles the transaction from what `SignRingSpend`
   returns. Keep `BuildTransfer` and `BuildSolWithdrawal` until the default rail
   moves.
4. **Policies and grants.** One Turnkey digest policy for the enclave
   credential, descriptor grants per ring and per program instead of per
   operation, and the transaction-shape policies retired.

Check during step 2 whether a withdrawal leg may settle inside a
`ring_transact`. If it may not, unshielding from a ring needs another shape and
step 2 grows.

## Later, in Zolana

`ConfidentialP256` does not exist. `CircuitId` carries `ConfidentialEddsa`,
`RingEddsa`, `RingAuthority`, and `RingP256`, and
`prover/server/circuits/spp_transaction/default/` holds only `eddsa_only.go`.

Build it when an ordinary ZK program, one that CPIs `transact` as the swap and
escrow examples do, must work without the loose browser policy. A ZK program
written as a ring program needs none of this.

Nothing here needs permissionless ring creation. `create_ring_config` gates that
behind the ring creation authority unless the protocol config opens it, and the
gate is correct. Custom rings are an audited set, so they stay curated on
mainnet.

The job is sized by whether the circuit builds without a change under
`prover/server/circuits/spp_transaction/shared/`. Every transfer key across
every shape and variant must come from one circuit revision, so a change there
rotates all four families.

- `prover/server/circuits/spp_transaction/default/p256.go`, new. Signature
  section from `custom/p256.go`, output-owner section from
  `default/eddsa_only.go`, no ring binding, ring fields pinned to `0`, BSB22
  commitment kept, `AssertDefaultP256Owner` unconditional.
- `prover/server/prover/common/`, a `transfer-p256` circuit type in `types.go`,
  the key path in `lazy_key_manager.go`, the request decode in `marshal.go`, and
  the gate in `proof_request_meta.go`.
- `prover/server/prover/transfer_eddsa_only/p256.go` pins
  `TransferP256RingCircuitType` today. `SetupP256Transfer` needs the variant
  switch.
- Ten keys, `transfer_p256_1_1` through `transfer_p256_5_4`, ten entries in
  `provingkeys/proving-keys.lock` whose `prefix` rotates, and ten Rust verifying
  keys from `groth16_solana::vk::gnark`.
- `program-libs/interface/src/verifying_keys/circuit.rs`, append
  `ConfidentialP256(u8, u8, u8, RingP256ProofData)`. The enum carries a `u16`
  tag, so append and never insert. Arms for the shape getters,
  `is_confidential` true, `is_ring` false, `is_p256` true,
  `bsb22_commitment`, `default_p256_owner_tag`,
  `requires_input_signatures`, `output_owner_mode` as `All`, `is_supported`, and
  `verifying_key`.
- `programs/shielded-pool/src/instructions/transact/processor.rs`, accept the
  new selector on `Transact`.
- `programs/shielded-pool/src/instructions/transact/account.rs`, a default-ring
  P-256 spend carries no owner signers. Confirm the parser and
  `signer_pk_hashes` accept an empty set. Most likely place for a latent
  assumption.
- `sdk-libs/client/src/prover/transact/p256.rs`, new sibling of `ring_p256.rs`.
  `transact/witness.rs` and `prover/verify.rs` build
  `CircuitId::ConfidentialEddsa` unconditionally, so select by owner curve.
- Tests, the selector accepted on `Transact` and rejected on `RingTransact`, a
  default-ring P-256 transfer and withdrawal end to end, and the `RingP256`
  bindings in `program-tests/shielded-pool/invariants/` extended to the new
  selector.

## Open questions

- Whether a withdrawal leg may settle a default-ring input inside a ring
  transact. `program-tests/ring-test-program/tests/p256_ring_lifecycle.rs`
  covers a transfer, not an unshield.
- Whether the `RingP256` shape family covers the intended input and output
  counts.
- Whether the two identities share one on-chain public identity registration.
