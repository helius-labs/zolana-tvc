# Open-ecosystem private transactions

The TVC protocol protects private keys and private economic effects without
embedding one adapter per ecosystem program. It keeps four operation kinds:

1. `BootstrapKeyholder`
2. `DeriveViewTags`
3. `DecryptUtxos`
4. `AuthorizeSpend`

`AuthorizeSpend` is a two-phase protocol. The TypeScript client may hide the
two requests behind a convenience method, but the enclave always prepares
before it signs.

## The small trusted core

TVC has four spend responsibilities:

1. rediscover private inputs and verify wallet or declared program ownership;
2. enforce exact private-asset conservation and produce the common proof;
3. seal the prepared artifact and its authorization constraints;
4. verify a complete transaction against that capsule and sign once through
   Turnkey.

Transfer, withdrawal, ring movement, swap, and future application names are
wallet or program SDK concepts. They are not TVC operation variants.

## Direct transitions

A direct plan describes source and destination domains:

```text
PrivateDomain =
    Default
  | Ring { program_id, lookup_table }
```

The route is derived from the domains rather than repeated in a direction enum:

| Source | Destination | Meaning |
| --- | --- | --- |
| Default | Default | Default-pool private transfer |
| Ring(A) | Ring(A) | Private transfer remaining in A |
| Ring(A) | Default | Move privately from A to the default pool |
| Default | Ring(A) | Move into A using exact named bridge UTXOs |
| Ring(A) | Public SOL | Withdraw from A |
| Default | Public SOL | Withdraw from the default pool |

Ring(A) to Ring(B) is deliberately invalid. A wallet composes it as Ring(A) to
an exact self-owned Default UTXO, waits for that commitment to be indexed, then
spends that exact UTXO from Default to Ring(B). This is an on-chain ring-policy
boundary. The source and destination domains fully describe both transitions.

For a direct plan, prepare returns one complete unsigned transaction. The
capsule commits to its exact bytes. Finalize accepts only those bytes.

Balance-neutral consolidation is also a direct settlement, but not a route
between domains. It is valid only in Default and uses Zolana's fixed
`merge_8_1` transition to replace fragmented same-asset UTXOs with one
same-owner UTXO. It remains inside `AuthorizeSpend`; it is not a fifth TVC
operation or an ecosystem-program adapter.

## Program transitions

A program plan declares the common SPP transition:

```text
program ID and input tree
circuit shape
wallet and program-owned inputs
program-authority PDA seeds
private outputs and messages
short expiry
```

TVC independently synchronizes wallet inputs, recomputes program-owned input
commitments and PDAs, checks per-asset conservation, supplies the wallet's
nullifier role, builds the SPP witness, and locally verifies the returned proof.
It returns the serialized transact, `private_tx_hash`, external-data hash, and a
sealed capsule. No private role returns to the browser or ecosystem SDK. The
development common prover still receives the plaintext witness, including the
long-lived nullifier secret, as documented below.

The ecosystem SDK then builds its program-specific proof. Swap, escrow, lending,
or another application interprets its own data outside the TVC release. Its
target instruction binds the program proof to the prepared `private_tx_hash`.

## One universal finalize request

Finalize always has one wire shape:

```text
AuthorizeSpend::Finalize {
    sealed_authorization_capsule,
    unsigned_transaction,
}
```

The capsule chooses the validator:

- a direct capsule requires an exact transaction digest match;
- a program capsule requires exactly one prepared target instruction containing
  the `private_tx_hash`, plus the prepared tree, SPP program, System Program,
  wallet signer, and declared program authorities.

The ecosystem SDK supplies the complete Solana transaction, not a special
single-instruction fragment. It may include additional instructions and
executable programs approved by the wallet UI. TVC resolves lookup tables,
validates the private binding, refreshes the blockhash, and asks Turnkey to sign
the exact resulting message once.

The current version permits only the registered wallet as signer. Supporting
additional independent signers is a transaction-coordination extension, not a
private-proof change.

## Security boundary

TVC guarantees the prepared private inputs, nullifiers, outputs, recipients,
assets, amounts, program authorities, and target binding. An ecosystem program
cannot substitute another private transition while reusing the proof.

TVC cannot prove arbitrary public behavior implemented by a Solana program.
The selected target and additional instructions receive the same user trust as
programs in a conventional wallet transaction. This is intentional: requiring
TVC to understand every program would recreate a closed adapter registry and a
new enclave release per application.

The existing browser already authorizes ordinary Turnkey wallet transactions.
Allowing normal composition during program finalize therefore does not create a
new public-wallet trust model; it preserves the one the user already has while
keeping private effects cryptographically fixed.

## Provers

The common SPP prover used during prepare is pinned by the TVC release. A caller
does not select it with a `prover_profile_id` field. Program-specific proving is
separate: the swap SDK, for example, calls its own local or remote prover after
TVC returns `private_tx_hash`.

The current common and direct development prover boundary still receives a
plaintext witness containing the long-lived nullifier secret. This prevents a
production privacy claim and must be replaced before mainnet use.

## What adding a program requires

An ecosystem program needs:

- the Zolana SPP `transact` interface;
- a program proof or authorization rule bound to `private_tx_hash`;
- an SDK that declares the common transition, consumes the prepared artifact,
  builds the program proof, and assembles the complete transaction;
- wallet UI capable of presenting the target and public transaction effects.

It does not need a new TVC operation, manifest registry, dynamically loaded
adapter, caller-selected TVC prover, or enclave deployment.

The canonical Zolana swap `make`, `take`, and `cancel` flows are the first
integration. Its TVC-specific adapter lives in
[`examples/private-swap`](../examples/private-swap); the program, circuits,
prover, keys, and protocol-neutral SDK remain in Zolana. A second independent
program should be added before freezing the interface.
