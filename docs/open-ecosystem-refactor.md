# Open-ecosystem refactor

Plan for a wallet that supports the pseudonymous default ring and anonymous
custom rings, keeps four TVC operations, and eventually needs no TVC release
per third-party ZK program.

**Status:** transfer and SOL withdrawal are deployed for disposable devnet
funds. Both strict `AuthorizeSpend` paths are implemented and included in the
devnet release: the built-in UI flow prepares an exact transaction, while the
ecosystem flow prepares a program-neutral SPP transition and finalizes one
outer program instruction. The generic path still needs its first deployed
ecosystem-program integration.

## The fact that drives it

ZK programs CPI the shielded pool's `transact`. In `zolana-examples`, both
`swap-program` and `escrow-program` import
`zolana_interface::instruction::tag::TRANSACT`, store no state, own no accounts,
and register no ring. `transact` accepts `ConfidentialEddsa`, so authorization
is the pool's signer-account check and the owner signs the Solana transaction.
There is no second shielded signature on that rail, and `sign_prepared` in the
Zolana wallet SDK signs nothing.

The existing Turnkey Ed25519 wallet can therefore authorize an ecosystem
program transaction without a second owner identity. The ceiling was in TVC's
construction API: the built-in `AuthorizeSpend` adapter knew only transfer and
SOL withdrawal. Adding swap by compiling `SwapMake`, `SwapTake`, and
`SwapCancel` into that enum would reproduce the narrow operation surface under
different names.

The first implementation tried `RingP256`, but the deployed custom-ring program
accepts only `RingEddsa`, and the representative P-256 v0 transaction is 1,257
bytes—25 bytes over Solana's packet limit. The basic wallet flow therefore uses
the deployed Ed25519 rail. P-256 remains a possible later protocol change, not
the current spend path.

## Rails

| | Default ring | Custom rings |
| --- | --- | --- |
| Owner | Registered Ed25519 identity | Registered Ed25519 identity |
| Instruction | `transact`, `ConfidentialEddsa` | `ring_transact`, `RingEddsa` |
| Authorization | on-chain signer | on-chain signer |
| Privacy | pseudonymous | anonymous |
| Hosts | any ZK program, permissionless | ring programs, curated |

One registered Ed25519 owner spans the default and custom rings. `expand_roles`
gives its nullifier and viewing keys, while the ring program ID in each UTXO
provides the ecosystem boundary. This matches the deployed `RingEddsa` custom-
ring program and keeps the wallet address usable by programs added later.

Shielding is a proofless deposit on either rail, so the browser builds and signs
it with no privacy secret.

A ring program can be selected by the built-in adapter, but that is not the
same as executing a ZK-program action such as swap `make`, `take`, or `cancel`.
A custom ring is an input policy domain; a ZK program is the action that
transforms private state. The generic protocol keeps those concepts separate.

## Built-in devnet path

No key leaves the enclave. TVC syncs from its pinned endpoints, selects inputs,
builds the witness, calls the pinned prover, assembles the transaction, and
signs. The client submits the exact returned transaction, which needs nothing
secret.

| Operation | Bound to a transaction shape |
| --- | --- |
| `BootstrapKeyholder` | no |
| `DeriveViewTags` | no |
| `DecryptUtxos` | no |
| `AuthorizeSpend` | yes: transfer or SOL withdrawal |

Prepare takes an optional custom ring, a settlement, and a prover profile, and
returns an unsigned proven transaction plus a sealed capsule. Finalize accepts
only that exact pair and returns the signed transaction. `ring: null` selects
the default ring.

The enclave keeps sync because `private_tx_hash` chains each input's
`utxo_hash`, `nullifier`, and tree roots with the output hashes, and because a
hash alone does not say whose UTXO it is. An enclave signing a chain the client
assembled would bind structure and not ownership. Reading the chain itself is
what makes the signature mean the wallet authorized its own inputs.

Turnkey does not interpret the private action. The descriptor grant, attested
TVC release, and typed construction path are the gate on the single registered
Ed25519 identity.

The pinned indexer, RPC, and prover egress stays. The prover still receives the
plaintext witness, so this stays devnet for the same reason it is today.

Default- and custom-ring spends both stay inside TVC. The existing Turnkey
Ed25519 wallet is the registered shielded owner and fee payer, so the exact
transaction needs only one signature. The browser retains public registration
and deposits but never receives the derivation seed or nullifier key.

The service-user Turnkey policy authorizes transaction signing for that wallet
account without enumerating programs. The attested application is the typed
transaction gate. A hardened root quorum that excludes the browser credential
alone is required before this separation is a security boundary.

## Generic split-phase ZK-program authorization

The simpler design keeps program-specific code outside TVC. TVC prepares and
proves the common SPP state transition; the ecosystem SDK builds its own
program proof around that prepared transition; TVC then verifies the binding and
signs the final transaction.

This supports arbitrary programs conforming to Zolana's ZK-program interface
without a program manifest, adapter registry, dynamically loaded code, or TVC
release per program. It does not mean that TVC can safely infer the semantics of
an unrelated Solana program. The supported boundary is a program whose action
settles through SPP `transact` and binds its proof to the prepared
`private_tx_hash`.

### Keep four operation kinds

The protocol keeps the current operation set:

1. `BootstrapKeyholder`
2. `DeriveViewTags`
3. `DecryptUtxos`
4. `AuthorizeSpend`

`AuthorizeSpend` gains two phases rather than being split into more operation
kinds:

```text
AuthorizeSpend::Prepare
AuthorizeSpend::Finalize
```

There is no protocol-level execute operation or parallel wire variant. The
strict shape nests the phase so unknown fields remain rejectable without custom
parsing:

```text
{ type: "AuthorizeSpend", spend: { phase: "Prepare", ... } }
{ type: "AuthorizeSpend", spend: { phase: "Finalize", ... } }
```

wallet-kit may expose a one-call `authorizeSpend()` convenience method, but it
always performs these two protocol requests.

Prepare never calls Turnkey transaction signing. Finalize calls it exactly once.
Both phases use the same descriptor grant and App-Proof operation kind.

### Prepare a generic SPP transition

The ecosystem SDK sends a declarative SPP plan, not a serialized transaction:

```text
SppPlanV1 {
    program_id: Address,
    input_tree: Address,
    shape: { inputs, outputs },
    inputs: Vec<SppPlanInputV1>,
    outputs: Vec<SppPlanOutputV1>,
    messages: Vec<SppMessageV1>,
    public_effects: PrivateOnly,
    prover_profile_id,
    expires_at_ms: u64,
}

SppPlanInputV1 =
    Wallet {
        commitment,
    }
  | Program {
        commitment,
        authority_seeds,
        asset,
        amount,
        blinding,
        data_hash,
        nullifier_secret,
    }

SppPlanOutputV1 {
    recipient,
    asset,
    amount,
    blinding,
    data,
    data_hash,
    memo,
}
```

A wallet input is a note the descriptor-bound identity owns. The browser may
already know its plaintext from `DecryptUtxos`, but TVC does not trust that
plaintext: it independently synchronizes the wallet, matches the commitment,
checks ownership, and requires the default ring. Custom-ring actions still need
the typed built-in path or a future multi-program private sandbox.

A program input is a program-owned private object such as a swap order UTXO.
The plan supplies its opening, nullifier capability, and the PDA seeds under
the target program. TVC recomputes the commitment and authority and obtains a
Merkle proof for that commitment from the pinned indexer. The target program
still has to satisfy its own proof and PDA-authority rules on chain.

Outputs can carry arbitrary `utxo_data`, discovery messages, and shielded
recipient addresses. TVC does not interpret program-specific data, but its
committed hash, owner, asset, and amount enter the prepared SPP transition and
its economic checks. Generic v1 does not add a separate custom-ring transform;
the built-in adapter remains the custom-ring path.

### What TVC does during prepare

For `AuthorizeSpend::Prepare`, TVC:

1. Verifies the encrypted request, descriptor, release, checkpoint, target
   program, expiry, circuit shape, and `PrivateOnly` policy.
2. Synchronizes wallet and program inputs against the pinned indexer and RPC.
3. Recomputes every claimed input commitment and verifies wallet ownership or
   declared program authority.
4. Checks exact per-asset conservation and output destinations.
5. Supplies the wallet's nullifier role without returning it to the caller.
6. Builds output ciphertexts, messages, nullifiers, external data, and
   `private_tx_hash`.
7. Sends the complete SPP witness to the pinned generic prover and locally
   verifies the returned SPP proof.
8. Seals the exact prepared transition and authorization limits into a
   short-lived, wallet-bound capsule.

The response is:

```text
PreparedSpendV1 {
    type: Spp,
    program_id,
    input_tree,
    plan_digest,
    transact,
    transact_digest,
    private_tx_hash,
    external_data_hash,
}
```

The enclosing prepare result also carries the sealed authorization capsule and
the unchanged wallet checkpoint.

The prepared SPP proof, public nullifiers, ciphertexts, commitments,
`private_tx_hash`, and `external_data_hash` are safe to return. The latter lets
the ecosystem circuit recompute its private transaction commitment without
reimplementing SPP ciphertext hashing. The result contains no long-lived
nullifier secret, viewing secret, Turnkey credential, or generic signing
capability.

The capsule binds at least:

```text
wallet and descriptor digest
release and Quorum epoch
program ID
input/output tree
program-input PDA authorities
prepared transact/proof digest
private_tx_hash
private-only policy
expiry
unique prepare request ID
```

The service remains stateless. Replaying a capsule can at most ask TVC to sign
the same prepared private transition; on-chain nullifiers prevent that
transition from landing twice.

### Program proof stays in the ecosystem SDK

The dapp's normal SDK consumes `PreparedSpendV1` and produces its own
program-specific proof and wrapper instruction. This is where swap, escrow,
lending, compression, or another program interprets private application data.

For swap `make`:

```text
prepared SPP transact
    + order terms
    + order and change preimages
    -> swap make proof
    -> swap make instruction
```

For swap `take`:

```text
prepared SPP transact
    + decrypted order opening
    + maker and taker outputs
    -> swap take proof
    -> swap take instruction
```

The ecosystem may use its own browser, local, or remote program prover. That
prover receives the program-specific witness the SDK supplies, but it does not
receive the wallet's long-lived nullifier secret from TVC. The current generic
SPP prover still receives that secret during prepare, so the existing devnet
privacy warning remains.

This ordering matches the ZK-program interface: the program proof is constructed
after the common SPP `private_tx_hash` exists and commits its action to that
hash.

### Finalize the outer program transaction

The SDK returns one completed target-program instruction:

```text
AuthorizeSpend::Finalize {
    sealed_authorization_capsule,
    instruction,
    address_lookup_tables,
}
```

TVC unseals the capsule and verifies:

1. The capsule is authentic, unexpired, and bound to this wallet, descriptor,
   release, Quorum epoch, and target program.
2. The outer instruction contains the exact serialized prepared SPP transact;
   a hash or caller assertion is not enough.
3. No different SPP proof or private state transition has been substituted.
4. The wallet/fee-payer is the only signer.
5. The target program is the prepared program and is not a signer-sensitive
   System, token, associated-token, compute-budget, or loader program.
6. The shielded pool is present read-only and is the only executable account
   the target instruction receives.
7. Every program-input PDA derived during prepare is present; an absent account
   is accepted only when it is one of those derived PDA authorities.
8. Lookup tables resolve the exact accounts and the final v0 message fits
   Solana's packet and compute limits.

TVC adds a fresh blockhash only after the program proof is ready. It then asks
Turnkey to sign the exact final transaction once and returns the signed bytes for
the browser to journal and submit.

The instruction must carry the serialized transact without clearing or
replacing a marker before serialization. The prepared SPP proof is the
authority: changing an input, output, amount, recipient, message commitment, or
settlement invalidates the proof through `private_tx_hash` or
`external_data_hash`. A program that ignores the prepared transition can make
the transaction fail, but it cannot manufacture a different valid wallet spend
without the nullifier witness TVC withheld.

### Why generic v1 is private-only

An arbitrary program that can CPI System or SPL Token while holding the wallet
signer is a public-wallet signing oracle. Generic v1 avoids that whole class
instead of trying to describe and check arbitrary public postconditions.

TVC permits exactly one top-level ecosystem instruction. Besides its own target
program, the only executable account it may receive is the shielded pool,
read-only and non-signing. System, classic token, Token-2022, associated-token,
compute-budget, and loader programs are unavailable to the target. Solana also
prevents a program from debiting or rewriting the system-owned fee payer
directly. TVC itself adds the compute-budget instruction and fresh blockhash.

The target may change accounts it owns as part of its own public program state,
and the payer pays the normal transaction fee. It cannot use this path for a
public withdrawal, token approval, account creation, or public swap leg. Those
actions require a future explicitly authorized public-effect design or a typed
exact-transaction adapter. Basic unshield remains on the built-in exact path.

### Why this is safe without program adapters

The caller never receives the wallet's nullifier secret and therefore cannot
produce a second valid SPP proof for a different private transition. It receives
only the proof TVC prepared for the approved:

- inputs and nullifiers;
- output commitments and ciphertexts;
- assets and amounts;
- shielded recipients;
- program data commitments and discovery messages;
- input-tree and target-program bindings.

The ecosystem program can execute that transition correctly or fail. It cannot
change the private economic effects while reusing the proof, and it is not
given the executable programs needed to move the wallet's public assets.

TVC does not need to understand the program's business semantics. The on-chain
program and its custom ZK proof decide whether the action is a valid swap,
escrow, loan, or other state transition. TVC decides only whether the exact
private effects are authorized by this wallet and whether the outer instruction
stays within the private-only sandbox.

### How arbitrary the support is

This design supports an arbitrary program that:

- settles private state through SPP `transact`;
- binds its program proof or authorization logic to the prepared
  `private_tx_hash`;
- can accept the prepared SPP transaction in its instruction or CPI path;
- provides an SDK/prover that constructs the outer proof after prepare;
- does not require public wallet debits or auxiliary executable programs.

That fits private swap and escrow actions whose only value transition is SPP.
It does not claim safe semantic support for an unrelated Solana program with no
SPP binding, or for a swap that also needs a public token leg.

No signed program manifest is required for authorization. A wallet may consume
optional manifests for discovery, argument decoding, warnings, and human-readable
display, but the security boundary is the target program, prepared proof,
capsule, exact-carry instruction, and executable-account restriction.

### What this removes

The trusted TVC application no longer needs:

- compiled transfer adapters per ecosystem program;
- a signed adapter registry;
- dynamically loaded WebAssembly;
- program-specific RPC or prover code;
- one operation or enum variant per program action;
- program-specific effect decoders.

The core added surface is limited to:

```text
generic SPP plan validator and prover
sealed prepare/finalize capsule
outer-instruction proof-binding validator
private-only final-message validator
```

### Implementation status

1. **Complete:** split `AuthorizeSpend` into prepare and finalize and seal the
   exact built-in transaction into a short-lived capsule.
2. **Complete:** expose both phases in the TypeScript client and compose them
   behind the one-call built-in UI method.
3. **Complete:** define `SppPlanV1`, the prepared result, generic SPP proof
   builder, and sealed exact-transact capsule.
4. **Complete:** finalize one exact-carry outer instruction under the
   private-only executable-account rule.
5. **Complete locally:** reject transact substitution, extra signers, reserved
   targets, wrong trees, and executable-account escalation. A deployed generic
   integration remains outstanding.
6. Adapt swap `make` to carry the exact serialized transact as the first
   external SDK integration; then exercise program inputs with `take` and
   `cancel`.
7. Add escrow as the second independent SDK to prove the interface is not
   swap-specific.
8. Treat the generic interface as experimental until both independent
   integrations pass deployed end-to-end tests.

### Non-goals

- Do not accept a blind, single-phase caller-supplied transaction for signing.
- Do not add one TVC operation or core enum variant per ecosystem action.
- Do not load program-specific executable code into the TVC trust boundary.
- Do not let the program SDK alter the prepared SPP transition after prepare.
- Do not admit public wallet effects in generic v1.
- Do not claim interoperability with private-state systems that do not use the
  Zolana SPP transaction boundary.

## What is done

Four operations, none exposing a generic signing oracle. Default- and
custom-ring deposits and spends use the registered Ed25519 identity. Bootstrap
returns only public identity plus sealed state. See
[the privacy-wallet profile](privacy-wallet.md).

## What is left here

- Add a deployed generic-path end-to-end test and adversarial tests for transact
  substitution, extra signers, reserved targets, and executable accounts.
- Adapt and validate swap `make`, `take`, and `cancel` against the exact-carry
  instruction rule.
- Integrate a second independent ecosystem SDK, preferably escrow, before
  freezing the interface.
- Replace the external prover boundary, which still receives the plaintext
  witness including the long-lived nullifier secret.
- Verify root-quorum migration so a browser credential cannot rewrite the
  service-user policy.

## Rejected alternatives

**One operation or enum variant per program action.** This merely recreates the
old eight-operation coupling and requires a protocol and TVC release for every
ecosystem addition.

**Blind single-phase caller-supplied transactions.** Structure alone does not
prove input ownership or user-approved effects. Finalize may accept ecosystem
instructions only after TVC has prepared the private transition and sealed its
proof and effect constraints into the authorization capsule.

**Program adapters inside TVC.** Compiled adapters require a release per
program; dynamic WebAssembly adds a large executable and sandboxing boundary.
The ecosystem SDK already knows how to build its program proof once TVC returns
the prepared SPP `private_tx_hash`, so neither adapter form belongs in the
trusted host.

**Mandatory signed program manifests.** Manifests are useful for discovery,
argument decoding, and display, but they do not authorize value movement. The
prepared proof, sealed capsule, exact-carry instruction, and private-only
executable-account rule are the security boundary.

**A generic public-effect guard in v1.** Correct postconditions across SOL,
classic token, Token-2022, account creation/closure, fees, and arbitrary program
state are another protocol. Keeping generic v1 private-only is smaller and
removes signer-capable auxiliary programs entirely. Typed built-in adapters can
still authorize exact public exits.

**Treat every ZK program as a custom ring.** Rings are policy domains attached
to UTXOs. Swap and escrow are actions over private state and may create
program-owned objects; forcing them into rings conflates two independent
protocol concepts and can strand value in a program domain.

**A second P-256 shielded owner.** The deployed default and custom-ring rails
already accept the existing Turnkey Ed25519 owner, which also pays the Solana
fee with one signature. A second identity adds registration, recovery, packet,
and circuit complexity without solving program-specific construction or
effect validation.
