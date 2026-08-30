# Privacy-wallet profile

**Status: implemented for disposable devnet funds.** The profile supports
verified connection, sealed deterministic bootstrap, client-relayed key
oracles, public registration and deposits, and end-to-end default-ring private
transfer. It is not production-safe because the spend sends the complete
plaintext witness—including the long-lived `nullifier_secret`—to the pinned
external prover.

## Boundary

TVC holds the derivation seed, viewing key, and nullifier key. The browser holds
only:

- a non-exportable P-256 request key;
- the public shielded identity;
- an opaque QOS-sealed key-state blob;
- display balances/history and an exact signed-transaction journal.

Read synchronization remains relayed: TVC derives tags, the browser queries the
indexer, and TVC decrypts the returned ciphertexts. Private spending is the one
temporary exception. `AuthorizeSpend` performs pinned indexer/RPC/prover calls
inside TVC because the Zolana witness needs the nullifier key.

This compromise keeps the secret out of browser JavaScript and closes the PoC,
but it moves the secret to the prover. A prover compromise can compute the
wallet's nullifiers and damage unlinkability. Do not use production funds.

## Parties

| Party | Role and visibility |
| --- | --- |
| Browser | Verifies TVC, authorizes typed operations, relays read sync, builds public registration/deposit transactions, and submits signed transactions. It never receives the seed or raw privacy keys. |
| Privacy-wallet TVC | Unseals privacy keys for one request. It answers read oracles and owns construction of a bounded devnet spend. |
| Turnkey | Holds the ordinary Ed25519 key, creates the deterministic bootstrap signature, evaluates narrow policies, and signs the final transaction. |
| Photon / Solana RPC | See browser read queries; during spend operations, fixed endpoints are also called directly by TVC. |
| Development prover | Sees the complete plaintext witness, including `nullifier_secret`. It is inside the PoC privacy trust boundary. |

## Sealed state and recovery

The sealed plaintext contains the 64-byte derivation seed and binding metadata:

```text
quorum_encrypt(
    derivation_seed
  || wallet_id || descriptor_digest || policy_version
  || ed25519_public_key || derivation_suite
  || quorum_key_id || quorum_key_epoch
)
```

TVC stores nothing between requests. It checks the envelope against the
request, decrypts it, and checks the inner fields again against the descriptor
and envelope. A blob is usable only for the exact wallet, descriptor, security
domain, Quorum key, and epoch that produced it.

The blob is a cache, not the recovery root. The bootstrap input to Turnkey is a
fixed message and Ed25519 signatures are deterministic, so the same Turnkey
wallet produces the same seed. After blob loss or Quorum rotation:

1. verify the replacement release and its Boot Proof;
2. call `BootstrapKeyholder` without an old checkpoint;
3. compare every returned public identity field with the identity already
   known for the wallet;
4. accept the newly sealed blob only if they match.

The client fails with `ShieldedIdentityChanged` on a mismatch. Losing or
disabling the underlying Turnkey wallet remains unrecoverable unless a separate
custody recovery rail exists.

## HTTP API

The deployed service exposes four routes. JSON is strict, duplicate and unknown
fields are rejected, binary values are lowercase hex, and wire integers are
canonical decimal strings.

| Call | Description |
| --- | --- |
| `GET /health` | Load-balancer readiness only. Returns exactly `{"status":"Healthy"}` after QOS keys are ready, otherwise a generic `503`. It exposes no identifiers and proves no enclave identity. |
| `GET /v1/info` | Untrusted `ServiceInfoV1` discovery: release/manifest/executable/security-domain bindings, Quorum and Ephemeral public keys, key epoch, operation list, envelope limits, and Boot Proof lookup key. The client compares security-relevant fields with an independently signed release policy. |
| `POST /v1/ping` | QOS connection challenge. The request is encrypted with the Quorum encryption subkey; the exact canonical challenge is signed with the replica's Ephemeral signing subkey. The client verifies the App Proof and matching AWS Nitro Boot Proof. It grants no wallet capability. |
| `POST /v1/operations` | The only wallet endpoint. It accepts a QOS-encrypted `OperationRequestV1` bound to one descriptor, device key, release, executable, Quorum epoch, validity window, operation, response key, and optional checkpoint. |

Every operation response is encrypted to a one-time client response key. The
Ephemeral App Proof binds the request digest, encrypted-result digest,
operation, and exact state digest. Successful decryption alone is never enough
to accept a result.

### Operations

| Operation | Input | Checkpoint | Egress | Output |
| --- | --- | --- | --- | --- |
| `BootstrapKeyholder` | No operation fields | Forbidden | Turnkey | Public Solana/shielded identity, sealed version-1 state, Turnkey activity evidence. |
| `DeriveViewTags` | No operation fields | Required | None | The wallet's stable recipient bootstrap tags, one per viewing key held. |
| `DecryptUtxos` | Up to 256 encrypted UTXO/ring-deposit payloads | Required | None | Ordered plaintext-or-malformed results bound to the supplied checkpoint. |
| `AuthorizeSpend::Prepare` | A direct transfer/unshield transition or a declarative SPP program transition | Required | Photon, Solana RPC, prover | Exact unsigned transaction or exact proved SPP transition, short-lived sealed authorization capsule, prior selected-input balance, and unchanged checkpoint. |
| `AuthorizeSpend::Finalize` | Capsule plus one complete unsigned transaction | Required | Solana RPC for program account/LUT checks; Turnkey | Signed transaction, transaction signature, prior selected-input balance, unchanged checkpoint, and Turnkey evidence. |

The Turnkey service-user policy authorizes transaction signing only with the
provisioned wallet account. TVC constructs and validates the typed spend before
requesting that signature, so the Turnkey policy does not enumerate ecosystem
programs. Production rollout additionally requires a root quorum the browser
credential cannot satisfy alone; otherwise it could rewrite these policies.

A custom-ring note keeps the wallet's registered Ed25519 owner. A direct intent
names source and destination domains; the pair determines whether value enters,
exits, or remains in the same ring. Turnkey's one transaction signature
authorizes the shielded owner and Solana fee payer. A ring transaction is a v0
message over a caller-named address lookup table, which the application verifies
against the accounts the instruction needs.

The ring itself is caller input on every spend, so a new ring needs no wallet
re-provisioning. The rail's gates are the deployed `RingEddsa` circuit and the
ring program's own policy, not an enumerated list or a second signing key.

No operation exports the seed, viewing key, nullifier key, witness, generic
message signature, generic transaction signature, wallet export, caller-picked
URL, or generic Turnkey activity.

## Read sync

1. Browser sends `DeriveViewTags` with the sealed checkpoint.
2. Browser queries Photon using those tags.
3. Browser sends returned ciphertexts to `DecryptUtxos` with the same
   checkpoint.
4. Browser deserializes candidates and checks their owner against its recorded
   identity.

The last check is required because the shielded transport cipher is
unauthenticated: a ciphertext for another wallet may decrypt to garbage instead
of failing. The TypeScript `syncTvcWallet` helper owns paging but accepts
the indexer fetch as a callback; ordinary read sync does not hide indexer I/O in
the TVC package.

## Public setup and shield

Registration and deposits do not need a privacy secret. The demo builds them in
the browser with `@heliuslabs/zolana`, signs them with the user's ordinary
Turnkey wallet session, journals the signed bytes, and submits with preflight
enabled.

The demo supports SOL. A ring transfer settlement can also name a classic SPL
mint plus its registered asset ID, and the TVC Rust path verifies that pair
against the on-chain shielded-pool asset registry. The current demo does not yet
expose an SPL form. Token-2022 is unsupported.

## Direct devnet spending

The direct `AuthorizeSpend` adapter is one closed two-phase construction
path. A withdrawal settlement calls the SDK's explicit SOL withdrawal
constructor instead of recipient auto-resolution, so exiting to the registered
public wallet is unambiguous. The end-to-end flow is:

1. Browser sends `AuthorizeSpend::Prepare` with a `Direct` plan containing
   source and destination domains, settlement, exact default commitments for a
   Default-to-Ring transition, and the sealed checkpoint.
2. TVC rejects production descriptors, mainnet, zero amount,
   caller-selected origins, and invalid/unregistered assets.
3. TVC unseals the seed and restores the registered Ed25519 Turnkey-backed
   keypair.
4. TVC synchronizes the wallet from the compile-time Photon/Solana endpoints.
5. TVC selects notes in the source domain, or rediscovers the explicitly named
   default inputs for a ring entry and requires their exact sum, then constructs
   the shielded transaction.
6. The Zolana SDK assembles the prover witness. This witness contains
   `nullifier_secret` in plaintext.
7. TVC sends that plaintext witness over the current pinned development HTTP
   endpoint to the external prover.
8. TVC parses and locally verifies the returned Groth16 proof, seals the exact
   unsigned transaction into a short-lived wallet/release/state-bound capsule,
   and returns both without contacting Turnkey transaction signing.
9. Browser sends `AuthorizeSpend::Finalize` with the capsule and exact unsigned
   transaction. TVC revalidates both, then asks Turnkey to sign once as owner
   and fee payer and independently verifies the returned signature/message.
10. Browser verifies both encrypted results and App/Boot Proof chains, persists
    the exact signed bytes as pending, submits them with preflight, and keeps the
    journal on an unknown outcome.

The browser receives neither the witness nor `nullifier_secret`. This is better
than returning the witness to JavaScript, but it does not make the prover
confidential.

The result reports `shielded_balance_before`; the browser uses this proof-bound
value for display bookkeeping. A freshly confirmed deposit can briefly return
`ShieldedBalanceNotReady` until Photon indexes it. Retrying is safe because the
checkpoint is unchanged and an on-chain nullifier prevents a confirmed spend
from landing twice.

## Generic private-program spending

The generic `Program` plan is not a caller-supplied transaction. It declares the
target program, input tree and shape, wallet commitments, optional
program-PDA-owned inputs, declared program-authority PDA seeds, shielded outputs,
messages, and expiry. Its common SPP transition is always asset-conserving and
private. TVC independently synchronizes the wallet, verifies
input ownership/openings and exact per-asset conservation, builds and locally
verifies the common SPP proof, and returns its exact serialized transact in a
sealed capsule.

The ecosystem SDK builds its program proof after receiving the prepared
`private_tx_hash`, then gives finalize a complete unsigned Solana transaction.
Exactly one instruction for the prepared target must contain that hash. The
program may wrap or reconstruct its CPI transact; the on-chain SPP proof remains
bound to the same hash. TVC rejects a different target or tree, another signer,
a missing or ambiguous hash binding, or missing declared program authorities.
It permits additional user-approved instructions and executable programs,
refreshes the blockhash, and requests the single Turnkey signature.

This path permits arbitrary SPP-bound private program semantics. The prepared
transition fixes private inputs, outputs, assets, and amounts; it is not a proof
of arbitrary public behavior in the complete transaction. The user trusts the
target and additional instructions exactly as in a conventional Solana wallet.
The canonical Zolana swap `make`, `take`, and `cancel` flows
exercise this path on devnet; a typed public exit remains on the direct
exact-transaction path. Swap order discovery stays client-relayed: TVC decrypts
candidate output bytes, while the host-side adapter reconstructs and checks the
program-owned order commitment before it can enter a spend plan.

## Failure behavior

External failures are mapped to a closed stage such as sync,
indexer proofs, witness assembly, external prover, local proof verification, or
Turnkey signing. They are returned only inside the encrypted operation result;
public HTTP errors remain generic.

The browser journals a signed transaction before treating it as complete. A
timeout is an unknown outcome and remains resumable. It clears a pending entry
only after a definitive chain failure or proven blockhash expiry. An expired
spend can be rebuilt because its key checkpoint was not advanced.

## Security debt accepted for the PoC

- The prover learns `nullifier_secret` and every private proof input.
- The current prover connection is plain HTTP to a compile-time development
  endpoint.
- Turnkey can reproduce the deterministic bootstrap seed.
- Turnkey policy evidence remains
  `CryptographicallyValidButUnbound`; `decisionContextDigest` is not bound to
  the exact activity and must never be labelled `Verified`.
- Browser-requested decrypted history is visible to compromised live browser
  code, and tag queries are linkable at the indexer.
- Production release governance, multi-device coordination, and production
  replay/state coordination remain incomplete.

## Production replacement for the prover boundary

Before production funds, replace the plaintext external-prover call with one of
these reviewed boundaries:

1. an attested prover and an authenticated encrypted channel bound to its
   verified attestation; or
2. proof generation inside the same attested wallet boundary.

Merely adding TLS is insufficient: it protects transport but still gives the
prover process the long-lived secret. Returning plaintext witness bytes to the
browser is also not an acceptable replacement.

## Deployment identity

The privacy wallet requires its own TVC app ID, Quorum key, OCI digest, pivot
digest, manifest, signed release policy, descriptor operation grants, egress
policy, dependency lock, and review line.
The demo must pin all of these independently before `connectAndVerify` can
produce `VerifiedConnection`.
