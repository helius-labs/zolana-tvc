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
temporary exception. `SignRingSpend` performs pinned indexer/RPC/prover calls
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
| `SignRingSpend` | A required ring, a settlement, and a fixed development prover profile | Required | Photon, Solana RPC, prover, Turnkey | Signed v0 transaction, transaction signature, prior shielded balance, unchanged checkpoint, and Turnkey evidence. |

The Turnkey policies attached to a provisioned wallet allow exactly the shapes
this profile produces, and the custom-ring transact is one of them. It is the
only shape that must travel as a v0 message over an address lookup table, so it
has its own policy: the other policies all require zero lookups. It is pinned as
tightly as the rest, because Solana never moves an invoked program into a lookup
table -- both programs and the signer stay in the static keys and stay nameable.
The policy therefore names the ring programs it allows, which means the set has
to be known when the policies are written; a ring registered afterwards needs
the wallet provisioned again before it can be spent in.

The two custom-ring kinds carry the same request shape as their default-ring
counterparts, and naming a `ring` in the intent is what selects them. They are
separate kinds because they are separate authority. A ring spend spends as the
ring identity, a P-256 owner whose signature the circuit checks rather than the
runtime, so it is not a Solana signer and Turnkey signs only as fee payer. The
spend binds every input and output to a caller-named program, and the
transaction is a v0 message over a caller-named address lookup table, which the
application verifies against the accounts the instruction needs.

The descriptor's ring grant names the P-256 key and the rings the wallet may
spend in, and a grant may list the two ring kinds only where that key exists. A
ring the grant does not name is refused before any chain read. That grant is the
gate, because on this rail Turnkey signs a digest it cannot read.

A ring spend therefore reads a second wallet. The ring identity shares the
nullifier and viewing keys, so one scan serves both, but the owner hashes differ
and the two hold different notes.

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

## Devnet spending

`SignRingSpend` is one closed construction path. A withdrawal settlement calls
the SDK's explicit SOL withdrawal constructor instead of recipient
auto-resolution, so exiting to the registered public wallet is unambiguous. The
end-to-end flow is:

1. Browser sends `SignRingSpend(ring, settlement, prover_profile_id)` with the
   sealed checkpoint.
2. TVC rejects production descriptors, mainnet, zero amount, unknown prover
   profile, caller-selected origins, and invalid/unregistered assets.
3. TVC refuses a ring the descriptor's grant does not name, then unseals the
   seed and restores the ring identity's Turnkey-backed keypair.
4. TVC synchronizes the wallet from the compile-time Photon/Solana endpoints.
5. TVC selects inputs and constructs the shielded transaction.
6. The Zolana SDK assembles the prover witness. This witness contains
   `nullifier_secret` in plaintext.
7. TVC sends that plaintext witness over the current pinned development HTTP
   endpoint to the external prover.
8. TVC parses and locally verifies the returned Groth16 proof before it can ask
   Turnkey to sign.
9. TVC asks Turnkey to sign the exact transaction as fee payer under the
   descriptor-bound policy and independently verifies the returned
   signature/message.
10. Browser verifies the encrypted result and App/Boot Proof chain, persists
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

## Failure behavior

External failures are mapped to a closed stage such as sync,
indexer proofs, witness assembly, external prover, local proof verification, or
Turnkey signing. They are returned only inside the encrypted operation result;
public HTTP errors remain generic.

The browser journals a signed transaction before treating it as complete. A
timeout is an unknown outcome and remains resumable. It clears a pending entry
only after a definitive chain failure or proven blockhash expiry. An expired
Either spend can be rebuilt because its key checkpoint was not advanced.

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
