# Keyholder profile

**Status: partially implemented.** `BootstrapKeyholder`, `DeriveViewTags` and
`DecryptUtxos` are built in `apps/keyholder-wallet`. `AssembleSpend` is not: it
depends on the proof-request question in the open questions below.

## The idea

TVC is a stateless oracle for the wallet's privacy keys, not a wallet.

It reaches no network except Turnkey. The browser makes every call — indexer,
prover, Solana RPC — and builds every transaction, but holds no key it could
read that data with. It sends ciphertext in and gets the key-dependent answer
back out.

Two properties follow, and they are the point of the design:

- **The device holds nothing worth stealing at rest.** No seed, no viewing key,
  no nullifier key. Only an opaque blob sealed to the quorum key.
- **New protocol actions stay cheap.** TVC never has to learn how to *build* a
  transaction, only how to answer a question about keys. Custom rings, swaps and
  third-party ZK programs are the client's problem to construct, which is where
  the SDK already lives.

## Who is involved

| Party | Role |
| --- | --- |
| Browser | Runs the app and every network call. Holds a device-bound P-256 key that authorizes TVC requests, and an opaque sealed blob it cannot read. |
| Ordinary Turnkey wallet | Signs public transactions such as registration and deposits. |
| TVC | Holds the wallet's privacy keys. Answers key-dependent questions and nothing else. Reaches no network but Turnkey. |
| Turnkey | Custodian of the Ed25519 signing key. Evaluates the narrow signing policies. |
| Indexer / prover / RPC | Reached by the browser, never by TVC. |

---

## What is stored where

The browser stores an opaque sealed blob and nothing else of value:

```
sealed_key_state = quorum_encrypt(
    derivation_seed(64)          the secret
  ‖ wallet_id, descriptor_digest, policy_version
  ‖ ed25519_public_key, derivation_suite
  ‖ quorum_key_id, quorum_key_epoch
)
```

The browser cannot read it, cannot use it against a different descriptor, and
cannot replay it past a quorum key rotation. The binding fields are checked
twice on every request: the envelope against the request, then the decrypted
contents against the envelope and the descriptor.

The browser also stores public display data — balances and history as TVC last
reported them. That is bookkeeping, not privacy material.

TVC stores nothing. It unseals, answers, and forgets.

---

## Operations

Three typed operations on top of bootstrap. Each takes the sealed key state and
returns only what the keys were needed for.

### `DeriveViewTags`

**In:** sealed key state, a tag window (`from_tx_count`, `count`).
**Out:** the view tags for that window.

The client needs tags to query the indexer, and tags derive from the viewing
key, so only TVC can produce them. Windows are capped and a window that would
wrap is rejected rather than truncated, so a caller never receives tags for a
range it did not ask for.

Neither this operation nor `DecryptUtxos` makes any outbound call: both are
answered entirely from the unsealed seed.

### `DecryptUtxos`

**In:** sealed key state, the ciphertexts the client fetched.
**Out:** one plaintext per ciphertext. It keeps nothing.

**It does not say which payloads are yours, and it cannot.** The shielded-pool
transport cipher is AES-CTR with no authentication tag, so a payload addressed
to another wallet decrypts to garbage instead of failing. A batch of 256
ciphertexts returns 256 plaintexts whether or not any of them are this wallet's.

The ownership check is the client's: deserialize each plaintext with the SDK and
compare the recovered `owner_pubkey` against its own. That check needs no key, so
it belongs on the client, and putting it in the enclave would pull the whole
transaction-serialization crate into the attested image for a test the client
must repeat anyway.

### `AssembleSpend`

**In:** sealed key state, the chosen input UTXOs with their Merkle proofs, the
output description, and the transaction skeleton the client built.
**Out:** the nullifiers, and the proof request.

This is the only operation that uses the nullifier key. How the proof request
leaves TVC is the first open question below, and it decides how much this
design is worth.

---

## Flow — set up

| # | Who | What happens |
| --- | --- | --- |
| 1 | Browser | Creates a non-exportable P-256 device key. |
| 2 | Browser | Verifies the release policy, fetches `/v1/info`, runs the encrypted QOS ping, resolves and verifies the Boot Proof. Nothing proceeds until this passes. |
| 3 | Browser → TVC | Sends `BootstrapKeyholder`, encrypted to the quorum key. |
| 4 | TVC → Turnkey | Asks Turnkey to sign one fixed derivation message with the wallet key. |
| 5 | TVC | Takes `r ‖ s` of that signature as the seed and derives the shielded identity. **The seed is never returned.** |
| 6 | TVC → Browser | Public identity plus the sealed key state. |
| 7 | Browser | Stores the sealed blob. |

## Flow — sync

| # | Who | What happens |
| --- | --- | --- |
| 1 | Browser → TVC | `DeriveViewTags` with the sealed state and a window. |
| 2 | TVC → Browser | The tags for that window. |
| 3 | Browser → Indexer | Fetches by those tags. TVC is not involved. |
| 4 | Browser → TVC | `DecryptUtxos` with the ciphertexts it received. |
| 5 | TVC → Browser | One plaintext per ciphertext, with no claim about ownership. |
| 6 | Browser | Deserializes each plaintext and keeps the ones whose owner matches. Updates its balance and history view. |

Two round trips per sync. That is the main running cost of this design, and the
reason the first increment below measures it before anything else is built.

## Flow — spend

| # | Who | What happens |
| --- | --- | --- |
| 1 | Browser | Syncs as above, picks which UTXOs to spend, fetches their Merkle proofs from the indexer. |
| 2 | Browser | Builds the transaction skeleton with the Zolana SDK. Construction stays here, which is what keeps new protocol actions cheap. |
| 3 | Browser → TVC | `AssembleSpend` with the inputs, proofs and skeleton. |
| 4 | TVC | Computes the nullifiers and assembles the proof request. |
| 5 | TVC → Browser | The proof request, and the nullifiers to place in the transaction. |
| 6 | Browser → Prover | Relays the proof request. |
| 7 | Browser | Places the returned proof in the transaction. |
| 8 | Browser → TVC | `AuthorizeDefaultRingTransfer`, the narrow signing rail. |
| 9 | TVC | Validates the fixed transaction shape and asks Turnkey to sign it. |
| 10 | Browser | Submits to the network. |

Steps 8 to 10 are the existing narrow signing rail, unchanged. This design adds
key custody in front of it rather than replacing it.

---

## What each party can see

| | Seed | Private history | Amount and recipient |
| --- | --- | --- | --- |
| Browser | No | Only what TVC returns for a window it fetched | Yes, it chose them |
| TVC | Yes, per request | Only the batch in front of it, then forgets | Yes, for that request |
| Prover | No | Proof inputs | **Yes**, and the nullifier secret with them |
| Turnkey | Recomputable from the signature it produced | No | No |
| Indexer | No | View tags only, never contents | No |
| Your server, load balancer, relay | No | No | No |

---

## What this protects against, and what it does not

**Protects: a compromised device at rest.** The browser holds an opaque blob.
No viewing key, no nullifier key, no seed — not even briefly, unless a
transaction is in flight.

**Does not protect: the prover.** The proof witness carries `nullifier_secret`,
the long-lived nullifier key secret — see
`sdk-libs/client/src/prover/transact/assembly.rs`. Whoever assembles the
witness, it reaches the prover, and from it the prover can compute every
nullifier this wallet will ever produce. See the first open question.

**Does not protect: Turnkey.** Ed25519 signatures are deterministic and the
derivation message is fixed, so Turnkey computed the seed and can recompute it
at will. Closing this needs a seed Turnkey does not solely determine, which is
a separate design.

**Does not protect: linkability at the indexer.** The client must know its tags
to query by them, so the indexer still learns which tags belong to one session.
Amounts and recipients stay hidden.

**Partial: a compromised device in use.** If TVC returns plaintext UTXOs and a
plaintext proof request, a compromised browser sees them while a transaction is
in flight — but not at rest, and not for history it has not fetched.

---

## Open questions

These are decisions, not details. Each changes what the design is worth.

### 1. Does the proof request leave TVC in the clear?

If TVC returns the witness as plaintext, `nullifier_secret` passes through the
browser and "no keys on the client" becomes a formality.

The alternative: **TVC encrypts the witness to the prover's public key, and the
browser relays ciphertext it cannot read.** TVC still needs no egress and the
client becomes a dumb relay. This requires the prover to accept encrypted
requests, which is a change on its side.

Settle this before building. It may change the shape of `AssembleSpend`.

### 2. How does the client learn its tags?

Asking TVC, as specced above, leaks tags to the indexer. Fetching a range
instead leaks nothing there but costs bandwidth proportional to chain activity.
Pick deliberately rather than inheriting the first option by default.

### 3. Request size

`DecryptUtxos` sends ciphertexts through the QOS envelope, against
`PHASE0_MAX_ENCRYPTED_REQUEST_BYTES` of 262144. A wallet with a large history
needs paging, and paging must be designed so a page boundary cannot be used to
probe the wallet.

### 4. Name

`keyholder-wallet` is a placeholder.

### 5. Deployment identity

On this repository's rule that a privacy boundary is an application and not a
mode, this needs its own app id, quorum key, manifest, release policy and review
line. That operational cost is real and should be weighed against the gain.

---

## What is built

`apps/keyholder-wallet` implements bootstrap, the sealed key state, and the two
oracle operations, with `AuthorizeDefaultRingTransfer` carried over unchanged as
the signing rail.

Batches are bounded at 256 payloads per `DecryptUtxos` call and 512 tags per
`DeriveViewTags` window. The envelope limit already bounds request bytes, but it
bounds bytes rather than work: a small request can still ask for a large number
of decryptions. These are the bounds on work, and clients page against them.

Still open before this is a product: the proof-request question below, a
deployment identity, and measurement of what a sync round trip actually costs
against a wallet with real history.
