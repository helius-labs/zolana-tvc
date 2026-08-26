# Keyholder profile — design proposal

**Status: proposal, not normative.** Nothing here is implemented. The two
shipped profiles are described in [Architecture](architecture.md) and
[Wallet flows](wallet-flows.md); this document proposes a third.

## The problem this solves

The two existing profiles trade privacy against extensibility, and neither
trade is comfortable.

The lightweight profile keeps the derivation seed in the browser, so a
compromised device reveals the wallet's whole private history. But it composes
well: TVC only has to *recognise* a transaction shape, so the client can build
whatever the protocol supports.

The full-enclave profile keeps the seed inside TVC, but TVC has to *build* every
transaction. Supporting a new protocol action means teaching the enclave to
construct it, giving it the egress that construction needs, rebuilding the
image, recomputing PCRs, and running a release ceremony. That does not scale to
custom rings, swaps, or third-party ZK programs, where the shape is not known in
advance.

This profile takes the privacy property from the second and the extensibility
property from the first.

## The idea in one paragraph

TVC becomes a stateless oracle for the wallet's privacy keys rather than a
wallet. It never talks to the indexer, the prover, or Solana RPC. The client
does every network call and builds every transaction, but holds no privacy key —
it cannot read what it fetches. It sends ciphertext in, gets the key-dependent
answer out.

## Who is involved

| Party | Role |
| --- | --- |
| Browser | Runs the app and every network call. Holds a device-bound P-256 key that authorizes TVC requests, and an opaque sealed blob it cannot read. |
| Ordinary Turnkey wallet | Signs public transactions, as in the lightweight profile. |
| TVC | Holds the wallet's privacy keys. Answers key-dependent questions and nothing else. Reaches no network but Turnkey. |
| Turnkey | Custodian of the Ed25519 signing key. Evaluates the narrow policies. |
| Indexer / prover / RPC | Reached by the browser, never by TVC. |

---

## Trust boundary

| | Lightweight | **Keyholder** | Full enclave |
| --- | --- | --- | --- |
| Seed at rest | Browser, device-sealed | **Quorum-sealed, browser cannot read** | Quorum-sealed |
| Viewing key | Browser | **TVC only** | TVC only |
| Nullifier key | Browser | **TVC only** | TVC only |
| Who fetches from the indexer | Browser | **Browser** | TVC |
| Who calls the prover | Browser | **Browser, as a relay** | TVC |
| Who builds the transaction | Browser | **Browser** | TVC |
| TVC egress | Turnkey only | **Turnkey only** | Turnkey, indexer, RPC, prover |
| New protocol action needs | TVC to recognise a shape | **TVC to recognise a shape** | TVC to build it |

The row that matters: TVC gains the key custody of the full-enclave profile
while keeping the egress surface and the extensibility of the lightweight one.

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

This is the same construction as the full-enclave sealed checkpoint, reused
here. The browser cannot read it, cannot use it against a different descriptor,
and cannot replay it past a quorum key rotation.

It also stores public display data — balances and history as TVC last reported
them — which is bookkeeping, not privacy material.

---

## Operations

Three new typed operations, on top of the existing bootstrap.

### `DeriveViewTags`

Input: sealed key state, a tag window (`from_tx_count`, `count`).
Output: the view tags for that window.

The client needs tags to query the indexer. They come from the viewing key, so
only TVC can produce them.

### `DecryptUtxos`

Input: sealed key state, the ciphertexts the client fetched.
Output: the decrypted UTXO set — asset, amount, blinding, leaf index.

This is the operation that replaces client-side sync. TVC decrypts with the
viewing key and returns plaintext. It holds nothing afterwards.

### `AssembleSpend`

Input: sealed key state, the chosen input UTXOs with their Merkle proofs, the
output description, and the transaction skeleton the client built.
Output: the nullifiers, and the proof request.

This is where the nullifier key is used. See the open question on how the proof
request leaves TVC.

---

## Flow — set up

| # | Who | What happens |
| --- | --- | --- |
| 1 | Browser | Verifies the release policy, runs the QOS ping, verifies the Boot Proof. Unchanged from both existing profiles. |
| 2 | Browser → TVC | `BootstrapKeyholder`. |
| 3 | TVC → Turnkey | Signs the fixed derivation message; `r ‖ s` is the seed. |
| 4 | TVC | Derives the shielded identity. **Does not return the seed.** |
| 5 | TVC → Browser | Public identity plus the sealed key state. |
| 6 | Browser | Stores the sealed blob. |

## Flow — sync

| # | Who | What happens |
| --- | --- | --- |
| 1 | Browser → TVC | `DeriveViewTags` with the sealed state and a window. |
| 2 | TVC → Browser | The tags. |
| 3 | Browser → Indexer | Fetches by those tags. TVC is not involved. |
| 4 | Browser → TVC | `DecryptUtxos` with the ciphertexts. |
| 5 | TVC → Browser | Plaintext UTXOs. |
| 6 | Browser | Updates its balance view. |

Two round trips per sync where the lightweight profile has none. That is the
main cost of this design.

## Flow — spend

| # | Who | What happens |
| --- | --- | --- |
| 1 | Browser | Syncs as above, picks which UTXOs to spend, fetches Merkle proofs from the indexer. |
| 2 | Browser | Builds the transaction skeleton with the Zolana SDK. **The client still owns construction, which is what keeps new protocol actions cheap.** |
| 3 | Browser → TVC | `AssembleSpend` with the inputs, proofs, and skeleton. |
| 4 | TVC | Computes nullifiers with the nullifier key and assembles the proof request. |
| 5 | TVC → Browser | The proof request, and the nullifiers to place in the transaction. |
| 6 | Browser → Prover | Relays the proof request. |
| 7 | Browser | Places the returned proof in the transaction. |
| 8 | Browser → TVC | `AuthorizeDefaultRingTransfer` — the existing operation, unchanged. |
| 9 | TVC | Validates the shape and asks Turnkey to sign. |
| 10 | Browser | Submits. |

Steps 8 to 10 are exactly the lightweight profile's spend rail. This profile
adds key custody in front of it; it does not replace it.

---

## What each party can see

| | Seed | Private history | Amount and recipient |
| --- | --- | --- | --- |
| Browser | No | Only what TVC returns for a window it fetched | Yes, it chose them |
| TVC | Yes | Only the batch in front of it, then forgets | Yes, for that request |
| Prover | No | Proof inputs | **Yes**, and the nullifier secret with them |
| Turnkey | Recomputable from the signature it produced | No | No |
| Indexer | No | View tags only, not contents | No |
| Your server, load balancer, relay | No | No | No |

Compare the same table in [Wallet flows](wallet-flows.md): the row that changes
against the lightweight profile is the browser's, and only that one.

---

## What this protects against, and what it does not

**Protects: a compromised device at rest.** The browser holds an opaque blob. No
viewing key, no nullifier key, no seed, not even briefly, unless a transaction
is in flight.

**Does not protect: the prover.** The proof witness contains
`nullifier_secret` — the long-lived nullifier key secret, verified in
`sdk-libs/client/src/prover/transact/assembly.rs`. Whoever assembles the witness,
it reaches the prover, and from it the prover can compute every nullifier this
wallet will ever produce. See the open question below.

**Does not protect: Turnkey.** Ed25519 signatures are deterministic and the
derivation message is fixed, so Turnkey computed the seed and can recompute it.
This is true of all three profiles and is the largest single gap in the model.

**Does not protect: the indexer's view of linkability.** The client must know its
tags to query by them, so the indexer still learns which tags belong to one
session. Amounts and recipients stay hidden.

**Partial: a compromised device in use.** If TVC returns plaintext UTXOs and a
proof request, a compromised browser sees them while a transaction is in
flight — but not at rest, and not for history it has not fetched.

---

## Open questions

These are decisions, not details. Each changes what the profile is worth.

### 1. Does the proof request leave TVC in the clear?

If TVC returns the witness as plaintext, `nullifier_secret` passes through the
browser and "no keys on the client" becomes a formality.

The alternative: **TVC encrypts the witness to the prover's public key and the
browser relays ciphertext it cannot read.** TVC still needs no egress, and the
client becomes a dumb relay. This requires the prover to accept encrypted
requests, which is a change on its side.

Without this, the profile's privacy gain over lightweight is much smaller than
it looks. This should be settled before building.

### 2. How does the client learn its tags?

Asking TVC (as specced above) leaks tags to the indexer, same as today. Fetching
a range instead leaks nothing to the indexer but costs bandwidth proportional to
chain activity. Pick deliberately.

### 3. Request size

`DecryptUtxos` sends ciphertexts through the QOS envelope, against
`PHASE0_MAX_ENCRYPTED_REQUEST_BYTES` of 262144. A wallet with a large history
will need paging, and paging has to be designed so a page boundary cannot be
used to probe the wallet.

### 4. Name

`keyholder-wallet` is a placeholder. The existing names describe where the
privacy boundary sits — client-owned, enclave-owned. This one is enclave-owned
keys with client-owned I/O, and deserves a name that says so.

### 5. Is this a third application?

Yes, on the repository's own rule: profiles are separate applications, not modes.
That means a third app id, quorum key, manifest, release policy, and review line.
The operational cost is real and should be weighed against the gain.

---

## Suggested first increment

Do not build the profile. Build one operation and measure.

**`DecryptUtxos` alone**, against the existing lightweight application, with the
seed still where it is today. It answers the questions that decide whether the
rest is worth building:

- how large is a realistic ciphertext batch, and does it fit the envelope;
- what does a sync round trip cost in latency;
- does the decrypt path fit the enclave's memory and CU profile.

If those numbers are bad, the design does not work and nothing else was wasted.
If they are good, the remaining work is well understood: two more operations,
the sealed key state, and a third deployment identity.
