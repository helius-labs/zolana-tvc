# Wallet flows

This document walks through the lifecycle of a private wallet — set up,
register, shield, transfer, unshield — and says who does each step in each of
the two profiles. Where the current development profile does not yet have a
usable end-to-end path, the limitation is called out explicitly.

For the design rationale behind having two profiles at all, see
[Architecture](architecture.md). For what is and is not verified, see
[Security](security.md).

## Who is involved

| Party | Role |
| --- | --- |
| Browser | Runs the app. Holds a device-bound P-256 key that authorizes TVC requests. |
| Ordinary Turnkey wallet | The user's normal embedded wallet. Signs public transactions. |
| TVC | The attested application. Holds the Turnkey credential that can invoke the narrow wallet policies. |
| Turnkey | Custodian of the Ed25519 signing key. Evaluates the installed policies. |
| Indexer / prover / RPC | Zolana services. The prover receives private proof inputs. |

The Ed25519 signing key never leaves Turnkey in either profile. What differs is
where the *privacy* material lives and who builds the transaction.

## The endpoints

The production-shaped deployments expose the same four endpoints:

| Endpoint | Purpose |
| --- | --- |
| `GET /health` | Readiness for a load balancer. Returns `{"status":"Healthy"}` and nothing else. Client verification never uses it. |
| `GET /v1/info` | Untrusted discovery, checked field by field against the signed release policy. |
| `POST /v1/ping` | Encrypted challenge that ties the responding replica to a Boot Proof. |
| `POST /v1/operations` | Every real typed wallet operation, encrypted end to end. |

The local unattested harness additionally compiles
`POST /dev/v1/bootstrap-ed25519` behind the `local-dev` Cargo feature. That
route is absent from deployed images, whose default feature set is empty.

The Boot Proof is **not** a TVC endpoint. It is fetched through the caller's own
authenticated Turnkey session, via the `resolveBootProof` callback.

### What `/v1/info` is for

It advertises the running release id, manifest and executable digests, quorum
key id and epoch, supported operations, size limits, security domain and proof
type.

The client trusts none of it. Every field is compared against the independently
signed release policy, which fails closed on a mismatch — a wrong deployment, a
stale release or an unexpected quorum key is caught immediately.

Two fields are not verification inputs at all: `ephemeral_public_key` and
`boot_proof_lookup_key`. The key that matters comes from the ping response and
is only trusted once the Boot Proof ties it to a pinned-PCR attestation.

Discovery could in principle be replaced by static configuration, and it would
be no more secure — because nothing here grants anything. It would just force
every client to hardcode the full runtime description.

### What `/v1/ping` is for

It is an attestation handshake, not a health check:

1. the client generates a random 32-byte challenge;
2. encrypts it to the quorum **encryption** key, which the release policy pins;
3. the replica decrypts it — only a holder of the quorum private key can;
4. the replica signs the exact challenge with its ephemeral **signing** key;
5. the client fetches the Boot Proof for that key and checks the Nitro chain,
   the pinned PCRs and the QOS manifest commitment.

The 130-byte QOS key is `encryption(65) ‖ signing(65)`. The challenge goes to the
first half and the signature is checked against the second, so the two roles
cannot be swapped without the exchange failing.

Ping alone proves **liveness**, not authenticity: anyone holding the quorum
decryption key could answer. Authenticity comes from step 5. The client fetches
and policy-binds `/v1/info` first; without a Boot Proof resolver or pinned PCRs,
it then fails with `BootProofUnverified` before sending `/v1/ping` or any wallet
operation.

Keeping this separate from the first operation is a development choice. It could
be folded in later; as a separate step it makes connection failures legible.

## The difference in one paragraph

In the **lightweight** profile the browser is the wallet. It holds the
derivation seed, syncs from the indexer, picks which UTXOs to spend, calls the
prover, and builds the transaction. TVC is a narrow gatekeeper: it hands out the
seed through the bootstrap rail while that Turnkey policy remains active, and
after that it only checks the shape of a finished transaction before asking
Turnkey to sign it. The current POC does not enforce bootstrap as a one-shot
operation; production enrollment is expected to revoke that policy explicitly.
    
In the **full-enclave** profile the enclave is the wallet. It holds the seed,
syncs, picks inputs, calls the prover, and builds the transaction. The browser
holds an encrypted blob it cannot read, sends it back with each request, and
decides when a new blob becomes the current one.

Both keep the enclave itself stateless between requests. The difference is who
can read the derived privacy material and the indexer-recovered wallet state.
The full-enclave browser still keeps readable local bookkeeping for operations
it initiated; only the cryptographic checkpoint is opaque to it.

---

# Lightweight profile

TVC exposes exactly two operations: `BootstrapClientEd25519` and
`AuthorizeDefaultRingTransfer`. Everything else happens in the browser or
through the user's ordinary Turnkey wallet.

## Step 0 — Set up the wallet

| # | Who | What happens |
| --- | --- | --- |
| 1 | Browser | Creates a non-exportable P-256 key in IndexedDB. This is the device key that authorizes TVC requests. |
| 2 | Browser | Verifies the release policy, fetches `/v1/info`, runs the encrypted QOS ping, resolves and verifies the Boot Proof. Nothing proceeds until this passes. |
| 3 | Browser → TVC | Sends `BootstrapClientEd25519`, encrypted to the quorum key. |
| 4 | TVC → Turnkey | Asks Turnkey to sign one fixed message (`ed25519_derivation_message`) with the wallet key. |
| 5 | TVC | Takes `r ‖ s` of that signature as a 64-byte seed and derives the shielded identity from it. |
| 6 | TVC → Browser | Returns the seed and the public identity, encrypted to a one-time response key. |
| 7 | Browser | Checks the address matches the descriptor, re-derives the identity from the seed and checks it matches. |
| 8 | Browser | Seals the seed with a non-exportable AES-GCM key and stores it in IndexedDB. |

The derivation is deterministic: the same signature gives the same seed. While
the bootstrap Turnkey policy remains active, a lost local copy can be derived
again. Once that policy is revoked, recovery requires a separately designed
backup/re-enrollment path; the sealed browser copy is not unconditionally a
disposable cache.

## Step 1 — Register on chain

| # | Who | What happens |
| --- | --- | --- |
| 1 | Browser | Builds the registration transaction locally. |
| 2 | Ordinary Turnkey wallet | Signs it. **TVC is not involved** — this is a public transaction. |
| 3 | Browser | Submits it and marks the wallet registered. |

## Step 2 — Shield (public SOL → private balance)

| # | Who | What happens |
| --- | --- | --- |
| 1 | Browser | Builds the deposit transaction locally. |
| 2 | Ordinary Turnkey wallet | Signs it. **TVC is not involved.** |
| 3 | Browser | Submits it. |
| 4 | Browser | Syncs from the indexer and finds the new UTXO. |

A deposit is public by nature — anyone can see that address X put N SOL into the
pool. There is nothing to hide, so it does not need the narrow policy.

## Step 3 — Private transfer

This is where TVC comes in, because private funds are being spent.

| # | Who | What happens |
| --- | --- | --- |
| 1 | Browser | Syncs if the local snapshot is older than 10 seconds. |
| 2 | Browser | Picks which UTXOs to spend. |
| 3 | Browser → Prover | Requests the zero-knowledge proof. **The prover sees the private inputs.** |
| 4 | Browser | Builds the finished transaction bytes. |
| 5 | Browser | Computes the intent digest: commits recipient, amount and asset to the exact hash of those bytes. |
| 6 | Browser | Signs the request digest with the device P-256 key. |
| 7 | Browser → TVC | Sends the request in a QOS envelope. Your server, the load balancer and any relay see only ciphertext. |
| 8 | TVC | Checks the transaction shape: exactly one signature, first account is this wallet, 2–3 instructions, the last one is the shielded pool program with the `TRANSACT` tag. |
| 9 | TVC → Turnkey | Requests the signature under the narrow policy. |
| 10 | TVC | Verifies Turnkey returned the same message, one signature, valid under the wallet key. |
| 11 | TVC → Browser | Returns the signed transaction plus an App Proof binding request digest to result digest. |
| 12 | Browser | Re-verifies independently: same message bytes, signature valid under the descriptor key, base58 id matches. Verifies a fresh Boot Proof. |
| 13 | Browser | Writes the pending entry to its journal **before** submitting. |
| 14 | Browser | Submits to the network. |
| 15 | Browser | On confirmation calls `completeDefaultRingTransaction`. It calls `expireDefaultRingTransaction` only after a definitive pre-submission failure or proven blockhash expiry. A timeout or unknown RPC outcome keeps the journal entry pending for later signature lookup. |

## Step 4 — Unshield (private balance → public SOL)

Same rail as a transfer, with one difference: the intent digest uses a separate
domain (`..._SOL_WITHDRAWAL_INTENT_V1` instead of the transfer domain), so a
withdrawal digest cannot be passed off as a transfer.

Everything else is identical. TVC sees the same `TRANSACT` shape and does not
distinguish a withdrawal from a transfer.

---

# Full-enclave profile

TVC exposes `CreateWallet`, `BootstrapEd25519`, `PrepareWallet`, `ShieldSol` and
`BuildTransfer`. Bootstrap creates the sealed checkpoint. Later state-changing
operations return that checkpoint alongside the signed transaction; in the
current implementation they return the same bytes and version they received.

Full-enclave unshield is **not end-to-end usable in the current acceptance
profile**. `BuildTransfer` asks the Zolana SDK to resolve the recipient: a
registered address becomes a private transfer and an unregistered address
becomes a public withdrawal. However, the installed
`zolana-tvc-sol-withdrawal` Turnkey policy permits the public recipient account
only when it is the same provisioned wallet address. After `PrepareWallet`, that
address is registered, so it resolves to a private self-transfer instead. An
arbitrary unregistered address produces a withdrawal transaction but is
rejected by the current Turnkey account-key policy.

Completing this flow requires a distinct typed withdrawal intent/operation (or
an equivalent explicit SDK path) plus a matching narrow Turnkey policy. The
document therefore describes `BuildTransfer` below as the currently usable
private-transfer path, not as an implemented unshield API.

## Step 0 — Set up the wallet

| # | Who | What happens |
| --- | --- | --- |
| 1 | Browser | Same device key and same connection verification as the lightweight profile. |
| 2 | Browser → TVC | Sends `BootstrapEd25519`. |
| 3 | TVC → Turnkey | Same fixed-message signature, same seed derivation. |
| 4 | TVC | Derives the shielded identity and **keeps the seed inside**. It is not returned. |
| 5 | TVC → Browser | Returns the public identity plus the first sealed checkpoint. |
| 6 | Browser | Stores the checkpoint. It is an opaque blob; the browser cannot read it. |

## Step 1 — Register on chain

| # | Who | What happens |
| --- | --- | --- |
| 1 | Browser → TVC | Sends `PrepareWallet` with the current checkpoint and a recent blockhash. |
| 2 | TVC | Unseals the checkpoint, builds the registration transaction, has Turnkey sign it. |
| 3 | TVC → Browser | Returns the signed transaction and the checkpoint it received. |
| 4 | Browser | Journals both. Submits the transaction. |
| 5 | Browser | On confirmation, settles the journal, retains the returned checkpoint and marks the wallet registered. |

## Step 2 — Shield

| # | Who | What happens |
| --- | --- | --- |
| 1 | Browser → TVC | Sends `ShieldSol` with the amount, or `ShieldSpl` with the mint, asset id and amount, plus the current checkpoint. |
| 2 | TVC | Unseals, restores the keypair, builds the deposit, has Turnkey sign it. For SPL it first resolves the mint through the shielded-pool asset registry, reads the token program from the mint account's owner, and derives the associated token account — none of these come from the caller. |
| 3 | TVC → Browser | Signed transaction plus the unchanged current checkpoint. |
| 4 | Browser | Journals, submits, and on confirmation settles the entry, retains the returned checkpoint and credits its local balance. |

Unlike the lightweight profile, shielding here goes through TVC because this
profile keeps transaction construction and its narrow Turnkey signing rail in
the attested application. The deposit changes chain state, but it does not
currently mutate the sealed checkpoint.

## Step 3 — Private transfer

| # | Who | What happens |
| --- | --- | --- |
| 1 | Browser → TVC | Sends `BuildTransfer` with recipient, amount, prover profile and the current checkpoint. |
| 2 | TVC | Unseals the checkpoint and restores the wallet. |
| 3 | TVC → Indexer | Syncs. |
| 4 | TVC | Resolves the recipient in the shielded registry and picks which UTXOs to spend. The currently accepted path requires a registered recipient. |
| 5 | TVC → Prover | Requests the proof. **The prover still sees the private inputs.** |
| 6 | TVC | Builds the transaction and has Turnkey sign it under the narrow policy. |
| 7 | TVC → Browser | Signed transaction, the balance it spent from, and the unchanged current checkpoint. |
| 8 | Browser | Checks the amount does not exceed the reported balance, journals, submits. |
| 9 | Browser | On confirmation settles the journal and updates its local balance; a self-transfer is net zero. It abandons only a definitively failed or expired transaction. An unknown outcome remains pending. |

## What a sealed checkpoint actually contains

It is worth being precise, because the name suggests a wallet snapshot and it is
not one. Decrypted, a checkpoint holds:

| Field | Purpose |
| --- | --- |
| `derivation_seed` (64 bytes) | The actual secret. This is what the seal protects. |
| `wallet_id`, `descriptor_digest`, `policy_version` | Binds the checkpoint to one descriptor at one policy version. |
| `ed25519_public_key`, `derivation_suite` | Binds it to one wallet key and derivation scheme. |
| `state_version`, `previous_state_digest` | A continuity chain. |
| `quorum_key_id`, `quorum_key_epoch` | Binds it to the quorum key that sealed it. |

**There are no UTXOs and no balances in it.** The enclave re-syncs the wallet
from the indexer on every operation, so the spendable set always comes from the
chain, never from the checkpoint.

So a checkpoint is really a sealed carrier for the derivation seed, plus enough
binding metadata that it cannot be replayed against a different descriptor,
policy version, wallet, or quorum key epoch. It saves the enclave from asking
Turnkey to re-derive the seed on every request.

This binding is not a general anti-replay mechanism. The same checkpoint can be
reused with the same descriptor and quorum epoch today because its version does
not advance after bootstrap.

When the enclave unseals one it checks every field twice: the outer envelope
against the request, then the decrypted inner state against the envelope and the
descriptor. Any mismatch is rejected before the seed is used.

## What the checkpoint does today, and what it is built for

In the current implementation, only bootstrap creates a checkpoint, at
`state_version: 1`. Every later operation returns **the same sealed bytes it
received**, with the version unchanged. `previous_state_digest` and the version
chain are protocol scaffolding for stateful operations that do not exist yet.

That means the journal's checkpoint promotion is, right now, promoting a value
identical to the one it replaces. What the journal genuinely protects today is:

- **the signed transaction**, so a crash mid-flight leaves a record you can
  check against the chain rather than blindly re-issuing;
- **the browser's local balance and history**, which are its own bookkeeping on
  top of the balance the enclave reported, not values read back from the
  checkpoint;
- **one in-flight transaction per local browser-state instance**, so that one
  instance does not issue a second spend while its first result is unknown.

There is no cross-device lock or server-side compare-and-swap today. Two devices
holding the same valid checkpoint can race operations; the chain will reject a
double spend, but the local journals and confirmation handling must recover from
that outcome independently.

The sequence still matters, and will matter more once operations start
advancing the state:

1. **Journal** — store the signed transaction and the checkpoint it *would*
   produce, side by side, keeping the current checkpoint authoritative.
2. **Confirm** — submit and wait for a final on-chain outcome.
3. **Activate** — confirmed: settle the entry and apply the balance change.
   Definitively failed or expired: drop it, leaving balance and checkpoint as
   they were. Unknown: keep it pending and resume by transaction signature.

---

# Side by side

The wire transport is identical. What differs is the content of the encrypted
`/v1/operations` body and where the wallet logic runs.

| | Lightweight | Full enclave |
| --- | --- | --- |
| Operations | `BootstrapClientEd25519`, `AuthorizeDefaultRingTransfer` | `CreateWallet`, `BootstrapEd25519`, `PrepareWallet`, `ShieldSol`, `ShieldSpl`, `BuildTransfer` |
| Who holds the seed | Browser, sealed with a device key | TVC only |
| Who syncs the wallet | Browser | TVC |
| Who picks input UTXOs | Browser | TVC |
| Who calls the prover | Browser | TVC |
| Who builds the transaction | Browser | TVC |
| What TVC checks | Client authorization, descriptor/release bindings, fixed transaction shape, and the exact Turnkey result | Typed intent, client/descriptor/checkpoint bindings, registry and balance constraints, proof/prover profile, Turnkey result, and final transaction bounds |
| Register | Ordinary Turnkey wallet | TVC (`PrepareWallet`) |
| Shield | Ordinary Turnkey wallet, SOL only | TVC (`ShieldSol`, `ShieldSpl`) |
| Transfer | TVC (`AuthorizeDefaultRingTransfer`) | TVC (`BuildTransfer`) |
| Unshield | TVC, same rail, caller picks the intent domain | Not yet end-to-end usable; requires an explicit narrow withdrawal rail/policy |
| TVC between requests | Stateless | Stateless |
| Wallet state | Browser, readable by the browser | Derivation seed in an opaque checkpoint; local balance, pending entry and locally initiated history remain browser-readable |
| Browser compromise reveals history | Yes | Reveals local requests/journal, but not the enclave-recovered UTXO set or complete indexer-derived private history |
| TVC egress | Turnkey only — no indexer, prover, RPC or wallet-sync calls at all | Turnkey, plus indexer, RPC and prover |

## What each party can see

| | Seed | Private history | Amount and recipient |
| --- | --- | --- | --- |
| Browser (lightweight) | Yes | Yes | Yes |
| Browser (full enclave) | No | Only what TVC reports | Yes, it asked for it |
| TVC (lightweight) | During each permitted bootstrap call, then forgets | No | No — only the shape |
| TVC (full enclave) | Yes | Yes | Yes |
| Prover | No | Proof inputs | **Yes, in both profiles** |
| Turnkey | Produces the signature it is derived from | No | No private-transfer semantics; it receives the transaction bytes |
| TVC ingress server, load balancer, relay | No | No | No plaintext amount or recipient; request size and timing remain visible |

Three things worth being blunt about:

- **The prover sees private inputs in both profiles.** Moving the caller from
  the browser into the enclave changes which software talks to it, not the fact
  of the disclosure.
- **The lightweight TVC cannot recover amount or recipient from the shielded
  instruction.** The intent digest commits them, but the browser computes it,
  so a compromised browser can commit to something the user did not intend. It
  still cannot obtain a signature for an arbitrary transaction shape.
- **The full enclave sees the typed amount and recipient and builds the
  transaction, but device authorization is not proof of human intent.** A
  compromised browser can still request values different from what its UI
  displayed. A production design needs an independently authenticated owner
  intent if that distinction is part of the security claim.
