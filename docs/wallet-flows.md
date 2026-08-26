# Wallet flows

This document walks through the full lifecycle of a private wallet — set up,
register, shield, transfer, unshield — and says who does each step in each of
the two profiles.

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

## The difference in one paragraph

In the **lightweight** profile the browser is the wallet. It holds the
derivation seed, syncs from the indexer, picks which notes to spend, calls the
prover, and builds the transaction. TVC is a narrow gatekeeper: it hands out the
seed once, and after that it only checks the shape of a finished transaction
before asking Turnkey to sign it.
    
In the **full-enclave** profile the enclave is the wallet. It holds the seed,
syncs, picks inputs, calls the prover, and builds the transaction. The browser
holds an encrypted blob it cannot read, sends it back with each request, and
decides when a new blob becomes the current one.

Both keep the enclave itself stateless between requests. The difference is who
can *read* the wallet state: the browser, or only the attested code.

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

The derivation is deterministic: the same signature always gives the same seed,
so local storage is a recoverable cache, not the root of the funds.

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
| 4 | Browser | Syncs from the indexer and finds the new note. |

A deposit is public by nature — anyone can see that address X put N SOL into the
pool. There is nothing to hide, so it does not need the narrow policy.

## Step 3 — Private transfer

This is where TVC comes in, because private funds are being spent.

| # | Who | What happens |
| --- | --- | --- |
| 1 | Browser | Syncs if the local snapshot is older than 10 seconds. |
| 2 | Browser | Picks which notes to spend. |
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
| 15 | Browser | On confirmation calls `completeDefaultRingTransaction`; on failure or expiry calls `expireDefaultRingTransaction`. |

## Step 4 — Unshield (private balance → public SOL)

Same rail as a transfer, with one difference: the intent digest uses a separate
domain (`..._SOL_WITHDRAWAL_INTENT_V1` instead of the transfer domain), so a
withdrawal digest cannot be passed off as a transfer.

Everything else is identical. TVC sees the same `TRANSACT` shape and does not
distinguish a withdrawal from a transfer.

---

# Full-enclave profile

TVC exposes `CreateWallet`, `BootstrapEd25519`, `PrepareWallet`, `ShieldSol` and
`BuildTransfer`. Each state-changing operation returns a new sealed checkpoint.

Unshield has no operation of its own here. `BuildTransfer` covers both: the
Zolana SDK resolves the recipient against the shielded registry, and when the
recipient is an ordinary public address that is not registered, it builds a
withdrawal instead of a private transfer. Turnkey has a matching policy for that
shape (`zolana-tvc-sol-withdrawal`, two instructions and six account keys
including the SOL interface), so the signature goes through.

The practical difference from the lightweight profile is that the caller does
not choose: it passes a recipient, and whether that becomes a transfer or a
withdrawal is decided by whether the address is registered.

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
| 3 | TVC → Browser | Returns the signed transaction **and a new checkpoint**. |
| 4 | Browser | Journals both. Submits the transaction. |
| 5 | Browser | On confirmation, promotes the new checkpoint and marks the wallet registered. |

## Step 2 — Shield

| # | Who | What happens |
| --- | --- | --- |
| 1 | Browser → TVC | Sends `ShieldSol` with the amount and the current checkpoint. |
| 2 | TVC | Unseals, restores the keypair, builds the deposit, has Turnkey sign it. |
| 3 | TVC → Browser | Signed transaction plus a new checkpoint. |
| 4 | Browser | Journals, submits, and on confirmation promotes the checkpoint and credits the balance. |

Unlike the lightweight profile, shielding here goes through TVC, because TVC
owns the wallet state that the deposit changes.

## Step 3 — Private transfer, or unshield

| # | Who | What happens |
| --- | --- | --- |
| 1 | Browser → TVC | Sends `BuildTransfer` with recipient, amount, prover profile and the current checkpoint. |
| 1a | TVC | Looks the recipient up in the shielded registry. Registered means a private transfer; unregistered means a withdrawal to that public address. |
| 2 | TVC | Unseals the checkpoint and restores the wallet. |
| 3 | TVC → Indexer | Syncs. |
| 4 | TVC | Picks which notes to spend. |
| 5 | TVC → Prover | Requests the proof. **The prover still sees the private inputs.** |
| 6 | TVC | Builds the transaction and has Turnkey sign it under the narrow policy. |
| 7 | TVC → Browser | Signed transaction, the balance it spent from, and a new checkpoint. |
| 8 | Browser | Checks the amount does not exceed the reported balance, journals, submits. |
| 9 | Browser | On confirmation promotes the checkpoint and debits the balance; on failure abandons it. |

## Why the journal exists

The enclave keeps nothing between requests. It hands back a new checkpoint and
forgets the request.

So if the browser adopted that checkpoint straight away and the transaction then
failed, the saved state would say those notes are spent while the chain says
they are not. The wallet could not rebuild those inputs to retry, and the funds
would be stuck.

The journal avoids that:

1. **Journal** — store the signed transaction and the checkpoint it *would*
   produce, side by side, keeping the old checkpoint authoritative.
2. **Confirm** — submit and wait for a final on-chain outcome.
3. **Activate** — confirmed: promote the new checkpoint. Failed or expired: drop
   it, the old one stands, and a retry works.

It also means a crash mid-flight is recoverable: on reload the journal is still
there, so the app can check whether that transaction landed instead of blindly
re-issuing it.

---

# Side by side

| | Lightweight | Full enclave |
| --- | --- | --- |
| Who holds the seed | Browser, sealed with a device key | TVC only |
| Who syncs the wallet | Browser | TVC |
| Who picks inputs | Browser | TVC |
| Who calls the prover | Browser | TVC |
| Who builds the transaction | Browser | TVC |
| What TVC checks | Transaction shape only | It builds it, so nothing to check |
| Register | Ordinary Turnkey wallet | TVC (`PrepareWallet`) |
| Shield | Ordinary Turnkey wallet | TVC (`ShieldSol`) |
| Transfer | TVC (`AuthorizeDefaultRingTransfer`) | TVC (`BuildTransfer`) |
| Unshield | TVC, same rail, caller picks the intent domain | TVC, same `BuildTransfer`, chosen by whether the recipient is registered |
| TVC between requests | Stateless | Stateless |
| Wallet state | Browser, readable by the browser | Browser, sealed and unreadable |
| Browser compromise reveals history | Yes | Intended not to |
| TVC needs indexer / prover / RPC access | No | Yes |

## What each party can see

| | Seed | Private history | Amount and recipient |
| --- | --- | --- | --- |
| Browser (lightweight) | Yes | Yes | Yes |
| Browser (full enclave) | No | Only what TVC reports | Yes, it asked for it |
| TVC (lightweight) | Derives once, then forgets | No | No — only the shape |
| TVC (full enclave) | Yes | Yes | Yes |
| Prover | No | Proof inputs | **Yes, in both profiles** |
| Turnkey | Produces the signature it is derived from | No | No |
| Your server, load balancer, relay | No | No | No |

Two things worth being blunt about:

- **The prover sees private inputs in both profiles.** Moving the caller from
  the browser into the enclave changes which software talks to it, not the fact
  of the disclosure.
- **TVC cannot check that the amount matches what the user was shown.** Those
  values are hidden inside the zero-knowledge instruction. The intent digest
  commits them, but the browser computes it — so in the lightweight profile a
  compromised browser can commit to something the user did not intend. It still
  cannot move funds with an arbitrary transaction, because Turnkey will only
  sign the one allowed shape.
