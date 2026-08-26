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

### The sealed state is a cache, not the root of recovery

The seed comes from a deterministic Ed25519 signature over a fixed message, so
the same Turnkey wallet always produces the same seed and therefore the same
shielded identity. Bootstrap is repeatable, and it is the recovery path.

That makes Quorum key rotation ordinary work rather than a migration:

| # | Who | What happens |
| --- | --- | --- |
| 1 | Operator | Deploys a new release with a new Quorum key. |
| 2 | Browser | Verifies the new release and its Boot Proof. |
| 3 | Browser → TVC | Calls `BootstrapKeyholder` with no prior blob. Presenting one is rejected, so a caller cannot choose which state a fresh derivation appears to continue. |
| 4 | TVC → Turnkey | Gets the same fixed derivation signature. |
| 5 | Browser | **Checks the returned identity against the one it already knew** and refuses a mismatch. |
| 6 | TVC | Seals the same seed under the new Quorum key. |
| 7 | Browser | Stores the new blob and drops the old one. |

Step 5 is load-bearing. Without it a release returning a different identity
would be adopted silently, leaving the old balance unreachable and unremarked.
`bootstrapKeyholder` takes the previously observed identity for exactly this and
fails with `ShieldedIdentityChanged` rather than proceeding.

No separate rewrap operation is needed, and step 7 needs no atomicity: a browser
that loses both blobs re-bootstraps. Blobs are never portable between
deployments — each is bound to the Quorum key epoch that produced it.

**What this moves the single point of failure to.** Losing the sealed blob is
survivable; losing the Turnkey wallet is not. If that key is deleted, or the
policy permitting the fixed derivation signature is revoked with no alternative
rail, the wallet is gone. In production that key needs a retention policy of no
deletion and no export, plus an audited recovery process. That is the real
custody requirement this design creates, and it should be stated in the
deployment runbook rather than discovered.

A new descriptor may name a different release, Quorum key or epoch, but must
name the same Turnkey wallet account. A new device is a new P-256 key, which
must be user-authorized into the descriptor before it can be used.

---

## HTTP API

The deployed keyholder has four public routes. All JSON is strict: unknown and
duplicate fields are rejected, binary values are lowercase hex, and integers on
the wire are canonical decimal strings. `POST` requests require
`Content-Type: application/json`.

| Call | Purpose | Trust boundary |
| --- | --- | --- |
| `GET /health` | Readiness probe. Returns exactly `{"status":"Healthy"}` only after QOS keys and the approved manifest are loaded; otherwise it returns a generic `503`. | Liveness only. It exposes no keys, wallet IDs or release IDs and proves no enclave identity. |
| `GET /v1/info` | Returns `ServiceInfoV1`: release and executable digests, security domain, Quorum and Ephemeral public keys, supported operations, envelope limits and the Boot Proof lookup key. | Untrusted discovery. The client first verifies an independently signed release policy, then checks every security-relevant field from this response against it. |
| `POST /v1/ping` | Proves that the running process can decrypt with the QOS Quorum encryption key and sign with the QOS Ephemeral signing key. | Connection verification only. It takes no wallet descriptor, calls no Turnkey API and grants no wallet capability. |
| `POST /v1/operations` | Executes one descriptor-bound, client-authorized keyholder operation through a QOS-encrypted envelope. | The only wallet operation endpoint. It is not a generic signing or `ShieldedKeypairTrait` RPC surface. |

### `GET /health`

The body is deliberately smaller than `/v1/info`:

```json
{"status":"Healthy"}
```

Use it for load-balancer readiness only. A healthy response must not be treated
as attestation or release verification.

### `GET /v1/info`

This call supplies the public material needed to start verification, including
`manifest_digest`, `executable_digest`, `quorum_public_key`,
`ephemeral_public_key`, `quorum_key_epoch`, `supported_operations` and
`boot_proof_lookup_key`. None of those values is trusted merely because it came
over HTTPS. The client binds them to its signed `ReleasePolicyV1`, then verifies
the QOS ping and matching AWS Nitro Boot Proof before creating a
`VerifiedConnection`.

### `POST /v1/ping`

The client creates a fresh canonical challenge:

```json
{"challenge":"<32-byte hex>","type":"zolana.tvc.qos_ping.v1","version":1}
```

It QOS-encrypts those exact UTF-8 bytes to the Quorum encryption public key and
sends the ciphertext in `QosPingRequestV1`. TVC decrypts it and returns the same
canonical payload in a `TvcAppProofV1`, signed by the Ephemeral signing key. The
client checks the challenge, signature, release binding and Boot Proof. The
encryption and signing halves of both 130-byte QOS public keys are distinct and
must never be swapped.

### `POST /v1/operations`

The clear outer request contains only the version, Quorum key identity and QOS
ciphertext:

```json
{
  "version": 1,
  "quorum_key_id": "<id>",
  "quorum_key_epoch": "1",
  "ciphertext": "<hex>"
}
```

The encrypted `OperationRequestV1` binds the request ID and validity window,
verified release and executable digests, wallet descriptor, optional sealed
checkpoint, a fresh one-time response public key, and exactly one typed
operation. A descriptor-authorized device key signs the domain-separated client
authorization digest with raw low-S P-256; this is prehash signing, so the
digest is not hashed a second time.

The response contains `request_id`, `encrypted_result` and a TVC App Proof. The
result is encrypted to the request's one-time response key. Before accepting
it, the client verifies the Ephemeral signature and Boot Proof and checks that
the proof commits to the exact request digest, encrypted-result digest,
operation type and state digest.

The endpoint accepts these keyholder operations:

| Operation | Plaintext operation fields | Checkpoint | Egress | Result |
| --- | --- | --- | --- | --- |
| `BootstrapKeyholder` | `{"type":"BootstrapKeyholder"}` | Must be absent; a presented blob is rejected. | Turnkey only, for the fixed deterministic Ed25519 derivation signature. | Public shielded identity, opaque `sealed_wallet_state`, version/digest, and Turnkey evidence. The seed is never returned. |
| `DeriveViewTags` | `type`, `from_tx_count`, `count` | Required and must match the sealed state. | None. | The exact requested window of tags. `count` is `1..=512`; addition overflow is rejected rather than truncated. |
| `DecryptUtxos` | `type`, `payloads` | Required and must match the sealed state. | None. | One indexed `Plaintext` or `Malformed` result per input. A batch is `1..=256`; `Plaintext` is not an ownership claim. |
| `AuthorizeDefaultRingTransfer` | `type`, `intent_digest`, `unsigned_transaction` | Absent; transaction signing does not read privacy state. | Turnkey only, after validating the narrow default-ring transaction shape. | Signed transaction, signature, echoed intent digest and Turnkey evidence. It cannot sign an arbitrary transaction or message. |

`DeriveViewTags` and `DecryptUtxos` unseal the supplied checkpoint, answer from
the recovered seed and forget it. They do not contact Turnkey, the indexer, the
prover or Solana RPC. Every stateful result is bound by the App Proof to the
digest of the checkpoint against which it was computed.

The `local-dev` build additionally has `POST /dev/v1/bootstrap-ed25519` for its
unattested harness. That route is not compiled into `/tvc_app`, is not part of
the deployed keyholder API, and must not be used as a substitute for the
verified operation flow above.

---

## Operations

Bootstrap plus two key-state oracle operations are implemented. Each oracle
takes the sealed key state and returns only what the keys were needed for. The
existing narrow transaction-authorization rail is exposed through the same
encrypted endpoint but does not read that state.

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
