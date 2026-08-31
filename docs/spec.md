# Zolana TVC privacy-wallet protocol v1

This document is normative for the v1 wire contract. “MUST”, “MUST NOT”,
“SHOULD”, and “MAY” use their RFC 2119 meanings. English wins over translated
or explanatory material.

The implementation is development-only. Production descriptors and mainnet
MUST be rejected. The current external prover receives a plaintext witness that
contains `nullifier_secret`; disposable devnet funds only.

## 1. Scope

The protocol defines:

- strict JSON and canonical encodings;
- release discovery and independent release-policy authorization;
- AWS Nitro/QOS connection verification;
- descriptor-bound P-256 client authorization;
- encrypted operation requests and proof-bound results;
- sealed keyholder state; and
- four closed wallet operations.

It does not define a generic signing API, wallet export, arbitrary Turnkey
activity, caller-selected RPC/indexer/prover, or production release governance.

## 2. Encoding

All JSON inputs MUST reject duplicate and unknown fields. Objects used in a
digest MUST use RFC 8785/JCS. Text is UTF-8.

- Binary fields are lowercase hexadecimal without `0x`.
- `u64` wire values are canonical decimal strings: `0` or a non-zero digit
  followed by digits. Signs, whitespace, fractions, exponent form, and leading
  zeroes are invalid.
- P-256 public keys are 65-byte uncompressed SEC1 points.
- P-256 signatures are 64-byte raw low-S `r || s`. DER, compressed keys, high-S
  signatures, and signatures over a second hash are invalid.
- Ed25519 Solana addresses and transaction signatures use base58 where the
  corresponding type says so.

The maximum encrypted request and response size in the current release is
262,144 bytes. Absolute protocol ceilings are 16,777,216 bytes. A
`DecryptUtxos` batch is at most 256 payloads; a `DeriveViewTags` window is at
most 512 tags.

## 3. Hashes and signatures

`H(domain, payload) = SHA256(domain || 0x00 || payload)`.

Important domains:

| Purpose | Domain |
| --- | --- |
| Request | `ZOLANA_TVC_REQUEST_V1` |
| Client authorization | `ZOLANA_TVC_CLIENT_AUTH_V1` |
| Encrypted result | `ZOLANA_TVC_RESULT_V1` |
| Sealed-state digest | `ZOLANA_TVC_STATE_DIGEST_V1` |
| Release policy | `ZOLANA_TVC_RELEASE_POLICY_V1` |
| Descriptor provisioning | `ZOLANA_TVC_PROVISIONING_AUTH_V1` |

`request_digest` is `H(request-domain, JCS(request-without-only-
authorization.signature))`. `authorization.client_key_id` and
`authorization.scheme` remain included.

`client_auth_digest = H(client-auth-domain, request_digest)`. The client signs
this 32-byte digest through a prehash P-256 API. Implementations MUST NOT hash
it again.

`result_digest = H(result-domain, encrypted_result_bytes)`.

Release authorities sign
`H(release-policy-domain, JCS(ReleasePolicyV1))`. Empty, duplicate, and unknown
key IDs do not count toward the independently pinned threshold.

## 4. QOS P-256 envelope

The protocol uses the QOS algorithm, not HPKE or generic ECIES.

`P256Public` is exactly 130 bytes:

```text
encryption_public_sec1[65] || signing_public_sec1[65]
```

For encryption:

```text
shared_secret = ECDH_x(ephemeral_secret, receiver_encryption_public) // 32 bytes
pre_image = ephemeral_public || receiver_public || shared_secret
key_material = HMAC-SHA512(
  key = pre_image,
  msg = "qos_encryption_hmac_message"
)
cipher_key = key_material[0..32]
aad = ephemeral_public || 0x41 || receiver_public || 0x41
```

Encrypt with AES-256-GCM. The Borsh envelope is:

```text
nonce[12]
ephemeral_sender_public[65]
encrypted_message = ciphertext || gcm_tag[16]
```

Never swap the QOS encryption and signing subkeys. QOS App Proof P-256
signatures use SHA-256 and are verified over the exact UTF-8 proof payload.

## 5. HTTP surface

The deployed application uses HTTP/1 and exposes exactly these public routes:

### `GET /health`

Returns `200 {"status":"Healthy"}` only after runtime keys are ready. Otherwise
it returns a generic `503`. Health contains no key or deployment identifiers
and is not enclave evidence.

### `GET /v1/info`

Returns untrusted `ServiceInfoV1`: version, environment, security domain,
release ID, manifest and executable digests, QOS Quorum and Ephemeral public
keys, Quorum ID/epoch, operation list, envelope limits, proof type, and Boot
Proof lookup key.

The client MUST verify an independent signed `ReleasePolicyV1` before accepting
these values and MUST compare every security-relevant discovery field with that
policy.

### `POST /v1/ping`

Accepts a QOS-encrypted canonical `QosPingChallengeV1` under the Quorum
encryption key. The response contains an App Proof signed by the running
replica's Ephemeral signing key over the exact challenge bytes. The client MUST
also fetch and verify the matching AWS Nitro Boot Proof and PCR/manifest chain.
Ping grants no wallet authority.

### `POST /v1/operations`

Accepts a public `EncryptedRequestV1` wrapper containing a QOS-encrypted
`OperationRequestV1`. Public parse/decrypt/validation failures are generic.
Detailed operation failures appear only inside authenticated encrypted results.

## 6. Wallet descriptor

`WalletDescriptorV1` binds one logical wallet to:

- security domain and development environment;
- owning Turnkey organization, HD wallet ID, and Solana account address;
- exactly one P-256 client grant with its allowed operations; and
- the provisioning signature over the descriptor digest.

Signing uses the account address. The wallet ID is derived as
`wallet-<turnkey_wallet_id>`, the expected Ed25519 public key is the decoded
address, and the client key ID is derived from the grant public key. The
derivation path, policy version, and provisioning key are pinned in the
release, not carried on the wire.

The descriptor is provisioned out of band. The wallet package does not mint or
silently rotate descriptor authority.

## 7. Operation request

An `OperationRequestV1` contains:

- version `1`, 32-byte request ID, issue and expiry times;
- target release, manifest, executable, Quorum key ID and epoch;
- complete wallet descriptor;
- either the sealed key state or no state;
- one-time 130-byte client response public key;
- one operation; and
- client key ID, `p256-sha256`, and raw signature.

The request MUST expire within the release bounds. The current maximum request
age is 300,000 ms with at most 60,000 ms clock skew.

The application MUST check release, descriptor, environment, client grant,
operation grant, timestamp, sealed state, and client signature before invoking a
key-dependent action.

## 8. Sealed state and recovery

`BootstrapKeyholder` obtains a deterministic Ed25519 signature over the fixed
derivation message from the descriptor-bound Turnkey wallet. The 64-byte
signature is the derivation seed. TVC derives the public shielded identity and
returns the seed only inside `SealedWalletStateV1`, encrypted to the QOS Quorum
key and bound internally and externally to wallet, descriptor, derivation
suite, security domain, Quorum key ID, and epoch.

The result contains the registered Ed25519 public identity and the sealed
bytes; the state digest is the digest of those exact bytes and the App Proof
commits to it. The result MUST NOT contain the derivation seed, viewing
secret, nullifier secret, or a second ring-signing identity.

Custom-ring UTXOs keep the registered Ed25519 identity. A later spend restores
that same Turnkey-backed owner from the sealed seed and uses one transaction
signature for the owner and fee-payer roles. A descriptor or checkpoint that
introduces a second ring-signing identity is invalid.

The ring a spend names is caller input, not granted input. The circuit binds
every input and output to it, and the ring program's own policy authorizes the
transact, so an enumerated list would add re-provisioning without adding a
check the proof does not already make.

The service is replica-stateless. A sealed blob is a cache; the Turnkey wallet
is the recovery root. After blob loss or Quorum rotation, the client verifies
the replacement release, calls `BootstrapKeyholder` without old state, and
accepts the new blob only if every public identity field equals the previously
recorded identity.

## 9. Operations

| Operation | State | Meaning |
| --- | --- | --- |
| `BootstrapKeyholder` | Forbidden | Derive public shielded identity and return Quorum-sealed key state. |
| `DeriveViewTags` | Required | Return the wallet's stable recipient bootstrap tags, one per viewing key held. |
| `DecryptUtxos { payloads, include_spendable_outputs }` | Required | Decrypt bounded public ciphertext material and optionally reconcile a bounded list of currently spendable output commitments and public metadata against pinned RPC/indexer state. |
| `AuthorizeSpend { spend: Prepare { plan } }` | Required | Prepare either a direct default/custom-ring transaction or a program-neutral SPP transition, plus a short-lived sealed authorization capsule. Does not call Turnkey transaction signing. |
| `AuthorizeSpend { spend: Finalize { unsigned_transaction, ... } }` | Required | Let the capsule select the validator, verify the complete unsigned transaction, then owner-and-fee-payer-sign once through Turnkey. |

`SpendIntentV1` contains a source domain, a settlement, and exact input
commitments when required. `PrivateDomainV1` is `Default` or
`Ring { program_id, lookup_table }`. A private transfer also names its
destination domain. Direction is derived: Ring(A) to Ring(A) remains in A,
Ring(A) to Default exits, and Default to Ring(A) enters. The last form consumes
explicitly named default-pool commitments whose sum MUST equal the settlement
amount. A direct Ring(A) to Ring(B) transition is invalid. The application
builds a custom-ring transaction as a v0 message and checks the table against
the instruction's accounts.

A custom-ring A to custom-ring B move is two independent `AuthorizeSpend`
transactions: Ring(A) to an exact self-owned default-pool UTXO, followed by a
Default to Ring(B) transition consuming that UTXO's commitment. There is no direct cross-ring
transition and no public unshield between the two legs.

`SpendSettlementV1` is one of
`Transfer { asset, recipient, amount, destination }` to a registered shielded
recipient, `Withdrawal { asset, recipient, amount }` to a public wallet owner,
or `Consolidate { asset }`. Consolidation is valid only in the default domain,
keeps all value private under the same owner, and uses Zolana's fixed
`merge_8_1` circuit to replace two to eight plain UTXOs with one UTXO.
For classic SPL, withdrawal derives that owner's associated token account. They
are separate variants so a public recipient can never be resolved as a
registered one. `AssetV1` is either `Sol` or
`Spl { mint, asset_id }`. SOL is reserved asset ID 1. SPL mint/asset ID MUST
match the on-chain classic SPL asset registry. Token-2022 is unsupported.

`SpendPlanV1::Program` is the ecosystem extension point. Its declarative plan names
the target program, input tree, supported circuit shape, wallet/program inputs,
program-authority PDA seeds, shielded outputs, messages, and a short expiry.
The common transition always conserves assets privately; prover endpoints and
the program's own proof system are not caller-selected TVC fields. TVC independently rediscovers wallet commitments,
recomputes program-PDA-owned commitments, enforces exact per-asset
conservation, constructs and locally verifies the SPP proof, and seals the exact
serialized transact plus its `private_tx_hash` in the capsule.

Finalize always accepts one complete unsigned transaction. For a direct
capsule its bytes MUST equal the prepared transaction. For a program capsule,
exactly one instruction for the prepared target MUST contain the prepared
`private_tx_hash`; this binds the application proof to the sealed SPP
transition. The binding instruction must carry the prepared shielded tree,
shielded-pool program, System Program required by the SPP ABI, wallet signer,
and every declared program authority. The complete transaction may contain
additional user-approved instructions and executable programs. TVC does not
claim to prove their semantics: users trust that public behavior exactly as in
a conventional Solana wallet. The wallet remains the sole signer in this
version, TVC supplies a fresh blockhash, and public withdrawals remain on the
typed direct path.

The same operation covers both rails. `BootstrapKeyholder` never returns the
derivation seed; TVC restores the Ed25519 shielded identity from sealed state.

`DecryptUtxos` does not assert ownership. The pool transport cipher is
unauthenticated; another wallet's ciphertext may decrypt to garbage. The
client MUST deserialize each candidate and compare its recovered owner with the
known wallet identity. When `include_spendable_outputs` is true, TVC also syncs
the wallet using its enclave-held nullifier role. Before reconstruction it MUST
load the classic SPL registry from the pinned shielded-pool program and MUST
reject an oversized response, a wrong account owner, a non-canonical registry
PDA, or an inconsistent asset mapping. The result contains no nullifiers or
UTXO secrets: only commitment, asset, amount, and ring program ID.
The client MUST use this set, rather than decrypted history or a local journal,
as the authority for current balance and spendability.

Public registration and SOL/SPL deposits are not TVC operations because they
do not require privacy secrets. The authenticated browser constructs them with
the Zolana SDK and asks the ordinary Turnkey wallet session to sign.

## 10. Spend construction

For direct `AuthorizeSpend`, the application MUST:

1. reject production, mainnet, zero amount, caller-selected
   origins, and invalid assets;
2. unseal and validate the complete key checkpoint;
3. synchronize from compile-time-pinned indexer and RPC endpoints;
4. for Default to Ring, rediscover every named input as an unspent default-pool UTXO on
   the configured tree, reject duplicates, and require their exact sum;
5. construct the ring witness with the Zolana SDK;
6. send the witness to the pinned development prover;
7. for transfer/withdrawal rails, locally verify the returned Groth16 proof
   against the compiled verifying key and locally constructed public inputs;
8. return the exact unsigned transaction with a short-lived sealed capsule
   bound to the wallet, release, checkpoint, and transaction digest;
9. on a separate finalize request, unseal and revalidate the capsule and exact
   unsigned transaction;
10. ask Turnkey to sign only that exact validated transaction, as owner and fee payer;
11. independently verify Turnkey's returned signature and message; and
12. return exact signed bytes, signature, prior shielded balance, unchanged
   checkpoint, and Turnkey evidence.

For `Consolidate`, the application MUST additionally require the registered
owner's on-chain merging opt-in, select only unspent plain same-asset UTXOs from
the configured default tree, and bind every inclusion/non-inclusion proof to
that tree. The proof itself establishes shielded ownership, so finalize's one
Turnkey signature is only the Solana fee-payer signature. An invalid external
merge proof can make the exact transaction fail on chain but cannot change its
locally constructed inputs, output, or balance-neutral semantics.

For generic SPP preparation and finalization, the application MUST additionally
enforce the plan ownership/conservation checks and `private_tx_hash` binding,
single-signer, target-program, lookup-table, packet-size, and expiry checks
described above. The authenticated wallet caller supplies the complete
instruction set; TVC refreshes the blockhash before the Turnkey signature.

The witness contains plaintext `nullifier_secret`, and the pinned prover
receives it. This remains the development exception that prevents a production
privacy claim.

## 11. Result verification

`EncryptedResponseV1` contains version, request ID, encrypted result, and one
Ephemeral App Proof. The proof payload type is
`zolana.tvc.wallet_operation.v1` and binds:

- request ID and request digest;
- digest of the encrypted result;
- exact operation kind; and
- exact state digest used for the answer.

The client MUST verify the proof and bindings before accepting plaintext.
Bootstrap and spend results also include Turnkey App Proofs. They are verified
cryptographically but their policy classification is exactly
`CryptographicallyValidButUnbound`; no implementation may upgrade them to
`Verified` without a signed decision-context binding.

The client MUST independently verify the Ed25519 signature over the exact
returned Solana transaction. Transaction submission is caller-owned and MUST
use preflight. Exact signed bytes MUST be journaled before waiting for
confirmation. Timeout is an unknown outcome, not failure.

An operation failure exposes only its operation kind and a closed, non-secret
stage marker inside the encrypted result. Spendable snapshot implementations
MUST distinguish `AssetRegistry`, `WalletIndexRead`, `WalletReconstruction`,
`WalletNullifierRead`, `WalletSnapshotTooLarge`, and the overall `WalletSync`
deadline. Public HTTP failures MUST remain generic and MUST NOT reveal these
stages.

## 12. Release and deployment

A release policy pins release/application/security-domain identity, accepted
manifest and executable digests, Quorum key and epoch, allowed operations,
envelope limits, Turnkey trust-root/profile versions, validity interval, and
revocation epoch.

The application image MUST be a single-platform `linux/amd64` OCI manifest
pinned by digest. The pivot binary SHA-256 is independently pinned as the
expected executable digest. Each deployment uses a dedicated TVC app and
dedicated Quorum key. A debug-mode enclave with zero PCRs is not a verifier.

The local harness and its development bootstrap route are not part of this
protocol and MUST NOT be deployed or accepted as attested evidence.

## 13. Conformance

The Rust and TypeScript implementations MUST pass the committed
content-addressed fixtures under `crates/protocol/fixtures`. The manifest hashes
every fixture by SHA-256. Interoperability is tested against the pinned official
QOS P-256 crate; the official crate is test-only for the reusable protocol
crate.
