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
- exact Turnkey parent and owning organization;
- either a private-key ID or an HD wallet-account tuple;
- an optional Turnkey P-256 key ID backing the ring identity;
- Turnkey service user and API key;
- expected Ed25519 public key;
- one or more P-256 client grants and their allowed operations;
- policy version and optional predecessor digest; and
- provisioning and optional owner/rotation evidence.

For an HD wallet, signing uses the account address and the descriptor MUST
carry wallet ID, account ID, address, and derivation path. A Turnkey wallet ID
MUST NOT be guessed to be a private-key ID.

The descriptor is provisioned out of band. The wallet package does not mint or
silently rotate descriptor authority.

## 7. Operation request

An `OperationRequestV1` contains:

- version `1`, 32-byte request ID, issue and expiry times;
- target release, manifest, executable, Quorum key ID and epoch;
- complete wallet descriptor;
- either the complete sealed-state tuple or no state;
- one-time 130-byte client response public key;
- one operation; and
- client key ID, `p256-sha256`, and raw signature.

The request MUST expire within the release bounds. The current maximum request
age is 300,000 ms with at most 60,000 ms clock skew.

The application MUST check release, descriptor, environment, client grant,
operation grant, timestamp, state tuple, and client signature before invoking a
key-dependent action.

## 8. Sealed state and recovery

`BootstrapKeyholder` obtains a deterministic Ed25519 signature over the fixed
derivation message from the descriptor-bound Turnkey wallet. The 64-byte
signature is the derivation seed. TVC derives the public shielded identity and
returns the seed only inside `SealedWalletStateV1`, encrypted to the QOS Quorum
key and bound internally and externally to wallet, descriptor, derivation
suite, security domain, Quorum key ID, and epoch.

The result contains the default public identity, the ring public identity when
the descriptor names a ring signing key, state version/digest, and sealed bytes.
It MUST NOT contain the derivation seed, viewing secret, or nullifier secret.

The ring identity shares the nullifier and viewing keys the seed expands to and
differs only in its signing key, so the two owner hashes differ. The sealed
state carries the ring signing public key, so a later spend restores that
identity without reading Turnkey again.

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
| `DecryptUtxos { payloads }` | Required | Decrypt bounded public ciphertext material and return index-aligned plaintext-or-malformed candidates. |
| `SignRingSpend { intent }` | Required | Build, prove, verify, and fee-payer-sign one spend by the ring identity. |

`RingSpendIntentV1` contains a required ring, a settlement, and a known prover
profile ID. The ring names a program and an address lookup table. A ring spend
binds every input and output to that program and is built as a v0 message over
that table, and the application checks the table against the accounts the
instruction needs.

`RingSettlementV1` is either `Transfer { asset, recipient, amount }` to a
registered shielded recipient or `SolWithdrawal { recipient, amount }` to a
public address. They are separate variants so a public recipient can never be
resolved as a registered one. `AssetV1` is either `Sol` or
`Spl { mint, asset_id }`. SOL is reserved asset ID 1. SPL mint/asset ID MUST
match the on-chain classic SPL asset registry. Token-2022 is unsupported.

A default-ring spend is not a TVC operation. `BootstrapKeyholder` returns the
derivation seed on this profile, so the client expands the roles, builds,
proves, and signs that rail as the Ed25519 owner. That is devnet only.

`DecryptUtxos` does not assert ownership. The pool transport cipher is
unauthenticated; another wallet's ciphertext may decrypt to garbage. The
client MUST deserialize each candidate and compare its recovered owner with the
known wallet identity.

Public registration and SOL/SPL deposits are not TVC operations because they
do not require privacy secrets. The authenticated browser constructs them with
the Zolana SDK and asks the ordinary Turnkey wallet session to sign.

## 10. Spend construction

For `SignRingSpend`, the application MUST:

1. reject production, mainnet, zero amount, unknown profile, caller-selected
   origins, and invalid assets;
2. unseal and validate the complete key checkpoint;
3. synchronize from compile-time-pinned indexer and RPC endpoints;
4. construct the ring witness with the Zolana SDK;
5. send the witness to the pinned development prover;
6. locally verify the returned Groth16 proof against the compiled verifying
   key and locally constructed public inputs;
7. ask Turnkey to sign only the exact validated transaction, as fee payer;
8. independently verify Turnkey's returned signature and message; and
9. return exact signed bytes, signature, prior shielded balance, unchanged
   checkpoint, and Turnkey evidence.

The witness contains plaintext `nullifier_secret`, and the pinned prover
receives it. On this profile `BootstrapKeyholder` also returns the derivation
seed, so the browser expands the roles itself. Both are development exceptions and neither
satisfies the production privacy claim.

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
