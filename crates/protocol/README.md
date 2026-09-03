# zolana-tvc-protocol

The wire protocol between a client and the privacy-wallet enclave, as Rust
types and functions: strict JSON parsing, JCS canonicalization,
domain-separated digests, P-256 client authorization, the QOS P-256 envelope,
release-policy signing and threshold verification, the `/health` and
`/v1/info` handlers, and named errors that carry no secret.
[`packages/tvc-wallet/src/protocol`](../../packages/tvc-wallet/src/protocol)
implements the same protocol in TypeScript; the [fixtures](#fixtures) keep the
two in agreement. This document is the normative specification of v1.

## Encoding

JSON inputs reject unknown and duplicate fields. Digested objects are
canonicalized with RFC 8785 (JCS). Binary fields are lowercase hex without
`0x`; `u64` values are canonical decimal strings; P-256 public keys are 65-byte
uncompressed SEC1; P-256 signatures are 64-byte raw low-S `r || s`; Solana
addresses and transaction signatures are base58.

## Digests

`H(domain, payload) = SHA256(domain || 0x00 || payload)`.

| Domain | Payload | Use |
| --- | --- | --- |
| `ZOLANA_TVC_REQUEST_V1` | `JCS(request)` without `authorization.signature` | `request_digest`; `client_key_id` and `scheme` stay in |
| `ZOLANA_TVC_CLIENT_AUTH_V1` | `request_digest` | What the client key signs, through a prehash API |
| `ZOLANA_TVC_RESULT_V1` | The encrypted result bytes | `result_digest`, bound by the App Proof |
| `ZOLANA_TVC_SEALED_SEED_DIGEST_V1` | The sealed seed wire bytes | Names the seed a response used |
| `ZOLANA_TVC_WALLET_ID_V1` | The wallet id | Binds a sealed seed to its wallet |
| `ZOLANA_TVC_PROVISIONING_AUTH_V1` | `JCS(descriptor)` without `provisioning_signature` | What the provisioning key signs |
| `ZOLANA_TVC_RELEASE_POLICY_V1` | `JCS(policy)` | What a release authority signs |

## Envelope

Requests and responses travel in the QOS P-256 envelope. `P256Public` is
`encryption_sec1[65] || signing_sec1[65]`. The symmetric key is
`HMAC-SHA512(key = ephemeral_pub || receiver_pub || ECDH_x, msg =
"qos_encryption_hmac_message")[0..32]`; the cipher is AES-256-GCM with AAD
`ephemeral_pub || 0x41 || receiver_pub || 0x41`; the frame is Borsh
`nonce[12] || ephemeral_pub[65] || ciphertext || tag[16]`.

An `EncryptedRequest` names the Quorum key id and epoch and carries the
`OperationRequest` encrypted to the Quorum key. The `OperationRequest`
carries a fresh 32-byte request id, `issued_at_ms` and `expires_at_ms`, the
release pins (`target_release_id`, `target_manifest_digest`,
`target_executable_digest`, Quorum key id and epoch), the wallet descriptor,
the sealed seed (absent on `Bootstrap`), a one-time response public key, the
operation, and a `ClientAuthorization`: the client key id, the scheme, and
the client key's signature over `H(client-auth, request_digest)`.

An `EncryptedResponse` echoes the request id and carries the result
encrypted to the response key, plus an App Proof: a P-256/SHA-256 signature by
the replica's Ephemeral key over the exact UTF-8 payload, which binds the
request digest, the result digest, the operation kind, and the digest of the
sealed seed used. Verify the proof before reading the plaintext.

Bodies are at most 262,144 bytes each way. A request expires within 300 s of
`issued_at_ms`, with 60 s of clock skew allowed.

## Operations

`POST /v1/operations` serves five operations. They are exactly the Zolana
SDK's `ShieldedKeys` and `ProofAuthority` methods, so `TvcKeys` in
`@zolana/tvc-wallet` implements the SDK's `WalletKeys` over them.

| Operation | Sealed seed | Returns |
| --- | --- | --- |
| `Bootstrap` | forbidden | The public identity (Solana address, owner hash, nullifier and viewing public keys), the sealed seed, and Turnkey's App Proofs for the signing. Also the recovery path: the client passes the identity it knows and refuses another. |
| `Decrypt { items }` | required | The transfer cipher's output for each `{ ciphertext, viewing_public_key, transaction_viewing_public_key, salt, slot_index, label }`, label `Transfer` or `RingDeposit`. The enclave interprets nothing; the SDK decodes and matches commitments. |
| `Derive { items }` | required | One 32-byte value per item: `Nullifier { utxo_hash, blinding }`, `MergeDummyNullifier { first_nullifier, slot_index }`, or `MergeOutputBlinding { first_nullifier }`. |
| `TransactionKeys { items }` | required | The per-transaction viewing secret for each `{ viewing_public_key, first_nullifier }`. The derivation is one way: a secret opens that transaction and nothing else. |
| `Prove { request }` | required | The prover's answer to the SDK's prover request after the enclave has written its nullifier secret into every `null` slot. Circuits `transfer-confidential`, `transfer-ring`, and `merge`; at most 8 input slots. |

A batch takes up to 256 items. The pool cipher is unauthenticated, so
`Decrypt` cannot tell whose ciphertext it opened; the SDK adopts a UTXO only
when its commitment equals the indexed one. `Prove` does not check who owns the
inputs: a slot filled for another wallet's UTXO gives a witness the circuit
rejects, and a proof reveals nothing about the secret either way. The client
checks Turnkey's App Proofs as signatures only: their payload carries no
decision-context binding, so they show that a Turnkey enclave signed, not that
the signing was the one the policy permits, and nothing treats them as
authorization. Failures surface only inside the encrypted result as a closed
stage marker (`Prover`, `TurnkeySigning`); public HTTP errors are generic.

Both the descriptor and the running environment must be `development`; a
production descriptor is rejected.

## Wallet descriptor and sealed seed

A wallet descriptor is the operator's grant that lets client keys drive the
enclave operations of one Turnkey wallet. It binds a security domain, the
`development` environment, a Turnkey organization and wallet id, the Solana
address, and the allowed clients (each a P-256 public key with its allowed
operations), under a provisioning signature over the descriptor digest that
the enclave verifies against the provisioning public key compiled into it. A
descriptor names public keys and identifiers only; it is not a secret.

The sealed seed is the derivation seed encrypted to the Quorum key. Its
envelope names the Quorum key id and epoch and the wallet id hash; its
contents repeat them and add the descriptor digest, the derivation suite, and
the seed. `Bootstrap` returns it; every other operation presents it, and the
enclave accepts it only under the descriptor and Quorum key epoch it was
issued for. It contains nothing the Turnkey wallet cannot reproduce, so
losing it costs one more `Bootstrap`.

## Release policy

A release policy names a release: its id, the environment, the TVC
application id, the security domain, the accepted manifest and executable
digests, the Quorum key id, epoch and public key, the allowed operations, and
the request and response size limits. Release authorities sign
`H(ZOLANA_TVC_RELEASE_POLICY_V1, JCS(policy))`; a client accepts the policy
at a threshold of authority signatures, and verification fails closed on an
empty, duplicate, or unknown key. A re-signed policy is a new authority set
every client must accept.

The trust material a client pins is the policy, the authority public keys,
and the QOS identity PCRs. `connectAndVerify()` in `@zolana/tvc-wallet`
verifies the policy, binds every security field of `GET /v1/info` to it,
completes the Quorum-encrypted `POST /v1/ping`, and verifies the Nitro Boot
Proof against the PCRs and the accepted manifest digests. Wallet calls take
the resulting `VerifiedConnection` only. `/v1/info` is discovery, not a trust
root, `/health` reports process readiness only, and HTTPS alone establishes
nothing.

## Fixtures

`fixtures/` is generated by the conformance tests and hashed in
`fixtures/MANIFEST.json`. The Rust and TypeScript implementations must
produce these bytes. `just regenerate-protocol-fixtures` rewrites them; review
fixture and manifest diffs together, since the TypeScript suite reads the
committed files.
