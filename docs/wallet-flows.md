# Wallet flows

The product has one privacy-wallet architecture. “Keyholder” below names the
security model and the `BootstrapKeyholder` wire operation; it is not a second
user-facing wallet mode.

## Connect

1. Load an independently signed release policy and pinned release authorities.
2. Fetch `/v1/info` as untrusted discovery and bind it to that policy.
3. Complete the QOS ping and verify its App Proof.
4. Fetch and verify the matching AWS Nitro Boot Proof.
5. Return an opaque `VerifiedConnection`; no wallet operation accepts an
   unverified URL or raw discovery object.

## Open private balances

1. Load or create the browser's non-exportable P-256 request key.
2. Provision a descriptor binding that client key to the signed-in Turnkey HD
   wallet account.
3. Call `BootstrapKeyholder`. Turnkey signs the fixed derivation message; TVC
   derives the shielded identity and returns only public identity plus sealed
   state.
4. Persist the checkpoint locally. On recovery, compare every identity field
   with the previously known identity before accepting replacement state.
5. Build and submit public shielded-identity registration if it is not already
   on chain.

## Synchronize

1. Ask TVC for a bounded `DeriveViewTags` window.
2. Query the indexer from the browser with those tags.
3. Send fetched ciphertexts to TVC in bounded `DecryptUtxos` batches.
4. Deserialize returned plaintext candidates and confirm their owner matches
   the wallet identity; decryption alone cannot prove ownership because the
   transport cipher is unauthenticated.
5. Reconstruct balance, spendable UTXOs, and history in the client.

## Shield SOL or classic SPL

Registration and deposits use no privacy secret, so the browser constructs the
public Zolana transaction, signs it with the ordinary Turnkey wallet session,
journals exact signed bytes, and submits with preflight enabled. Classic SPL
assets require the mint/asset-ID pair registered by the shielded pool.
Token-2022 is not supported.

The UI can optimistically show “arriving” after confirmation, but confirmed and
spendable private balance must wait for the indexer.

## Private transfer

1. Browser sends `AuthorizeSpend::Prepare` with a `Builtin` plan: `ring: null`
   for the default ring or a custom ring descriptor with `Enter`/`Exit`, a
   transfer settlement, prover profile, exact entry commitments when entering,
   and checkpoint.
2. TVC unseals privacy keys, synchronizes against pinned services, selects
   inputs, and assembles the witness.
3. TVC sends the plaintext witness—including `nullifier_secret`—to the pinned
   development prover and locally verifies the returned Groth16 proof.
4. TVC returns the unsigned transaction and a short-lived sealed authorization
   capsule without asking Turnkey to sign.
5. Browser sends both through `AuthorizeSpend::Finalize`; TVC revalidates their
   exact binding, asks Turnkey to sign once as owner and fee payer, and
   independently verifies the signature.
6. Browser verifies both encrypted proof-bound results, journals exact bytes,
   submits them, and retains the journal on an unknown outcome.

## Unshield SOL

A `SolWithdrawal` settlement follows the same flow with an explicit public-SOL
withdrawal constructor. The public recipient is never reinterpreted as a
registered private recipient, including when withdrawing to the wallet's own
public address.

The same flow covers the default ring and custom rings. The browser never
receives the derivation seed or another private spend role.

## Move between rings

There is no direct custom-ring A to custom-ring B transaction. The wallet first
creates an exact self-owned note in the default pool: an `Exit` when the source
is custom, or a default-to-default reshape when the source is already default.
After that transaction confirms and the indexer exposes its output commitment,
the wallet submits an `Enter` for the destination ring naming only that bridge
commitment. The exact-sum rule prevents any other default balance from becoming
ring-bound as change.

The browser persists the signed bridge, the wait for its indexed commitment,
and the signed entry as distinct recovery phases. Each confirmed leg updates
both affected ring balances; the whole-wallet private balance does not change.

## Private ecosystem program

1. The ecosystem SDK sends an `Spp` plan naming the target program, input tree,
   supported shape, wallet/program inputs, shielded outputs, messages, expiry,
   program-authority PDA seeds, and `PrivateOnly` SPP effects.
2. TVC rediscovers wallet inputs, verifies program-PDA openings and asset
   conservation, proves the common SPP transition, and returns the exact
   serialized transact plus a sealed capsule.
3. The SDK builds its program-specific proof and one outer instruction carrying
   the prepared `private_tx_hash` exactly once.
4. Finalize checks the capsule, target, hash binding, sole wallet signer,
   lookup tables, and that the target receives only the shielded pool plus the
   read-only System Program required by the SPP ABI. TVC adds compute budget
   and a fresh blockhash, then signs once through Turnkey.
5. The browser verifies, journals, and submits the exact signed transaction.

`PrivateOnly` constrains the SPP transition, not arbitrary code in the target;
the user must trust the selected program with the wallet signer. Typed
transfer/unshield stays on the built-in exact-transaction path. Canonical Zolana
swap `make`, `take`, and expired-order `cancel` exercise generic finalization on
devnet.

## Recovery and retry

A timeout after submission is an unknown outcome, not failure. Keep the exact
transaction until chain status or blockhash expiry is definitive. A confirmed
spend cannot land twice because the nullifier is unique.

A lost or old-epoch checkpoint is recovered by re-running
`BootstrapKeyholder` and requiring the same public shielded identity. Loss of
the underlying Turnkey wallet still requires Turnkey custody recovery.
