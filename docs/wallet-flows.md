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

1. Ask TVC for stable `DeriveViewTags`.
2. Query the indexer from the browser with those tags.
3. Send fetched ciphertexts to TVC in bounded `DecryptUtxos` batches and ask
   the final batch for the spendable-output snapshot.
4. TVC loads the classic SPL asset registry from the pinned shielded-pool
   program, validates registry owners and canonical PDAs, reconstructs owned
   UTXOs, and reconciles their nullifiers against the pinned index.
5. Deserialize returned plaintext candidates and confirm their owner matches
   the wallet identity; decryption alone cannot prove ownership because the
   transport cipher is unauthenticated.
6. Keep client-decrypted openings only when their commitment appears in TVC's
   snapshot. Sum the snapshot for balances; never overlay historical local
   journal balances on a later snapshot.

## Shield SOL or classic SPL

Registration and deposits use no privacy secret, so the browser constructs the
public Zolana transaction, signs it with the ordinary Turnkey wallet session,
journals exact signed bytes, and submits with preflight enabled. Classic SPL
assets require the mint/asset-ID pair registered by the shielded pool.
Token-2022 is not supported.

The UI can optimistically show “arriving” after confirmation, but confirmed and
spendable private balance must wait for the indexer.

## Private transfer

1. Browser sends `AuthorizeSpend::Prepare` with a `Direct` plan: explicit source
   and destination domains, a transfer settlement, exact default commitments
   when entering a ring, and checkpoint.
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

## Unshield SOL or classic SPL

A `Withdrawal { asset, recipient, amount }` settlement follows the same flow
with an explicit public-withdrawal constructor. For SPL, TVC validates the
mint/asset-ID pair against the pool registry and derives the recipient owner's
classic associated token account. The public recipient is never reinterpreted
as a registered private recipient, including when withdrawing to the wallet's
own public address.

The same flow covers the default ring and custom rings. The browser never
receives the derivation seed or another private spend role.

## Move between rings

There is no direct custom-ring A to custom-ring B transaction. The wallet first
creates an exact self-owned UTXO in the default pool: Ring(source)-to-Default
when the source is custom, or a default-to-default reshape otherwise.
After that transaction confirms and the indexer exposes its output commitment,
the wallet submits a Default-to-destination transition naming only that bridge
commitment. The exact-sum rule prevents any other default balance from becoming
ring-bound as change. Each leg is described entirely by its source and
destination domains.

The browser persists the asset, signed bridge, the wait for its indexed
commitment, and the signed entry as distinct recovery phases. Each confirmed
leg updates both affected balances for that asset; its whole-wallet private
balance does not change.

## Private ecosystem program

1. The ecosystem SDK sends a `Program` plan naming the target program, input tree,
   supported shape, wallet/program inputs, shielded outputs, messages, expiry,
   and program-authority PDA seeds. The common SPP transition conserves private assets.
2. TVC rediscovers wallet inputs, verifies program-PDA openings and asset
   conservation, proves the common SPP transition, and returns the exact
   serialized transact plus a sealed capsule.
3. The SDK builds its program-specific proof and a complete Solana transaction.
   Exactly one target instruction carries the prepared `private_tx_hash`.
4. Finalize checks the capsule, target, hash binding, sole wallet signer,
   lookup tables, tree, pool interface, and declared program authorities.
   Additional user-approved instructions are allowed. TVC refreshes the
   blockhash, then signs once through Turnkey.
5. The browser verifies, journals, and submits the exact signed transaction.

The SPP proof constrains private effects, not arbitrary public behavior in the
complete transaction; the user must trust the selected program with the wallet
signer. Typed transfer/unshield stays on the direct exact-transaction path. Canonical Zolana
swap `make`, `take`, and expired-order `cancel` exercise generic finalization on
devnet.

## Recovery and retry

A timeout after submission is an unknown outcome, not failure. Keep the exact
transaction until chain status or blockhash expiry is definitive. A confirmed
spend cannot land twice because the nullifier is unique.

A lost or old-epoch checkpoint is recovered by re-running
`BootstrapKeyholder` and requiring the same public shielded identity. Loss of
the underlying Turnkey wallet still requires Turnkey custody recovery.
