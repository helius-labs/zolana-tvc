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

## Private transfer inside a ring

1. Browser sends `SignRingSpend` with the ring, a transfer settlement naming a
   registered recipient and positive amount, the prover profile, and the
   checkpoint.
2. TVC unseals privacy keys, synchronizes against pinned services, selects
   inputs, and assembles the witness.
3. TVC sends the plaintext witness—including `nullifier_secret`—to the pinned
   development prover and locally verifies the returned Groth16 proof.
4. TVC asks Turnkey to sign the exact bounded transaction as fee payer and
   independently verifies the signature.
5. Browser verifies the encrypted proof-bound result, journals exact bytes,
   submits them, and retains the journal on an unknown outcome.

## Unshield SOL

A `SolWithdrawal` settlement follows the same flow with an explicit public-SOL
withdrawal constructor. The public recipient is never reinterpreted as a
registered private recipient, including when withdrawing to the wallet's own
public address.

## Default-ring spend

The enclave does not build one. Bootstrap returns the derivation seed on this
profile, so the browser expands the roles, syncs, builds the witness, proves,
and signs as the Ed25519 owner with its own Turnkey session.

## Recovery and retry

A timeout after submission is an unknown outcome, not failure. Keep the exact
transaction until chain status or blockhash expiry is definitive. A confirmed
spend cannot land twice because the nullifier is unique.

A lost or old-epoch checkpoint is recovered by re-running
`BootstrapKeyholder` and requiring the same public shielded identity. Loss of
the underlying Turnkey wallet still requires Turnkey custody recovery.
