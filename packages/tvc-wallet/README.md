# `@zolana/tvc-wallet`

Pre-production TypeScript clients for three deliberately separate Zolana TVC
wallet profiles. None is currently a production-funds wallet or a generic
Turnkey signer.

## Keyholder boundary

`@zolana/tvc-wallet/keyholder` keeps the derivation seed, viewing key, and
nullifier key inside the attested application. `DeriveViewTags` and
`DecryptUtxos` support client-relayed indexer reads. The temporary devnet
`BuildTransfer` and `BuildSolWithdrawal` operations are an explicit exception:
TVC syncs from the pinned services and sends the plaintext prover witness,
including the long-lived `nullifier_secret`, to the pinned external prover.
The browser never receives that secret, but the prover can derive future
nullifiers from it.

The operations are typed by their exact intent fields; the SOL withdrawal is a
separate discriminant and cannot be confused with recipient-resolving private
transfer. There is no generic signing or witness-export API. The caller
receives the verified signed transaction and remains responsible for exact-byte
journaling and submission. `@zolana/tvc-wallet/keyholder/browser` stores the
opaque checkpoint, public identity, display balance, and pending submission in
a database isolated from the other profiles.

## Lightweight boundary

The authenticated user client owns the ordinary Zolana wallet runtime:

- Photon/indexer and Solana RPC traffic;
- encrypted local wallet state and synchronization;
- private balance and input selection;
- prover calls and transaction construction;
- exact signed-transaction submission.

TVC is stateless and exposes only two operations:

- `BootstrapClientEd25519` returns a deterministic derivation seed encrypted to
  the authenticated client. The browser adapter seals it with a non-exportable
  device-local AES-GCM key. Repeating the operation for the same Turnkey wallet
  reproduces the same shielded identity, so sealed browser state is a
  recoverable cache rather than the root of funds.
- `AuthorizeDefaultRingTransfer` validates one bounded, non-versioned Solana
  default-ring transaction shape and asks Turnkey to sign those exact bytes.

There is no TVC API for `signMessage`, generic `signTransaction`, export,
wallet sync, prover access, indexer access, or transaction broadcast.

## Full-enclave boundary

`@zolana/tvc-wallet/enclave` targets the separate full-enclave app. The client
still performs release and Boot Proof verification, request authorization,
encryption, response-proof validation, and transaction submission. The
attested app owns the shielded identity, wallet synchronization, encrypted UTXO
decryption, input selection, prover call, transaction construction, and
Turnkey signing.

Its closed API is:

- `BootstrapEd25519`;
- `PrepareWallet`;
- `ShieldSol`;
- `BuildTransfer`.

`CreateWallet` remains available to explicit operator tooling, but the browser
demo binds an already authenticated embedded wallet and does not grant that
operation to its device key. There is no generic signing or export method.

Every state-changing response carries a new opaque sealed checkpoint, and
`TvcEnclaveWallet` owns when that checkpoint becomes authoritative:

1. **Journal.** The signed transaction and the checkpoint it *would* produce are
   persisted together, while the previous checkpoint stays authoritative.
2. **Confirm.** The application submits the transaction and waits for a terminal
   on-chain outcome.
3. **Activate.** `settlePending` promotes the journaled checkpoint and records
   the balance change; `abandonPending` drops it and keeps the previous one.

Adopting the new checkpoint at step 1 would be wrong. The enclave is stateless
and the client holds its sealed state, so if a transaction never lands, an
already-advanced checkpoint would describe notes as spent that the chain still
considers unspent, and the wallet could not rebuild those inputs to retry. The
journal is what makes a failed transaction recoverable, and what makes a reload
mid-flight resume rather than re-issue.

## Verification

`connectAndVerify` verifies an independently signed release policy before using
`/v1/info`, performs the encrypted QOS ping, resolves the exact replica's Boot
Proof, validates its AWS Nitro/QOS identity commitments, and returns an opaque
`VerifiedConnection`.

Discovery is bound to the pinned policy field by field. `/v1/info` also
advertises an `ephemeral_public_key`, but `/v1/info` and `/v1/ping` may be
served by different healthy replicas, so it is never a verification input: the
key that matters is the one the ping proof is signed with, and it is trusted
only once the Boot Proof ties it to an attestation with the pinned PCRs.

A Boot Proof carries no nonce, so `verifyBootProof` requires the caller's clock
and rejects an attestation older than an hour, as well as validating the AWS
Nitro certificate chain against that clock rather than against a timestamp the
document supplies about itself.

Operation responses are QOS-encrypted to a one-time response key and bound to
the request/result digests and an Ephemeral-key App Proof. Turnkey policy
evidence remains `CryptographicallyValidButUnbound`; the public proof does not
bind `decisionContextDigest` to the exact activity and must never be labelled
`Verified`.

The current Zolana TypeScript SDK validates and assembles the prover inputs but
does not yet run the Groth16 verifier in the browser. Solana verifies the proof
on chain, and RPC preflight stays enabled, but local Groth16 verification is a
remaining production-hardening task.

## Typed API

```ts
import {
  createTvcWalletClient,
  defaultRingTransferIntentDigest,
} from "@zolana/tvc-wallet";

const client = createTvcWalletClient({
  endpoint: new URL("https://tvc.example.invalid"),
  releasePolicy: independentlyObtainedSignedPolicy,
  releaseAuthorities: independentlyPinnedAuthorities,
  qosIdentityPcrs: independentlyPinnedPcr0Through3,
  resolveBootProof: ({ appProof }) =>
    existingTurnkeySession.getBootProofForAppProof(appProof),
  operations: {
    walletDescriptor,
    authorizer: deviceBoundP256Authorizer,
  },
});

const connection = await client.connectAndVerify();
const bootstrap = await client.bootstrapClientEd25519(connection);

const authorized = await client.authorizeDefaultRingTransfer(connection, {
  kind: "transfer",
  intent: {
    walletId: walletDescriptor.wallet_id,
    solanaAddress,
    recipient,
    asset: { type: "Sol" },
    amount,
    unsignedTransaction,
  },
});
```

The client derives the intent digest from the very transaction bytes it sends,
so the digest and the bytes cannot be paired incorrectly. The intent digest
commits the user-visible fields to the exact transaction digest. TVC still cannot reconstruct private recipient/amount semantics from
the zero-knowledge instruction; a compromised authenticated client remains in
the lightweight profile's trust boundary.

## Shielded wallet facade

Applications should normally use the higher-level facade instead of assembling
the Zolana authority and encrypted state transitions themselves:

```ts
import { createTvcShieldedWallet } from "@zolana/tvc-wallet/shielded-wallet";

const wallet = await createTvcShieldedWallet({
  client,
  connection,
  authorizer: deviceBoundBrowserAuthorizer,
  state: provisionedBrowserWalletState,
  zolanaClientConfig: { solanaRpcUrl, indexerUrl, proverUrl },
  persistState: saveBrowserWalletState,
});

await wallet.sync();
const splDeposit = await wallet.depositSplTransaction({
  mint,
  amount,
});
const pending = await wallet.authorizeDefaultRingTransfer({
  asset: { type: "Sol", symbol: "SOL", decimals: 9 },
  recipient,
  amount,
});

const withdrawal = await wallet.authorizeDefaultRingSolWithdrawal({
  recipient: wallet.solanaAddress,
  amount,
});
```

`createTvcShieldedWallet` performs first-use bootstrap or restores the encrypted
seed and wallet snapshot, verifies that their public identity matches the
descriptor, and owns the exact pending-submission journal. The application
submits `pending.signedTransaction` with preflight enabled and calls
`completeDefaultRingTransaction` once it confirms, or
`expireDefaultRingTransaction` if it will never land.

The facade exposes typed registration, SOL and classic SPL Token deposits,
sync, balance/history, and default-ring transfer and SOL-withdrawal methods.
For an SPL deposit it verifies that the mint is owned by the classic SPL Token
Program and derives the depositor's associated token account. Token-2022 is not
supported by this facade. Transfer and withdrawal
intents use separate digest domains even though the current enclave release
authorizes both through the same fixed-shape `AuthorizeDefaultRingTransfer`
rail. The facade does not expose the underlying
`WalletAuthority`, derivation seed, viewing/nullifier keys, `signMessage`, or a
generic transaction signer. It requires `@heliuslabs/zolana` and `@solana/kit`
as peer dependencies; the protocol-only and verification entry points do not.

## Full-enclave typed API

```ts
import {
  createTvcEnclaveWallet,
  createTvcEnclaveWalletClient,
} from "@zolana/tvc-wallet/enclave";

const client = createTvcEnclaveWalletClient({
  endpoint,
  releasePolicy,
  releaseAuthorities,
  qosIdentityPcrs,
  resolveBootProof,
  operations: { walletDescriptor, authorizer: deviceBoundP256Authorizer },
});

const connection = await client.connectAndVerify();

const wallet = await createTvcEnclaveWallet({
  client,
  connection,
  clientKeyId: authorizer.clientKeyId,
  state: (await loadEnclaveBrowserWalletState()) ?? provisionedEnclaveState,
  persistState: saveEnclaveBrowserWalletState,
});

const pending = await wallet.shieldSol(amount);
await submitAndConfirm(pending.signedTransaction);
await wallet.settlePending(pending.transactionSignature);
```

`checkpointFromResult` and the raw `client.*` operations remain available for
tooling that manages checkpoints itself.

Use `@zolana/tvc-wallet/enclave/react` for
`TvcEnclaveWalletProvider` / `useTvcEnclaveWallet`, and
`@zolana/tvc-wallet/enclave/browser` for the isolated checkpoint journal.
These are separate entry points rather than a runtime mode on the lightweight
provider.

## Browser persistence

`@zolana/tvc-wallet/browser` stores only:

- a non-exportable P-256 request-authorizer key;
- a non-exportable AES-GCM storage key;
- the descriptor and public bootstrap identity;
- encrypted derivation seed and encrypted Zolana wallet snapshot;
- an exact-byte pending submission journal.

Balances and history in the lightweight profile are reconstructed from the
decrypted wallet after client sync. Full-enclave state uses a separate database
and stores only the sealed checkpoint, public display metadata, and exact-byte
pending submissions.

## Composition with Helius Wallet Kit

Use a separate `TvcWalletProvider` / `useTvcWallet` below the application's
single `HeliusWalletProvider`. The existing Turnkey session supplies only the
narrow Boot Proof lookup and wallet enrollment bridge. Do not adapt TVC to the
generic `HeliusWallet` signing/export interface or make it a provider mode.

`@zolana/tvc-wallet/protocol` mirrors the subset of the Rust protocol that the
three shipped profiles use, not the protocol in full. Owner authorization,
descriptor rotation, recovery intents, quorum rotation, and release channels
exist in `crates/protocol` with no TypeScript path; their digest constructors
are deliberately absent here rather than present and unexercised. The English
specification remains authoritative for the complete wire format.

Public entry points:

- `@zolana/tvc-wallet/protocol`
- `@zolana/tvc-wallet/browser`
- `@zolana/tvc-wallet/shielded-wallet`
- `@zolana/tvc-wallet/react`
- `@zolana/tvc-wallet/enclave`
- `@zolana/tvc-wallet/enclave/browser`
- `@zolana/tvc-wallet/enclave/react`
- `@zolana/tvc-wallet/keyholder`
- `@zolana/tvc-wallet/keyholder/browser`
- `@zolana/tvc-wallet/keyholder/react`

Production recovery, multi-device state, independently distributed release
metadata, proof-verifier parity, and production spending remain out of scope.
