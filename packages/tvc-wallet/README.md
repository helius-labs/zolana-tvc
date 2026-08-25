# `@zolana/tvc-wallet`

Development-only TypeScript client for the lightweight Zolana TVC wallet
profile. It is not a production-funds wallet or a generic Turnkey signer.

## Boundary

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

## Verification

`connectAndVerify` verifies an independently signed release policy before using
`/v1/info`, performs the encrypted QOS ping, resolves the exact replica's Boot
Proof, validates its AWS Nitro/QOS identity commitments, and returns an opaque
`VerifiedConnection`.

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

const intentDigest = defaultRingTransferIntentDigest({
  walletId: walletDescriptor.wallet_id,
  solanaAddress,
  recipient,
  asset: { type: "Sol" },
  amount,
  unsignedTransaction,
});
const authorized = await client.authorizeDefaultRingTransfer(connection, {
  intentDigest,
  unsignedTransaction,
});
```

The intent digest commits the user-visible fields to the exact transaction
digest. TVC still cannot reconstruct private recipient/amount semantics from
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
`completeDefaultRingTransaction` only after chain confirmation.

The facade exposes typed registration, SOL deposit, sync, balance/history, and
default-ring transfer and SOL-withdrawal methods. Transfer and withdrawal
intents use separate digest domains even though the current enclave release
authorizes both through the same fixed-shape `AuthorizeDefaultRingTransfer`
rail. The facade does not expose the underlying
`WalletAuthority`, derivation seed, viewing/nullifier keys, `signMessage`, or a
generic transaction signer. It requires `@heliuslabs/zolana` and `@solana/kit`
as peer dependencies; the protocol-only and verification entry points do not.

## Browser persistence

`@zolana/tvc-wallet/browser` stores only:

- a non-exportable P-256 request-authorizer key;
- a non-exportable AES-GCM storage key;
- the descriptor and public bootstrap identity;
- encrypted derivation seed and encrypted Zolana wallet snapshot;
- an exact-byte pending submission journal.

Balances and history are reconstructed from the decrypted wallet after client
sync. There are no enclave checkpoints or migrations from the superseded
full-enclave prototype.

## Composition with Helius Wallet Kit

Use a separate `TvcWalletProvider` / `useTvcWallet` below the application's
single `HeliusWalletProvider`. The existing Turnkey session supplies only the
narrow Boot Proof lookup and wallet enrollment bridge. Do not adapt TVC to the
generic `HeliusWallet` signing/export interface or make it a provider mode.

Public entry points:

- `@zolana/tvc-wallet/protocol`
- `@zolana/tvc-wallet/browser`
- `@zolana/tvc-wallet/shielded-wallet`
- `@zolana/tvc-wallet/react`

Production recovery, multi-device state, independently distributed release
metadata, proof-verifier parity, and production spending remain out of scope.
