# `@zolana/tvc-wallet`

Client for the Zolana TVC privacy wallet. It verifies the signed release policy
and the AWS Nitro Boot Proof before handing out a `VerifiedConnection`, wraps
every operation in a QOS P-256 envelope, checks the proof-bound result, and
answers the Zolana SDK's `WalletKeys` interface through `TvcKeys`, so every
`@heliuslabs/zolana` flow runs over the enclave unchanged.

Pre-production, disposable devnet funds only: the pinned prover receives a
plaintext witness containing the nullifier secret.

## Usage

```ts
import {
  Wallet,
  buildDepositTransaction,
  buildTransferTransaction,
  createZolanaClient,
  syncWallet,
} from "@heliuslabs/zolana";
import { AssetRegistry } from "@heliuslabs/zolana/transaction";
import {
  TvcKeys,
  sealedSeedOf,
  createTvcClient,
  identityOf,
  shieldedAddressOf,
} from "@zolana/tvc-wallet";

const tvc = createTvcClient(config); // release policy, authorities, PCRs, descriptor, authorizer
const connection = await tvc.connectAndVerify();

// Once per wallet; also the recovery path after the sealed seed is lost or the Quorum key rotates.
const bootstrap = await tvc.bootstrap(connection, { expectedIdentity: stored ?? undefined });
const identity = identityOf(bootstrap); // persist
const sealedSeed = sealedSeedOf(bootstrap); // persist; presented on every later call

// The enclave as the SDK's keys. Nothing below learns a secret.
const keys = new TvcKeys({ client: tvc, connection, sealedSeed, identity });
const zolana = await createZolanaClient({ solanaRpcUrl, indexerUrl, proverUrl });
const wallet = new Wallet({
  identity: shieldedAddressOf(identity),
  registry: new AssetRegistry([[assetId, mint]]),
});

await syncWallet({ client: zolana, wallet, keys });
const transaction = await buildTransferTransaction({
  client: zolana,
  wallet,
  keys,
  feePayer: solanaSigner.address,
  recipient,
  amount,
});
// Sign with the wallet's Solana signer (a Turnkey session, a keypair) and submit.
```

`TvcClient` has exactly `connectAndVerify`, `bootstrap`, `decrypt`, `derive`,
`transactionKeys`, and `prove`, the wire form of the five enclave operations;
`TvcKeys` is the same surface as the SDK's `WalletKeys`, and forwards the SDK's
`RequestContext` (abort signal and timeout) to every enclave call, so a
cancelled sync stops its decrypt batches as a cancelled build stops its proof.
No operation
returns a long-lived secret, none signs a Solana transaction, and none takes a
caller-selected network origin. The enclave bounds a proof at 75 s and by the
request's expiry, below the 90 s a front proxy typically allows. The pool
cipher is unauthenticated, so the SDK adopts a decrypted UTXO only when its
commitment matches the indexed output.

`snapshotCipher(keys)` is the SDK's `WalletStateCipher` for
`syncPersistedWallet` and `loadPersistedWallet`, keyed by a per-transaction key
the enclave mints under a context no transaction can have, so a sealed wallet
snapshot persists at rest and reopens on any device that can drive this
wallet's enclave operations.

## Entry points

- `@zolana/tvc-wallet`: client, `TvcKeys`, `snapshotCipher`, release-policy
  verification, and `createTvcOperationAuthorizer` for a caller-held P-256
  request key outside the browser.
- `@zolana/tvc-wallet/protocol`: wire types, `TvcError`, hex codecs, the
  descriptor digest a provisioner signs, and `clientKeyIdFor`.
- `@zolana/tvc-wallet/browser`: non-exportable P-256 request signer, the
  persisted enclave-state parser, and IndexedDB record helpers.
- `@zolana/tvc-wallet/react`: `TvcWalletProvider` / `useTvcWallet` for the
  connection lifecycle.
- `@zolana/tvc-wallet/testing`: loopback-only unattested testkit client. The
  build fails if it becomes reachable from a production entry.

## Verification

From the repository root:

```sh
pnpm ci:ts
```
