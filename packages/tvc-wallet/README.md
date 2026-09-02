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
  checkpointOf,
  createTvcClient,
  identityOf,
  shieldedAddressOf,
} from "@zolana/tvc-wallet";

const tvc = createTvcClient(config); // release policy, authorities, PCRs, descriptor, authorizer
const connection = await tvc.connectAndVerify();

// Once per wallet; also the recovery path after checkpoint loss or Quorum rotation.
const bootstrap = await tvc.bootstrap(connection, { expectedIdentity: stored ?? undefined });
const identity = identityOf(bootstrap); // persist
const checkpoint = checkpointOf(bootstrap); // persist; presented on every later call

// The enclave as the SDK's keys. Nothing below learns a secret.
const keys = new TvcKeys({ client: tvc, connection, checkpoint, identity });
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
`TvcKeys` is the same surface as the SDK's `WalletKeys`. No operation returns a
long-lived secret, none signs a Solana transaction, and none takes a
caller-selected network origin. The pool cipher is unauthenticated, so the SDK
adopts a decrypted UTXO only when its commitment matches the indexed output.

## Entry points

- `@zolana/tvc-wallet`: client, `TvcKeys`, verification.
- `@zolana/tvc-wallet/protocol`: wire types, JCS, digests, errors.
- `@zolana/tvc-wallet/browser`: non-exportable P-256 request signer and
  IndexedDB persistence for descriptor, identity, and checkpoint.
- `@zolana/tvc-wallet/react`: `TvcWalletProvider` / `useTvcWallet` for the
  connection lifecycle.
- `@zolana/tvc-wallet/testing`: loopback-only unattested testkit client. The
  build fails if it becomes reachable from a production entry.

## Verification

From the repository root:

```sh
pnpm ci:ts
```
