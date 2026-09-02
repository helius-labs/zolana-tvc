# `@zolana/tvc-wallet`

Client for the Zolana TVC privacy wallet. It verifies the signed release policy
and the AWS Nitro Boot Proof before handing out a `VerifiedConnection`, wraps
every operation in a QOS P-256 envelope, checks the proof-bound result, and
composes with `@heliuslabs/zolana` for everything the enclave does not do:
sync bookkeeping, UTXO selection, deposits, registration, and submission.

Pre-production, disposable devnet funds only: the pinned prover receives a
plaintext witness containing the nullifier secret.

## Usage

```ts
import { createZolanaClient, buildDepositTransaction } from "@heliuslabs/zolana";
import { AssetRegistry } from "@heliuslabs/zolana/transaction";
import {
  checkpointOf,
  createTvcClient,
  identityOf,
  shieldedAddressOf,
  spend,
  syncWallet,
} from "@zolana/tvc-wallet";

const tvc = createTvcClient(config); // release policy, authorities, PCRs, descriptor, authorizer
const connection = await tvc.connectAndVerify();

// Once per wallet; also the recovery path after checkpoint loss or Quorum rotation.
const bootstrap = await tvc.bootstrap(connection, { expectedIdentity: stored ?? undefined });
const identity = identityOf(bootstrap); // persist
const checkpoint = checkpointOf(bootstrap); // persist; presented on every later call
const address = shieldedAddressOf(identity); // deposit / register with the Zolana SDK

const zolana = await createZolanaClient({ solanaRpcUrl, indexerUrl, proverUrl });
const registry = new AssetRegistry([[assetId, mint]]);

// A Zolana `Wallet` with this identity's UTXOs, each carrying its nullifier.
let wallet = await syncWallet({
  client: tvc, connection, checkpoint, identity: address, indexer: zolana, registry,
});

// Inputs are selected here (largest first, or pass `inputs`); the enclave
// nullifies, encrypts, proves, and signs. Submit the bytes yourself.
const { transaction } = await spend({
  client: tvc, connection, checkpoint, wallet,
  action: { kind: "transfer", recipient, asset: SOL_MINT, amount },
});
wallet = await syncWallet({ ..., wallet }); // marks the inputs spent
```

`TvcClient` has exactly `connectAndVerify`, `bootstrap`, `viewTags`,
`decrypt`, and `spend`. `spend` returns a signed transaction and never
submits; `decrypt` returns candidates, and `syncWallet` adopts only those
whose commitment matches the indexed output, because the pool cipher is
unauthenticated. There is no message signer, key export, or caller-selected
network origin.

## Entry points

- `@zolana/tvc-wallet`: client, `syncWallet`, `spend`, verification.
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
