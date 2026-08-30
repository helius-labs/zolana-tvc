# `@zolana/tvc-wallet`

Typed client for the Zolana TVC privacy wallet. The package verifies the signed
release policy and AWS Nitro Boot Proof before exposing an opaque
`VerifiedConnection`, encrypts operation envelopes with QOS P-256, validates
proof-bound results, and provides strict browser persistence and React
bindings.

This is pre-production software for disposable devnet funds. The current
external prover receives a plaintext witness containing `nullifier_secret`.

## API

```ts
import { createTvcWalletClient } from "@zolana/tvc-wallet";
import {
  loadOrCreatePersistentBrowserTvcAuthorizer,
  loadPersistentBrowserTvcWalletState,
  savePersistentBrowserTvcWalletState,
} from "@zolana/tvc-wallet/browser";
```

The root client exposes only typed operations:

- `connectAndVerify`
- `bootstrapKeyholder`
- `deriveViewTags`
- `decryptUtxos`
- `authorizeSpend`
- `prepareSpend` / `finalizeSpend`
- `prepareSppSpend`

There is no generic `signMessage`, `signTransaction`, wallet export, arbitrary
Turnkey activity, or caller-selected network origin.

`bootstrapKeyholder` returns public identity and an opaque checkpoint. It never
returns the derivation seed or another private spend role. On recovery or Quorum rotation, pass the
previously recorded public identity as `expectedIdentity`; a different result
fails with `ShieldedIdentityChanged`.

Read sync is client-relayed. `syncTvcWallet` derives the wallet's stable view tags,
passes them to the caller-provided indexer fetch, and sends returned ciphertexts
back to TVC in bounded decrypt batches. Decrypted bytes are candidates: the
shielded transport cipher is unauthenticated, so callers must deserialize them
and confirm the recovered owner.

A ring spend accepts semantic intent. The client verifies the returned
transaction against the App Proof before returning the result.

## Private spends

`authorizeSpend` covers default and custom rings. The settlement is a closed
pair so a public withdrawal cannot be read as a private transfer.

```ts
await client.authorizeSpend(connection, {
  checkpoint,
  source: { kind: "ring", programId, lookupTable },
  settlement: {
    kind: "transfer",
    asset: { type: "Sol" },
    recipient,
    amount,
    destination: { kind: "ring", programId, lookupTable },
  },
});
```

Use `{ kind: "default" }` for the default pool. No direction enum exists: the
route follows from `source` and the transfer's `destination`. A default-to-ring
transition names one or more exact default-pool `inputCommitments`; they must
total the settlement amount so unrelated default balance cannot follow as
change. A custom ring's lookup table must be at least one slot old when the
transaction lands. The existing Turnkey Ed25519 wallet signs once as both
shielded owner and fee payer.

There is intentionally no direct custom-ring A to custom-ring B transition.
Wallets implement it as A to an exact self-owned default note, then that note to
B. Both signed transactions can be persisted and resumed independently.

For ecosystem programs, `prepareSppSpend` accepts a declarative,
asset-conserving SPP plan and returns the exact proved transact plus a sealed
capsule. The ecosystem SDK builds a complete unsigned transaction;
the same `finalizeSpend` used by direct spends requires exactly one
target-program instruction carrying the
prepared `private_tx_hash`. Other instructions and executable programs are
allowed under the wallet's ordinary user-approval boundary. TVC fixes the
private inputs and outputs, but users still trust the selected program's public
behavior as in a conventional Solana wallet. Public unshield remains on the
direct exact-transaction path. The canonical
Zolana swap `make`, `take`, and `cancel` flows exercise the program API on
devnet. Program-owned order inputs use the same plan format as wallet inputs;
the browser persists opaque, untrusted recovery context while TVC and the
program revalidate every opening and proof.

## React

```tsx
import { TvcWalletProvider, useTvcWallet } from "@zolana/tvc-wallet/react";

function PrivateBalance() {
  const { client, connection, connect, status } = useTvcWallet();
  // Application flow decides when to connect and which typed operation to run.
  return <button onClick={() => void connect()}>{status}</button>;
}

export function App({ config, children }) {
  return <TvcWalletProvider config={config}>{children}</TvcWalletProvider>;
}
```

The React entry is a client component. It provides connection lifecycle only;
wallet provisioning, chain submission, and UX policy remain application work.

## Entry points

- `@zolana/tvc-wallet`
- `@zolana/tvc-wallet/protocol`
- `@zolana/tvc-wallet/browser`
- `@zolana/tvc-wallet/react`

## Verification

```sh
npx --yes pnpm@9.15.0 --filter @zolana/tvc-wallet test
npx --yes pnpm@9.15.0 --filter @zolana/tvc-wallet typecheck
npx --yes pnpm@9.15.0 --filter @zolana/tvc-wallet build
```

See the repository [architecture](../../docs/architecture.md) and detailed
[privacy-wallet profile](../../docs/privacy-wallet.md).
