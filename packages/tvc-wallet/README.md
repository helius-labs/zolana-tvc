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
- `buildTransfer`
- `buildSolWithdrawal`
- `authorizeDefaultRingTransfer`

There is no generic `signMessage`, `signTransaction`, wallet export, arbitrary
Turnkey activity, or caller-selected network origin.

`bootstrapKeyholder` returns public identity plus an opaque checkpoint. It does
not return the derivation seed. On recovery or Quorum rotation, pass the
previously recorded public identity as `expectedIdentity`; a different result
fails with `ShieldedIdentityChanged`.

Read sync is client-relayed. `syncTvcWallet` derives bounded view-tag windows,
passes them to the caller-provided indexer fetch, and sends returned ciphertexts
back to TVC in bounded decrypt batches. Decrypted bytes are candidates: the
shielded transport cipher is unauthenticated, so callers must deserialize them
and confirm the recovered owner.

Private spends accept semantic intent. The client derives authorization
digests from the exact transaction bytes and independently verifies the final
Ed25519 signature before returning the result.

## Custom rings

A `ring` on `buildTransfer` or `buildSolWithdrawal` spends inside that ring
instead of the default one.

```ts
await client.buildTransfer(connection, {
  checkpoint,
  asset: { type: "Sol" },
  recipient,
  amount: 1_000_000n,
  proverProfileId,
  ring: { programId, lookupTable },
});
```

The ring names a different authority, not a different shape. The client asks
for `BuildCustomRingTransfer` or `BuildCustomRingSolWithdrawal` and fails with
`OperationNotAllowed` before the request leaves the browser unless the release
advertises that kind and the descriptor grants it. Every input spent and output
produced is bound to the named program, and the spend travels as a v0 message
over the named address lookup table, which must be at least one slot old when
the transaction lands.

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
