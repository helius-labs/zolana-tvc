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
- `prepareSppSpend` / `finalizeSppSpend`

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
pair so a public exit cannot be read as a private transfer.

```ts
await client.authorizeSpend(connection, {
  checkpoint,
  ring: { direction: "exit", programId, lookupTable },
  settlement: { kind: "transfer", asset: { type: "Sol" }, recipient, amount },
  proverProfileId,
});
```

Use `ring: null` for a default-pool spend. `direction: "exit"` spends from the
custom ring into the default pool. `direction: "enter"` spends one or more
exact default-pool `inputCommitments` into the custom ring; the commitments
must total the settlement amount so unrelated default balance cannot follow as
change. A custom ring's lookup table must be at least one slot old when the
transaction lands. The existing Turnkey Ed25519 wallet signs once as both
shielded owner and fee payer.

There is intentionally no direct custom-ring A to custom-ring B transition.
Wallets implement it as A to an exact self-owned default note, then that note to
B. Both signed transactions can be persisted and resumed independently.

For ecosystem programs, `prepareSppSpend` accepts a declarative, private-only
SPP plan and returns the exact proved transact plus a sealed capsule.
`finalizeSppSpend` accepts one target-program instruction carrying those exact
bytes. TVC permits no other signer and no executable account besides the
shielded pool, so this path cannot move the wallet's public SOL or tokens.
Public unshield remains on the built-in exact-transaction path. The generic API
is implemented and shipped in the devnet TVC release, but has not yet been
exercised end to end against a deployed ecosystem program.

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
