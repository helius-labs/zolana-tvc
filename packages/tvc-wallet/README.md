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
- `signRingSpend`

There is no generic `signMessage`, `signTransaction`, wallet export, arbitrary
Turnkey activity, or caller-selected network origin.

`bootstrapKeyholder` returns public identity, an opaque checkpoint, and the role
secrets this devnet profile hands the caller. It does not return the derivation
seed. On recovery or Quorum rotation, pass the
previously recorded public identity as `expectedIdentity`; a different result
fails with `ShieldedIdentityChanged`.

Read sync is client-relayed. `syncTvcWallet` derives bounded view-tag windows,
passes them to the caller-provided indexer fetch, and sends returned ciphertexts
back to TVC in bounded decrypt batches. Decrypted bytes are candidates: the
shielded transport cipher is unauthenticated, so callers must deserialize them
and confirm the recovered owner.

A ring spend accepts semantic intent. The client verifies the returned
transaction against the App Proof before returning the result.

## Ring spends

`signRingSpend` is the one spend the enclave performs. The ring is required, and
the settlement is a closed pair so a public exit cannot be read as a private
transfer.

```ts
await client.signRingSpend(connection, {
  checkpoint,
  ring: { programId, lookupTable },
  settlement: { kind: "transfer", asset: { type: "Sol" }, recipient, amount },
  proverProfileId,
});
```

The spend runs as the wallet's ring identity, a P-256 owner whose signature the
circuit checks rather than the runtime, so Turnkey signs only as fee payer. The
descriptor's ring grant names that key and the rings the wallet may spend in, and
a ring it does not name is refused before any chain read. The lookup table must
be at least one slot old when the transaction lands.

## Default-ring spends

The enclave does not build them. `bootstrapKeyholder` returns the derivation
seed on this devnet profile, so the caller expands the roles with
`ClientEd25519WalletAuthority.fromDerivationSeed`, syncs, builds the witness,
proves, and signs as the Ed25519 owner with its own Turnkey session. Holding that
seed makes the caller a full view and spend authority for the default ring.

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
