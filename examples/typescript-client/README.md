# TypeScript client with a TVC wallet

A client example for `@heliuslabs/zolana` with the shielded keys held by a TVC
enclave (`@zolana/tvc-wallet`), in the layout of
[zolana-examples](https://github.com/helius-labs/zolana-examples).

- **[deposit_transfer_withdraw](examples/deposit_transfer_withdraw.ts)** - Deposit, private transfer, and withdraw, with the enclave as the key holder

## What a TVC wallet is

In the plain client, the application holds the shielded keys of a private
wallet. In a TVC wallet, an attested enclave (Turnkey Verifiable Compute on
AWS Nitro) holds them. The application still runs the Zolana SDK: it syncs
the balance, selects inputs, builds transactions and sends them. The enclave
answers five operations only:

| Operation         | What it does                                                                                                               |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `Bootstrap`       | Derives the shielded identity from a Turnkey signature of the wallet. Returns the public identity and a sealed checkpoint. |
| `Decrypt`         | Opens encrypted outputs from the index.                                                                                    |
| `Derive`          | Derives nullifiers and blindings for a spend.                                                                              |
| `TransactionKeys` | Mints the per-transaction viewing key.                                                                                     |
| `Prove`           | Completes the proof witness with the nullifier secret and calls the prover.                                                |

The enclave never sees a balance, never selects an input and never signs a
Solana transaction. Every Solana transaction is signed by the Turnkey wallet
that owns the identity, in a browser by the signed-in session, in this
headless example by a Turnkey API key.

This is for applications with Turnkey embedded wallets that want private
balances without keeping shielded keys in a browser or on a server.

## How the example works

1. `createTvcClient` takes the endpoint and the trust material, then
   `connectAndVerify` checks the signed release policy, the AWS Nitro Boot
   Proof, the PCRs and the manifest against pins the client holds.
2. `bootstrap` runs once per wallet. Its result, the public identity and the
   sealed checkpoint, is stored in a file. Neither value is a secret. If the
   file is lost, `bootstrap` runs again and returns the same identity.
3. `new TvcKeys({ client, connection, checkpoint, identity })` is the SDK's
   `WalletKeys`, answered by the enclave.
4. The SDK does the rest: `Wallet`, `syncWallet`, `buildDepositTransaction`,
   `buildTransferTransaction`, `buildWithdrawalTransaction`. The calls are the
   same as with local keys.
5. The application signs each transaction with the Turnkey wallet, sends it,
   confirms it and syncs the wallet to the landed slot.

The plain client does the same with `LocalKeys.fromKeypair(keypair,
client.proofService)` in place of `TvcKeys`. Nothing else changes.

## What you need

- Node.js 24+ and pnpm.
- A Helius devnet API key.
- A TVC deployment: its endpoint and its trust material, a JSON file with
  `releasePolicy`, `releaseAuthorities` and `qosIdentityPcrs`, published by
  the operator. Do not copy these values from the service itself.
- A Boot Proof endpoint. A client session cannot read the enclave's Boot
  Proof from Turnkey, so a server the operator runs returns the public
  document. [`zolana-tvc-boot-proof`](../../crates/boot-proof/README.md)
  fetches it with a Turnkey API key of the TVC organization; the wallet-kit
  demo serves it at `POST /api/tvc/boot-proof` with body
  `{ "ephemeralKey": "<hex>" }`.
- A Turnkey organization that holds the wallet, with the enclave's service
  user allowed to sign the bootstrap payload (Helius wallet-kit creates this
  policy for embedded wallets).
- A wallet descriptor for your client key, signed by the operator's
  provisioning service. The first run of the example creates the client key
  and reports its public key to enroll.
- A Turnkey API key of a user who may sign with the wallet in the descriptor.

## Setup

From the repository root:

```bash
pnpm install
pnpm build:ts
cd examples/typescript-client
cp .env.example .env # ...and fill in the values
```

The first run creates the client key at `TVC_CLIENT_KEY_PATH` and stops with
the client public key to enroll. Send it to the provisioning service, save the
returned descriptor at `TVC_DESCRIPTOR_PATH`, and run again.

## Run

```bash
pnpm example examples/deposit_transfer_withdraw.ts
```

The wallet in the descriptor pays fees and the deposit, so it needs devnet
SOL.

## Run locally

The same example runs against the local testkit and a fresh Zolana localnet,
with a disposable keypair as the wallet in place of Turnkey and pinned process
keys in place of Nitro attestation. It needs a sibling `../zolana` checkout
with its localnet toolchain (Solana CLI, Go, Rust, `just`); see
[`examples/headless-wallet`](../headless-wallet/README.md) for the stack.
From the repository root:

```bash
just client-example-local        # port offset 200
just client-example-local 400
```

The recipe builds the package, starts the validator, Photon, the prover and
the testkit, funds the keypair, runs the example, and tears everything down.
Setting `TVC_LOCAL_TESTKIT_ENDPOINT` (with `TVC_SOLANA_KEYPAIR_PATH`,
`TVC_WALLET_PATH`, and the `ZOLANA_*` URLs) runs it against a stack you
started yourself.

## Persistence

The example syncs the wallet from the index on every run. An application that
reopens a wallet often can store the SDK wallet snapshot instead. The enclave
provides the snapshot key, so no secret is kept on the device:

```ts
import { loadPersistedWallet, syncPersistedWallet } from "@heliuslabs/zolana";
import { snapshotCipher } from "@zolana/tvc-wallet";

const cipher = await snapshotCipher(keys);
const wallet =
  (await loadPersistedWallet({ store, cipher })) ?? new Wallet({ identity });
await syncPersistedWallet({ client, wallet, keys, store, cipher });
```

`store` is any `{ load, save }` pair over a string, for example a file or
IndexedDB.

## Notes

- Pre-production, devnet only, disposable funds. The prover receives a
  plaintext witness that contains the nullifier secret.
- Never commit `.env`, the client key, the descriptor, or the stored wallet.

## Documentation

- [Connect](https://www.helius.dev/docs/privacy/connect)
- [Documentation](https://helius.dev/docs/privacy)
- [Source Code](https://github.com/helius-labs/zolana)
- [`@zolana/tvc-wallet`](../../packages/tvc-wallet/README.md)
