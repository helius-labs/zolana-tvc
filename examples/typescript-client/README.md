# TypeScript client with a TVC wallet

A client example for `@heliuslabs/zolana` with the shielded keys held by a TVC
enclave (`@zolana/tvc-wallet`), in the layout of
[zolana-examples](https://github.com/helius-labs/zolana-examples).

- **[enroll](examples/enroll.ts)** - One-time setup of a Turnkey wallet for this client: the client key, the enclave's grant, and the descriptor request for the operator
- **[deposit_transfer_withdraw](examples/deposit_transfer_withdraw.ts)** - Deposit, private transfer, and withdraw, with the enclave as the key holder
- **[spl_deposit_transfer_withdraw](examples/spl_deposit_transfer_withdraw.ts)** - The same lifecycle for an SPL token registered with the pool
- **[ring_deposit_transfer_exit](examples/ring_deposit_transfer_exit.ts)** - Deposit into a custom ring, transfer inside it, and exit back to the default ring

## What a TVC wallet is

In the plain client, the application holds the shielded keys of a private
wallet. In a TVC wallet, an attested enclave (Turnkey Verifiable Compute on
AWS Nitro) holds them. The application still runs the Zolana SDK: it syncs
the balance, selects inputs, builds transactions and sends them. The enclave
answers five operations only:

| Operation         | What it does                                                                                                               |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `Bootstrap`       | Derives the shielded identity from a Turnkey signature of the wallet. Returns the public identity and the seed sealed to the enclave key. |
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
   sealed seed, is stored in a file. Neither is a secret to the client. If the
   file is lost, `bootstrap` runs again and returns the same identity.
3. `new TvcKeys({ client, connection, sealedSeed, identity })` is the SDK's
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
  the operator (`apps/privacy-wallet/deploy/privacy-wallet.trust.json` for the
  release this repository is at). Do not copy these values from the service
  itself.
- A Boot Proof source. Only a user of the TVC organization can read the
  enclave's Boot Proof from Turnkey, so a server the operator runs returns the
  public document to other clients (`TVC_BOOT_PROOF_URL`; the wallet-kit demo
  serves it at `POST /api/tvc/boot-proof` with body
  `{ "ephemeralKey": "<hex>" }`, and
  [`zolana-tvc-boot-proof`](../../crates/boot-proof/README.md) is the same
  fetch as a command). A client whose Turnkey API key is a user of that
  organization reads it directly: set `TVC_ORGANIZATION_ID` instead of the URL.
- A Turnkey organization and an API key of a root user of it, as the key pair
  or a Turnkey API key file (`TURNKEY_API_KEY_PATH`). The example signs with
  it, and the enrollment step below uses it to grant the enclave the one
  signature `bootstrap` needs (Helius wallet-kit installs the same grant for
  embedded wallets from the signed-in session). The wallet can exist already
  or be created by enrollment.
- A wallet descriptor for your client key, signed by the operator with the
  provisioning key. The enrollment step prints what the operator needs.

## Setup

From the repository root:

```bash
pnpm install
pnpm build:ts
cd examples/typescript-client
cp client.env.example .env # ...and fill in the values
```

## Enroll a wallet

Set `TURNKEY_ORGANIZATION_ID` in `.env`, and `TURNKEY_WALLET_ADDRESS` if the
wallet exists already, then:

```bash
pnpm example examples/enroll.ts
```

The step creates the client key at `TVC_CLIENT_KEY_PATH` if there is none,
finds the wallet behind the address (or creates a Solana wallet in the
organization when no address is set; put the printed address in `.env` for
later runs), and installs the enclave's grant in the organization: a service
user whose API key is the enclave's signing key, and a policy that lets this
user sign the bootstrap payload with this wallet account and nothing else.
Running it again changes nothing. It ends with the `provision-descriptor`
command for the operator, who signs the descriptor from the `zolana-tvc`
repository root:

```bash
node scripts/provision-descriptor.mjs --organization-id <org> --wallet-id <id> \
  --address <address> --client-public-key <hex> --out descriptor.json
```

The descriptor is public data. Save it at `TVC_DESCRIPTOR_PATH`.

## Run

```bash
pnpm example examples/deposit_transfer_withdraw.ts
```

The wallet in the descriptor pays fees and the deposit, so it needs devnet
SOL: the SOL and ring examples each deposit 0.01 SOL, so 0.1 SOL covers a
run of everything. For the SPL example set `SPL_MINT`, `SPL_ASSET_ID` (the id the pool
registered the mint under) and `SPL_TOKEN_ACCOUNT` (the wallet's token account
the deposit leaves from), and optionally `SPL_AMOUNT`:

```bash
pnpm example examples/spl_deposit_transfer_withdraw.ts
```

The ring example needs `RING_PROGRAM_ID`, a custom ring program registered
with the pool on the network you run against; it creates the ring's address
lookup table itself:

```bash
pnpm example examples/ring_deposit_transfer_exit.ts
```

## Run locally

Both examples run against the local testkit and a fresh Zolana localnet, with
a disposable keypair as the wallet in place of Turnkey and pinned process keys
in place of Nitro attestation. The Rust testkit runs the real handlers of the
five operations; the `@zolana/tvc-wallet/testing` client still verifies
envelopes, signatures and bindings, and accepts loopback HTTP only. It needs a
sibling `../zolana` checkout with its localnet toolchain (Solana CLI, Go, Rust,
`just`). From the repository root:

```bash
just headless-e2e        # port offset 200
just headless-e2e 400
```

The recipe builds the package, starts the validator, Photon and the prover
(`scripts/start-localnet.sh`, which also mints a test SPL asset and initializes
a custom ring), starts the testkit, funds the keypair, runs the three examples,
and tears everything down.
[`headless-local-e2e.yml`](../../.github/workflows/headless-local-e2e.yml)
runs it in CI. Setting `TVC_LOCAL_TESTKIT_ENDPOINT` (with
`TVC_SOLANA_KEYPAIR_PATH`, `TVC_WALLET_PATH`, the `ZOLANA_*` URLs, the
`SPL_*` values and `RING_PROGRAM_ID`) runs an example against a stack you
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
