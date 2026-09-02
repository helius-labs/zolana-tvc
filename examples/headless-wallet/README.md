# Headless wallet E2E

Runs the wallet lifecycle against the unattested local testkit and a fresh
Zolana localnet: bootstrap, register, then for SOL and a freshly minted SPL
asset deposit, sync, private self-transfer, sync, withdraw, sync to zero.

The Rust process runs the real encrypted handlers for `Bootstrap`, `ViewTags`,
`Decrypt`, and `Spend`. Two boundaries are replaced: pinned local process keys
stand in for Nitro attestation and a local Ed25519 key for Turnkey custody, both
read from [`local-testkit.json`](../../packages/tvc-wallet/src/local-testkit.json).
The `@zolana/tvc-wallet/testing` client still verifies envelopes, signatures,
digests, and bindings; it accepts loopback HTTP only.

## Run

Needs a sibling `../zolana` checkout with its localnet toolchain (Solana CLI,
Go, Rust, `just`):

```sh
just headless-e2e        # port offset 200
just headless-e2e 400
```

The recipe builds the SDK, starts the validator, Photon, and prover through
`scripts/start-localnet.sh`, starts the testkit on `http://127.0.0.1:44020` with
a temporary funded keypair, runs `src/main.ts`, and tears everything down.

## Configuration

`just headless-e2e` sets everything. To drive services you started yourself,
copy `headless.env.example` and run `pnpm e2e:headless:local`.

| Variable | Meaning |
| --- | --- |
| `TVC_ENDPOINT` | Testkit endpoint, default `http://127.0.0.1:44020`. |
| `TVC_SOLANA_RPC_URL`, `TVC_INDEXER_URL`, `TVC_PROVER_URL` | Localnet services, shared by the Node driver and the testkit. |
| `TVC_SOLANA_KEYPAIR_PATH` | Disposable 64-byte Solana keypair JSON; fee payer and local custody. |
| `TVC_IDENTITY_PATH` | Where the bootstrapped identity is cached and checked on re-runs. |
| `TVC_E2E_SPL_MINT`, `TVC_E2E_SPL_ASSET_ID`, `TVC_E2E_SPL_TOKEN_ACCOUNT` | From `zolana dev pool test-mint`; fresh per fixture. |
| `TVC_E2E_DEPOSIT_LAMPORTS`, `TVC_E2E_SPL_AMOUNT`, `TVC_E2E_SYNC_TIMEOUT_MS` | Amounts and the per-sync deadline. |

## CI

[`headless-local-e2e.yml`](../../.github/workflows/headless-local-e2e.yml) runs
on pull requests, pushes to `main`, dispatch, and nightly, with the sibling
Zolana checkout pinned to the SDK revision this repository builds against.
