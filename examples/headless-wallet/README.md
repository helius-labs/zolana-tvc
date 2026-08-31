# Headless Node wallet E2E

This example runs the complete wallet lifecycle against the local TVC testkit
and a fresh Zolana localnet:

1. start the Rust privacy-wallet service with local custody;
2. bootstrap the shielded identity;
3. register it on chain when necessary;
4. derive view tags and synchronize spendable UTXOs;
5. shield, privately self-transfer, and unshield SOL;
6. repeat the default-domain cycle for a freshly minted classic SPL Token asset;
7. create lookup tables for two independent custom rings;
8. deposit into ring A and move privately through default into ring B;
9. spend within ring B, return through default, and unshield;
10. create eight default SOL UTXOs, consolidate them into one, and unshield it;
11. verify every private domain is empty and both public assets are restored
    apart from SOL transaction fees and lookup-table rent.

The Rust process executes the real encrypted handlers for
`BootstrapKeyholder`, `DeriveViewTags`, `DecryptUtxos`, and `AuthorizeSpend`,
including sealed state, wallet synchronization, proving, transaction assembly,
and final validation. The `@zolana/tvc-wallet/testing` entrypoint uses the same
client interface and still verifies encryption, signatures, request/result
digests, operation bindings, and state bindings.

Two production boundaries are deliberately replaced: pinned local process keys
stand in for Nitro attestation, and a local Ed25519 key stands in for Turnkey
custody. The test-only client accepts loopback HTTP only and pins the testkit's
fixed QOS public keys. This is therefore a protocol and wallet integration test,
not a Turnkey or Nitro acceptance test.

Rust and TypeScript read their deterministic test-only identities from the same
[`local-testkit-v1.json`](../../fixtures/local-testkit-v1.json) fixture. The SDK's
unattested connector is reachable only through `@zolana/tvc-wallet/testing` and
is not bundled into the production entry points.

The Zolana CLI starts the validator, Photon indexer, and prover locally. The
fixture deploys two instances of the custom-ring program, initializes their
configs, and creates an SPL mint owned by the temporary wallet. A ring RPC is
not needed because this test exercises private spending rather than auditor
reads. The recipe shares its temporary wallet only with the Node driver and
local Rust custody backend and removes every generated secret after the run.
It needs no hosted service, faucet, Turnkey organization, or repository secret,
and it never reads the Solana CLI's default wallet.

## Run

```sh
just headless-e2e
```

That one recipe builds the SDK, asks the sibling `../zolana` checkout to start
the validator, Photon, and prover, starts the Rust testkit on
`http://127.0.0.1:44020`, runs the full lifecycle, and stops every service. The
default Zolana port offset is `200`; pass another offset when necessary:

```sh
just headless-e2e 400
```

A successful run restores the starting public SPL balance, leaves no private
UTXOs in default or either custom ring, and spends only SOL fees and rent.

Configuration and indexer framing tests do not access the network:

```sh
pnpm test:examples
pnpm typecheck:examples
```

## Configuration

| Variable | Meaning |
| --- | --- |
| `TVC_SOLANA_KEYPAIR_PATH` | Optional disposable 64-byte Solana keypair JSON. The recipe generates a temporary one when unset. |
| `TVC_ENDPOINT` | Local testkit endpoint. Defaults to `http://127.0.0.1:44020`. |
| `TVC_SOLANA_RPC_URL` | Local validator JSON-RPC endpoint used by the Node driver and Rust testkit. |
| `TVC_INDEXER_URL` | Local Photon endpoint used by the Node driver and Rust testkit. |
| `TVC_PROVER_URL` | Local Zolana prover endpoint used by the Node driver and Rust testkit. |
| `TVC_IDENTITY_PATH` | Optional identity cache. The recipe uses a temporary file when unset. |
| `TVC_ALLOW_INSECURE_HTTP` | Set to `1` only for an explicitly trusted development endpoint. |

The recipe also provisions `TVC_E2E_SPL_MINT`, `TVC_E2E_SPL_ASSET_ID`,
`TVC_E2E_SPL_TOKEN_ACCOUNT`, `TVC_E2E_RING_A_PROGRAM_ID`, and
`TVC_E2E_RING_B_PROGRAM_ID`. They describe fresh local accounts and should not
be copied into a persistent environment file.

Optional tuning variables are `TVC_E2E_DEPOSIT_LAMPORTS` (default
`20000000`), `TVC_E2E_TRANSFER_LAMPORTS` (defaults to the deposit),
`TVC_E2E_SPL_AMOUNT` (default `200000`), `TVC_E2E_RING_BRIDGE_LAMPORTS`
(default `30000000`), `TVC_E2E_MERGE_INPUT_LAMPORTS` (default `2000000`),
`TVC_E2E_FEE_RESERVE_LAMPORTS` (default `20000000`),
`TVC_E2E_SYNC_TIMEOUT_MS` (default `180000`), and `TVC_E2E_SYNC_POLL_MS`
(default `3000`). `TVC_E2E_REQUIRE_EMPTY_PRIVATE_BALANCE=1` is useful for a
fresh fixture but makes recovery from an interrupted run less convenient.

## CI

[`headless-local-e2e.yml`](../../.github/workflows/headless-local-e2e.yml) runs
for pull requests, pushes to `main`, manual dispatches, and the nightly
schedule. It remains separate from the faster static/unit workflow, pins a
sibling Zolana checkout at the same revision used by the SDK, installs its
localnet toolchain, caches proving keys, and needs no repository secrets.
