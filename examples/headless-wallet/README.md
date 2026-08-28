# Headless wallet example

Verifies a privacy-wallet release from Node, derives the shielded identity, and
prints the view tags a caller queries the indexer with. It makes no chain call,
so it needs no RPC access and cannot spend.

A browser holds a non-exportable client key. This example holds a local one, so
run it against disposable devnet material only.

## Configuration

| Variable | Locks in |
| --- | --- |
| `TVC_ENDPOINT` | The service to talk to. Discovery from it is untrusted until the policy check passes. |
| `TVC_RELEASE_POLICY_PATH` | The independently signed release policy. Everything security-relevant is compared against this, never against discovery. |
| `TVC_RELEASE_AUTHORITIES_PATH` | The pinned keys that policy must be signed by. |
| `TVC_BOOT_PROOF_URL` | An endpoint holding an authenticated Turnkey session, which returns the Boot Proof for a given App Proof. |
| `TVC_DESCRIPTOR_PATH` | The provisioned wallet descriptor. Its first client grant must name the key below. |
| `TVC_CLIENT_PRIVATE_KEY_HEX` | The P-256 client key the descriptor grants. |
| `TVC_IDENTITY_PATH` | Optional. Written on first run, then compared on every later run, so a re-bootstrap cannot adopt a different wallet. |

## Run

```sh
pnpm --filter zolana-tvc-headless-example start
```

## What it does not do

Reading the indexer, deserializing decrypted candidates, and submitting
transactions stay with the caller. Feed the printed tags to an indexer and pass
the returned ciphertexts to `decryptUtxos`, or use `syncTvcWallet` with your own
fetch function.
