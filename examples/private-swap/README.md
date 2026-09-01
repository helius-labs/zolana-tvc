# Private swap integration

This example adapts the canonical Zolana confidential swap to the TVC wallet
protocol. Zolana owns the swap program, circuits, prover, proving keys, and SDK;
this repository owns only the TVC plan/finalize integration.

The `swap-tvc-adapter` CLI exposes:

- `make-plan`, `take-plan`, and `cancel-plan`, which produce program-neutral
  `AuthorizeSpend` plans;
- `prove-make`, `prove-take`, and `prove-cancel`, which bind the swap proof and
  outer instruction to TVC's prepared `private_tx_hash`;
- `decode-order`, which reconstructs and validates a client-relayed encrypted
  order.

The common SPP proof is produced inside TVC. This adapter invokes the separate,
program-owned swap prover; it is never called through TVC egress.

## Build and test

The sibling repositories must have this layout:

```text
zolana/
├── zolana/
└── zolana-tvc/
```

Download and verify the canonical proving keys from the Zolana checkout, then
build the adapter:

```sh
cd ../zolana
just ensure-swap-keys
cd ../zolana-tvc/examples/private-swap
cargo test --locked
cargo build --locked --release
```

At runtime, point `SWAP_PROVER_KEYS_DIR` at the sibling Zolana checkout's
`sdk-tests/zk-program-swap/build/gnark` directory and invoke
`examples/private-swap/target/release/swap-tvc-adapter` from the `zolana-tvc`
checkout.
