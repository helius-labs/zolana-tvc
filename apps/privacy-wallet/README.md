# Privacy-wallet TVC application

Holds the wallet's privacy roles (nullifier key and viewing key, expanded from a
Turnkey-derived seed) out of browser JavaScript. Replica-stateless: the client
carries the seed sealed to the QOS Quorum key and presents it on every call.

Routes:

- `GET /health`: `{"status":"Healthy"}` once runtime keys are loaded.
- `GET /v1/info`: untrusted discovery the client binds to a signed release policy.
- `POST /v1/ping`: QOS connection challenge.
- `POST /v1/operations`: `Bootstrap`, `Decrypt`, `Derive`, `TransactionKeys`,
  `Prove`, specified in [`crates/protocol`](../../crates/protocol/README.md).

Module map: `operations/` (request validation, `bootstrap.rs`, `keys.rs` for
the three derivation operations, `prove.rs` for completing and forwarding a
prover request, `sealed.rs` for the sealed seed), `custody.rs` (Turnkey
signing of the derivation message behind one trait), `turnkey.rs` (Turnkey API
stamping with the Quorum signing subkey), `local_dev.rs` (testkit, `local-dev`
feature only).

Every network origin is compiled in: Turnkey and the devnet prover. The prover
receives the plaintext witness, including the nullifier secret, so this
application must not hold production funds.

## Build

```sh
just check lint test        # from the repository root
just image-privacy-wallet   # linux/amd64 image; prints the /tvc_app SHA-256
```

## Local testkit

Unattested. Real handlers, pinned local QOS keys instead of Nitro, a local
Ed25519 key instead of Turnkey. `just headless-e2e` runs it end to end; to run
it by hand:

```sh
cargo run -p zolana-tvc-privacy-wallet --features local-dev \
  --bin zolana-tvc-privacy-wallet-local -- \
  --wallet-keypair /path/to/disposable-keypair.json --prover-url http://127.0.0.1:3001
```

The `local-dev` feature is never enabled in the enclave binary.

## Operation costs

For deployed-service measurements, use the [live TVC benchmark](../../examples/typescript-client/README.md#benchmark-the-deployed-tvc).
The local benchmark below measures a CPU baseline on its host, not deployed TVC cost.

Run the local CPU benchmark on Linux with Python 3, `taskset`, and the pinned
Rust toolchain:

```sh
python3 scripts/bench-operations.py --vcpu-hour 0.68
```

It builds the optimized `operations-benchmark` example binary, pins it to one logical CPU, and runs three
repetitions of the real encrypted Axum handlers. Results and a cost table are
written to `target/operation-benchmarks/latest/report.md` and `results.json`.
Use `--output PATH` to retain separate runs; `--seconds`, `--samples`,
`--repeats`, and `--cpu` control sampling. A quick correctness pass is:

```sh
python3 scripts/bench-operations.py --seconds 0.05 --samples 2 --repeats 1
```

The measured interval includes server authorization, seed unsealing and key
expansion, operation work, response encryption, and App Proof signing. Client
request construction and response verification run outside it. Every response
is authenticated and checked. Batches contain 1, 16, 64, or 128 items; decryption
uses 128-byte synthetic plaintexts. `Derive` measures the nullifier variant.

Bootstrap uses the testkit's local Ed25519 signer. Prove fills synthetic
requests and calls a separate-process loopback stub; no real proof is generated.
One stub case waits 50 ms to demonstrate the difference between CPU and wall
time. No Turnkey account, external prover, validator, or real wallet is used.

These measurements estimate the application's CPU work on the host machine.
They do not measure Nitro/QOS transport overhead, the production musl build,
Turnkey network/approval handling, external proving, client Boot Proof
verification, or fleet utilization. The report keeps those limits explicit;
sequential handler timings are not a deployed-service throughput benchmark.

The optional `benchmark-metrics` Cargo feature is for temporary measurement
images on real TVC. It adds numeric `x-tvc-benchmark-cpu` response headers to
successful operation requests. Default builds omit this middleware. The
[TypeScript benchmark](../../examples/typescript-client/README.md#cpu-timing-on-real-tvc)
collects these counters and distinguishes app CPU from request elapsed time.
