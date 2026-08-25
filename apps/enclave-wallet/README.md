# Zolana Enclave Wallet TVC Service

For a non-normative explanation of how Turnkey custody, the enclave, Photon,
the prover, and the browser client fit together, see
[`TVC Private Wallet Architecture`](ARCHITECTURE.md).
Exact security rules and formats remain in
[`TVC_SPEC.md`](../../spec/TVC_SPEC.md).

This is the full enclave-owned reference profile. It is a separate binary and
deployment from the preferred client-owned profile in
[`../client-wallet`](../client-wallet); the two profiles must never share a TVC
application or release policy.

The checked-in versioned deployment descriptors are provenance records for the
earlier full-profile images and intentionally retain their original OCI
references. A new build must use a new descriptor and digest; do not overwrite
those records or reuse them for the client-owned profile.

This is an attested, no-production-funds feasibility service. It exposes:

- `GET /health` with the exact `{"status":"Healthy"}` wire shape;
- `GET /v1/info` as untrusted discovery derived from QOS runtime state; and
- `POST /v1/ping`, a pet-only encrypted challenge proving the QOS Quorum
  encryption and Ephemeral signing paths are not swapped;
- `POST /v1/operations` for the closed development-only
  `CreateWallet`, `BootstrapEd25519`, the fixed-shape `PrepareWallet`
  registration step, typed `ShieldSol`, and default-ring `BuildTransfer`
  acceptance flow.

It must not be used with production descriptors or funds. Boot Proofs are
verified by the relying party, not by the enclave that emits App Proofs. The
operator E2E harness uses the pinned official Rust verifier before accepting
any result.

The binary compiles the closed `zolnet-devnet-external-http-v1` prover
profile for the default-ring `BuildTransfer` path. It points only to
the manifest-approved `../zolnet` devnet prover, deliberately permits that
public plaintext HTTP origin, and rejects production environments. The profile
locally verifies the returned `transfer_confidential` Groth16 proof before it
returns proof bytes to transaction construction. It makes no privacy claim for
proof inputs sent over the plaintext path. Each acceptance deployment pins one
provisioning public key and the default devnet tree. A provisioned descriptor
pins one verified HD-wallet account and one browser client key. Transfers may
select native SOL or an SPL mint whose exact asset ID is verified against its
canonical on-chain registry PDA. These values are an acceptance-test profile,
not a generic wallet service. A browser descriptor may bind those operations to
an ordinary embedded wallet under a different Turnkey parent organization. Its
active owner session must install the enclave Quorum public key and narrow
per-wallet policies in that child organization; the TVC application and private
Quorum key remain in the separate TVC organization.

`CreateWallet` is operator-only and accepts no wallet parameters.
It creates one unfunded 24-word Turnkey HD wallet with exactly one
Ed25519/Solana account at `m/44'/501'/0'/0'`; both wallet and account labels are
unique and deterministically derived from the authenticated request ID. It
returns no mnemonic. Before
bootstrap, an external provisioner independently re-queries the exact
wallet/account, installs per-wallet Turnkey policies, and signs a descriptor
granting only the browser's separate TVC key. The integrated wallet-kit demo
skips `CreateWallet` and binds directly to its authenticated embedded wallet.
Its existing owner session, rather than the unrelated TVC operator credential,
authorizes the child-org authority and policies before the localhost descriptor
provisioner signs the deterministic development profile. The operator-only
creation path remains for standalone acceptance tests.

`PrepareWallet` accepts only the authenticated recent blockhash and the exact
sealed bootstrap state. It constructs inside the enclave exactly one Ed25519
registry transaction and signs it through the pinned Turnkey account;
arbitrary transaction bytes are never accepted. `ShieldSol` constructs one
bounded public-to-private SOL deposit from that same account. The external
localhost faucet grants setup gas and, through a separate one-time action,
exactly 1 ZDEV. Its keys remain outside this image and outside TVC.

`BuildTransfer` accepts an authenticated amount, recipient, and typed asset.
SOL uses the reserved native asset. For SPL, the enclave derives and verifies
the canonical `SplAssetRegistry` PDA before syncing the wallet and constructing
the default-ring transfer. The faucet-backed ZDEV mint remains asset ID 14;
other registered SPL assets can be transferred when the wallet already owns a
private balance.

The derivation signature is kept only inside `SealedWalletStateV1`, encrypted
to the QOS Quorum encryption key. Expanded nullifier/viewing roles are rebuilt
and dropped per request. Turnkey API requests are stamped directly by the QOS
Quorum signing subkey; the image contains no Turnkey API private key.
The service remains stateless between calls: the relying client must carry and
durably checkpoint the opaque sealed state. A Turnkey Embedded Wallet session
does not replace that TVC/Zolana state store.

The binary links QOS 0.12.1, which is AGPL-3.0-only; this service is therefore
declared AGPL-3.0-only and is not published as a reusable crate.

Its runtime uses official `qos_core::handles::Handles` and `qos_p256` operations;
it does not put the QOS 0.12.1 runtime graph into Zolana's main workspace or
reimplement QOS private-key handling. `zolana-tvc-protocol` remains a path
dependency for the Zolana wire schemas, strict JSON, and canonical proof payload.

Run its tests from the repository root with:

```sh
cargo test --manifest-path apps/enclave-wallet/Cargo.toml --all-features --locked
```

Build the image from the repository root:

```sh
docker build \
  --platform linux/amd64 \
  --provenance=false \
  -f apps/enclave-wallet/Dockerfile \
  .
```

The build prints `SHA256=<hex>` for `/tvc_app`. That exact hex value is the
deployment's `expectedPivotDigest`; the final OCI reference must additionally
be pinned to its single-platform `@sha256:` manifest digest. Do not publish a
multi-platform index or a provenance-wrapped index as the deployment image.

## Local wallet harness

`Dockerfile.local` is a separate, deliberately unattested developer image. It
generates disposable QOS-compatible runtime keypairs and a disposable
in-process Ed25519 mock signer when the container starts. The local-only
`POST /dev/v1/bootstrap-ed25519` endpoint injects that signer through
`TurnkeyActivities` and exercises the real
`TurnkeyEd25519ShieldedKeypair::bootstrap` path. It returns public address
material only, explicitly labeled `local-unattested`.

This is not a Turnkey wallet, does not call Turnkey, has no Boot Proof, cannot
produce a `VerifiedConnection`, and loses the mock key when the container
stops. Never deploy this image or send funds to an address it returns.

Build and run it from the repository root:

```sh
docker build \
  --platform linux/amd64 \
  --provenance=false \
  -f apps/enclave-wallet/Dockerfile.local \
  -t zolana-tvc-enclave-wallet-local:dev \
  .

docker run --rm \
  --name zolana-tvc-enclave-wallet-local \
  -p 127.0.0.1:44020:44020 \
  zolana-tvc-enclave-wallet-local:dev
```

In another terminal:

```sh
curl --fail --silent --show-error \
  -H 'content-type: application/json' \
  --data '{"version":1}' \
  http://127.0.0.1:44020/dev/v1/bootstrap-ed25519
```

The production `Dockerfile` never enables `local-dev`, links the mock custody
implementation, or contains `/tvc_local`.
