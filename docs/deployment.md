# Deployment

Deploy the client-owned and enclave-owned profiles as different products. A TVC
application identity belongs to exactly one profile and one independently
reviewed release line.

## Release inputs

Each release needs:

- a dedicated Turnkey TVC application and non-demo Quorum key;
- an independently reviewed QOS manifest and release policy;
- a single-platform `linux/amd64` OCI image pinned by `@sha256`;
- the SHA-256 digest of the exact `/tvc_app` pivot binary;
- profile-specific runtime arguments and egress policy;
- independent release/provisioning authorities outside the enclave.

Do not deploy one profile over the other's app, reuse its Quorum private state,
or treat a mutable image tag as a release identity.

## Build

From the repository root:

```sh
just image-client-wallet
# or
just image-enclave-wallet
```

The Docker build is pinned to `linux/amd64`, disables provenance wrapping, uses
the workspace's checked-in lockfile, and prints the pivot binary SHA-256. Push
the resulting single-platform image to the chosen OCI repository and record its
manifest digest separately from the pivot digest.

## Operator tooling

Turnkey publishes [`tvc`](https://crates.io/crates/tvc), the official CLI for
TVC app, deployment, and Quorum-key lifecycle
([`tkhq/rust-sdk`](https://github.com/tkhq/rust-sdk)). It covers steps 4 and 6
below; prefer it over bespoke tooling for those steps.

```sh
cargo install tvc

tvc app init --name <profile> --output app.json     # then fill in quorum key, operators
tvc app create --config-file app.json
tvc deploy init --output deploy.json                # then fill in appId, pinned image
tvc deploy create --config-file deploy.json
tvc deploy approve --deploy-id <UUID> --operator-id <UUID>
```

`deploy approve` fetches the manifest and `manifest_id` itself, validates the
manifest set, signs `VersionedManifest::manifest_hash()` with the operator key,
and reports whether the approval quorum is reached. `--approval-out` writes the
signed approval for an offline operator to submit separately.

For a Quorum key that Turnkey never holds in full, use the local flow
(`tvc keys generate-local-quorum-key`) rather than the hosted one
(`tvc keys create-quorum-key`). `tvc keys re-encrypt-local-share` is the
share-rotation primitive.

Three env vars authenticate the CLI without touching disk, for CI use:
`TVC_ORG_ID`, `TVC_API_KEY_PUBLIC`, `TVC_API_KEY_PRIVATE`.

This repository's own operator binaries stay separate and are not replaced by
the CLI: `zolana-tvc-provision` binds Zolana signing policies to the Turnkey
organization, and `zolana-tvc-e2e` plus the `proof-verifier` binary are
relying-party verification. The CLI does not create users, policies, or wallets.

## Acceptance sequence

`just deploy-check <profile> <descriptor>` runs steps 1 and the mechanical half
of step 4 together. It verifies that the image is pinned by digest rather than a
mutable tag, that debug mode is off, that `qosVersion` matches the profile's
`qos_core` pin, and that the release id, pivot digest, and app id are not reused
by any other descriptor. Add `--pivot-digest <hex>` from the image build to
confirm the descriptor describes the binary you actually built. It signs and
publishes nothing.

1. Run `just ci` from a clean commit.
2. Review the selected profile's dependency lock and runtime permissions.
3. Build and push the immutable image.
4. Create a new deployment descriptor with the OCI and pivot digests
   (`tvc deploy init` / `tvc deploy create`).
5. Independently sign the release policy. This is a Zolana release policy and is
   separate from the QOS manifest approval that `tvc deploy approve` signs.
6. Deploy to the matching TVC application without reusing the other profile's
   identity (`tvc deploy approve`).
7. Verify `/health`, then verify release policy, `/v1/info`, QOS ping, App Proof,
   and matching Boot Proof from a relying client.
8. Exercise only disposable devnet funds and the typed acceptance flow.

`/health` returning `{"status":"Healthy"}` proves readiness, not authenticity.
`/v1/info` is also untrusted until bound to the verified release.

## Egress

The client-wallet application needs Turnkey egress for bootstrap and bounded
authorization, and nothing else: its source contains no indexer, prover, Solana
RPC, or wallet-sync call at all, so its egress policy has exactly one
destination. The enclave-wallet application additionally needs its explicitly
pinned development indexer/RPC/prover origins. Enable only the destinations
required by the chosen profile and pin them in its egress policy.

## Historical descriptors

Versioned full-profile descriptors under `apps/enclave-wallet/deploy` are
provenance records for earlier images and intentionally retain their original
OCI names. Do not edit or reuse them. Create a new descriptor for every new
image or profile.

The normative deployment and verification requirements remain in
[`spec.md`](spec.md).
