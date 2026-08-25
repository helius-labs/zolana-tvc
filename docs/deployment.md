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

## Acceptance sequence

1. Run `just ci` from a clean commit.
2. Review the selected profile's dependency lock and runtime permissions.
3. Build and push the immutable image.
4. Create a new deployment descriptor with the OCI and pivot digests.
5. Independently sign the release policy.
6. Deploy to the matching TVC application without reusing the other profile's
   identity.
7. Verify `/health`, then verify release policy, `/v1/info`, QOS ping, App Proof,
   and matching Boot Proof from a relying client.
8. Exercise only disposable devnet funds and the typed acceptance flow.

`/health` returning `{"status":"Healthy"}` proves readiness, not authenticity.
`/v1/info` is also untrusted until bound to the verified release.

## Egress

The client-wallet application needs Turnkey egress for bootstrap and bounded
authorization, but does not call the indexer, prover, Solana RPC, or wallet-sync
services. The enclave-wallet application additionally needs its explicitly
pinned development indexer/RPC/prover origins. Enable only the destinations
required by the chosen profile and pin them in its egress policy.

## Historical descriptors

Versioned full-profile descriptors under `apps/enclave-wallet/deploy` are
provenance records for earlier images and intentionally retain their original
OCI names. Do not edit or reuse them. Create a new descriptor for every new
image or profile.

The normative deployment and verification requirements remain in
[`TVC_SPEC.md`](../spec/TVC_SPEC.md).
