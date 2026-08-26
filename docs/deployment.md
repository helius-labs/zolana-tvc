# Deployment

The production-shaped application is `apps/privacy-wallet`. It must have its
own Turnkey TVC application, Quorum key, OCI image digest, release policy,
wallet descriptor, and review line.

## Image

```sh
just image-privacy-wallet
```

The image must be a single-platform `linux/amd64` manifest pinned by
`@sha256:`. Record both the OCI manifest digest and the printed SHA-256 digest
of `/tvc_app`; the latter becomes `expectedPivotDigest`.

Do not deploy the local harness image. It has no AWS Nitro Boot Proof and
includes a development-only bootstrap route.

## TVC application

1. Create a dedicated app with `tvc --non-interactive --message-format json`.
2. Create a dedicated Quorum key; do not seal wallet state with Turnkey's demo
   shared Quorum key.
3. Configure public HTTP/1 ingress.
4. Configure only the fixed egress destinations required by the app: Turnkey,
   the pinned indexer/RPC, and the pinned development prover.
5. Create and approve a deployment pinned to the OCI and pivot digests.

Before submitting a descriptor, validate it locally:

```sh
just deploy-preflight apps/privacy-wallet/deploy/privacy-wallet-v5.deployment.json
```

The committed live descriptor retains release ID `keyholder-v5` because release
identity is signed deployment data, not branding. A future deployment can use a
privacy-wallet release ID after independently signing its new policy.

## Client trust material

Publish `ReleasePolicyV1` separately from `/v1/info`, sign it with the pinned
release-authority set, and configure the client with those signatures and
authority public keys. Provision each wallet descriptor out of band with the
browser client grant and the exact Turnkey organization, wallet account, service
user, API key, and expected Ed25519 public key.

Deployment is not complete until the client verifies the release, QOS ping,
Boot Proof, and a descriptor-bound bootstrap without bypass flags.
