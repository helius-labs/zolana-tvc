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
4. Enable egress. QOS currently provides a transparent outbound bridge rather
   than a destination allowlist; the application binary pins Turnkey, devnet
   RPC, indexer, and prover origins. Add an external VPC/firewall/proxy allowlist
   before treating this as a production boundary. See [TVC egress](egress.md).
5. Create and approve a deployment pinned to the OCI and pivot digests.
6. Provision every hosted share-set member with `tvc deploy provision`, wait
   for the deployment replicas to become healthy, then make it live with
   `tvc app set-live-deploy`.

Before submitting a descriptor, validate it locally:

```sh
just deploy-preflight apps/privacy-wallet/deploy/<release>.deployment.json
```

The release ID is immutable signed deployment data, not product branding. Use a
new ID for every executable or protocol change; never reuse a policy authority
set for a replacement release.

## Client trust material

Publish `ReleasePolicyV1` separately from `/v1/info`, sign it with the pinned
release-authority set, and configure the client with those signatures and
authority public keys.

Write the policy as JSON in the camelCase shape the client pins, then sign it
with a one-time authority key:

```sh
cargo run -p zolana-tvc-protocol --example sign-release-policy \
    -- policy.json <release-id>-<yyyy-mm>
```

It prints the two objects the client needs and nothing else: the private half
is generated, used once, and discarded. That is the property, not an
inconvenience -- a policy cannot be quietly re-signed later, because re-signing
requires a new authority set, and a new authority set is a change every client
must be updated to accept. It follows that the digests must be right before
signing: `acceptedExecutableDigests` is the printed `/tvc_app` digest, and
`acceptedManifestDigests` is only readable from the deployment once it is live.
Sign after the deployment answers `/v1/info`, not before. Provision each wallet descriptor out of band with the
browser client grant and the exact Turnkey organization, wallet account, service
user, API key, and expected Ed25519 public key.

## Two credentials, not one

The relying party holds two Turnkey credentials, and they rotate on different
clocks.

`TVC_PROVISIONING_KEY_JSON` signs wallet descriptors. Its public half is pinned
in the application image, so replacing it means building and approving a new
release. Treat it as release material, not as a service secret.

`TVC_TURNKEY_API_KEY_JSON` reads Turnkey: Boot Proofs, activities, wallet
accounts. Nothing is pinned to it, so it can be replaced whenever a deployment
needs its own or an old one should stop working.

A deployment that sets only the first still works -- the reader falls back to
it -- but then the read credential cannot be rotated without a release, which
is the coupling worth avoiding.

Deployment is not complete until the client verifies the release, QOS ping,
Boot Proof, and a descriptor-bound bootstrap without bypass flags.
