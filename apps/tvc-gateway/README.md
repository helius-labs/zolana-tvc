# tvc-gateway

Helius-hosted backend for the Zolana private embedded wallet. It sits behind
gatekeeper at `/v1/private-wallet/*` and gives any Helius customer the
private-wallet backend with only an API key. It fronts:

- the Zolana TVC enclave (`apps/privacy-wallet`),
- Turnkey (Boot Proofs and wallet ownership),

and holds the provisioning key that signs wallet descriptors. The Zolana
indexer and prover are gatekeeper's own `/v1/zolana/*` routes.

Devnet only: the enclave accepts `development` descriptors only.

## Request flow

```
client (browser or mobile, Helius API key)
  → helius-router → gatekeeper   (API key, domain ACL, rate limit, billing)
  → tvc-gateway                  (Authorization: gatekeeper origin secret,
                                  X-Helius-Project-Id: caller's project)
  → enclave / Turnkey
```

The gateway trusts `X-Helius-Project-Id` only on requests carrying
gatekeeper's origin `Authorization` value. Its listener must be reachable only
from gatekeeper.

## Endpoints

All paths are under `/v1/private-wallet`.

| Method | Path                                  | Auth         | Upstream                            |
| ------ | ------------------------------------- | ------------ | ----------------------------------- |
| GET    | `/info`                               | project      | enclave `GET /v1/info`              |
| POST   | `/ping`                               | project      | enclave `POST /v1/ping`             |
| POST   | `/operations`                         | wallet grant | enclave `POST /v1/operations`       |
| GET    | `/boot-proof/{ephemeralKey}`          | project      | Turnkey `get_boot_proof` (cached)   |
| GET    | `/policy`                             | project      | signed release policy               |
| POST   | `/enrollment-challenge`               | project      | none                                |
| POST   | `/provision-descriptor`               | project      | Turnkey whoami + wallet accounts    |
| POST   | `/wallet-grant`                       | project      | Turnkey whoami (cached)             |

`GET /health` needs no credentials.

Errors are `{"error": "<Code>"}`. Once a request has reached the enclave or
Turnkey, failures are `424`, never `5xx`, because gatekeeper
re-sends 5xx responses.

### Enrollment

1. `POST /enrollment-challenge` with
   `{parentOrganizationId, organizationId, walletName: "Solana Wallet", turnkeyWalletId, solanaAddress, clientPublicKey}`.
   The response is `{token, message}`. The token is bound to the caller's
   project and is valid for 5 minutes.
2. The wallet owner signs `message` (Ed25519, through Turnkey).
3. `POST /provision-descriptor` with `{token, ownerSignature}`. The gateway
   checks:
   - the signature;
   - that the Turnkey sub-org is named after the caller's project;
   - that the wallet account has the claimed address.

   It returns `{descriptor, walletGrant}`.

### Wallet grants

A wallet grant is the protocol's `WalletGrant` (`crates/protocol/README.md`):
signed with the grant key for one descriptor and client key, bound to the
caller's project, and valid for `wallet_grant.ttl_secs` (at most an hour).
`/operations` takes the enclave's `EncryptedRequest` with the grant in its
`wallet_grant` field and forwards it byte for byte. The gateway checks the
grant's signature, project, expiry and revocation. The enclave checks that it
names the request's descriptor and client key.

To renew a grant, `POST /wallet-grant` with `{descriptor, issuedAtMs, signature}`:

- `signature` is the raw 64-byte P-256 signature by the descriptor's client key over
  `"HELIUS_TVC_GATEWAY_WALLET_GRANT_RENEWAL_V1" || 0x00 || descriptor_digest || be_u64(issuedAtMs)`.
- `issuedAtMs` must be within 60 s of the gateway clock.

A WebCrypto or Secure Enclave ECDSA-SHA256 signature over that message is in
the expected form. `@zolana/tvc-wallet` builds the request: the browser
authorizer's `signWalletGrantRenewal`, or `signWalletGrantRenewal` in
`@zolana/tvc-wallet/protocol` for a caller-held key.

To revoke a client key, add its `tvc-browser-p256-…` ID to
`wallet_grant.revoked_client_key_ids`. The gateway then issues, renews and
accepts no grant for it. The enclave refuses its operations once its last grant
expires, within `wallet_grant.ttl_secs`.

### Limits

- **In-flight enclave calls:** at most `enclave.max_in_flight_per_project` per project (`429`).
- **Turnkey calls:** at most 32 at once across all projects (`429`); both Turnkey keys are shared.
- **Replays:** an `/operations` ciphertext repeated within `enclave.replay_window_secs` gets `409`, however its JSON is encoded. With `enclave.replay_redis_url` set, every task shares the guard through Redis (`SET NX EX`) and it survives restarts; an unreachable Redis refuses the request with `424`. Without it, each process keeps its own.
- **Body size:** `enclave.max_body_bytes`.

## Configuration

`configs/config.yaml` holds the non-secret values. Secrets come from `TVC_GATEWAY_*`
environment variables, with nested fields joined by `__`:

| Variable                                                          | Value                                                                                     |
| ----------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| `TVC_GATEWAY_ORIGIN_AUTH_HEADER`                                  | The `Authorization` value gatekeeper sends, 32 bytes or more. Always required.            |
| `TVC_GATEWAY_PROVISIONING__PRIVATE_KEY`                           | Provisioning P-256 secret, hex. Must match `provisioning.expected_public_key`.            |
| `TVC_GATEWAY_PROVISIONING__ENROLLMENT_SECRET`                     | Enrollment HMAC key, 32 bytes or more.                                                    |
| `TVC_GATEWAY_WALLET_GRANT__PRIVATE_KEY`                           | Wallet-grant P-256 secret, hex. Must match `wallet_grant.expected_public_key`.            |
| `TVC_GATEWAY_ENCLAVE__REPLAY_REDIS_URL`                           | Optional. Redis for the shared replay guard, such as `rediss://host:6379/2`.              |
| `TVC_GATEWAY_TURNKEY__BOOT_PROOF_API_KEY__{PUBLIC,PRIVATE}_KEY`   | Turnkey API key in the TVC organization that can read Boot Proofs.                        |
| `TVC_GATEWAY_TURNKEY__WAAS_API_KEY__{PUBLIC,PRIVATE}_KEY`         | Turnkey API key in the Helius WaaS parent organization, with read access to its sub-orgs. |

`configs/release-policy.json` and `configs/release-authorities.json` hold the
signed release policy clients pin, and the authority set it must verify against.
The service refuses to start if the policy does not verify.

**When a new enclave release ships:** `scripts/release.mjs pins` rewrites both
files; publish a new image and redeploy.

## Development

The crate is outside the root workspace, like `crates/boot-proof`, so the
Turnkey client and server graph stay out of the enclave build. `just fmt`,
`just lint` and `just test` cover it. Directly:

```sh
cargo clippy --manifest-path apps/tvc-gateway/Cargo.toml --all-targets --locked -- -D warnings
cargo test --manifest-path apps/tvc-gateway/Cargo.toml --all-targets --locked
```

To run it, from `apps/tvc-gateway`:

```sh
TVC_GATEWAY_...=... cargo run -- configs/config.yaml
```

### Local end to end

```sh
just gateway-e2e
```

Runs everything on loopback:

- the local unattested testkit enclave (`zolana-tvc-privacy-wallet-local`), with fixed test keys and mock custody;
- a mock Turnkey answering the ownership queries (`scripts/local-e2e/mock-turnkey.mjs`);
- the gateway, with a release policy from `cargo run --example local_release_policy`;
- `scripts/local-e2e/driver.mjs`, which sends the headers gatekeeper would add
  and drives a wallet through enrollment, Bootstrap, an operation, grant
  renewal, and the replay, wrong-project, missing-grant and forged-renewal
  refusals.

It needs node 24 or newer. `PROVISIONING_KEY=<other 32-byte hex>` or
`GRANT_KEY=<other 32-byte hex>` on `apps/tvc-gateway/scripts/local-e2e/run.sh`
makes the gateway sign descriptors or grants with a key the enclave does not
trust, so the run fails at Bootstrap.

## Deployment

The service runs on AWS as one ECS Fargate task in the zolnet devnet stack
(`helius-labs/zolana-infra`, `infra/modules/zolnet/ecs_tvc_gateway.tf`), behind
that stack's ALB and a CloudFront distribution of its own.

1. Run the `publish-tvc-gateway-image` workflow. It pushes to the zolnet ECR
   repository `zolnet-tvc-gateway`, and its summary prints the `tvc_gateway_image`
   digest reference.
2. Pin that reference in the zolana-infra env's `terraform.tfvars` with
   `enable_tvc_gateway = true`, then deploy the env.
3. Populate the `zolnet-<env>/tvc-gateway` secret, as described in zolana-infra's
   `infra/README.md`.

The container needs `TVC_GATEWAY_LISTEN=0.0.0.0:8940`, since the shipped config
listens on loopback, and `TVC_GATEWAY_STAGE=prod` for JSON logs. The zolana-infra
task definition sets both. The enclave timeout is 55s, under CloudFront's 60s
origin read timeout.

## Metrics

statsd, prefix `tvc_gateway`:

- `request.latency`, tagged by `route` and `status`.
- `upstream.latency`, tagged by `target` and `status`.
- `upstream.failed`.
- `turnkey.rejected` and `turnkey.failed`, tagged by `call`.
- `ownership.rejected`, tagged by `reason`.
- `enclave.in_flight_rejected`.
- `enclave.replay_rejected`.
- `origin_auth_rejected`.
- `boot_proof.cache_hit`.
