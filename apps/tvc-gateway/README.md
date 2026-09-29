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

All paths are under `/v1/private-wallet`, and all take the caller's project
from gatekeeper.

| Method | Path          | Body                                        | Answer                     |
| ------ | ------------- | ------------------------------------------- | -------------------------- |
| POST   | `/session`    | the enclave's ping request                  | `{info, ping, bootProof}`  |
| POST   | `/enroll`     | an owner-signed enrollment                  | `{descriptor}`             |
| POST   | `/operations` | `{descriptor, request}`                     | `{response, bootProof}`    |

`GET /health` needs no credentials.

Errors are `{"error": "<Code>"}`. A non-success enclave answer is passed
through. Once a request has reached the enclave or Turnkey, failures are `424`,
never `5xx`, because gatekeeper re-sends 5xx responses.

### Session

The body is the enclave's `POST /v1/ping` request: a challenge encrypted to the
release's quorum key. The gateway sends it to the enclave with `GET /v1/info`,
and answers with both enclave answers and the Turnkey Boot Proof of the replica
that signed the ping. The client verifies all three; the gateway vouches for
none of them.

### Enrollment

The wallet owner signs, with the wallet's Ed25519 key through Turnkey:

```
"ZOLANA_TVC_WALLET_ENROLLMENT_V2\n" || hex(sha256(fields joined by "\n"))
```

where the fields are `parentOrganizationId`, `organizationId`, `walletName`,
`turnkeyWalletId`, `solanaAddress`, `clientPublicKey` and the decimal
`issuedAtMs`. `walletEnrollmentMessage` in `@zolana/tvc-wallet/protocol`
builds it.

`POST /enroll` with
`{parentOrganizationId, organizationId, walletName: "Solana Wallet", turnkeyWalletId, solanaAddress, clientPublicKey, issuedAtMs, ownerSignature}`.
The gateway checks:

- that `issuedAtMs` is at most 5 minutes old and at most 30 s ahead;
- the signature;
- that the Turnkey sub-org is named after the caller's project;
- that the wallet account has the claimed address.

It answers `{descriptor}`, signed with the provisioning key for that one client
key. Enrolling again answers the same descriptor.

### Operations

`request` is the enclave's `EncryptedRequest` without `wallet_grant`. The
gateway checks:

- that it signed the descriptor, and that its client key is not revoked;
- that the ciphertext is not a replay;
- that the descriptor's Turnkey sub-org is named after the caller's project.

It then adds a wallet grant, the protocol's `WalletGrant`
(`crates/protocol/README.md`), signed with the grant key for this descriptor
and project and valid for `wallet_grant.ttl_secs`. The enclave checks the grant
names the request's descriptor and client key. The answer is the enclave's
`EncryptedResponse` and the Boot Proof of the replica that answered.

To revoke a client key, add its `tvc-browser-p256-…` ID to
`wallet_grant.revoked_client_key_ids`. The gateway refuses its enrollments and
operations from the next deploy.

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
| `TVC_GATEWAY_WALLET_GRANT__PRIVATE_KEY`                           | Wallet-grant P-256 secret, hex. Must match `wallet_grant.expected_public_key`.            |
| `TVC_GATEWAY_ENCLAVE__REPLAY_REDIS_URL`                           | Optional. Redis for the shared replay guard, such as `rediss://host:6379/2`.              |
| `TVC_GATEWAY_TURNKEY__BOOT_PROOF_API_KEY__{PUBLIC,PRIVATE}_KEY`   | Turnkey API key in the TVC organization that can read Boot Proofs.                        |
| `TVC_GATEWAY_TURNKEY__WAAS_API_KEY__{PUBLIC,PRIVATE}_KEY`         | Turnkey API key in the Helius WaaS parent organization, with read access to its sub-orgs. |

`configs/release-policy.json` and `configs/release-authorities.json` hold the
signed release policy that descriptors are issued under, and the authority set
it must verify against. The service refuses to start if the policy does not
verify.

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

Runs `e2e/`, a vitest suite, on loopback. Its global setup (`e2e/stack.ts`)
starts:

- the local unattested testkit enclave (`zolana-tvc-privacy-wallet-local`), with fixed test keys and mock custody;
- a mock Turnkey answering the ownership and Boot Proof queries (`e2e/mock-turnkey.ts`);
- the gateway, with a release policy from `cargo run --example local_release_policy`.

The tests send the headers gatekeeper would add and drive a wallet through
the testkit client in gateway mode: enrollment, one session, Bootstrap and
TransactionKeys, and the refusals of stale, forged and foreign enrollments,
resent operations, other projects' wallets and descriptors this gateway did
not provision. CI runs it after `just ci`. Service logs go to a temporary
directory the run prints.

`fixtures/wallet-enrollment.json` is the enrollment message test vector that
both this crate and `walletEnrollmentMessage` in `@zolana/tvc-wallet` check.

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
