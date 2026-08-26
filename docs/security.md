# Security model

This repository narrows and attests private-wallet operations; it does not
replace either Turnkey custody or Zolana's on-chain privacy protocol.

## Enforced invariants

- Production descriptors and mainnet environments are rejected.
- No public generic `signMessage`, `signTransaction`, wallet export, or raw
  `ShieldedKeypairTrait` network surface exists.
- Client authorization uses a domain-separated SHA-256 digest and P-256
  prehash signing. Wire signatures are 64-byte raw, low-S `r || s` values.
- QOS payload encryption follows the pinned QOS P-256 envelope exactly; it is
  not substituted with a different ECIES or HPKE construction.
- A release policy is verified before `/v1/info` is trusted.
- Operation results are accepted only after App Proof and matching AWS Nitro
  Boot Proof verification.
- The three application profiles never share a TVC app, Quorum key, manifest,
  release policy, or deployment image.
- Health responses contain readiness only and use the exact
  `{"status":"Healthy"}` wire shape.

The canonical implementation and content-addressed test fixtures live in
[`crates/protocol`](../crates/protocol). The host-side verifier uses the pinned
official [`turnkey_proofs`](https://crates.io/crates/turnkey_proofs) crate.

## Trust boundaries

Turnkey remains the custodian of the wallet's Ed25519 private key and evaluates
the installed signing policies. TVC's QOS runtime supplies distinct Quorum
encryption/signing material and per-replica Ephemeral proof keys. Do not swap
their encryption and signing roles.

The client-wallet profile trusts the authenticated client with derived privacy
material, wallet state, and proof inputs. The keyholder and enclave-wallet
profiles keep raw privacy keys in TVC. Every current spend path discloses proof
inputs to the external development prover; keyholder and enclave-wallet also
disclose the long-lived `nullifier_secret` contained in the witness.

## Known limitations

- Turnkey policy evidence is only `CryptographicallyValidButUnbound` because
  `decisionContextDigest` cannot be cryptographically bound to the exact
  activity. It must never be reported as `Verified`.
- The external development prover is not a confidential proving boundary.
- Production release distribution, revocation, and threshold governance are
  not implemented.
- Cross-device state recovery, Quorum rotation, replay coordination, and
  bootstrap-policy revocation are incomplete. Turnkey's official `tvc` CLI
  provides the share-rotation primitive (`keys re-encrypt-local-share`); it is
  not yet wired into a reviewed rotation procedure here.
- The lightweight TypeScript path still needs independent browser-side
  Groth16 verification before production authorization.

The complete production acceptance gates are normative in
[`spec.md`](spec.md).

## Secret handling

Never commit Turnkey API private keys, `operator.json`, `.env` files, Quorum
private material, release/provisioning private keys, or wallet checkpoints.
Deployment descriptors may contain public identifiers and public keys, but a
new deployment must be reviewed independently and pinned by digest.
