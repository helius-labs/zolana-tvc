# Security

## Enforced properties

- Unknown and duplicate JSON fields are rejected; wire integers and binary
  encodings are canonical.
- Release policy is verified before discovery. Discovery, QOS App Proof, and
  AWS Nitro Boot Proof must describe the same release and boot.
- Client requests are signed with a non-exportable browser P-256 key and bound
  to release, descriptor, operation, expiration, response key, and checkpoint.
- Results are QOS-encrypted and their App Proof binds request digest, encrypted
  result digest, operation, and state digest.
- The derivation seed is never returned. State is sealed to the wallet
  descriptor and Quorum epoch.
- Signing is limited to the fixed bootstrap message and the exact transaction
  TVC prepared, proved, and sealed into a short-lived authorization capsule. A
  separate finalize request must return that exact capsule/transaction pair.
  No generic signing or wallet-export API exists.
- Production descriptors and mainnet are rejected.
- Callers cannot select a network origin. The measured executable pins Turnkey,
  devnet RPC, indexer, and prover destinations.

## Trusted parties

Turnkey can reproduce the deterministic bootstrap seed and signs final
transactions. The pinned indexer and RPC affect availability and supplied chain
data. The current external prover receives the complete plaintext witness,
including `nullifier_secret`, and can compute wallet nullifiers. It is therefore
inside the PoC privacy trust boundary.

The live QOS application has transparent egress enabled. Destination pinning is
currently enforced by the measured application code, not by a QOS per-host
network allowlist. The default development indexer/prover origin also uses
plain HTTP. See [TVC egress](egress.md).

Turnkey policy evidence remains `CryptographicallyValidButUnbound`: the
currently available proof does not bind `decisionContextDigest`, so the code
never labels it `Verified`.

## Remaining work before production

- Move proving into the enclave or use an independently attested prover with a
  confidential channel bound to the prover attestation.
- Enforce the compiled destination set with a separate VPC, firewall, or
  audited egress proxy.
- Replace the development release-authority threshold and distribution process
  with the production release system.
- Complete independent security review of descriptor provisioning, recovery,
  browser persistence, wallet synchronization, and transaction policies.
- Add operational monitoring, incident response, key rotation, rollback, and
  revocation procedures.

Until these are complete, use only disposable devnet funds.
