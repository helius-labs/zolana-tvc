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
- This profile returns the viewing and nullifier secrets to the client, so it
  can build the default rail. The client is therefore a full view and spend
  authority for the default ring, and this is devnet only.
- Signing is limited to the fixed bootstrap message, a transaction the
  application built itself, and one validated default-ring shape from the
  client. No generic signing or wallet-export API exists.
- Production descriptors and mainnet are rejected.

## Trusted parties

Turnkey can reproduce the deterministic bootstrap seed and signs final
transactions. The pinned indexer and RPC affect availability and supplied chain
data. The current external prover receives the complete plaintext witness,
including `nullifier_secret`, and can compute wallet nullifiers. It is therefore
inside the PoC privacy trust boundary.

Turnkey policy evidence remains `CryptographicallyValidButUnbound`: the
currently available proof does not bind `decisionContextDigest`, so the code
never labels it `Verified`.

## Remaining work before production

- Move proving into the enclave or use an independently attested prover with a
  confidential channel bound to the prover attestation.
- Replace the development release-authority threshold and distribution process
  with the production release system.
- Complete independent security review of descriptor provisioning, recovery,
  browser persistence, wallet synchronization, and transaction policies.
- Add operational monitoring, incident response, key rotation, rollback, and
  revocation procedures.

Until these are complete, use only disposable devnet funds.
