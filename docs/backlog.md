# Backlog

## Dependency maintenance

- Upgrade the Zolana SDK from the Agave 4.1 client/runtime graph to the latest
  stable Agave 4.2.x line. Do this in Zolana first, run its hermetic and SDK
  suites, then repin `zolana-tvc` and `wallet-kit` to the merged commit. Do not
  adopt the Agave 4.3 beta line as part of this update.

## Production hardening

- Replace the plaintext external-prover witness path with an attested,
  confidential prover boundary or move proving into the enclave.
- Define production release distribution, monitoring, recovery, rotation, and
  incident-response procedures.
