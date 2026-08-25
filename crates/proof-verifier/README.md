# Zolana TVC Proof Verifier

Host-side relying-party utility around the pinned official
`turnkey_proofs = 0.14.0` crate. It fetches every App Proof for a Turnkey
activity, fetches the matching Boot Proof, and verifies the App Proof
signature, AWS Nitro certificate/attestation, QOS manifest approvals and
hashes, live PCR0-3 commitments, and Ephemeral-key binding.

It is a host-side workspace crate and must not be linked into the TVC
enclave that creates an App Proof. Turnkey policy evidence remains
`CryptographicallyValidButUnbound` until Turnkey publishes a signed binding
from the policy outcome to the exact activity/intent.

The main `zolana-tvc-proof-verifier` binary provides four narrow commands:

- `boot-proof` fetches public Boot Proof material for the exact Ephemeral key;
  the TypeScript client performs verification against its independent pins.
- `activity` verifies every App Proof for one Turnkey activity with the official
  verifier.
- `wallet-account` validates the public binding of one non-exported Solana HD
  wallet account before descriptor provisioning.
- `inspect-wallet` reads only the public identity of an interrupted
  operator-created wallet.

The lightweight browser demo uses `boot-proof` and `wallet-account`. API keys
remain server-side and command output never contains private key material.

`zolana-tvc-provision` is an operator helper for development users, credentials,
and exact per-wallet policies. `zolana-tvc-e2e` preserves the older full-enclave
acceptance harness, including its crash-safe local journal; it is not part of
the lightweight client-wallet flow described in
[`../../apps/client-wallet/ARCHITECTURE.md`](../../apps/client-wallet/ARCHITECTURE.md).
