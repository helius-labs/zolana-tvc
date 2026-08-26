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

The privacy-wallet demo uses `boot-proof` and `wallet-account`. API keys remain
server-side and command output never contains private key material. Descriptor
provisioning is application-owned and is not a generic command in this crate.

See the [privacy-wallet architecture](../../apps/privacy-wallet/ARCHITECTURE.md).
