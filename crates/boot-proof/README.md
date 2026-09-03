# zolana-tvc-boot-proof

Fetches the public AWS Nitro Boot Proof of a TVC replica from Turnkey, for a
relying party whose own Turnkey session cannot read the TVC organization. The
privacy-wallet demo runs it server-side behind `/api/tvc/boot-proof`; the
browser client verifies the returned proof against its independent pins.

```sh
zolana-tvc-boot-proof --organization-id <tvc-org> \
  --ephemeral-key <130-byte hex boot_proof_lookup_key> \
  --api-key-path <turnkey-api-key.json>
```

It is a standalone workspace with its own lockfile so the Turnkey client graph
stays out of the enclave build, and it is never linked into the enclave.
