# Documentation

Start with the repository [README](../README.md), then use the document that
matches the decision you are making:

| Document | Purpose |
| --- | --- |
| [Architecture](architecture.md) | Choose between the client-owned and enclave-owned privacy boundaries. |
| [Wallet flows](wallet-flows.md) | Follow set up, register, shield, transfer, and unshield across all three profiles. |
| [Keyholder profile](keyholder-profile.md) | Implemented middle profile: TVC holds privacy keys, reads are client-relayed, and the temporary devnet spend discloses its plaintext witness to a pinned prover. |
| [Security](security.md) | Understand what is verified, what remains visible, and why the project is development-only. |
| [Development](development.md) | Set up the toolchains and run repeatable Rust and TypeScript checks. |
| [Deployment](deployment.md) | Build and release each profile without mixing application identities. |

Profile-specific implementation notes remain beside each application:

- [Client-wallet architecture](../apps/client-wallet/ARCHITECTURE.md)
- [Enclave-wallet architecture](../apps/enclave-wallet/ARCHITECTURE.md)
- [Keyholder-wallet architecture](../apps/keyholder-wallet/ARCHITECTURE.md)
- [Turnkey keypair backend](../crates/keypair-turnkey/README.md)
- [Protocol crate](../crates/protocol/README.md)
- [Proof verifier](../crates/proof-verifier/README.md)
