# Documentation

Start with the repository [README](../README.md), then use the document that
matches the decision you are making:

| Document | Purpose |
| --- | --- |
| [Architecture](architecture.md) | Choose between the client-owned and enclave-owned privacy boundaries. |
| [Wallet flows](wallet-flows.md) | Follow set up, register, shield, transfer, and unshield step by step in both profiles. |
| [Keyholder profile](keyholder-profile.md) | Design proposal: TVC holds the privacy keys and answers key-dependent questions; the client does all I/O. Not implemented. |
| [Security](security.md) | Understand what is verified, what remains visible, and why the project is development-only. |
| [Development](development.md) | Set up the toolchains and run repeatable Rust and TypeScript checks. |
| [Deployment](deployment.md) | Build and release either profile without mixing its identity with the other. |

Profile-specific implementation notes remain beside each application:

- [Client-wallet architecture](../apps/client-wallet/ARCHITECTURE.md)
- [Enclave-wallet architecture](../apps/enclave-wallet/ARCHITECTURE.md)
- [Turnkey keypair backend](../crates/keypair-turnkey/README.md)
- [Protocol crate](../crates/protocol/README.md)
- [Proof verifier](../crates/proof-verifier/README.md)