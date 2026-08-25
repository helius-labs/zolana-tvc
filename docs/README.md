# Documentation

Start with the repository [README](../README.md), then use the document that
matches the decision you are making:

| Document | Purpose |
| --- | --- |
| [Architecture](architecture.md) | Choose between the client-owned and enclave-owned privacy boundaries. |
| [Security](security.md) | Understand what is verified, what remains visible, and why the project is development-only. |
| [Development](development.md) | Set up the sibling repositories and run repeatable checks. |
| [Deployment](deployment.md) | Build and release either profile without mixing its identity with the other. |

Profile-specific implementation notes remain beside each application:

- [Client-wallet architecture](../apps/client-wallet/ARCHITECTURE.md)
- [Enclave-wallet architecture](../apps/enclave-wallet/ARCHITECTURE.md)
- [Turnkey keypair backend](../crates/keypair-turnkey/README.md)
- [Protocol crate](../crates/protocol/README.md)
- [Proof verifier](../crates/proof-verifier/README.md)

The normative protocol is [TVC_SPEC.md](../spec/TVC_SPEC.md). Its
[Russian translation](../spec/TVC_SPEC_RU.md) is explanatory; English wins for
byte and field formats. When an overview and the specification disagree, the
specification is authoritative.
