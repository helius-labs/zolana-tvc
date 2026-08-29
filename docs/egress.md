# TVC egress

The privacy-wallet application needs outbound network access for Turnkey,
devnet chain reads, wallet synchronization, and proof generation. Egress is
enabled for the live TVC application. QOS currently exposes that capability as
a transparent outbound bridge, not as a destination allowlist.

The measured application binary therefore provides the current destination
boundary: every origin below is compiled into the executable, and no operation
accepts an RPC, indexer, prover, callback, or generic fetch URL from its caller.
Changing an origin changes the executable digest and requires a new reviewed
release. This is useful application-level pinning, but it is not a substitute
for a network firewall if the application is compromised.

## Destinations

| Destination | Transport | Used by | Data sent |
| --- | --- | --- | --- |
| `api.turnkey.com` | HTTPS | `BootstrapKeyholder`; `AuthorizeSpend::Finalize` | The fixed bootstrap signing request or the exact validated Solana transaction, plus descriptor-bound Turnkey identifiers and activity polling. |
| `api.devnet.solana.com` | HTTPS-only client | `AuthorizeSpend::Prepare`; generic `AuthorizeSpend::Finalize` | Public account, registry, tree, lookup-table, slot, and blockhash reads. TVC does not submit the final transaction. |
| `zolnet-devnet-1779374825.eu-north-1.elb.amazonaws.com` | Plain HTTP | Built-in and generic `AuthorizeSpend::Prepare` | Photon/indexer queries and proofs; default-ring and generic SPP prover witnesses. |
| `d30sgubc9yxiri.cloudfront.net` | HTTPS | Custom-ring `AuthorizeSpend::Prepare` | The custom-ring proof witness and public inputs. |

The default development origin is passed to the Zolana client as both its
indexer and default prover base. A custom-ring spend still synchronizes through
that indexer, then uses the separately pinned CloudFront prover for its ring
proofs.

DNS and the QOS host bridge are transport machinery, not caller-selectable
application destinations. A caller-provided ring or ecosystem program ID is a
Solana address and causes only reads through the pinned Solana RPC.

## Operation matrix

| Request | Application egress |
| --- | --- |
| `GET /health`, `GET /v1/info`, `POST /v1/ping` | None |
| `BootstrapKeyholder` | Turnkey |
| `DeriveViewTags` | None |
| `DecryptUtxos` | None; the browser relays ciphertexts from the indexer |
| Built-in `AuthorizeSpend::Prepare` | Solana RPC, Photon/indexer, default or custom-ring prover |
| Built-in `AuthorizeSpend::Finalize` | Turnkey |
| Generic SPP `AuthorizeSpend::Prepare` | Solana RPC, Photon/indexer, generic SPP prover |
| Generic SPP `AuthorizeSpend::Finalize` | Solana RPC for program/account/LUT validation and a fresh blockhash, then Turnkey |

Public registration, shielding, transaction submission, and ordinary balance
queries are browser-owned flows and are not TVC application egress.

## Sensitive disclosures

Turnkey can reproduce the deterministic bootstrap signature used as the
privacy derivation seed. The indexer can link the tags and commitments queried
during an enclave-owned spend. Most importantly, the current prover receives a
plaintext witness containing private inputs, outputs, amounts, and the
long-lived `nullifier_secret`.

Local Groth16 verification prevents an invalid prover response from authorizing
a different transition. It does not make the witness confidential. The plain
HTTP default origin additionally exposes the witness to the network path.

## Production requirements

Before accepting production funds:

1. move proof generation into the wallet enclave, or use an independently
   attested prover over a confidential channel bound to that attestation;
2. replace the plain-HTTP development origin;
3. enforce the same destination set outside the application with a VPC,
   firewall, or audited egress proxy; and
4. monitor and version every egress-policy change as release material.

Merely adding TLS is not sufficient: it protects the transport while leaving
the prover process able to read the long-lived secret.
