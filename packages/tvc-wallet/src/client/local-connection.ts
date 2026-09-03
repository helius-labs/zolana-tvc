import {
  API_VERSION,
  TVC_APP_PROOF_TYPE,
} from "../protocol/constants.js";
import { TvcError } from "../protocol/error.js";
import type { OperationKind } from "../protocol/types.js";
import {
  createVerifiedConnection,
  fetchQosPingProof,
  fetchServiceInfo,
  type ConnectedTvcRuntime,
} from "./connection.js";
import { createDefaultTransport, type TvcTransport } from "./transport.js";

export type LocalUnattestedConnectionConfig = {
  readonly endpoint: URL;
  readonly expectedReleaseId: string;
  readonly expectedSecurityDomainId: string;
  readonly expectedManifestDigest: string;
  readonly expectedExecutableDigest: string;
  readonly expectedQuorumKeyId: string;
  readonly expectedQuorumPublicKey: string;
  readonly expectedEphemeralPublicKey: string;
  readonly expectedOperations: readonly OperationKind[];
  readonly nowMs?: () => bigint;
  readonly transport?: TvcTransport;
};

/** Internal connection path reachable only from the package's testkit entry. */
export async function connectLocalUnattestedTvc(
  config: LocalUnattestedConnectionConfig,
): Promise<ConnectedTvcRuntime> {
  if (
    config.endpoint.protocol !== "http:" ||
    !["127.0.0.1", "localhost", "[::1]"].includes(config.endpoint.hostname)
  ) {
    throw new TvcError("DiscoveryUntrusted", "local testkit must use a loopback HTTP endpoint");
  }
  const transport = config.transport ?? createDefaultTransport();
  const info = await fetchServiceInfo(config.endpoint, transport);
  if (
    info.version !== API_VERSION ||
    info.environment !== "development" ||
    info.release_id !== config.expectedReleaseId ||
    info.security_domain_id !== config.expectedSecurityDomainId ||
    info.manifest_digest !== config.expectedManifestDigest ||
    info.executable_digest !== config.expectedExecutableDigest ||
    info.quorum_key_id !== config.expectedQuorumKeyId ||
    info.quorum_key_epoch !== "1" ||
    info.proof_type !== TVC_APP_PROOF_TYPE ||
    info.quorum_public_key !== config.expectedQuorumPublicKey ||
    info.ephemeral_public_key !== config.expectedEphemeralPublicKey ||
    info.boot_proof_lookup_key !== config.expectedEphemeralPublicKey ||
    info.supported_operations.length !== config.expectedOperations.length ||
    config.expectedOperations.some(
      (operation, index) => info.supported_operations[index] !== operation,
    )
  ) {
    throw new TvcError("DiscoveryUntrusted", "local testkit identity does not match");
  }

  const appProof = await fetchQosPingProof(config.endpoint, info, transport);
  if (appProof.publicKey !== config.expectedEphemeralPublicKey) {
    throw new TvcError("DiscoveryUntrusted", "local ping used another key");
  }
  const nowMs = config.nowMs ?? (() => BigInt(Date.now()));
  return {
    connection: createVerifiedConnection(info.release_id),
    endpoint: config.endpoint,
    info,
    transport,
    acceptedManifestDigests: [config.expectedManifestDigest],
    releasePolicyValidFromMs: 0n,
    releasePolicyExpiresAtMs: 0xffff_ffff_ffff_ffffn,
    nowMs,
    trustVerifier: Object.freeze({
      async verifyOperationAppProof(proof) {
        if (proof.publicKey !== config.expectedEphemeralPublicKey) {
          throw new TvcError("TurnkeyEvidenceInvalid");
        }
      },
      verifyCustodyProofs(proofs) {
        if (proofs.length !== 0) throw new TvcError("TurnkeyEvidenceInvalid");
      },
    }),
  };
}
