/**
 * Explicitly unsafe local TVC testkit.
 *
 * This entrypoint preserves the encrypted operation protocol and all response
 * binding checks, but replaces Nitro and Turnkey evidence with pinned local
 * process keys. It accepts loopback HTTP only and must never be used for funds.
 */
import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha256";
import localTestkit from "../../../fixtures/local-testkit-v1.json";

import { createLocalTvcSession } from "./client/local-session.js";
import type { TvcTransport } from "./client/transport.js";
import { createTvcOperationAuthorizer } from "./platform/authorizer.js";
import {
  clientKeyIdFor,
  descriptorDigestFromWallet,
} from "./protocol/digest.js";
import { decodeLowerHex, encodeLowerHex } from "./protocol/hex.js";
import type { OperationKind, WalletDescriptorV1 } from "./protocol/types.js";
import { buildTvcWalletClient } from "./keyholder/client-core.js";
import type { TvcWalletClient } from "./keyholder/index.js";

const te = new TextEncoder();
if (localTestkit.version !== 1) throw new Error("UnsupportedLocalTestkitFixture");
const LOCAL_PROVISIONING_SECRET = decodeLowerHex(localTestkit.provisioningPrivateKeyHex);
const LOCAL_CLIENT_SECRET = decodeLowerHex(localTestkit.clientPrivateKeyHex);
const digestLabel = (label: string) => encodeLowerHex(sha256(te.encode(label)));
const LOCAL_OPERATIONS = localTestkit.operations as readonly OperationKind[];

export type LocalTvcWalletClientConfig = {
  readonly endpoint: URL;
  readonly solanaAddress: string;
  readonly nowMs?: () => bigint;
  readonly transport?: TvcTransport;
};

function localDescriptor(solanaAddress: string): WalletDescriptorV1 {
  const clientPublic = p256.getPublicKey(LOCAL_CLIENT_SECRET, false);
  const unsigned = {
    version: 1,
    security_domain_id: digestLabel(localTestkit.securityDomainLabel),
    environment: "development",
    turnkey_organization_id: localTestkit.organizationId,
    turnkey_wallet_id: localTestkit.walletId,
    address: solanaAddress,
    allowed_clients: [
      {
        client_public_key: encodeLowerHex(clientPublic),
        allowed_operations: [...LOCAL_OPERATIONS],
      },
    ],
    provisioning_signature: "",
  } satisfies WalletDescriptorV1;
  const signature = p256.sign(
    descriptorDigestFromWallet(unsigned),
    LOCAL_PROVISIONING_SECRET,
    { lowS: true, prehash: false },
  );
  return Object.freeze({
    ...unsigned,
    provisioning_signature: encodeLowerHex(signature.toCompactRawBytes()),
  });
}

export function createLocalTvcWalletClient(
  config: LocalTvcWalletClientConfig,
): TvcWalletClient {
  const descriptor = localDescriptor(config.solanaAddress);
  const clientPublic = p256.getPublicKey(LOCAL_CLIENT_SECRET, false);
  const authorizer = createTvcOperationAuthorizer({
    clientKeyId: clientKeyIdFor(clientPublic),
    async sign(message: Uint8Array) {
      return p256
        .sign(sha256(message), LOCAL_CLIENT_SECRET, { lowS: true, prehash: false })
        .toCompactRawBytes();
    },
  });
  return buildTvcWalletClient(
    createLocalTvcSession({
      endpoint: config.endpoint,
      expectedReleaseId: localTestkit.releaseId,
      expectedSecurityDomainId: digestLabel(localTestkit.securityDomainLabel),
      expectedManifestDigest: digestLabel(localTestkit.manifestLabel),
      expectedExecutableDigest: digestLabel(localTestkit.executableLabel),
      expectedQuorumKeyId: localTestkit.quorumKeyId,
      expectedQuorumPublicKey: localTestkit.quorumPublicKey,
      expectedEphemeralPublicKey: localTestkit.ephemeralPublicKey,
      expectedOperations: LOCAL_OPERATIONS,
      ...(config.nowMs === undefined ? {} : { nowMs: config.nowMs }),
      ...(config.transport === undefined ? {} : { transport: config.transport }),
      operations: { walletDescriptor: descriptor, authorizer },
    }),
  );
}
