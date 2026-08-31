/**
 * Explicitly unsafe local TVC testkit.
 *
 * This entrypoint preserves the encrypted operation protocol and all response
 * binding checks, but replaces Nitro and Turnkey evidence with pinned local
 * process keys. It accepts loopback HTTP only and must never be used for funds.
 */
import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha256";

import { createLocalTvcSession } from "./client/session.js";
import type { TvcTransport } from "./client/transport.js";
import { createTvcOperationAuthorizer } from "./platform/authorizer.js";
import {
  clientKeyIdFor,
  descriptorDigestFromWallet,
} from "./protocol/digest.js";
import { encodeLowerHex } from "./protocol/hex.js";
import type { WalletDescriptorV1 } from "./protocol/types.js";
import { buildTvcWalletClient } from "./keyholder/client-core.js";
import type { TvcWalletClient } from "./keyholder/index.js";

const LOCAL_PROVISIONING_SECRET = new Uint8Array(32).fill(0x11);
const LOCAL_CLIENT_SECRET = new Uint8Array(32).fill(0x22);
const LOCAL_SECURITY_DOMAIN =
  "effbe45f68b6fac325e936d0a7b31bed3183757fcb2035c1fea5b03e79ede4cc";
const LOCAL_QUORUM_PUBLIC =
  "042848b014f3f83727e56833002e282502d39be87129474e50a3e2ab7d6e1892dee8e73470ae287bd017f477707e47bf5b2f0365e0030f294c4615c6c3467be2c70440ed796fa332acf63defbb15c227ae5cdb194afed0594084b610716f12ad7e29cba3f42464dac7a66475c45a49c47ca6dc3fdd6de9f84076f7a50add0af4c937";
const LOCAL_EPHEMERAL_PUBLIC =
  "0468c2ed752eb165bfd38f2f22ad4d0dc23bfba6e9b01420467ee700229e6b60d7536357b719d8798a3165f4d494aa0d470b55fe634826fcb41bfee34234dd0e8b04c70dfb2635117d7b449600bd4801e66ca781a516fa9a12c156501ac2df1c06bce847ce4fa71ca24ad64d3dc4ed0bad8b450fffe28c75743694118d2e68ac521f";

const LOCAL_OPERATIONS = [
  "BootstrapKeyholder",
  "DeriveViewTags",
  "DecryptUtxos",
  "AuthorizeSpend",
] as const;

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
    security_domain_id: LOCAL_SECURITY_DOMAIN,
    environment: "development",
    turnkey_organization_id: "00000000-0000-4000-8000-000000000001",
    turnkey_wallet_id: "local-testkit-wallet",
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
      expectedQuorumPublicKey: LOCAL_QUORUM_PUBLIC,
      expectedEphemeralPublicKey: LOCAL_EPHEMERAL_PUBLIC,
      ...(config.nowMs === undefined ? {} : { nowMs: config.nowMs }),
      ...(config.transport === undefined ? {} : { transport: config.transport }),
      operations: { walletDescriptor: descriptor, authorizer },
    }),
  );
}
