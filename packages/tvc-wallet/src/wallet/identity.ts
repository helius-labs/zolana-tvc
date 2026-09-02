import { P256PublicKey, ShieldedAddress, ShieldedPublicKey, type Bytes32, type Bytes33 } from "@heliuslabs/zolana";
import { address, getAddressEncoder } from "@solana/kit";

import { TvcError } from "../protocol/error.js";
import { decodeLowerHex, encodeLowerHex } from "../protocol/hex.js";
import type { ShieldedIdentity } from "./client.js";

/** The Zolana address of a bootstrapped identity, checked against its owner hash. */
export function shieldedAddressOf(identity: ShieldedIdentity): ShieldedAddress {
  const owner = new Uint8Array(getAddressEncoder().encode(address(identity.solanaAddress)));
  const result = ShieldedAddress.fromPublicKeys(
    ShieldedPublicKey.fromEd25519(owner as Bytes32),
    decodeLowerHex(identity.shieldedNullifierPublicKey) as Bytes32,
    P256PublicKey.fromBytes(decodeLowerHex(identity.shieldedViewingPublicKey) as Bytes33),
  );
  if (encodeLowerHex(result.ownerHash()) !== identity.shieldedOwnerHash) {
    throw new TvcError("ShieldedIdentityChanged");
  }
  return result;
}
