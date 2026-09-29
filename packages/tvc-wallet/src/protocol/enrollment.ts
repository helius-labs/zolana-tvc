import { sha256 } from "@noble/hashes/sha256";

import { TvcError } from "./error.js";
import { encodeLowerHex } from "./hex.js";

/** tvc-gateway's domain for the enrollment message the wallet owner signs. */
export const WALLET_ENROLLMENT_DOMAIN = "ZOLANA_TVC_WALLET_ENROLLMENT_V2";

/** `POST /enroll`, less the owner's signature over [`walletEnrollmentMessage`]. */
export type WalletEnrollment = {
  readonly parentOrganizationId: string;
  readonly organizationId: string;
  readonly walletName: string;
  readonly turnkeyWalletId: string;
  readonly solanaAddress: string;
  /** Uncompressed SEC1 P-256 key, lowercase hex. */
  readonly clientPublicKey: string;
  readonly issuedAtMs: number;
};

/**
 * The text the wallet owner signs with Ed25519 through Turnkey:
 * `WALLET_ENROLLMENT_DOMAIN || "\n" || hex(sha256(fields))`, where `fields` are
 * the enrollment's values in declaration order, `issuedAtMs` in decimal,
 * joined by `"\n"`.
 */
export function walletEnrollmentMessage(enrollment: WalletEnrollment): string {
  if (!Number.isSafeInteger(enrollment.issuedAtMs) || enrollment.issuedAtMs < 0) {
    throw new TvcError("InvalidDecimal", "issuedAtMs must be a non-negative integer");
  }
  const fields = [
    enrollment.parentOrganizationId,
    enrollment.organizationId,
    enrollment.walletName,
    enrollment.turnkeyWalletId,
    enrollment.solanaAddress,
    enrollment.clientPublicKey,
    String(enrollment.issuedAtMs),
  ];
  if (fields.some((field) => field.includes("\n"))) {
    throw new TvcError("InvalidDescriptor", "enrollment fields cannot contain a newline");
  }
  return `${WALLET_ENROLLMENT_DOMAIN}\n${encodeLowerHex(sha256(new TextEncoder().encode(fields.join("\n"))))}`;
}
