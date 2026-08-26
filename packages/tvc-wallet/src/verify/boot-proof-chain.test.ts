// Runs against the real Turnkey/AWS Nitro seam, with nothing mocked. A
// synthetic attestation is well-formed and internally consistent but is not
// chained to the pinned AWS Nitro root, so acceptance here would mean the
// chain check is not load-bearing.
import { describe, expect, it } from "vitest";
import { verifyBootProof } from "./boot-proof.js";
import {
  appProof,
  bootProof,
  EXPECTED_PCRS,
  MANIFEST_DIGEST,
  NOW_MS,
} from "./boot-proof.testkit.js";
import { encodeLowerHex } from "../protocol/hex.js";

describe("Boot Proof AWS Nitro chain", () => {
  it("fails closed on an attestation that is not chained to the pinned AWS root", async () => {
    await expect(
      verifyBootProof({
        appProof: appProof(),
        bootProof: bootProof(),
        allowedManifestSha256: [encodeLowerHex(MANIFEST_DIGEST)],
        expectedPcrs: EXPECTED_PCRS,
        nowMs: NOW_MS,
      }),
    ).rejects.toThrowError(/BootProofUnverified/);
  });
});
