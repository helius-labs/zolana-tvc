import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { P256_PUBLIC_KEY_LENGTH } from "@heliuslabs/zolana/keypair";
import { EncryptedScheme } from "@heliuslabs/zolana/transaction";

import { confidentialCiphertextForTvc } from "./indexer.ts";

describe("headless indexer framing", () => {
  it("strips the public recipient key from ordinary confidential bodies", () => {
    const prefix = new Uint8Array(P256_PUBLIC_KEY_LENGTH).fill(1);
    const ciphertext = Uint8Array.of(2, 3, 4);
    const framed = Uint8Array.of(...prefix, ...ciphertext);
    assert.deepEqual(
      confidentialCiphertextForTvc(EncryptedScheme.confidential, framed),
      ciphertext,
    );
    assert.deepEqual(
      confidentialCiphertextForTvc(EncryptedScheme.ringConfidential, framed),
      ciphertext,
    );
  });

  it("rejects unsupported and truncated frames", () => {
    assert.equal(
      confidentialCiphertextForTvc(
        EncryptedScheme.confidential,
        new Uint8Array(P256_PUBLIC_KEY_LENGTH),
      ),
      undefined,
    );
    assert.equal(
      confidentialCiphertextForTvc(
        EncryptedScheme.ringDeposit,
        new Uint8Array(P256_PUBLIC_KEY_LENGTH + 1),
      ),
      undefined,
    );
  });
});
