import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  parseSolanaKeypair,
  positiveInteger,
  positiveLamports,
  required,
  validateCycleAmounts,
} from "./config.ts";

describe("headless live configuration", () => {
  it("accepts positive decimal lamports only", () => {
    assert.equal(positiveLamports(undefined, 7n, "AMOUNT"), 7n);
    assert.equal(positiveLamports("42", 7n, "AMOUNT"), 42n);
    for (const invalid of ["", "0", "-1", "+1", "1.5", " 1"]) {
      assert.throws(() => positiveLamports(invalid, 7n, "AMOUNT"), /AMOUNT/);
    }
  });

  it("requires fixture coordinates provisioned by the localnet recipe", () => {
    assert.equal(required("value", "FIELD"), "value");
    assert.throws(() => required(undefined, "FIELD"), /FIELD is required/);
    assert.throws(() => required("", "FIELD"), /FIELD is required/);
  });

  it("keeps the self-transfer within the amount restored by unshield", () => {
    assert.doesNotThrow(() => validateCycleAmounts(20n, 5n));
    assert.doesNotThrow(() => validateCycleAmounts(20n, 20n));
    assert.throws(() => validateCycleAmounts(20n, 21n), /not exceed the deposit/);
  });

  it("rejects unsafe timeout and polling values", () => {
    assert.equal(positiveInteger(undefined, 100, "TIMEOUT"), 100);
    assert.equal(positiveInteger("250", 100, "TIMEOUT"), 250);
    for (const invalid of ["0", "-1", "1.5", "9007199254740992"]) {
      assert.throws(() => positiveInteger(invalid, 100, "TIMEOUT"), /TIMEOUT/);
    }
  });

  it("accepts a Solana CLI keypair", () => {
    const bytes = Array.from({ length: 64 }, (_, index) => index);
    assert.deepEqual(parseSolanaKeypair(bytes), Uint8Array.from(bytes));
  });

  it("rejects malformed Solana keypair files", () => {
    assert.throws(() => parseSolanaKeypair([]), /64 bytes/);
    assert.throws(() => parseSolanaKeypair(Array(64).fill(-1)), /64 bytes/);
    assert.throws(() => parseSolanaKeypair(Array(64).fill(256)), /64 bytes/);
  });
});
