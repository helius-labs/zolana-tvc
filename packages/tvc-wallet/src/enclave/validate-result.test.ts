// Exercises validateResult through the real executeEnclaveWalletOperation path,
// with only the encrypted envelope stubbed. The builders' own tests do not
// reach this code, so without these the result checks are unverified.
import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha256";
import { describe, expect, it, vi } from "vitest";
import { signP256Message } from "../crypto/p256.js";
import { encodeLowerHex } from "../protocol/hex.js";

const executeEnvelopeMock = vi.hoisted(() => vi.fn());

vi.mock("../client/operation-executor.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../client/operation-executor.js")>()),
  executeOperationEnvelope: executeEnvelopeMock,
}));

const { executeEnclaveWalletOperation } = await import("./operations.js");

// A genuine Turnkey App Proof, so verifyTurnkeyProofs runs for real rather
// than being mocked away alongside the checks under test.
function turnkeyProof() {
  const encryption = sha256(new TextEncoder().encode("spl-proof-encryption"));
  const signing = sha256(new TextEncoder().encode("spl-proof-signing"));
  const proof_payload = JSON.stringify({
    type: "APP_PROOF_TYPE_POLICY_OUTCOME",
    outcome: "Completed",
    version: 1,
  });
  return {
    scheme: "SIGNATURE_SCHEME_EPHEMERAL_KEY_P256",
    public_key: encodeLowerHex(
      Uint8Array.from([
        ...p256.getPublicKey(encryption, false),
        ...p256.getPublicKey(signing, false),
      ]),
    ),
    proof_payload,
    signature: encodeLowerHex(
      signP256Message(signing, new TextEncoder().encode(proof_payload)),
    ),
  };
}

const CHECKPOINT = {
  sealedWalletState: "11".repeat(32),
  stateVersion: "1",
  stateDigest: "22".repeat(32),
};
const MINT = "5".repeat(44);

function splResult(overrides: Record<string, unknown> = {}) {
  return {
    type: "ShieldSpl",
    signed_transaction: "aabb",
    transaction_signature: "6".repeat(44),
    sealed_wallet_state: CHECKPOINT.sealedWalletState,
    state_version: "1",
    state_digest: CHECKPOINT.stateDigest,
    mint: MINT,
    asset_id: "7",
    public_balance_before: "1000",
    shielded_balance_before: "0",
    turnkey_activity_id: "activity-1",
    turnkey_app_proofs: [turnkeyProof()],
    evidence_classification: "CryptographicallyValidButUnbound",
    ...overrides,
  };
}

function run(
  result: Record<string, unknown>,
  operation: Record<string, unknown> = {
    type: "ShieldSpl",
    mint: MINT,
    asset_id: "7",
    amount: "1000",
  },
) {
  executeEnvelopeMock.mockResolvedValue({
    plaintext: JSON.stringify(result),
    stateDigest: CHECKPOINT.stateDigest,
  });
  return executeEnclaveWalletOperation(
    {} as never,
    operation as never,
    CHECKPOINT,
  );
}

describe("enclave result validation", () => {
  it("accepts a well-formed SPL deposit result", async () => {
    await expect(run(splResult())).resolves.toMatchObject({ type: "ShieldSpl", mint: MINT });
  });

  it("rejects a result for a different mint than the caller asked for", async () => {
    // The enclave resolves the asset itself, so an echoed mint that does not
    // match means it deposited something the caller did not request.
    await expect(run(splResult({ mint: "9".repeat(44) }))).rejects.toThrowError(
      "ReleaseBindingMismatch",
    );
  });

  it("rejects a result for a different asset id", async () => {
    await expect(run(splResult({ asset_id: "8" }))).rejects.toThrowError(
      "ReleaseBindingMismatch",
    );
  });

  it("rejects a result whose type does not match the operation", async () => {
    await expect(
      run(splResult(), { type: "ShieldSol", amount: "1000" }),
    ).rejects.toThrowError("ReleaseBindingMismatch");
  });

  it("rejects unknown and missing result fields", async () => {
    await expect(run(splResult({ unexpected: 1 }))).rejects.toThrowError("UnknownJsonField");
    const { mint: _mint, ...withoutMint } = splResult();
    await expect(run(withoutMint)).rejects.toThrowError("InvalidCanonicalJson");
  });

  it("rejects a state digest that does not match the proof", async () => {
    executeEnvelopeMock.mockResolvedValue({
      plaintext: JSON.stringify(splResult()),
      stateDigest: "33".repeat(32),
    });
    await expect(
      executeEnclaveWalletOperation({} as never, { type: "ShieldSpl", mint: MINT, asset_id: "7", amount: "1000" } as never, CHECKPOINT),
    ).rejects.toThrowError("ReleaseBindingMismatch");
  });
});
