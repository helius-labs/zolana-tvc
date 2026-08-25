import { describe, expect, expectTypeOf, it } from "vitest";
import type {
  BootstrapEd25519Result,
  BuildTransferOperationV1,
  BuildTransferResult,
  CreateWalletOperationV1,
  CreateWalletResult,
  PrepareWalletOperationV1,
  PrepareWalletResult,
  ShieldSolOperationV1,
  ShieldSolResult,
} from "../protocol/types.js";
import {
  checkpointFromResult,
  buildTransferOperation,
  shieldSolOperation,
  type EnclaveWalletResultFor,
} from "./operations.js";

describe("enclave wallet operation builders", () => {
  it("maps each operation discriminant to its exact result type", () => {
    type BootstrapResult = EnclaveWalletResultFor<{ type: "BootstrapEd25519" }>;
    expectTypeOf<BootstrapResult>().toEqualTypeOf<BootstrapEd25519Result>();
    expectTypeOf<EnclaveWalletResultFor<CreateWalletOperationV1>>()
      .toEqualTypeOf<CreateWalletResult>();
    expectTypeOf<EnclaveWalletResultFor<PrepareWalletOperationV1>>()
      .toEqualTypeOf<PrepareWalletResult>();
    expectTypeOf<EnclaveWalletResultFor<ShieldSolOperationV1>>()
      .toEqualTypeOf<ShieldSolResult>();
    expectTypeOf<EnclaveWalletResultFor<BuildTransferOperationV1>>()
      .toEqualTypeOf<BuildTransferResult>();
  });

  it("builds only the typed default-ring transfer intent", () => {
    expect(
      buildTransferOperation({
        checkpoint: {
          sealedWalletState: "11",
          stateVersion: "1",
          stateDigest: "22".repeat(32),
        },
        asset: { type: "Sol" },
        recipient: "4".repeat(44),
        amount: 1_000_000n,
        proverProfileId: "zolnet-devnet-external-http-v1",
      }),
    ).toEqual({
      type: "BuildTransfer",
      intent: {
        asset: { type: "Sol" },
        recipient: "4".repeat(44),
        amount: "1000000",
        prover_profile_id: "zolnet-devnet-external-http-v1",
      },
    });
  });

  it("rejects zero-value deposits", () => {
    expect(() =>
      shieldSolOperation({
        checkpoint: {
          sealedWalletState: "11",
          stateVersion: "1",
          stateDigest: "22".repeat(32),
        },
        amount: 0n,
      }),
    ).toThrowError("InvalidShieldAmount");
  });

  it("extracts and validates the opaque checkpoint", () => {
    expect(
      checkpointFromResult({
        type: "BootstrapEd25519",
        solana_address: "4".repeat(44),
        shielded_owner_hash: "11".repeat(32),
        shielded_nullifier_public_key: "22".repeat(32),
        shielded_viewing_public_key: `03${"33".repeat(32)}`,
        sealed_wallet_state: "44".repeat(64),
        state_version: "1",
        state_digest: "55".repeat(32),
        turnkey_activity_id: "activity",
        turnkey_app_proofs: [],
        evidence_classification: "CryptographicallyValidButUnbound",
      }),
    ).toEqual({
      sealedWalletState: "44".repeat(64),
      stateVersion: "1",
      stateDigest: "55".repeat(32),
    });
  });
});
