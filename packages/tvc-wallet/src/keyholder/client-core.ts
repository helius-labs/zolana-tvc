import { TvcError } from "../protocol/error.js";
import type {
  PreparedExactSpendResult,
  PreparedSppSpendResult,
  PreparedSpendResult,
} from "../protocol/types.js";
import type { TvcSession } from "../client/session.js";
import {
  decryptUtxosOperation,
  deriveViewTagsOperation,
  executeKeyholderOperation,
  finalizeSpendOperation,
  prepareSpendOperation,
  prepareSppSpendOperation,
} from "./operations.js";
import type { ShieldedIdentity, TvcWalletClient } from "./index.js";

function exactPrepared(result: PreparedSpendResult): PreparedExactSpendResult {
  if (result.prepared.type !== "ExactTransaction") {
    throw new TvcError("ReleaseBindingMismatch", "expected an exact transaction");
  }
  return result as PreparedExactSpendResult;
}

function sppPrepared(result: PreparedSpendResult): PreparedSppSpendResult {
  if (result.prepared.type !== "Spp") {
    throw new TvcError("ReleaseBindingMismatch", "expected an SPP transition");
  }
  return result as PreparedSppSpendResult;
}

function identityOf(result: Awaited<ReturnType<TvcWalletClient["bootstrapKeyholder"]>>): ShieldedIdentity {
  return Object.freeze({
    solanaAddress: result.solana_address,
    shieldedOwnerHash: result.shielded_owner_hash,
    shieldedNullifierPublicKey: result.shielded_nullifier_public_key,
    shieldedViewingPublicKey: result.shielded_viewing_public_key,
  });
}

function assertSameIdentity(observed: ShieldedIdentity, expected: ShieldedIdentity): void {
  if (
    observed.solanaAddress !== expected.solanaAddress ||
    observed.shieldedOwnerHash !== expected.shieldedOwnerHash ||
    observed.shieldedNullifierPublicKey !== expected.shieldedNullifierPublicKey ||
    observed.shieldedViewingPublicKey !== expected.shieldedViewingPublicKey
  ) {
    throw new TvcError("ShieldedIdentityChanged");
  }
}

function rethrowSpendPhase(phase: "Prepare" | "Finalize", error: unknown): never {
  if (error instanceof TvcError) {
    const prefix = `${error.code}: `;
    const detail = error.message.startsWith(prefix)
      ? error.message.slice(prefix.length)
      : error.message === error.code
        ? undefined
        : error.message;
    throw new TvcError(error.code, detail ? `${phase}: ${detail}` : phase);
  }
  throw error;
}

export function buildTvcWalletClient(session: TvcSession): TvcWalletClient {
  return {
    connectAndVerify: () => session.connectAndVerify(),

    async bootstrapKeyholder(connection, options) {
      const context = session.requireOperationContext(connection);
      const result = await executeKeyholderOperation(context, { type: "BootstrapKeyholder" });
      if (result.solana_address !== context.operations.walletDescriptor.address) {
        throw new TvcError("ReleaseBindingMismatch");
      }
      if (options?.expectedIdentity) {
        assertSameIdentity(identityOf(result), options.expectedIdentity);
      }
      return result;
    },

    deriveViewTags: (connection, input) =>
      executeKeyholderOperation(
        session.requireOperationContext(connection),
        deriveViewTagsOperation(),
        input.checkpoint,
      ),

    decryptUtxos: (connection, input) =>
      executeKeyholderOperation(
        session.requireOperationContext(connection),
        decryptUtxosOperation(input),
        input.checkpoint,
      ),

    async authorizeSpend(connection, input) {
      const context = session.requireOperationContext(connection);
      let prepared: PreparedSpendResult;
      try {
        prepared = await executeKeyholderOperation(
          context,
          prepareSpendOperation(input),
          input.checkpoint,
        );
      } catch (error) {
        rethrowSpendPhase("Prepare", error);
      }
      try {
        return await executeKeyholderOperation(
          context,
          finalizeSpendOperation({
            checkpoint: input.checkpoint,
            sealedAuthorizationCapsule: prepared.sealed_authorization_capsule,
            unsignedTransaction: exactPrepared(prepared).prepared.unsigned_transaction,
          }),
          input.checkpoint,
        );
      } catch (error) {
        rethrowSpendPhase("Finalize", error);
      }
    },

    async prepareSpend(connection, input) {
      const result = await executeKeyholderOperation(
        session.requireOperationContext(connection),
        prepareSpendOperation(input),
        input.checkpoint,
      );
      return exactPrepared(result);
    },

    finalizeSpend: (connection, input) =>
      executeKeyholderOperation(
        session.requireOperationContext(connection),
        finalizeSpendOperation(input),
        input.checkpoint,
      ),

    async prepareSppSpend(connection, input) {
      const result = await executeKeyholderOperation(
        session.requireOperationContext(connection),
        prepareSppSpendOperation(input),
        input.checkpoint,
      );
      return sppPrepared(result);
    },
  };
}
