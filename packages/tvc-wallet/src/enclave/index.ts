import { TvcError } from "../protocol/error.js";
import { encodeLowerHex } from "../protocol/hex.js";
import type {
  BootstrapEd25519Result,
  BuildTransferResult,
  CreateWalletResult,
  PrepareWalletResult,
  ShieldSolResult,
  ShieldSplResult,
  TvcWalletCheckpoint,
} from "../protocol/types.js";
import type {
  BootProofResolver,
  ResolveBootProofInput,
  TvcConnectionConfig,
  VerifiedConnection,
} from "../client/connection.js";
import { createTvcSession } from "../client/session.js";
import {
  buildTransferOperation,
  executeEnclaveWalletOperation,
  shieldSolOperation,
  shieldSplOperation,
  type BuildEnclaveTransferInput,
  type PrepareWalletInput,
  type ShieldSolInput,
  type ShieldSplInput,
  type TvcEnclaveOperationsConfig,
} from "./operations.js";

export type TvcEnclaveWalletClientConfig = TvcConnectionConfig & {
  /** Descriptor-bound authority for the closed enclave wallet operations. */
  operations?: TvcEnclaveOperationsConfig;
};

export type TvcEnclaveWalletClient = {
  connectAndVerify(): Promise<VerifiedConnection>;
  createWallet(connection: VerifiedConnection): Promise<CreateWalletResult>;
  bootstrapEd25519(connection: VerifiedConnection): Promise<BootstrapEd25519Result>;
  prepareWallet(
    connection: VerifiedConnection,
    input: PrepareWalletInput,
  ): Promise<PrepareWalletResult>;
  shieldSol(connection: VerifiedConnection, input: ShieldSolInput): Promise<ShieldSolResult>;
  shieldSpl(connection: VerifiedConnection, input: ShieldSplInput): Promise<ShieldSplResult>;
  buildTransfer(
    connection: VerifiedConnection,
    input: BuildEnclaveTransferInput,
  ): Promise<BuildTransferResult>;
};

export function createTvcEnclaveWalletClient(
  config: TvcEnclaveWalletClientConfig,
): TvcEnclaveWalletClient {
  const session = createTvcSession(config);

  return {
    connectAndVerify: () => session.connectAndVerify(),

    createWallet: (connection) =>
      executeEnclaveWalletOperation(session.requireOperationContext(connection), {
        type: "CreateWallet",
      }),

    async bootstrapEd25519(connection) {
      const context = session.requireOperationContext(connection);
      const result = await executeEnclaveWalletOperation(context, { type: "BootstrapEd25519" });
      const target = context.operations.walletDescriptor.turnkey_signing_target;
      if (target.type !== "HdWalletAccount" || result.solana_address !== target.address) {
        throw new TvcError("ReleaseBindingMismatch");
      }
      return result;
    },

    prepareWallet(connection, input) {
      if (input.recentBlockhash.length !== 32) throw new TvcError("InvalidBlockhash");
      return executeEnclaveWalletOperation(
        session.requireOperationContext(connection),
        { type: "PrepareWallet", recent_blockhash: encodeLowerHex(input.recentBlockhash) },
        input.checkpoint,
      );
    },

    shieldSol: (connection, input) =>
      executeEnclaveWalletOperation(
        session.requireOperationContext(connection),
        shieldSolOperation(input),
        input.checkpoint,
      ),

    shieldSpl: (connection, input) =>
      executeEnclaveWalletOperation(
        session.requireOperationContext(connection),
        shieldSplOperation(input),
        input.checkpoint,
      ),

    buildTransfer: (connection, input) =>
      executeEnclaveWalletOperation(
        session.requireOperationContext(connection),
        buildTransferOperation(input),
        input.checkpoint,
      ),
  };
}

export { checkpointFromResult } from "./operations.js";
export { createTvcEnclaveWallet, TvcEnclaveWallet } from "./wallet.js";
export type {
  CreateTvcEnclaveWalletInput,
  TvcEnclavePendingTransaction,
  TvcEnclaveWalletView,
} from "./wallet.js";
export type {
  BuildEnclaveTransferInput,
  EnclaveAssetInput,
  PrepareWalletInput,
  ShieldSolInput,
  ShieldSplInput,
  TvcEnclaveOperationsConfig,
  TvcOperationAuthorizer,
} from "./operations.js";
export type {
  BootstrapEd25519Result,
  BuildTransferResult,
  CreateWalletResult,
  PrepareWalletResult,
  ShieldSolResult,
  ShieldSplResult,
  TvcWalletCheckpoint,
  BootProofResolver,
  ResolveBootProofInput,
  VerifiedConnection,
};
