import { TvcError } from "../protocol/error.js";
import { encodeLowerHex } from "../protocol/hex.js";
import type {
  BootstrapEd25519Result,
  BuildTransferResult,
  CreateWalletResult,
  PrepareWalletResult,
  ShieldSolResult,
  TvcWalletCheckpoint,
} from "../protocol/types.js";
import {
  connectAndVerifyTvc,
  type BootProofResolver,
  type ResolveBootProofInput,
  type TvcConnectionConfig,
  type VerifiedConnection,
} from "../client/connection.js";
import type { OperationExecutionContext } from "../client/operation-executor.js";
import {
  buildTransferOperation,
  executeEnclaveWalletOperation,
  shieldSolOperation,
  type BuildEnclaveTransferInput,
  type PrepareWalletInput,
  type ShieldSolInput,
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
  buildTransfer(
    connection: VerifiedConnection,
    input: BuildEnclaveTransferInput,
  ): Promise<BuildTransferResult>;
};

export function createTvcEnclaveWalletClient(
  config: TvcEnclaveWalletClientConfig,
): TvcEnclaveWalletClient {
  let activeConnection: VerifiedConnection | null = null;
  let operationContext: OperationExecutionContext | null = null;

  function requireOperationContext(connection: VerifiedConnection): OperationExecutionContext {
    if (connection !== activeConnection || !operationContext || !config.operations) {
      throw new TvcError("OperationNotConfigured");
    }
    return operationContext;
  }

  return {
    async connectAndVerify() {
      const runtime = await connectAndVerifyTvc(config);
      activeConnection = runtime.connection;
      operationContext = config.operations
        ? { ...runtime, operations: config.operations }
        : null;
      return runtime.connection;
    },

    async createWallet(connection) {
      const result = await executeEnclaveWalletOperation(
        requireOperationContext(connection),
        { type: "CreateWallet" },
      );
      return result;
    },

    async bootstrapEd25519(connection) {
      const result = await executeEnclaveWalletOperation(
        requireOperationContext(connection),
        { type: "BootstrapEd25519" },
      );
      const target = config.operations?.walletDescriptor.turnkey_signing_target;
      if (target?.type !== "HdWalletAccount" || result.solana_address !== target.address) {
        throw new TvcError("ReleaseBindingMismatch");
      }
      return result;
    },

    async prepareWallet(connection, input) {
      if (input.recentBlockhash.length !== 32) throw new TvcError("InvalidBlockhash");
      const result = await executeEnclaveWalletOperation(
        requireOperationContext(connection),
        { type: "PrepareWallet", recent_blockhash: encodeLowerHex(input.recentBlockhash) },
        input.checkpoint,
      );
      return result;
    },

    async shieldSol(connection, input) {
      const result = await executeEnclaveWalletOperation(
        requireOperationContext(connection),
        shieldSolOperation(input),
        input.checkpoint,
      );
      return result;
    },

    async buildTransfer(connection, input) {
      const result = await executeEnclaveWalletOperation(
        requireOperationContext(connection),
        buildTransferOperation(input),
        input.checkpoint,
      );
      return result;
    },
  };
}

export { checkpointFromResult } from "./operations.js";
export type {
  BuildEnclaveTransferInput,
  EnclaveAssetInput,
  PrepareWalletInput,
  ShieldSolInput,
  TvcEnclaveOperationsConfig,
  TvcOperationAuthorizer,
} from "./operations.js";
export type {
  BootstrapEd25519Result,
  BuildTransferResult,
  CreateWalletResult,
  PrepareWalletResult,
  ShieldSolResult,
  TvcWalletCheckpoint,
  BootProofResolver,
  ResolveBootProofInput,
  VerifiedConnection,
};
