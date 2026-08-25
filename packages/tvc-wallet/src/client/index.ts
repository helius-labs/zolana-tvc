import { TvcError } from "../protocol/error.js";
import type {
  AuthorizeDefaultRingTransferResult,
  BootstrapClientEd25519Result,
} from "../protocol/types.js";
import {
  connectAndVerifyTvc,
  type BootProofResolver,
  type ResolveBootProofInput,
  type TvcConnectionConfig,
  type VerifiedConnection,
} from "./connection.js";
import {
  authorizeDefaultRingTransferOperation,
  executeWalletOperation,
  type AuthorizeDefaultRingTransferInput,
  type TvcWalletOperationsConfig,
} from "./operations.js";
import type { OperationExecutionContext } from "./operation-executor.js";

export {
  defaultRingSolWithdrawalIntentDigest,
  defaultRingTransferIntentDigest,
} from "./transfer-intent.js";
export type {
  DefaultRingSolWithdrawalIntentInput,
  DefaultRingTransferIntentInput,
} from "./transfer-intent.js";

export type TvcWalletClientConfig = TvcConnectionConfig & {
  /** Typed lightweight wallet authority. Omit for verify-only clients. */
  operations?: TvcWalletOperationsConfig;
};

export type TvcWalletClient = {
  connectAndVerify(): Promise<VerifiedConnection>;
  bootstrapClientEd25519(connection: VerifiedConnection): Promise<BootstrapClientEd25519Result>;
  authorizeDefaultRingTransfer(
    connection: VerifiedConnection,
    input: AuthorizeDefaultRingTransferInput,
  ): Promise<AuthorizeDefaultRingTransferResult>;
};

export function createTvcWalletClient(config: TvcWalletClientConfig): TvcWalletClient {
  let activeConnection: VerifiedConnection | null = null;
  let operationContext: OperationExecutionContext | null = null;

  function requireOperationContext(connection: VerifiedConnection): OperationExecutionContext {
    if (connection !== activeConnection || !operationContext || !config.operations) {
      throw new TvcError("OperationNotConfigured");
    }
    return operationContext;
  }

  return {
    async connectAndVerify(): Promise<VerifiedConnection> {
      const runtime = await connectAndVerifyTvc(config);
      activeConnection = runtime.connection;
      operationContext = config.operations
        ? { ...runtime, operations: config.operations }
        : null;
      return runtime.connection;
    },

    async bootstrapClientEd25519(connection) {
      const result = await executeWalletOperation(requireOperationContext(connection), {
        type: "BootstrapClientEd25519",
      });
      return result;
    },

    async authorizeDefaultRingTransfer(connection, input) {
      const result = await executeWalletOperation(
        requireOperationContext(connection),
        authorizeDefaultRingTransferOperation(input),
      );
      return result;
    },
  };
}

export type {
  AuthorizeTvcRequestInput,
  AuthorizeDefaultRingTransferInput,
  TvcOperationAuthorizer,
  TvcWalletOperationsConfig,
} from "./operations.js";
export type { BootProofResolver, ResolveBootProofInput, VerifiedConnection };
