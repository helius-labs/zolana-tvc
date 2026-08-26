import { TvcError } from "../protocol/error.js";
import {
  connectAndVerifyTvc,
  type TvcConnectionConfig,
  type VerifiedConnection,
} from "./connection.js";
import type {
  OperationExecutionContext,
  TvcWalletOperationsConfig,
} from "./operation-executor.js";

export type TvcSessionConfig = TvcConnectionConfig & {
  operations?: TvcWalletOperationsConfig;
};

export type TvcSession = {
  connectAndVerify(): Promise<VerifiedConnection>;
  /**
   * Rejects a connection that this session did not produce, so operations can
   * never run against a context left over from a superseded verification.
   */
  requireOperationContext(connection: VerifiedConnection): OperationExecutionContext;
};

export function createTvcSession(config: TvcSessionConfig): TvcSession {
  let activeConnection: VerifiedConnection | null = null;
  let operationContext: OperationExecutionContext | null = null;
  let pending: Promise<VerifiedConnection> | null = null;

  return {
    connectAndVerify(): Promise<VerifiedConnection> {
      // Single-flighted: two overlapping calls would otherwise each run a full
      // verification, and whichever resolved last would replace the active
      // connection, silently invalidating the one the first caller is holding.
      if (pending) return pending;
      pending = connectAndVerifyTvc(config)
        .then((runtime) => {
          activeConnection = runtime.connection;
          operationContext = config.operations
            ? { ...runtime, operations: config.operations }
            : null;
          return runtime.connection;
        })
        .finally(() => {
          pending = null;
        });
      return pending;
    },

    requireOperationContext(connection): OperationExecutionContext {
      if (connection !== activeConnection || !operationContext) {
        throw new TvcError("OperationNotConfigured");
      }
      return operationContext;
    },
  };
}
