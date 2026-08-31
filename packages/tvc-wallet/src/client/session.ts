import { TvcError } from "../protocol/error.js";
import {
  connectAndVerifyTvc,
  connectLocalUnattestedTvc,
  type LocalUnattestedConnectionConfig,
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

export type LocalTvcSessionConfig = LocalUnattestedConnectionConfig & {
  readonly operations: TvcWalletOperationsConfig;
};

function sessionFromConnector(
  connect: () => Promise<Awaited<ReturnType<typeof connectAndVerifyTvc>>>,
  operations: TvcWalletOperationsConfig | undefined,
): TvcSession {
  let activeConnection: VerifiedConnection | null = null;
  let operationContext: OperationExecutionContext | null = null;
  let pending: Promise<VerifiedConnection> | null = null;

  return {
    connectAndVerify(): Promise<VerifiedConnection> {
      if (pending) return pending;
      pending = connect()
        .then((runtime) => {
          activeConnection = runtime.connection;
          operationContext = operations ? { ...runtime, operations } : null;
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

export function createTvcSession(config: TvcSessionConfig): TvcSession {
  // Single-flighted: overlapping verification calls must not invalidate each
  // other's connection identity.
  return sessionFromConnector(() => connectAndVerifyTvc(config), config.operations);
}

export function createLocalTvcSession(config: LocalTvcSessionConfig): TvcSession {
  return sessionFromConnector(
    () => connectLocalUnattestedTvc(config),
    config.operations,
  );
}
