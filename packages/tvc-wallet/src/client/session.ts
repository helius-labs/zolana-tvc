import { awaitWithSignal, requestScope, type TvcRequestOptions } from "./request.js";
import { TvcError } from "../protocol/error.js";
import {
  connectAndVerifyTvc,
  type ConnectedTvcRuntime,
  type TvcConnectionConfig,
  type VerifiedConnection,
} from "./connection.js";
import type {
  OperationExecutionContext,
  OperationsConfig,
} from "./operation-executor.js";

export type TvcSessionConfig = TvcConnectionConfig & {
  /** Descriptor-bound authority for the wallet operations; absent for a verify-only client. */
  operations?: OperationsConfig;
};

export type TvcSession = {
  connectAndVerify(options?: TvcRequestOptions): Promise<VerifiedConnection>;
  /**
   * Rejects a connection that this session did not produce, so operations can
   * never run against a context left over from a superseded verification.
   */
  requireOperationContext(connection: VerifiedConnection): OperationExecutionContext;
};

export function sessionFromConnector(
  connect: (signal: AbortSignal) => Promise<ConnectedTvcRuntime>,
  operations: OperationsConfig | undefined,
  requestTimeoutMs?: number,
): TvcSession {
  let activeConnection: VerifiedConnection | null = null;
  let operationContext: OperationExecutionContext | null = null;
  type Flight = { controller: AbortController; promise: Promise<VerifiedConnection>; users: number };
  let pending: Flight | null = null;

  return {
    async connectAndVerify(options): Promise<VerifiedConnection> {
      const scope = requestScope(options, requestTimeoutMs);
      let flight: Flight | undefined;
      try {
        scope.signal.throwIfAborted();
        if (!pending) {
          const controller = new AbortController();
          const current: Flight = { controller, users: 0, promise: Promise.resolve().then(async () => {
            controller.signal.throwIfAborted();
            const runtime = await connect(controller.signal);
            // An abandoned connector may ignore cancellation and finish after its replacement.
            controller.signal.throwIfAborted();
            activeConnection = runtime.connection;
            operationContext = operations ? { ...runtime, operations } : null;
            return runtime.connection;
          }).finally(() => { if (pending === current) pending = null; }) };
          pending = current;
        }
        flight = pending;
        flight.users += 1;
        return await awaitWithSignal(flight.promise, scope.signal);
      } finally {
        scope.dispose();
        if (flight && --flight.users === 0 && pending === flight) {
          pending = null;
          // One cancelled caller must not cancel another caller's verification.
          flight.controller.abort(scope.signal.reason);
        }
      }
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
  return sessionFromConnector((signal) => connectAndVerifyTvc(config, signal), config.operations, config.requestTimeoutMs);
}
