import {
  connectLocalUnattestedTvc,
  type LocalUnattestedConnectionConfig,
} from "./local-connection.js";
import type { TvcWalletOperationsConfig } from "./operation-executor.js";
import { sessionFromConnector, type TvcSession } from "./session.js";

export type LocalTvcSessionConfig = LocalUnattestedConnectionConfig & {
  readonly operations: TvcWalletOperationsConfig;
};

export function createLocalTvcSession(config: LocalTvcSessionConfig): TvcSession {
  return sessionFromConnector(
    () => connectLocalUnattestedTvc(config),
    config.operations,
  );
}
