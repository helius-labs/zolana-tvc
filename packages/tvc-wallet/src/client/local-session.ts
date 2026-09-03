import {
  connectLocalUnattestedTvc,
  type LocalUnattestedConnectionConfig,
} from "./local-connection.js";
import type { OperationsConfig } from "./operation-executor.js";
import { sessionFromConnector, type TvcSession } from "./session.js";

type LocalTvcSessionConfig = LocalUnattestedConnectionConfig & {
  readonly operations: OperationsConfig;
};

export function createLocalTvcSession(config: LocalTvcSessionConfig): TvcSession {
  return sessionFromConnector(
    () => connectLocalUnattestedTvc(config),
    config.operations,
  );
}
