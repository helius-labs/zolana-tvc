import type {
  AuthorizeDefaultRingTransferResult,
  BootstrapClientEd25519Result,
} from "../protocol/types.js";
import type {
  BootProofResolver,
  ResolveBootProofInput,
  TvcConnectionConfig,
  VerifiedConnection,
} from "./connection.js";
import {
  authorizeDefaultRingTransferOperation,
  executeWalletOperation,
  type AuthorizeDefaultRingTransferInput,
  type TvcWalletOperationsConfig,
} from "./operations.js";
import { createTvcSession } from "./session.js";

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
  const session = createTvcSession(config);

  return {
    connectAndVerify: () => session.connectAndVerify(),

    bootstrapClientEd25519: (connection) =>
      executeWalletOperation(session.requireOperationContext(connection), {
        type: "BootstrapClientEd25519",
      }),

    authorizeDefaultRingTransfer: (connection, input) =>
      executeWalletOperation(
        session.requireOperationContext(connection),
        authorizeDefaultRingTransferOperation(input),
      ),
  };
}

export type {
  AuthorizeTvcRequestInput,
  AuthorizeDefaultRingTransferInput,
  TvcOperationAuthorizer,
  TvcWalletOperationsConfig,
} from "./operations.js";
export type { BootProofResolver, ResolveBootProofInput, VerifiedConnection };
