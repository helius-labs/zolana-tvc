import type { OperationKind, WalletOperationV1 } from "./types.js";

/**
 * The operation kind a request asks for.
 *
 * For a spend this is not the operation's own tag. Naming a ring asks for a
 * different authority, and the application reports the authority it acted
 * under -- in the App Proof it signs, and in a failure result. Anything
 * comparing against the tag instead will reject a custom-ring spend that was
 * answered correctly, so the rule lives here, once, next to the types.
 */
export function expectedOperationKind(operation: WalletOperationV1): OperationKind {
  if (operation.type === "BuildTransfer") {
    return operation.intent.ring ? "BuildCustomRingTransfer" : "BuildTransfer";
  }
  if (operation.type === "BuildSolWithdrawal") {
    return operation.intent.ring
      ? "BuildCustomRingSolWithdrawal"
      : "BuildSolWithdrawal";
  }
  return operation.type;
}
