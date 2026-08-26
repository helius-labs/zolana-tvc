import { TvcError } from "../protocol/error.js";
import { encodeDecimalU64 } from "../protocol/decimal.js";
import type { OperationKind } from "../protocol/types.js";
import type { VerifiedConnection } from "../client/connection.js";
import { requireHex } from "../client/operation-executor.js";
import type {
  EnclaveBrowserPendingSubmission,
  EnclaveBrowserTransaction,
  EnclaveBrowserWalletState,
} from "./browser-state.js";
import { checkpointFromResult } from "./operations.js";
import type { TvcEnclaveWalletClient } from "./index.js";

/** The state parser caps the journal; the facade must trim to the same bound. */
const MAX_TRANSACTIONS = 100;

const REQUIRED_GRANTS: readonly OperationKind[] = [
  "BootstrapEd25519",
  "PrepareWallet",
  "ShieldSol",
  "BuildTransfer",
];

export type TvcEnclavePendingTransaction = Readonly<{
  kind: EnclaveBrowserPendingSubmission["type"];
  signedTransaction: Uint8Array;
  transactionSignature: string;
}>;

export type TvcEnclaveWalletView = Readonly<{
  solanaAddress: string;
  registered: boolean;
  shieldedBalanceRaw: string;
  transactions: readonly EnclaveBrowserTransaction[];
  pending: TvcEnclavePendingTransaction | null;
}>;

export type CreateTvcEnclaveWalletInput = Readonly<{
  client: TvcEnclaveWalletClient;
  connection: VerifiedConnection;
  clientKeyId: string;
  state: EnclaveBrowserWalletState;
  persistState(state: EnclaveBrowserWalletState): Promise<void>;
  nowMs?: () => bigint;
}>;

function assertStateBinding(state: EnclaveBrowserWalletState, clientKeyId: string): void {
  const grant = state.walletDescriptor.allowed_clients.find(
    (candidate) => candidate.client_key_id === clientKeyId,
  );
  if (
    state.clientKeyId !== clientKeyId ||
    !grant ||
    grant.scheme !== "p256-sha256" ||
    !REQUIRED_GRANTS.every((operation) => grant.allowed_operations.includes(operation))
  ) {
    throw new TvcError("StorageCorrupted");
  }
}

function requireU64(value: string): bigint {
  const parsed = BigInt(value);
  encodeDecimalU64(parsed);
  return parsed;
}

/**
 * Client-side runtime for the full-enclave profile.
 *
 * The attested application owns the shielded identity, wallet synchronization,
 * input selection, proving, and transaction construction. What is left to the
 * client is exactly the part the enclave cannot do for it: deciding when a
 * sealed checkpoint becomes authoritative.
 *
 * Every state-changing operation returns a sealed checkpoint alongside a signed
 * transaction, and the transaction is journaled with it before submission.
 *
 * Be precise about what that buys today. A checkpoint seals the derivation seed
 * and its binding metadata, not UTXOs or balances -- the enclave re-syncs the
 * spendable set from the indexer on every operation. And in the current
 * implementation only bootstrap advances `state_version`; later operations echo
 * the checkpoint they were given. So promoting a checkpoint currently replaces
 * a value with an identical one.
 *
 * What the journal does protect now: the signed transaction survives a reload,
 * so a crash mid-flight leaves a record to check against the chain instead of
 * blindly re-issuing; the balance and history stay consistent, since they are
 * this facade's own bookkeeping over the balance the enclave reported rather
 * than values read back from the checkpoint; and only one transaction is ever
 * in flight. The sequence is also what makes stateful operations safe to add
 * later without another breaking change.
 */
export class TvcEnclaveWallet {
  readonly #client: TvcEnclaveWalletClient;
  readonly #connection: VerifiedConnection;
  readonly #persistState: (state: EnclaveBrowserWalletState) => Promise<void>;
  readonly #nowMs: () => bigint;
  #state: EnclaveBrowserWalletState;

  private constructor(input: Required<Omit<CreateTvcEnclaveWalletInput, "clientKeyId">>) {
    this.#client = input.client;
    this.#connection = input.connection;
    this.#state = input.state;
    this.#persistState = input.persistState;
    this.#nowMs = input.nowMs;
  }

  static async create(input: CreateTvcEnclaveWalletInput): Promise<TvcEnclaveWallet> {
    assertStateBinding(input.state, input.clientKeyId);
    const wallet = new TvcEnclaveWallet({
      client: input.client,
      connection: input.connection,
      state: input.state,
      persistState: input.persistState,
      nowMs: input.nowMs ?? (() => BigInt(Date.now())),
    });
    if (!wallet.#state.bootstrap) await wallet.#bootstrap();
    return wallet;
  }

  get solanaAddress(): string {
    const bootstrap = this.#state.bootstrap;
    if (!bootstrap) throw new TvcError("OperationNotAllowed");
    return bootstrap.solanaAddress;
  }

  get registered(): boolean {
    return this.#state.registered;
  }

  view(): TvcEnclaveWalletView {
    return Object.freeze({
      solanaAddress: this.solanaAddress,
      registered: this.#state.registered,
      shieldedBalanceRaw: this.#state.shieldedBalanceRaw,
      transactions: this.#state.transactions,
      pending: this.pendingTransaction(),
    });
  }

  pendingTransaction(): TvcEnclavePendingTransaction | null {
    const pending = this.#state.pendingSubmission;
    return pending
      ? Object.freeze({
          kind: pending.type,
          signedTransaction: requireHex(pending.signedTransaction),
          transactionSignature: pending.transactionSignature,
        })
      : null;
  }

  /** Registers the wallet on chain. Submit the result, then settle it. */
  async prepareRegistration(recentBlockhash: Uint8Array): Promise<TvcEnclavePendingTransaction> {
    if (this.#state.registered) throw new TvcError("OperationNotAllowed");
    const result = await this.#client.prepareWallet(this.#connection, {
      checkpoint: this.#requireCheckpoint(),
      recentBlockhash,
    });
    return this.#journal({
      type: "PrepareWallet",
      signedTransaction: result.signed_registration_transaction,
      transactionSignature: result.registration_signature,
      nextCheckpoint: checkpointFromResult(result),
      amountRaw: null,
      recipient: null,
      shieldedBalanceBeforeRaw: null,
    });
  }

  async shieldSol(amount: bigint): Promise<TvcEnclavePendingTransaction> {
    this.#requireRegistered();
    const result = await this.#client.shieldSol(this.#connection, {
      checkpoint: this.#requireCheckpoint(),
      amount,
    });
    return this.#journal({
      type: "ShieldSol",
      signedTransaction: result.signed_transaction,
      transactionSignature: result.transaction_signature,
      nextCheckpoint: checkpointFromResult(result),
      amountRaw: encodeDecimalU64(amount),
      recipient: null,
      shieldedBalanceBeforeRaw: result.shielded_balance_before,
    });
  }

  async transfer(input: {
    /** The browser facade currently journals one SOL balance. */
    asset: { readonly type: "Sol" };
    recipient: string;
    amount: bigint;
    proverProfileId: string;
  }): Promise<TvcEnclavePendingTransaction> {
    this.#requireRegistered();
    // Keep a runtime guard for untyped JavaScript callers. SPL remains
    // available on the low-level enclave client, whose caller owns per-asset
    // accounting; this SOL-only facade must never write SPL units as lamports.
    if (input.asset.type !== "Sol") throw new TvcError("InvalidTransferAsset");
    const result = await this.#client.buildTransfer(this.#connection, {
      checkpoint: this.#requireCheckpoint(),
      ...input,
    });
    // The enclave reports the balance it spent from; a transfer larger than it
    // would leave the journal describing a state the enclave never produced.
    if (input.amount > requireU64(result.shielded_balance_before)) {
      throw new TvcError("ReleaseBindingMismatch");
    }
    return this.#journal({
      type: "BuildTransfer",
      signedTransaction: result.signed_transaction,
      transactionSignature: result.transaction_signature,
      nextCheckpoint: checkpointFromResult(result),
      amountRaw: encodeDecimalU64(input.amount),
      recipient: input.recipient,
      shieldedBalanceBeforeRaw: result.shielded_balance_before,
    });
  }

  /**
   * Promotes the journaled checkpoint after the transaction is confirmed on
   * chain. Only call this once the transaction is final.
   */
  async settlePending(transactionSignature: string): Promise<void> {
    const pending = this.#requirePending(transactionSignature);
    const before = requireU64(pending.shieldedBalanceBeforeRaw ?? this.#state.shieldedBalanceRaw);
    const amount = pending.amountRaw === null ? 0n : requireU64(pending.amountRaw);
    const selfTransfer =
      pending.type === "BuildTransfer" && pending.recipient === this.solanaAddress;
    const balanceAfter =
      pending.type === "ShieldSol"
        ? before + amount
        : pending.type === "BuildTransfer"
          ? selfTransfer
            ? before
            : before - amount
          : before;
    if (balanceAfter < 0n) throw new TvcError("StorageCorrupted");

    const settled: EnclaveBrowserTransaction[] =
      pending.type === "PrepareWallet"
        ? []
        : [
            {
              type: pending.type,
              signature: pending.transactionSignature,
              amountRaw: encodeDecimalU64(amount),
              recipient: pending.recipient,
              balanceAfterRaw: encodeDecimalU64(balanceAfter),
              finalizedAtMs: encodeDecimalU64(this.#requireNow()),
            },
          ];

    await this.#commit({
      ...this.#state,
      registered: this.#state.registered || pending.type === "PrepareWallet",
      checkpoint: pending.nextCheckpoint,
      shieldedBalanceRaw: encodeDecimalU64(balanceAfter),
      pendingSubmission: null,
      transactions: [...settled, ...this.#state.transactions].slice(0, MAX_TRANSACTIONS),
    });
  }

  /**
   * Drops a transaction that will never land, keeping the previous checkpoint
   * authoritative so the same inputs can be spent again by a retry.
   */
  async abandonPending(transactionSignature: string): Promise<void> {
    this.#requirePending(transactionSignature);
    await this.#commit({ ...this.#state, pendingSubmission: null });
  }

  async #bootstrap(): Promise<void> {
    const result = await this.#client.bootstrapEd25519(this.#connection);
    const target = this.#state.walletDescriptor.turnkey_signing_target;
    if (target.type !== "HdWalletAccount" || result.solana_address !== target.address) {
      throw new TvcError("ReleaseBindingMismatch");
    }
    await this.#commit({
      ...this.#state,
      bootstrap: {
        solanaAddress: result.solana_address,
        shieldedOwnerHash: result.shielded_owner_hash,
        shieldedNullifierPublicKey: result.shielded_nullifier_public_key,
        shieldedViewingPublicKey: result.shielded_viewing_public_key,
      },
      checkpoint: checkpointFromResult(result),
    });
  }

  #journal(pending: EnclaveBrowserPendingSubmission): Promise<TvcEnclavePendingTransaction> {
    if (this.#state.pendingSubmission) throw new TvcError("OperationNotAllowed");
    return this.#commit({ ...this.#state, pendingSubmission: pending }).then(
      () => this.pendingTransaction() as TvcEnclavePendingTransaction,
    );
  }

  #requirePending(transactionSignature: string): EnclaveBrowserPendingSubmission {
    const pending = this.#state.pendingSubmission;
    if (!pending || pending.transactionSignature !== transactionSignature) {
      throw new TvcError("ReleaseBindingMismatch");
    }
    return pending;
  }

  #requireCheckpoint() {
    const checkpoint = this.#state.checkpoint;
    if (!checkpoint || this.#state.pendingSubmission) throw new TvcError("OperationNotAllowed");
    return checkpoint;
  }

  #requireRegistered(): void {
    if (!this.#state.registered) throw new TvcError("OperationNotAllowed");
  }

  #requireNow(): bigint {
    const now = this.#nowMs();
    if (now <= 0n || now > 0xffff_ffff_ffff_ffffn) throw new TvcError("StorageCorrupted");
    return now;
  }

  /** Persists before adopting, so a failed write never leaves memory ahead of disk. */
  async #commit(next: EnclaveBrowserWalletState): Promise<void> {
    await this.#persistState(next);
    this.#state = next;
  }
}

export function createTvcEnclaveWallet(
  input: CreateTvcEnclaveWalletInput,
): Promise<TvcEnclaveWallet> {
  return TvcEnclaveWallet.create(input);
}
