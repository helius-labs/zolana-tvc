import {
  ClientEd25519WalletAuthority,
  SOL_MINT,
  SPL_TOKEN_PROGRAM_ID,
  Wallet,
  buildDepositTransaction,
  buildRegistrationTransaction,
  buildTransferTransaction,
  buildWithdrawalTransaction,
  createZolanaClient,
  deserializeWallet,
  getPrivateTokenBalances,
  getPrivateTransactions,
  serializeWallet,
  syncWallet,
  type Bytes64,
  type WalletAuthority,
  type ZolanaClientConfig,
} from "@heliuslabs/zolana";
import { address, getAddressEncoder, getTransactionEncoder, type Transaction } from "@solana/kit";
import type {
  AuthorizeDefaultRingTransferInput,
  TvcWalletClient,
  VerifiedConnection,
} from "../client/index.js";
import { CLIENT_ED25519_DERIVATION_SUITE } from "../protocol/constants.js";
import { TvcError } from "../protocol/error.js";
import { decodeLowerHex, encodeLowerHex } from "../protocol/hex.js";
import type { PersistentBrowserTvcAuthorizer } from "./browser-authorizer.js";
import type {
  PersistentBrowserTvcBootstrap,
  PersistentBrowserTvcPendingSubmission,
  PersistentBrowserTvcWalletState,
} from "./browser-state.js";

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });
const addressEncoder = getAddressEncoder();
const transactionEncoder = getTransactionEncoder();
const TRANSFER_SYNC_FRESHNESS_MS = 10_000n;

type ZolanaClient = Awaited<ReturnType<typeof createZolanaClient>>;

export type TvcShieldedAsset =
  | Readonly<{ type: "Sol"; symbol: string; decimals: 9 }>
  | Readonly<{
      type: "Spl";
      mint: string;
      assetId: string;
      symbol: string;
      /** `null` when the mint's precision is not known to this client. */
      decimals: number | null;
    }>;

export type TvcShieldedBalance = Readonly<{
  asset: TvcShieldedAsset;
  amountRaw: string;
}>;

export type TvcShieldedSplDepositInput = Readonly<{
  mint: string;
  amount: bigint;
}>;

export type TvcShieldedTransaction = Readonly<{
  kind: "deposit" | "privateTransfer" | "publicWithdrawal" | "split" | "merge";
  direction: "inbound" | "outbound" | "selfTransfer";
  asset: TvcShieldedAsset;
  signature: string;
  amountRaw: string;
  slot: string;
  index: string;
}>;

export type TvcShieldedWalletView = Readonly<{
  balances: readonly TvcShieldedBalance[];
  transactions: readonly TvcShieldedTransaction[];
}>;

export type TvcShieldedAuthorizedTransaction = Readonly<{
  kind: "transfer" | "solWithdrawal";
  intentDigest: string;
  signedTransaction: Uint8Array;
  transactionSignature: string;
}>;

export type CreateTvcShieldedWalletInput = Readonly<{
  client: TvcWalletClient;
  connection: VerifiedConnection;
  authorizer: PersistentBrowserTvcAuthorizer;
  state: PersistentBrowserTvcWalletState;
  zolanaClientConfig: ZolanaClientConfig;
  persistState(state: PersistentBrowserTvcWalletState): Promise<void>;
  nowMs?: () => bigint;
}>;

function aad(walletId: string, field: "derivation-seed" | "wallet-state"): Uint8Array {
  return textEncoder.encode(`zolana.tvc.lightweight-wallet.v1\0${walletId}\0${field}`);
}

function wireBytes(transaction: Transaction): Uint8Array {
  return new Uint8Array(transactionEncoder.encode(transaction));
}

function matchesHex(left: Uint8Array, rightHex: string): boolean {
  return encodeLowerHex(left) === rightHex;
}

function assertStateBinding(
  state: PersistentBrowserTvcWalletState,
  authorizer: PersistentBrowserTvcAuthorizer,
): void {
  const grant = state.walletDescriptor.allowed_clients.find(
    (candidate) => candidate.client_key_id === authorizer.clientKeyId,
  );
  if (
    (state.bootstrap === null) !== (state.sealedWalletState === null) ||
    (state.bootstrap === null && (state.registered || state.pendingSubmission !== null)) ||
    (!state.registered && state.pendingSubmission !== null) ||
    state.clientKeyId !== authorizer.clientKeyId ||
    !grant ||
    grant.client_public_key !== authorizer.clientPublicKey ||
    !grant.allowed_operations.includes("BootstrapClientEd25519") ||
    !grant.allowed_operations.includes("AuthorizeDefaultRingTransfer")
  ) {
    throw new TvcError("StorageCorrupted");
  }
}

async function assertBootstrapIdentity(
  authority: WalletAuthority,
  bootstrap: Omit<PersistentBrowserTvcBootstrap, "sealedDerivationSeed">,
): Promise<void> {
  const identity = await authority.shieldedAddress();
  if (
    authority.solanaPublicKey() !== bootstrap.solanaAddress ||
    !matchesHex(identity.ownerHash(), bootstrap.shieldedOwnerHash) ||
    !matchesHex(identity.nullifierPublicKey, bootstrap.shieldedNullifierPublicKey) ||
    !matchesHex(identity.viewingPublicKey.toBytes(), bootstrap.shieldedViewingPublicKey)
  ) {
    throw new TvcError("ReleaseBindingMismatch");
  }
}

function assetFromMint(
  mint: string,
  assetId: bigint,
  knownAssets: readonly TvcShieldedAsset[],
): TvcShieldedAsset {
  const known = knownAssets.find(
    (candidate) =>
      candidate.type === "Spl" &&
      candidate.mint === mint &&
      candidate.assetId === assetId.toString(),
  );
  if (known) return known;
  if (mint === SOL_MINT) {
    return { type: "Sol", symbol: "SOL", decimals: 9 };
  }
  // Precision is a property of the mint, not something to guess: reporting a
  // default here would render a 6-decimal token a thousandfold out. Callers
  // pass known mints through `knownAssets`; anything else stays raw.
  return {
    type: "Spl",
    mint,
    assetId: assetId.toString(),
    symbol: "SPL",
    decimals: null,
  };
}

function authorityFromSeed(solanaAddress: string, seed: Uint8Array): ClientEd25519WalletAuthority {
  return ClientEd25519WalletAuthority.fromDerivationSeed({
    solanaPublicKey: address(solanaAddress),
    derivationSeed: seed as Bytes64,
  });
}

/**
 * Client-owned shielded wallet runtime for the lightweight TVC profile.
 *
 * It deliberately exposes no signing key, nullifier key, viewing key, generic
 * message signing, generic transaction signing, or underlying WalletAuthority.
 */
export class TvcShieldedWallet {
  readonly #client: ZolanaClient;
  readonly #authority: WalletAuthority;
  readonly #wallet: Wallet;
  readonly #tvcClient: TvcWalletClient;
  readonly #connection: VerifiedConnection;
  readonly #authorizer: PersistentBrowserTvcAuthorizer;
  readonly #persistState: (state: PersistentBrowserTvcWalletState) => Promise<void>;
  readonly #nowMs: () => bigint;
  #state: PersistentBrowserTvcWalletState;

  static async create(input: CreateTvcShieldedWalletInput): Promise<TvcShieldedWallet> {
    const prepared = await prepareTvcShieldedWallet(input);
    return new TvcShieldedWallet({
      ...prepared,
      tvcClient: input.client,
      connection: input.connection,
      authorizer: input.authorizer,
      persistState: input.persistState,
      nowMs: input.nowMs ?? (() => BigInt(Date.now())),
    });
  }

  private constructor(input: {
    client: ZolanaClient;
    authority: WalletAuthority;
    wallet: Wallet;
    tvcClient: TvcWalletClient;
    connection: VerifiedConnection;
    authorizer: PersistentBrowserTvcAuthorizer;
    state: PersistentBrowserTvcWalletState;
    persistState(state: PersistentBrowserTvcWalletState): Promise<void>;
    nowMs: () => bigint;
  }) {
    this.#client = input.client;
    this.#authority = input.authority;
    this.#wallet = input.wallet;
    this.#tvcClient = input.tvcClient;
    this.#connection = input.connection;
    this.#authorizer = input.authorizer;
    this.#state = input.state;
    this.#persistState = input.persistState;
    this.#nowMs = input.nowMs;
  }

  get solanaAddress(): string {
    return this.#authority.solanaPublicKey();
  }

  get registered(): boolean {
    return this.#state.registered;
  }

  pendingDefaultRingTransaction(): TvcShieldedAuthorizedTransaction | null {
    const pending = this.#state.pendingSubmission;
    return pending
      ? {
          kind: pending.type === "DefaultRingTransfer" ? "transfer" : "solWithdrawal",
          intentDigest: pending.intentDigest,
          signedTransaction: decodeLowerHex(pending.signedTransaction),
          transactionSignature: pending.transactionSignature,
        }
      : null;
  }

  async registrationTransaction(): Promise<Uint8Array | null> {
    const transaction = await buildRegistrationTransaction({
      client: this.#client,
      owner: this.#authority.solanaPublicKey(),
      address: await this.#authority.shieldedAddress(),
    });
    return transaction ? wireBytes(transaction) : null;
  }

  async markRegistered(): Promise<void> {
    if (this.#state.registered) return;
    await this.#commit({ ...this.#state, registered: true });
  }

  async depositSolTransaction(amount: bigint): Promise<Uint8Array> {
    if (!this.#state.registered) throw new TvcError("OperationNotAllowed");
    return wireBytes(
      await buildDepositTransaction({
        client: this.#client,
        feePayer: this.#authority.solanaPublicKey(),
        recipient: this.#wallet.identity,
        amount,
      }),
    );
  }

  /** Builds a classic SPL Token deposit into this wallet's shielded identity. */
  async depositSplTransaction(input: TvcShieldedSplDepositInput): Promise<Uint8Array> {
    if (!this.#state.registered) throw new TvcError("OperationNotAllowed");
    const mint = address(input.mint);
    const mintAccount = await this.#client.getAccount(mint);
    if (mintAccount?.owner !== SPL_TOKEN_PROGRAM_ID) {
      // Token-2022 is intentionally outside this facade's current contract.
      throw new TvcError("InvalidTransferAsset");
    }
    return wireBytes(
      await buildDepositTransaction({
        client: this.#client,
        feePayer: this.#authority.solanaPublicKey(),
        recipient: this.#wallet.identity,
        asset: mint,
        amount: input.amount,
        splTokenProgram: SPL_TOKEN_PROGRAM_ID,
      }),
    );
  }

  async authorizeDefaultRingTransfer(input: {
    asset: TvcShieldedAsset;
    recipient: string;
    amount: bigint;
  }): Promise<TvcShieldedAuthorizedTransaction> {
    if (!this.#state.registered || this.#state.pendingSubmission) {
      throw new TvcError("OperationNotAllowed");
    }
    await this.#syncIfStale();
    const unsignedTransaction = wireBytes(
      await buildTransferTransaction({
        client: this.#client,
        wallet: this.#wallet,
        authority: this.#authority,
        feePayer: this.#authority.solanaPublicKey(),
        recipient: address(input.recipient),
        asset: input.asset.type === "Sol" ? SOL_MINT : address(input.asset.mint),
        amount: input.amount,
      }),
    );
    return this.#authorizeDefaultRingTransaction("DefaultRingTransfer", {
      kind: "transfer",
      intent: {
        walletId: this.#state.walletDescriptor.wallet_id,
        solanaAddress: this.#authority.solanaPublicKey(),
        recipient: input.recipient,
        asset:
          input.asset.type === "Sol"
            ? { type: "Sol" }
            : {
                type: "Spl",
                mint: input.asset.mint,
                assetId: BigInt(input.asset.assetId),
              },
        amount: input.amount,
        unsignedTransaction,
      },
    });
  }

  async authorizeDefaultRingSolWithdrawal(input: {
    recipient: string;
    amount: bigint;
  }): Promise<TvcShieldedAuthorizedTransaction> {
    if (!this.#state.registered || this.#state.pendingSubmission) {
      throw new TvcError("OperationNotAllowed");
    }
    await this.#syncIfStale();
    const unsignedTransaction = wireBytes(
      await buildWithdrawalTransaction({
        client: this.#client,
        wallet: this.#wallet,
        authority: this.#authority,
        feePayer: this.#authority.solanaPublicKey(),
        recipient: address(input.recipient),
        amount: input.amount,
      }),
    );
    return this.#authorizeDefaultRingTransaction("DefaultRingSolWithdrawal", {
      kind: "solWithdrawal",
      intent: {
        walletId: this.#state.walletDescriptor.wallet_id,
        solanaAddress: this.#authority.solanaPublicKey(),
        recipient: input.recipient,
        amount: input.amount,
        unsignedTransaction,
      },
    });
  }

  async #authorizeDefaultRingTransaction(
    type: PersistentBrowserTvcPendingSubmission["type"],
    input: AuthorizeDefaultRingTransferInput,
  ): Promise<TvcShieldedAuthorizedTransaction> {
    const createdAtMs = this.#nowMs();
    if (createdAtMs <= 0n || createdAtMs > 18_446_744_073_709_551_615n) {
      throw new TvcError("StorageCorrupted");
    }
    const authorized = await this.#tvcClient.authorizeDefaultRingTransfer(
      this.#connection,
      input,
    );
    const pending: PersistentBrowserTvcPendingSubmission = {
      type,
      intentDigest: authorized.intent_digest,
      signedTransaction: authorized.signed_transaction,
      transactionSignature: authorized.transaction_signature,
      createdAtMs: createdAtMs.toString(),
    };
    await this.#commit({ ...this.#state, pendingSubmission: pending });
    return {
      kind: type === "DefaultRingTransfer" ? "transfer" : "solWithdrawal",
      intentDigest: pending.intentDigest,
      signedTransaction: decodeLowerHex(pending.signedTransaction),
      transactionSignature: pending.transactionSignature,
    };
  }

  /**
   * Retires the journal entry for a transaction that confirmed on chain.
   *
   * Deliberately separate from `expireDefaultRingTransaction` even though both
   * currently clear the same entry: the caller knows whether the transfer
   * happened, and collapsing the two would erase that at the call site and
   * force another breaking change the moment the paths need to diverge.
   */
  async completeDefaultRingTransaction(signature: string): Promise<void> {
    await this.#retirePending(signature);
  }

  /** Retires the journal entry for a transaction that will never land. */
  async expireDefaultRingTransaction(signature: string): Promise<void> {
    await this.#retirePending(signature);
  }

  async #retirePending(signature: string): Promise<void> {
    if (this.#state.pendingSubmission?.transactionSignature !== signature) {
      throw new TvcError("ReleaseBindingMismatch");
    }
    await this.#commit({ ...this.#state, pendingSubmission: null });
  }

  async sync(knownAssets: readonly TvcShieldedAsset[] = []): Promise<TvcShieldedWalletView> {
    await syncWallet({
      wallet: this.#wallet,
      authority: this.#authority,
      client: this.#client,
    });
    const serialized = textEncoder.encode(serializeWallet(this.#wallet));
    try {
      const sealedWalletState = await this.#authorizer.seal(
        serialized,
        aad(this.#state.walletDescriptor.wallet_id, "wallet-state"),
      );
      await this.#commit({ ...this.#state, sealedWalletState });
    } finally {
      serialized.fill(0);
    }
    return this.view(knownAssets);
  }

  async #syncIfStale(): Promise<void> {
    const nowMs = this.#nowMs();
    const lastSyncedMs = this.#wallet.lastSynced * 1_000n;
    if (
      lastSyncedMs > 0n &&
      nowMs >= lastSyncedMs &&
      nowMs - lastSyncedMs <= TRANSFER_SYNC_FRESHNESS_MS
    ) {
      return;
    }
    await this.sync();
  }

  view(knownAssets: readonly TvcShieldedAsset[]): TvcShieldedWalletView {
    const balances = getPrivateTokenBalances(this.#wallet);
    const registry = new Map(
      balances.map((balance) => [
        balance.mint,
        assetFromMint(balance.mint, balance.assetId, knownAssets),
      ]),
    );
    const semanticTransactions = new Map<
      string,
      ReturnType<typeof getPrivateTransactions>[number]
    >();
    for (const transaction of getPrivateTransactions(this.#wallet)) {
      const key = `${transaction.id.signature}\0${transaction.id.slot}\0${transaction.id.index}`;
      const existing = semanticTransactions.get(key);
      if (existing === undefined || transaction.direction === "selfTransfer") {
        semanticTransactions.set(key, transaction);
      }
    }
    const transactions = [...semanticTransactions.values()].flatMap((transaction) => {
      const row: TvcShieldedTransaction = {
        kind: transaction.kind,
        direction: transaction.direction,
        asset:
          registry.get(transaction.asset) ??
          assetFromMint(
            transaction.asset,
            this.#wallet.registry.assetId(transaction.asset),
            knownAssets,
          ),
        signature: transaction.id.signature,
        amountRaw: transaction.amount.toString(),
        slot: transaction.id.slot.toString(),
        index: transaction.id.index.toString(),
      };
      const sentToSelf =
        transaction.kind === "privateTransfer" && transaction.direction === "selfTransfer";
      return sentToSelf
        ? [
            { ...row, direction: "outbound" as const },
            { ...row, direction: "selfTransfer" as const },
          ]
        : [row];
    });
    return {
      balances: balances.map((balance) => ({
        asset:
          registry.get(balance.mint) ?? assetFromMint(balance.mint, balance.assetId, knownAssets),
        amountRaw: balance.amount.toString(),
      })),
      transactions,
    };
  }

  async #commit(next: PersistentBrowserTvcWalletState): Promise<void> {
    await this.#persistState(next);
    this.#state = next;
  }
}

async function prepareTvcShieldedWallet(input: CreateTvcShieldedWalletInput) {
  assertStateBinding(input.state, input.authorizer);
  // createZolanaClient initializes Poseidon, which is required by the
  // shielded identity derivation below even before the client is returned.
  const zolanaClient = await createZolanaClient(input.zolanaClientConfig);
  const target = input.state.walletDescriptor.turnkey_signing_target;
  if (target.type !== "HdWalletAccount") {
    throw new TvcError("OperationNotAllowed");
  }
  const targetPublicKey = new Uint8Array(addressEncoder.encode(address(target.address)));
  if (
    encodeLowerHex(targetPublicKey) !== input.state.walletDescriptor.expected_ed25519_public_key
  ) {
    throw new TvcError("ReleaseBindingMismatch");
  }

  let state = input.state;
  let authority: ClientEd25519WalletAuthority;
  let wallet: Wallet;
  if (!state.bootstrap || !state.sealedWalletState) {
    const result = await input.client.bootstrapClientEd25519(input.connection);
    if (result.solana_address !== target.address) {
      throw new TvcError("ReleaseBindingMismatch");
    }
    const seed = decodeLowerHex(result.derivation_seed);
    try {
      authority = authorityFromSeed(result.solana_address, seed);
      const publicBootstrap = {
        solanaAddress: result.solana_address,
        shieldedOwnerHash: result.shielded_owner_hash,
        shieldedNullifierPublicKey: result.shielded_nullifier_public_key,
        shieldedViewingPublicKey: result.shielded_viewing_public_key,
        derivationSuite: CLIENT_ED25519_DERIVATION_SUITE,
      } as const;
      await assertBootstrapIdentity(authority, publicBootstrap);
      wallet = new Wallet({ identity: await authority.shieldedAddress() });
      const serialized = textEncoder.encode(serializeWallet(wallet));
      try {
        const [sealedDerivationSeed, sealedWalletState] = await Promise.all([
          input.authorizer.seal(seed, aad(state.walletDescriptor.wallet_id, "derivation-seed")),
          input.authorizer.seal(serialized, aad(state.walletDescriptor.wallet_id, "wallet-state")),
        ]);
        state = {
          ...state,
          bootstrap: { ...publicBootstrap, sealedDerivationSeed },
          sealedWalletState,
        };
        await input.persistState(state);
      } finally {
        serialized.fill(0);
      }
    } finally {
      seed.fill(0);
    }
  } else {
    const [seed, serialized] = await Promise.all([
      input.authorizer.open(
        state.bootstrap.sealedDerivationSeed,
        aad(state.walletDescriptor.wallet_id, "derivation-seed"),
      ),
      input.authorizer.open(
        state.sealedWalletState,
        aad(state.walletDescriptor.wallet_id, "wallet-state"),
      ),
    ]);
    try {
      authority = authorityFromSeed(state.bootstrap.solanaAddress, seed);
      await assertBootstrapIdentity(authority, state.bootstrap);
      wallet = deserializeWallet(textDecoder.decode(serialized));
      const identity = await authority.shieldedAddress();
      if (
        !matchesHex(wallet.identity.ownerHash(), encodeLowerHex(identity.ownerHash())) ||
        !matchesHex(
          wallet.identity.nullifierPublicKey,
          encodeLowerHex(identity.nullifierPublicKey),
        ) ||
        !matchesHex(
          wallet.identity.viewingPublicKey.toBytes(),
          encodeLowerHex(identity.viewingPublicKey.toBytes()),
        )
      ) {
        throw new TvcError("StorageCorrupted");
      }
    } finally {
      seed.fill(0);
      serialized.fill(0);
    }
  }

  if (authority.solanaPublicKey() !== target.address) {
    throw new TvcError("ReleaseBindingMismatch");
  }
  return {
    client: zolanaClient,
    authority,
    wallet,
    state,
  };
}

export function createTvcShieldedWallet(
  input: CreateTvcShieldedWalletInput,
): Promise<TvcShieldedWallet> {
  return TvcShieldedWallet.create(input);
}
