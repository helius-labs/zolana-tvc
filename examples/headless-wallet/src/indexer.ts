import { createZolanaClient, type Bytes32 } from "@heliuslabs/zolana";
import { P256_PUBLIC_KEY_LENGTH } from "@heliuslabs/zolana/keypair";
import { decodeRingDepositOutput } from "@heliuslabs/zolana/ring";
import {
  EncryptedScheme,
  decodeOutputData,
  type IndexedShieldedTransaction,
} from "@heliuslabs/zolana/transaction";
import type { TvcWalletFetchedPayload } from "@zolana/tvc-wallet";

export type HeadlessZolanaClient = Awaited<ReturnType<typeof createZolanaClient>>;

export type PayloadMeta = {
  readonly transactionSignature: string;
  readonly ringDeposit?: Readonly<{
    asset: string;
    amount: bigint;
    ringProgramId: string;
  }>;
};

function bytesToHex(bytes: Uint8Array): string {
  let result = "";
  for (const byte of bytes) result += byte.toString(16).padStart(2, "0");
  return result;
}

function viewTag(value: string): Bytes32 {
  if (!/^[0-9a-f]{64}$/.test(value)) throw new Error("InvalidViewTagEncoding");
  return Uint8Array.from(Buffer.from(value, "hex")) as Bytes32;
}

/** Bytes consumed by TVC's ordinary UTXO decryptor. */
export function confidentialCiphertextForTvc(
  scheme: EncryptedScheme,
  body: Uint8Array,
): Uint8Array | undefined {
  if (
    scheme !== EncryptedScheme.confidential &&
    scheme !== EncryptedScheme.ringConfidential
  ) {
    return undefined;
  }
  if (body.length <= P256_PUBLIC_KEY_LENGTH) return undefined;
  return body.slice(P256_PUBLIC_KEY_LENGTH);
}

function payloadsFromTransactions(
  transactions: readonly IndexedShieldedTransaction[],
): readonly TvcWalletFetchedPayload<PayloadMeta>[] {
  const payloads: TvcWalletFetchedPayload<PayloadMeta>[] = [];
  for (const transaction of transactions) {
    const transactionViewingPublicKey = transaction.txViewingPublicKey;
    const salt = transaction.salt;

    transaction.outputSlots.forEach((slot, slotIndex) => {
      let frame;
      try {
        frame = decodeOutputData(slot.payload);
      } catch {
        return;
      }
      const meta: PayloadMeta = Object.freeze({
        transactionSignature: transaction.txSignature,
      });

      if (frame.scheme === EncryptedScheme.ringDeposit) {
        let output;
        try {
          output = decodeRingDepositOutput(frame.body);
        } catch {
          return;
        }
        payloads.push({
          kind: "ciphertext",
          payload: {
            type: "RingDeposit",
            ciphertext: bytesToHex(output.encrypted.ciphertext),
            transaction_viewing_public_key: bytesToHex(
              output.encrypted.txViewingPublicKey,
            ),
            salt: bytesToHex(output.encrypted.salt),
          },
          meta: Object.freeze({
            transactionSignature: transaction.txSignature,
            ringDeposit: Object.freeze({
              asset: output.asset,
              amount: output.amount,
              ringProgramId: output.ringProgramId,
            }),
          }),
        });
        return;
      }
      if (frame.encoding === "plaintext") {
        payloads.push({ kind: "plaintext", plaintext: bytesToHex(frame.body), meta });
        return;
      }
      if (transactionViewingPublicKey === undefined || salt === undefined) return;
      const ciphertext = confidentialCiphertextForTvc(frame.scheme, frame.body);
      if (ciphertext === undefined) return;
      payloads.push({
        kind: "ciphertext",
        payload: {
          type: "Utxo",
          ciphertext: bytesToHex(ciphertext),
          transaction_viewing_public_key: bytesToHex(
            transactionViewingPublicKey.toBytes(),
          ),
          salt: bytesToHex(salt),
          slot_index: String(slotIndex),
        },
        meta,
      });
    });
  }
  return Object.freeze(payloads);
}

async function transactionsByViewTags(
  client: HeadlessZolanaClient,
  tags: readonly string[],
  requireSlot: bigint,
): Promise<readonly IndexedShieldedTransaction[]> {
  const transactions = new Map<string, IndexedShieldedTransaction>();
  const seenCursors = new Set<string>();
  let cursor: Uint8Array | undefined;

  for (let page = 0; page < 100; page += 1) {
    const response = await client.getShieldedTransactionsByTags(
      {
        tags: tags.map(viewTag),
        limit: 100,
        ...(cursor === undefined ? {} : { cursor }),
      },
      { ...client.indexerConfig, requireSlot },
      { timeoutMs: 30_000 },
    );
    for (const transaction of response.transactions) {
      transactions.set(transaction.txSignature, transaction);
    }
    if (response.nextCursor === undefined) return Object.freeze([...transactions.values()]);

    const cursorKey = bytesToHex(response.nextCursor);
    if (seenCursors.has(cursorKey)) throw new Error("IndexerCursorDidNotAdvance");
    seenCursors.add(cursorKey);
    cursor = response.nextCursor;
  }
  throw new Error("IndexerPaginationLimitExceeded");
}

/** Caller-side ciphertext discovery. TVC still performs its own spend-time sync. */
export function fetchByViewTags(
  client: HeadlessZolanaClient,
  requireSlot: bigint,
): (
  tags: readonly string[],
) => Promise<readonly TvcWalletFetchedPayload<PayloadMeta>[]> {
  return async (tags) => {
    if (tags.length === 0) return [];
    return payloadsFromTransactions(
      await transactionsByViewTags(client, tags, requireSlot),
    );
  };
}
