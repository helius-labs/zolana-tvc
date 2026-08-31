import {
  assertIsAddress,
  assertIsFullySignedTransaction,
  assertIsSignature,
  assertIsTransactionWithinSizeLimit,
  getSignatureFromTransaction,
  getTransactionDecoder,
  sendTransactionWithoutConfirmingFactory,
  signTransactionWithSigners,
  type Address,
  type KeyPairSigner,
  type Signature,
  type Transaction,
} from "@solana/kit";

import type { HeadlessZolanaClient } from "./indexer.ts";
function sleep(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

export async function waitForSignature(
  client: HeadlessZolanaClient,
  signature: Signature,
  timeoutMs: number,
  confirmation: "confirmed" | "finalized" = "confirmed",
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const { value } = await client.solanaRpc
      .getSignatureStatuses([signature], { searchTransactionHistory: true })
      .send({ abortSignal: AbortSignal.timeout(10_000) });
    const status = value[0];
    if (status?.err !== null && status?.err !== undefined) {
      throw new Error(`transaction ${signature} failed: ${JSON.stringify(status.err)}`);
    }
    if (
      status?.confirmationStatus === "finalized" ||
      (confirmation === "confirmed" && status?.confirmationStatus === "confirmed")
    ) {
      return;
    }
    await sleep(500);
  }
  throw new Error(`transaction confirmation timed out: ${signature}`);
}

export async function signSubmitAndConfirm(
  client: HeadlessZolanaClient,
  transaction: Transaction,
  signer: KeyPairSigner,
  timeoutMs: number,
  confirmation: "confirmed" | "finalized" = "confirmed",
): Promise<Signature> {
  const signed = await signTransactionWithSigners([signer], transaction);
  const signature = getSignatureFromTransaction(signed);
  await sendTransactionWithoutConfirmingFactory({ rpc: client.solanaRpc })(signed, {
    commitment: client.commitment,
  });
  await waitForSignature(client, signature, timeoutMs, confirmation);
  return signature;
}

export async function submitTvcTransaction(
  client: HeadlessZolanaClient,
  signedTransactionHex: string,
  expectedSignature: string,
  timeoutMs: number,
): Promise<Signature> {
  if (!/^[0-9a-f]+$/.test(signedTransactionHex) || signedTransactionHex.length % 2 !== 0) {
    throw new Error("TVC returned an invalid signed transaction encoding");
  }
  assertIsSignature(expectedSignature);
  const transaction = getTransactionDecoder().decode(
    Uint8Array.from(Buffer.from(signedTransactionHex, "hex")),
  );
  assertIsFullySignedTransaction(transaction);
  assertIsTransactionWithinSizeLimit(transaction);
  const embeddedSignature = getSignatureFromTransaction(transaction);
  if (embeddedSignature !== expectedSignature) {
    throw new Error("TVC transaction signature does not match its signed transaction");
  }
  await sendTransactionWithoutConfirmingFactory({ rpc: client.solanaRpc })(transaction, {
    commitment: client.commitment,
  });
  await waitForSignature(client, embeddedSignature, timeoutMs);
  return embeddedSignature;
}

export async function currentSlot(client: HeadlessZolanaClient): Promise<bigint> {
  return BigInt(
    await client.solanaRpc
      .getSlot({ commitment: client.commitment })
      .send({ abortSignal: AbortSignal.timeout(10_000) }),
  );
}

export async function publicBalance(
  client: HeadlessZolanaClient,
  value: string,
): Promise<bigint> {
  assertIsAddress(value);
  return BigInt(await client.getBalance(value as Address));
}

export async function tokenBalance(
  client: HeadlessZolanaClient,
  value: string,
): Promise<bigint> {
  assertIsAddress(value);
  const response = await client.solanaRpc
    .getTokenAccountBalance(value as Address)
    .send({ abortSignal: AbortSignal.timeout(10_000) });
  return BigInt(response.value.amount);
}

export async function waitUntilFinalizedAfter(
  client: HeadlessZolanaClient,
  slot: bigint,
  timeoutMs: number,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const current = BigInt(
      await client.solanaRpc
        .getSlot({ commitment: "finalized" })
        .send({ abortSignal: AbortSignal.timeout(10_000) }),
    );
    if (current > slot) return;
    await sleep(200);
  }
  throw new Error(`finalized slot did not advance past ${slot.toString()}`);
}
