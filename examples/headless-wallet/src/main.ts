// Headless end-to-end against the local Rust testkit: bootstrap, register,
// deposit, private self-transfer, withdraw, for SOL and one SPL mint. Every
// wallet flow is the Zolana SDK's; the enclave answers as the SDK's
// `WalletKeys` through `TvcKeys`, and the Solana signer stays local.
import { readFile, writeFile } from "node:fs/promises";
import { setTimeout as sleep } from "node:timers/promises";

import {
  SOL_MINT,
  Wallet,
  buildDepositTransaction,
  buildRegistrationTransaction,
  buildTransferTransaction,
  buildWithdrawalTransaction,
  createZolanaClient,
  syncWallet,
  type Address,
} from "@heliuslabs/zolana";
import { AssetRegistry } from "@heliuslabs/zolana/transaction";
import {
  assertIsFullySignedTransaction,
  assertIsTransactionWithinSizeLimit,
  createKeyPairSignerFromBytes,
  getSignatureFromTransaction,
  sendTransactionWithoutConfirmingFactory,
  signTransactionWithSigners,
  type Signature,
  type Transaction,
} from "@solana/kit";
import {
  TvcKeys,
  sealedSeedOf,
  identityOf,
  shieldedAddressOf,
  type ShieldedIdentity,
} from "@zolana/tvc-wallet";
import { createLocalTvcClient } from "@zolana/tvc-wallet/testing";

const env = (name: string, fallback?: string): string => {
  const value = process.env[name] ?? fallback;
  if (value === undefined) throw new Error(`${name} is required; use \`just headless-e2e\``);
  return value;
};

const config = {
  tvcEndpoint: new URL(env("TVC_ENDPOINT", "http://127.0.0.1:44020")),
  solanaRpcUrl: env("TVC_SOLANA_RPC_URL", "http://127.0.0.1:9099"),
  indexerUrl: env("TVC_INDEXER_URL", "http://127.0.0.1:8984"),
  proverUrl: env("TVC_PROVER_URL", "http://127.0.0.1:3201"),
  keypairPath: env("TVC_SOLANA_KEYPAIR_PATH"),
  identityPath: env("TVC_IDENTITY_PATH"),
  splMint: env("TVC_E2E_SPL_MINT") as Address,
  splAssetId: BigInt(env("TVC_E2E_SPL_ASSET_ID")),
  splTokenAccount: env("TVC_E2E_SPL_TOKEN_ACCOUNT") as Address,
  depositLamports: BigInt(env("TVC_E2E_DEPOSIT_LAMPORTS", "20000000")),
  splAmount: BigInt(env("TVC_E2E_SPL_AMOUNT", "200000")),
  timeoutMs: Number(env("TVC_E2E_SYNC_TIMEOUT_MS", "180000")),
};

const zolana = await createZolanaClient({
  solanaRpcUrl: config.solanaRpcUrl,
  indexerUrl: config.indexerUrl,
  proverUrl: config.proverUrl,
  allowInsecureHttp: true,
  indexerConfig: { poll: { numRetries: 5, delayMs: 500n, maxDelayMs: 2_000n } },
});
const signer = await createKeyPairSignerFromBytes(
  Uint8Array.from(JSON.parse(await readFile(config.keypairPath, "utf8")) as number[]),
);
const registry = new AssetRegistry([[config.splAssetId, config.splMint]]);

async function confirm(signature: Signature): Promise<void> {
  const deadline = Date.now() + config.timeoutMs;
  while (Date.now() < deadline) {
    const { value } = await zolana.solanaRpc
      .getSignatureStatuses([signature], { searchTransactionHistory: true })
      .send();
    const status = value[0];
    if (status?.err) throw new Error(`${signature} failed: ${JSON.stringify(status.err)}`);
    if (status?.confirmationStatus === "confirmed" || status?.confirmationStatus === "finalized") {
      return;
    }
    await sleep(500);
  }
  throw new Error(`${signature} did not confirm`);
}

async function signAndSend(transaction: Transaction): Promise<Signature> {
  const signed = await signTransactionWithSigners([signer], transaction);
  assertIsFullySignedTransaction(signed);
  assertIsTransactionWithinSizeLimit(signed);
  await sendTransactionWithoutConfirmingFactory({ rpc: zolana.solanaRpc })(signed, {
    commitment: zolana.commitment,
  });
  const signature = getSignatureFromTransaction(signed);
  await confirm(signature);
  return signature;
}

// 1. Connect to the local testkit and bootstrap (or recover) the identity.
const client = createLocalTvcClient({ endpoint: config.tvcEndpoint, solanaAddress: signer.address });
const connection = await client.connectAndVerify();
const expected = await readFile(config.identityPath, "utf8")
  .then((text) => JSON.parse(text) as ShieldedIdentity)
  .catch(() => undefined);
const bootstrap = await client.bootstrap(connection, expected ? { expectedIdentity: expected } : {});
const identity = identityOf(bootstrap);
const shielded = shieldedAddressOf(identity);
if (!expected) await writeFile(config.identityPath, JSON.stringify(identity, null, 2), { mode: 0o600 });
console.log(`[bootstrap] ${identity.solanaAddress} -> owner ${identity.shieldedOwnerHash.slice(0, 16)}...`);

// The enclave as the SDK's `WalletKeys`: every sync and build below goes
// through it, and none of them learns a secret.
const keys = new TvcKeys({ client, connection, sealedSeed: sealedSeedOf(bootstrap), identity });

// 2. Publish the shielded identity so senders can find it.
const registration = await buildRegistrationTransaction({
  client: zolana,
  owner: signer.address,
  address: shielded,
});
if (registration) console.log(`[register] ${await signAndSend(registration)}`);

const wallet = new Wallet({ identity: shielded, registry });

async function slot(): Promise<bigint> {
  return BigInt(await zolana.solanaRpc.getSlot({ commitment: zolana.commitment }).send());
}

async function syncedBalance(asset: Address, expectedAmount: bigint, afterSlot: bigint): Promise<void> {
  const deadline = Date.now() + config.timeoutMs;
  while (Date.now() < deadline) {
    await syncWallet({ client: zolana, wallet, keys, config: { requireSlot: afterSlot } });
    if (wallet.balance(asset).amount === expectedAmount) return;
    await sleep(2_000);
  }
  throw new Error(`private balance of ${asset} did not reach ${String(expectedAmount)}`);
}

async function cycle(label: string, asset: Address, amount: bigint, deposit: Transaction): Promise<void> {
  console.log(`[${label}] deposit ${await signAndSend(deposit)}`);
  await syncedBalance(asset, amount, await slot());
  console.log(`[${label}] private balance ${String(wallet.balance(asset).amount)}`);

  const transfer = await buildTransferTransaction({
    client: zolana,
    wallet,
    keys,
    feePayer: signer.address,
    recipient: shielded,
    asset,
    amount,
  });
  console.log(`[${label}] self-transfer ${await signAndSend(transfer)}`);
  await syncedBalance(asset, amount, await slot());

  const withdrawal = await buildWithdrawalTransaction({
    client: zolana,
    wallet,
    keys,
    feePayer: signer.address,
    recipient: signer.address,
    asset,
    amount,
  });
  console.log(`[${label}] withdrawal ${await signAndSend(withdrawal)}`);
  await syncedBalance(asset, 0n, await slot());
}

await cycle(
  "SOL",
  SOL_MINT,
  config.depositLamports,
  await buildDepositTransaction({
    client: zolana,
    feePayer: signer.address,
    recipient: shielded,
    amount: config.depositLamports,
  }),
);
await cycle(
  "SPL",
  config.splMint,
  config.splAmount,
  await buildDepositTransaction({
    client: zolana,
    feePayer: signer.address,
    recipient: shielded,
    asset: config.splMint,
    splTokenAccount: config.splTokenAccount,
    amount: config.splAmount,
  }),
);
console.log("ok");
