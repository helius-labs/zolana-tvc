import {
  SOL_MINT,
  ShieldedKeypair,
  Wallet,
  buildRegistrationTransaction,
  buildRingDepositTransaction,
  buildRingExitTransaction,
  buildRingTransferTransaction,
  syncWallet,
} from "@heliuslabs/zolana";
import { address } from "@solana/kit";
import { TvcKeys, shieldedAddressOf } from "@zolana/tvc-wallet";

import {
  expectBalance,
  loadOrBootstrapWallet,
  requiredEnv,
  sendAndConfirmFactory,
  setup,
} from "../src/lib.js";

// A custom ring has its own balances and an auditor who can read its transfers.
const RING_PROGRAM_ID = address(requiredEnv("RING_PROGRAM_ID"));
const DEPOSIT_AMOUNT = 10_000_000n;
const TRANSFER_AMOUNT = 3_000_000n;

async function main(): Promise<void> {
  const { zolana, tvc, connection, signer, walletPath } = await setup();

  const stored = await loadOrBootstrapWallet(tvc, connection, walletPath);
  const shielded = shieldedAddressOf(stored.identity);
  const keys = new TvcKeys({ ...stored, client: tvc, connection });
  const sendAndConfirm = sendAndConfirmFactory(zolana, signer);

  const registration = await buildRegistrationTransaction({
    client: zolana,
    owner: signer.address,
    address: shielded,
  });
  if (registration) await sendAndConfirm(registration);

  // The wallet may already hold balances from the other examples; every
  // expectation below is relative to what the first sync finds.
  const wallet = new Wallet({ identity: shielded });
  await syncWallet({ client: zolana, wallet, keys });
  const ringBefore = ringBalance(wallet);
  const defaultBefore = wallet.balance(SOL_MINT);

  // A ring deposit is public like a default deposit, and lands as a UTXO bound
  // to the ring. The wallet reports ring holdings apart from default ones.
  const deposit = await buildRingDepositTransaction({
    client: zolana,
    ringProgramId: RING_PROGRAM_ID,
    feePayer: signer.address,
    recipient: shielded,
    amount: DEPOSIT_AMOUNT,
  });
  const depositTx = await sendAndConfirm(deposit);
  await syncWallet({
    client: zolana,
    wallet,
    keys,
    config: { requireSlot: depositTx.slot },
  });
  expectBalance(
    "ring deposit",
    ringBalance(wallet),
    ringBefore.amount + DEPOSIT_AMOUNT,
    ringBefore.utxos.length + 1,
  );
  expectBalance(
    "default after ring deposit",
    wallet.balance(SOL_MINT),
    defaultBefore.amount,
    defaultBefore.utxos.length,
  );

  // A transfer inside the ring, funded from ring UTXOs only.
  const recipient = ShieldedKeypair.generate().shieldedAddress();
  const transfer = await buildRingTransferTransaction({
    client: zolana,
    ringProgramId: RING_PROGRAM_ID,
    wallet,
    keys,
    feePayer: signer.address,
    recipient,
    amount: TRANSFER_AMOUNT,
    inputs: "ring",
  });
  const transferTx = await sendAndConfirm(transfer);
  await syncWallet({
    client: zolana,
    wallet,
    keys,
    config: { requireSlot: transferTx.slot },
  });
  const afterTransfer = ringBalance(wallet);
  if (afterTransfer.amount !== ringBefore.amount + DEPOSIT_AMOUNT - TRANSFER_AMOUNT) {
    throw new Error(`ring transfer: expected ${ringBefore.amount + DEPOSIT_AMOUNT - TRANSFER_AMOUNT}, got ${afterTransfer.amount}`);
  }

  // What the deposit left in the ring returns to the wallet's default-ring
  // balance; the ring's spendable view drops to what it held before.
  const exit = await buildRingExitTransaction({
    client: zolana,
    ringProgramId: RING_PROGRAM_ID,
    wallet,
    keys,
    feePayer: signer.address,
    recipient: shielded,
    amount: DEPOSIT_AMOUNT - TRANSFER_AMOUNT,
  });
  const exitTx = await sendAndConfirm(exit);
  await syncWallet({
    client: zolana,
    wallet,
    keys,
    config: { requireSlot: exitTx.slot },
  });
  if (ringBalance(wallet).amount !== ringBefore.amount) {
    throw new Error(`ring exit: expected ${ringBefore.amount} left in the ring, got ${ringBalance(wallet).amount}`);
  }
  const remaining = wallet.balance(SOL_MINT);
  expectBalance(
    "default after ring exit",
    remaining,
    defaultBefore.amount + DEPOSIT_AMOUNT - TRANSFER_AMOUNT,
    defaultBefore.utxos.length + 1,
  );
  console.log(
    `ring exit private_balance=${remaining.amount} ring=${RING_PROGRAM_ID} tx=${exitTx.signature}`,
  );
}

/** The wallet's SOL in the example ring; zero with no UTXOs when it holds none there. */
function ringBalance(wallet: Wallet) {
  const ring = wallet.ringBalances().find((entry) => entry.ringProgramId === RING_PROGRAM_ID);
  return (
    ring?.assets.find((balance) => balance.mint === SOL_MINT) ?? {
      assetId: 0n,
      mint: SOL_MINT,
      amount: 0n,
      utxos: [],
    }
  );
}

await main();
