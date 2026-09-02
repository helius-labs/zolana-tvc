import {
  SOL_MINT,
  ShieldedKeypair,
  Wallet,
  buildDepositTransaction,
  buildRegistrationTransaction,
  buildTransferTransaction,
  buildWithdrawalTransaction,
  syncWallet,
} from "@heliuslabs/zolana";
import type { AssetBalance } from "@heliuslabs/zolana/transaction";
import {
  TvcKeys,
  sealedSeedOf,
  identityOf,
  shieldedAddressOf,
} from "@zolana/tvc-wallet";

import {
  loadWallet,
  saveWallet,
  sendAndConfirmFactory,
  setup,
} from "../src/lib.js";

const DEPOSIT_AMOUNT = 1_000_000_000n;
const TRANSFER_AMOUNT = 300_000_000n;
const WITHDRAW_AMOUNT = 300_000_000n;

function expectBalance(
  step: string,
  balance: AssetBalance,
  amount: bigint,
  utxos: number,
): void {
  if (balance.amount !== amount) {
    throw new Error(
      `${step}: expected amount ${amount}, got ${balance.amount}`,
    );
  }
  if (balance.utxos.length !== utxos) {
    throw new Error(
      `${step}: expected ${utxos} utxo(s), got ${balance.utxos.length}`,
    );
  }
}

async function main(): Promise<void> {
  const { zolana, tvc, signer, walletPath } = await setup();

  // Verify the enclave before anything else: the signed release policy, the
  // AWS Nitro Boot Proof, the PCRs and the manifest, all against pins this
  // client holds. Every operation below runs over this verified connection.
  const connection = await tvc.connectAndVerify();

  // Bootstrap once per wallet. The enclave derives the shielded identity from
  // a Turnkey signature of the wallet and returns the public identity plus the
  // seed sealed to the enclave's key. Both are stored; neither is a secret to
  // the client. Later runs reuse them. If the file is lost, bootstrap again:
  // the identity and the seed are the same.
  let stored = await loadWallet(walletPath);
  if (!stored) {
    const bootstrap = await tvc.bootstrap(connection, {});
    stored = {
      identity: identityOf(bootstrap),
      sealedSeed: sealedSeedOf(bootstrap),
    };
    await saveWallet(walletPath, stored);
  }
  const shielded = shieldedAddressOf(stored.identity);

  // The enclave as the SDK's `WalletKeys`. Every sync and every build below
  // goes through it: it decrypts outputs, derives nullifiers, mints
  // per-transaction keys and completes the prover witness. It never learns a
  // balance, never selects an input and never signs a Solana transaction.
  const keys = new TvcKeys({
    client: tvc,
    connection,
    sealedSeed: stored.sealedSeed,
    identity: stored.identity,
  });

  // The SDK hands back compiled transactions; the app owns signing and
  // sending. The signer is the Turnkey wallet that owns the identity.
  const sendAndConfirm = sendAndConfirmFactory(zolana, signer);

  // Publish the shielded identity so others can pay this wallet by its Solana
  // address. Returns nothing when it is already registered.
  const registration = await buildRegistrationTransaction({
    client: zolana,
    owner: signer.address,
    address: shielded,
  });
  if (registration) await sendAndConfirm(registration);

  // The private balance lives in the app. `syncWallet` reads the indexer and
  // asks the enclave to decrypt what belongs to this wallet.
  const wallet = new Wallet({ identity: shielded });

  // Deposit SOL into the private balance.
  // A deposit from a public balance reveals
  // sender, recipient, asset and amount.

  // 1. Build the deposit to the wallet's own shielded address.
  const deposit = await buildDepositTransaction({
    client: zolana,
    feePayer: signer.address,
    recipient: shielded,
    amount: DEPOSIT_AMOUNT,
  });

  // 2. Sign, send and confirm like any Solana transaction; confirmation yields
  // the landed slot.
  const depositTx = await sendAndConfirm(deposit);

  // 3. Sync the wallet, gated on the deposit's slot. The indexer returns the
  // encrypted outputs; the enclave opens them; the SDK keeps only the outputs
  // whose commitment matches the index.
  await syncWallet({
    client: zolana,
    wallet,
    keys,
    config: { requireSlot: depositTx.slot },
  });
  expectBalance("deposit", wallet.balance(SOL_MINT), DEPOSIT_AMOUNT, 1);

  // Confidential SOL transfer to another private balance.
  // A confidential transfer reveals only sender and recipient,
  // not the asset or amount.

  // 1. The recipient is any shielded address. Here it is a fresh SDK wallet
  // that keeps its own keys; a TVC wallet and a local-key wallet are the
  // same to the pool.
  const recipient = ShieldedKeypair.generate().shieldedAddress();

  // 2. Build the transfer. The SDK selects the inputs from the synced balance,
  // the enclave derives their nullifiers and completes the proof, and the
  // transaction comes back compiled with the fee payer set.
  const transfer = await buildTransferTransaction({
    client: zolana,
    wallet,
    keys,
    feePayer: signer.address,
    recipient,
    amount: TRANSFER_AMOUNT,
  });

  // 3. Sign, send and confirm. The fee payer is the wallet's own Solana
  // address; that signature authorizes the spend on chain.
  const transferTx = await sendAndConfirm(transfer);

  // 4. Sync again, gated on the transfer's slot, and read the change.
  await syncWallet({
    client: zolana,
    wallet,
    keys,
    config: { requireSlot: transferTx.slot },
  });
  expectBalance(
    "transfer",
    wallet.balance(SOL_MINT),
    DEPOSIT_AMOUNT - TRANSFER_AMOUNT,
    1,
  );

  // Withdraw SOL from the private balance to the public balance.
  // A withdrawal reveals the sender, recipient, asset, and amount.

  // 1. Build the withdrawal to the wallet's public Solana address.
  const withdrawal = await buildWithdrawalTransaction({
    client: zolana,
    wallet,
    keys,
    feePayer: signer.address,
    recipient: signer.address,
    amount: WITHDRAW_AMOUNT,
  });

  // 2. Sign, send and confirm.
  const withdrawalTx = await sendAndConfirm(withdrawal);

  // 3. Sync once more and read the remaining private balance.
  await syncWallet({
    client: zolana,
    wallet,
    keys,
    config: { requireSlot: withdrawalTx.slot },
  });
  const remaining = wallet.balance(SOL_MINT);
  expectBalance(
    "withdraw",
    remaining,
    DEPOSIT_AMOUNT - TRANSFER_AMOUNT - WITHDRAW_AMOUNT,
    1,
  );

  // 4. Read the remaining private balance and the public balance.
  const solanaBalance = await zolana.getBalance(signer.address);
  console.log(
    `withdraw private_balance=${remaining.amount} ` +
      `solana_balance=${solanaBalance} tx=${withdrawalTx.signature}`,
  );
}

await main();
