import { writeFile } from "node:fs/promises";

import {
  P256PublicKey,
  SPL_TOKEN_PROGRAM_ID,
  ShieldedAddress,
  ShieldedPublicKey,
  buildDepositTransaction,
  buildRegistrationTransaction,
  buildRingDepositTransaction,
  buildRingLookupTableTransaction,
  buildSetMergingEnabledTransaction,
  createZolanaClient,
  type Bytes32,
  type Bytes33,
} from "@heliuslabs/zolana";
import {
  address,
  createKeyPairSignerFromBytes,
  getAddressEncoder,
  type Signature,
  type Transaction,
} from "@solana/kit";
import {
  checkpointFromBootstrapResult,
  shieldedIdentityOf,
  syncTvcWallet,
  type AssetInput,
  type AuthorizeSpendInput,
  type ShieldedIdentity,
  type SpendableOutputV1,
  type TvcWalletClient,
  type TvcWalletSyncResult,
  type VerifiedConnection,
} from "@zolana/tvc-wallet";
import { decodeLowerHex, encodeLowerHex } from "@zolana/tvc-wallet/protocol";
import { createLocalTvcWalletClient } from "@zolana/tvc-wallet/testing";
import { setTimeout as sleep } from "node:timers/promises";

import {
  currentSlot,
  publicBalance,
  signSubmitAndConfirm,
  submitTvcTransaction,
  tokenBalance,
  waitUntilFinalizedAfter,
} from "./chain.ts";
import { loadLocalE2eConfig, type LocalE2eConfig } from "./config.ts";
import {
  fetchByViewTags,
  type HeadlessZolanaClient,
  type PayloadMeta,
} from "./indexer.ts";

type WalletSync = TvcWalletSyncResult<PayloadMeta>;

const MERGE_INPUT_COUNT = 8;

function defaultShieldedAddress(identity: ShieldedIdentity): ShieldedAddress {
  const result = ShieldedAddress.fromPublicKeys(
    ShieldedPublicKey.fromEd25519(
      new Uint8Array(
        getAddressEncoder().encode(address(identity.solanaAddress)),
      ) as Bytes32,
    ),
    decodeLowerHex(identity.shieldedNullifierPublicKey) as Bytes32,
    P256PublicKey.fromBytes(
      decodeLowerHex(identity.shieldedViewingPublicKey) as Bytes33,
    ),
  );
  if (encodeLowerHex(result.ownerHash()) !== identity.shieldedOwnerHash) {
    throw new Error("ShieldedIdentityMismatch");
  }
  return result;
}

function sameAsset(output: SpendableOutputV1, asset: AssetInput): boolean {
  if (asset.type === "Sol") return output.asset.type === "Sol";
  return (
    output.asset.type === "Spl" &&
    output.asset.mint === asset.mint &&
    BigInt(output.asset.asset_id) === asset.assetId
  );
}

function privateOutputs(
  outputs: readonly SpendableOutputV1[],
  asset: AssetInput,
  ringProgramId: string | null,
): readonly SpendableOutputV1[] {
  return outputs.filter(
    (output) => sameAsset(output, asset) && output.ring_program_id === ringProgramId,
  );
}

type BalanceExpectation = Readonly<{
  asset: AssetInput;
  ringProgramId: string | null;
  amount: bigint;
  utxoCount?: number;
}>;

async function waitForWallet(
  config: LocalE2eConfig,
  label: string,
  expectations: readonly BalanceExpectation[],
  run: () => Promise<WalletSync>,
  accept: (sync: WalletSync) => boolean = () => true,
): Promise<WalletSync> {
  const deadline = Date.now() + config.syncTimeoutMs;
  let lastError: unknown;
  let lastResult: WalletSync | undefined;
  while (Date.now() < deadline) {
    try {
      const result = await run();
      lastResult = result;
      const balancesMatch = expectations.every((expectation) => {
        const matching = privateOutputs(
          result.spendableOutputs,
          expectation.asset,
          expectation.ringProgramId,
        );
        const balance = matching.reduce(
          (total, output) => total + BigInt(output.amount),
          0n,
        );
        return (
          balance === expectation.amount &&
          (expectation.utxoCount === undefined || matching.length === expectation.utxoCount)
        );
      });
      if (balancesMatch && accept(result)) return result;
      lastError = undefined;
    } catch (error) {
      lastError = error;
    }
    await sleep(config.syncPollMs);
  }
  const observed = expectations
    .map((expectation) => {
      const ring = expectation.ringProgramId ?? "default";
      const asset = expectation.asset.type === "Sol" ? "SOL" : expectation.asset.mint;
      const matching =
        lastResult === undefined
          ? []
          : privateOutputs(
              lastResult.spendableOutputs,
              expectation.asset,
              expectation.ringProgramId,
            );
      const balance = matching.reduce(
        (total, output) => total + BigInt(output.amount),
        0n,
      );
      return `${asset}@${ring}=${balance.toString()}/${matching.length}`;
    })
    .join(", ");
  throw new Error(`${label} did not converge (${observed || "no result"})`, {
    cause: lastError,
  });
}

function assertSpendBalance(label: string, observed: string, expected: bigint): void {
  if (BigInt(observed) !== expected) {
    throw new Error(`${label} prepared against ${observed}, expected ${expected.toString()}`);
  }
}

async function submitSpend(
  client: TvcWalletClient,
  connection: VerifiedConnection,
  zolana: HeadlessZolanaClient,
  input: AuthorizeSpendInput,
  expectedSourceBalance: bigint,
  timeoutMs: number,
  label: string,
): Promise<Signature> {
  const result = await client.authorizeSpend(connection, input);
  assertSpendBalance(label, result.shielded_balance_before, expectedSourceBalance);
  return submitTvcTransaction(
    zolana,
    result.signed_transaction,
    result.transaction_signature,
    timeoutMs,
  );
}

async function main(): Promise<void> {
  const config = await loadLocalE2eConfig();
  const signer = await createKeyPairSignerFromBytes(config.solanaKeypairBytes);
  const client = createLocalTvcWalletClient({
    endpoint: config.tvcEndpoint,
    solanaAddress: signer.address,
  });
  const sol: AssetInput = Object.freeze({ type: "Sol" });
  const spl: AssetInput = Object.freeze({
    type: "Spl",
    mint: address(config.splMint),
    assetId: config.splAssetId,
  });
  const ringAProgramId = address(config.ringAProgramId);
  const ringBProgramId = address(config.ringBProgramId);

  console.log("[setup] loading the disposable local wallet fixture");
  console.log(`        wallet ${signer.address}`);
  console.log(`        SPL ${spl.mint} (asset ${spl.assetId.toString()})`);
  console.log(`        ring A ${ringAProgramId}`);
  console.log(`        ring B ${ringBProgramId}`);

  const connection = await client.connectAndVerify();
  console.log(`        TVC release ${connection.releaseId}`);

  const bootstrap = await client.bootstrapKeyholder(connection, {
    ...(config.expectedIdentity === undefined
      ? {}
      : { expectedIdentity: config.expectedIdentity }),
  });
  const identity = shieldedIdentityOf(bootstrap);
  if (identity.solanaAddress !== signer.address) {
    throw new Error("TVC bootstrapped a different Solana wallet");
  }
  if (config.identityPath && config.expectedIdentity === undefined) {
    await writeFile(config.identityPath, `${JSON.stringify(identity, null, 2)}\n`, {
      mode: 0o600,
      flag: "wx",
    });
    console.log(`        pinned identity in ${config.identityPath}`);
  } else if (config.expectedIdentity === undefined) {
    throw new Error("TVC_IDENTITY_PATH is required for a first local bootstrap");
  }
  const checkpoint = checkpointFromBootstrapResult(bootstrap);

  const zolana = await createZolanaClient({
    solanaRpcUrl: config.solanaRpcUrl,
    indexerUrl: config.indexerUrl,
    ...(config.proverUrl === undefined ? {} : { proverUrl: config.proverUrl }),
    allowInsecureHttp: config.allowInsecureHttp,
    indexerConfig: {
      poll: { numRetries: 5, delayMs: 500n, maxDelayMs: 2_000n },
    },
  });
  const shieldedAddress = defaultShieldedAddress(identity);

  console.log("[register] publishing the wallet's shielded identity");
  const registration = await buildRegistrationTransaction({
    client: zolana,
    owner: signer.address,
    address: shieldedAddress,
  });
  if (registration) {
    console.log(
      `           ${await signSubmitAndConfirm(zolana, registration, signer, config.syncTimeoutMs)}`,
    );
  } else {
    console.log("           registration already matches");
  }

  const identityTag = encodeLowerHex(shieldedAddress.signingPublicKey.confidentialViewTag());
  const seenPlaintextTransactions = new Set<string>();
  const syncAt = async (requireSlot: bigint): Promise<WalletSync> => {
    const result = await syncTvcWallet(client, {
      connection,
      checkpoint,
      fetchByViewTags: fetchByViewTags(zolana, requireSlot),
      additionalViewTags: [identityTag],
      deriveEnclaveTags: true,
    });
    for (const payload of result.payloads) {
      if (payload.decrypted.type === "Plaintext") {
        seenPlaintextTransactions.add(payload.meta.transactionSignature);
      }
    }
    return result;
  };
  const synced = async (
    label: string,
    expectations: readonly BalanceExpectation[],
    requireSlot: bigint,
    transaction?: Signature,
  ): Promise<WalletSync> =>
    waitForWallet(
      config,
      label,
      expectations,
      () => syncAt(requireSlot),
      transaction === undefined
        ? undefined
        : () => seenPlaintextTransactions.has(transaction),
    );
  const submitSpendAndSync = async (
    label: string,
    input: AuthorizeSpendInput,
    expectedSourceBalance: bigint,
    expectations: readonly BalanceExpectation[],
  ): Promise<WalletSync> => {
    const signature = await submitSpend(
      client,
      connection,
      zolana,
      input,
      expectedSourceBalance,
      config.syncTimeoutMs,
      label,
    );
    return synced(
      `${label} sync`,
      expectations,
      await currentSlot(zolana),
      signature,
    );
  };

  console.log("[baseline] deriving tags and verifying an empty private fixture");
  const baseline = await synced(
    "baseline sync",
    [
      { asset: sol, ringProgramId: null, amount: 0n },
      { asset: spl, ringProgramId: null, amount: 0n },
      { asset: sol, ringProgramId: ringAProgramId, amount: 0n },
      { asset: sol, ringProgramId: ringBProgramId, amount: 0n },
    ],
    await currentSlot(zolana),
  );
  if (baseline.viewTags.length < 2) {
    throw new Error("DeriveViewTags returned no recipient bootstrap tag");
  }
  if (config.requireEmptyPrivateBalance && baseline.spendableOutputs.length !== 0) {
    throw new Error(
      `the CI fixture private balance must start empty; observed ${baseline.spendableOutputs.length} UTXOs`,
    );
  }
  const publicSolBefore = await publicBalance(zolana, identity.solanaAddress);
  const publicSplBefore = await tokenBalance(zolana, config.splTokenAccount);
  const mergeTotal = config.mergeInputLamports * BigInt(MERGE_INPUT_COUNT);
  const largestPrincipal = [
    config.depositLamports,
    config.ringBridgeLamports,
    mergeTotal,
  ].reduce((largest, value) => (value > largest ? value : largest));
  if (publicSolBefore < largestPrincipal + config.feeReserveLamports) {
    throw new Error("fixture does not have enough public SOL for principals and fees");
  }
  if (publicSplBefore < config.splAmount) {
    throw new Error("fixture does not have enough public SPL for the cycle");
  }
  console.log(
    `           public SOL=${publicSolBefore.toString()} SPL=${publicSplBefore.toString()}`,
  );

  const runDefaultAssetCycle = async (cycle: {
    label: string;
    asset: AssetInput;
    amount: bigint;
    transferAmount: bigint;
    buildDeposit: () => Promise<Transaction>;
  }): Promise<void> => {
    console.log(`[default ${cycle.label}] shield -> private self-transfer -> unshield`);
    const depositSignature = await signSubmitAndConfirm(
      zolana,
      await cycle.buildDeposit(),
      signer,
      config.syncTimeoutMs,
    );
    const funded = [{ asset: cycle.asset, ringProgramId: null, amount: cycle.amount }];
    await synced(
      `${cycle.label} shield sync`,
      funded,
      await currentSlot(zolana),
      depositSignature,
    );
    await submitSpendAndSync(
      `default ${cycle.label} transfer`,
      {
        checkpoint,
        source: { kind: "default" },
        settlement: {
          kind: "transfer",
          asset: cycle.asset,
          recipient: identity.solanaAddress,
          amount: cycle.transferAmount,
          destination: { kind: "default" },
        },
      },
      cycle.amount,
      funded,
    );
    await submitSpend(
      client,
      connection,
      zolana,
      {
        checkpoint,
        source: { kind: "default" },
        settlement: {
          kind: "withdrawal",
          asset: cycle.asset,
          recipient: identity.solanaAddress,
          amount: cycle.amount,
        },
      },
      cycle.amount,
      config.syncTimeoutMs,
      `default ${cycle.label} withdrawal`,
    );
    await synced(
      `${cycle.label} withdrawal sync`,
      [{ asset: cycle.asset, ringProgramId: null, amount: 0n }],
      await currentSlot(zolana),
    );
  };

  await runDefaultAssetCycle({
    label: "SOL",
    asset: sol,
    amount: config.depositLamports,
    transferAmount: config.transferLamports,
    buildDeposit: () =>
      buildDepositTransaction({
        client: zolana,
        feePayer: signer.address,
        recipient: shieldedAddress,
        amount: config.depositLamports,
      }),
  });
  await runDefaultAssetCycle({
    label: "SPL",
    asset: spl,
    amount: config.splAmount,
    transferAmount: config.splAmount,
    buildDeposit: () =>
      buildDepositTransaction({
        client: zolana,
        feePayer: signer.address,
        recipient: shieldedAddress,
        asset: address(config.splMint),
        splTokenAccount: address(config.splTokenAccount),
        splTokenProgram: SPL_TOKEN_PROGRAM_ID,
        amount: config.splAmount,
      }),
  });

  console.log("[rings] creating lookup tables for both custom domains");
  const createLookupTable = async (ringProgramId: string): Promise<string> => {
    const table = await buildRingLookupTableTransaction({
      client: zolana,
      ringProgramId: address(ringProgramId),
      feePayer: signer.address,
    });
    await signSubmitAndConfirm(
      zolana,
      table.transaction,
      signer,
      config.syncTimeoutMs,
      "finalized",
    );
    await waitUntilFinalizedAfter(zolana, table.slot, config.syncTimeoutMs);
    return table.address;
  };
  const ringALookupTable = await createLookupTable(ringAProgramId);
  const ringBLookupTable = await createLookupTable(ringBProgramId);

  console.log("[rings] public deposit A -> default bridge -> B -> default -> public");
  const ringDeposit = await buildRingDepositTransaction({
    client: zolana,
    ringProgramId: ringAProgramId,
    feePayer: signer.address,
    recipient: shieldedAddress,
    amount: config.ringBridgeLamports,
  });
  const ringDepositSignature = await signSubmitAndConfirm(
    zolana,
    ringDeposit,
    signer,
    config.syncTimeoutMs,
  );
  await synced(
    "ring A deposit sync",
    [{ asset: sol, ringProgramId: ringAProgramId, amount: config.ringBridgeLamports }],
    await currentSlot(zolana),
    ringDepositSignature,
  );

  const bridgeInDefault = await submitSpendAndSync(
    "ring A to default",
    {
      checkpoint,
      source: {
        kind: "ring",
        programId: ringAProgramId,
        lookupTable: ringALookupTable,
      },
      settlement: {
        kind: "transfer",
        asset: sol,
        recipient: identity.solanaAddress,
        amount: config.ringBridgeLamports,
        destination: { kind: "default" },
      },
    },
    config.ringBridgeLamports,
    [
      { asset: sol, ringProgramId: ringAProgramId, amount: 0n },
      {
        asset: sol,
        ringProgramId: null,
        amount: config.ringBridgeLamports,
        utxoCount: 1,
      },
    ],
  );
  const bridgeOutput = privateOutputs(bridgeInDefault.spendableOutputs, sol, null)[0];
  if (bridgeOutput === undefined) throw new Error("ring bridge output is missing");

  await submitSpendAndSync(
    "default to ring B",
    {
      checkpoint,
      source: { kind: "default" },
      settlement: {
        kind: "transfer",
        asset: sol,
        recipient: identity.solanaAddress,
        amount: config.ringBridgeLamports,
        destination: {
          kind: "ring",
          programId: ringBProgramId,
          lookupTable: ringBLookupTable,
        },
      },
      inputCommitments: [bridgeOutput.commitment],
    },
    config.ringBridgeLamports,
    [
      { asset: sol, ringProgramId: null, amount: 0n },
      { asset: sol, ringProgramId: ringBProgramId, amount: config.ringBridgeLamports },
    ],
  );

  await submitSpendAndSync(
    "within ring B",
    {
      checkpoint,
      source: {
        kind: "ring",
        programId: ringBProgramId,
        lookupTable: ringBLookupTable,
      },
      settlement: {
        kind: "transfer",
        asset: sol,
        recipient: identity.solanaAddress,
        amount: config.ringBridgeLamports,
        destination: {
          kind: "ring",
          programId: ringBProgramId,
          lookupTable: ringBLookupTable,
        },
      },
    },
    config.ringBridgeLamports,
    [{ asset: sol, ringProgramId: ringBProgramId, amount: config.ringBridgeLamports }],
  );

  await submitSpendAndSync(
    "ring B to default",
    {
      checkpoint,
      source: {
        kind: "ring",
        programId: ringBProgramId,
        lookupTable: ringBLookupTable,
      },
      settlement: {
        kind: "transfer",
        asset: sol,
        recipient: identity.solanaAddress,
        amount: config.ringBridgeLamports,
        destination: { kind: "default" },
      },
    },
    config.ringBridgeLamports,
    [
      { asset: sol, ringProgramId: ringBProgramId, amount: 0n },
      { asset: sol, ringProgramId: null, amount: config.ringBridgeLamports },
    ],
  );
  await submitSpend(
    client,
    connection,
    zolana,
    {
      checkpoint,
      source: { kind: "default" },
      settlement: {
        kind: "withdrawal",
        asset: sol,
        recipient: identity.solanaAddress,
        amount: config.ringBridgeLamports,
      },
    },
    config.ringBridgeLamports,
    config.syncTimeoutMs,
    "ring bridge withdrawal",
  );
  await synced(
    "ring bridge withdrawal sync",
    [{ asset: sol, ringProgramId: null, amount: 0n }],
    await currentSlot(zolana),
  );

  console.log(`[merge] creating ${MERGE_INPUT_COUNT} default SOL UTXOs and consolidating 8 -> 1`);
  const enableMerging = await buildSetMergingEnabledTransaction({
    client: zolana,
    owner: signer.address,
    enabled: true,
  });
  await signSubmitAndConfirm(zolana, enableMerging, signer, config.syncTimeoutMs);
  let lastMergeDeposit: Signature | undefined;
  for (let index = 0; index < MERGE_INPUT_COUNT; index += 1) {
    const transaction = await buildDepositTransaction({
      client: zolana,
      feePayer: signer.address,
      recipient: shieldedAddress,
      amount: config.mergeInputLamports,
    });
    lastMergeDeposit = await signSubmitAndConfirm(
      zolana,
      transaction,
      signer,
      config.syncTimeoutMs,
    );
  }
  if (lastMergeDeposit === undefined) throw new Error("merge fixture did not deposit inputs");
  await synced(
    "merge inputs sync",
    [{ asset: sol, ringProgramId: null, amount: mergeTotal, utxoCount: MERGE_INPUT_COUNT }],
    await currentSlot(zolana),
    lastMergeDeposit,
  );
  await submitSpend(
    client,
    connection,
    zolana,
    {
      checkpoint,
      source: { kind: "default" },
      settlement: { kind: "consolidate", asset: sol },
    },
    mergeTotal,
    config.syncTimeoutMs,
    "default SOL merge",
  );
  await synced(
    "merge output sync",
    [{ asset: sol, ringProgramId: null, amount: mergeTotal, utxoCount: 1 }],
    await currentSlot(zolana),
  );
  await submitSpend(
    client,
    connection,
    zolana,
    {
      checkpoint,
      source: { kind: "default" },
      settlement: {
        kind: "withdrawal",
        asset: sol,
        recipient: identity.solanaAddress,
        amount: mergeTotal,
      },
    },
    mergeTotal,
    config.syncTimeoutMs,
    "merged SOL withdrawal",
  );

  const finalSync = await synced(
    "final wallet sync",
    [
      { asset: sol, ringProgramId: null, amount: 0n },
      { asset: spl, ringProgramId: null, amount: 0n },
      { asset: sol, ringProgramId: ringAProgramId, amount: 0n },
      { asset: sol, ringProgramId: ringBProgramId, amount: 0n },
    ],
    await currentSlot(zolana),
  );
  const publicSolAfter = await publicBalance(zolana, identity.solanaAddress);
  const publicSplAfter = await tokenBalance(zolana, config.splTokenAccount);
  if (
    publicSolAfter > publicSolBefore ||
    publicSolBefore - publicSolAfter > config.feeReserveLamports
  ) {
    throw new Error(
      `unexpected public SOL delta: before=${publicSolBefore.toString()} after=${publicSolAfter.toString()}`,
    );
  }
  if (publicSplAfter !== publicSplBefore) {
    throw new Error(
      `SPL cycle did not restore the fixture: before=${publicSplBefore.toString()} after=${publicSplAfter.toString()}`,
    );
  }
  if (finalSync.spendableOutputs.length !== 0) {
    throw new Error(`final fixture still has ${finalSync.spendableOutputs.length} spendable UTXOs`);
  }
  console.log(
    `PASS release=${connection.releaseId} SOL-fees=${(publicSolBefore - publicSolAfter).toString()} SPL=${publicSplAfter.toString()} private=0`,
  );
}

await main();
