import { describe, expect, it, vi } from "vitest";
import { createTvcEnclaveWallet } from "./wallet.js";
import { parseEnclaveBrowserWalletState } from "./browser-state.js";
import type { EnclaveBrowserWalletState } from "./browser-state.js";
import type { VerifiedConnection } from "../client/connection.js";
import type { TvcEnclaveWalletClient } from "./index.js";

const ADDRESS = "4".repeat(44);
const CLIENT_KEY_ID = `tvc-browser-p256-${"ab".repeat(16)}`;
const CONNECTION = {} as VerifiedConnection;

function checkpoint(version: string) {
  return {
    sealedWalletState: version.repeat(2).padStart(64, "0"),
    stateVersion: version,
    stateDigest: version.padStart(2, "0").repeat(32),
  };
}

function baseState(): EnclaveBrowserWalletState {
  return {
    version: 1,
    clientKeyId: CLIENT_KEY_ID,
    turnkeyServicePublicKey: `02${"44".repeat(32)}`,
    walletDescriptor: {
      version: 1,
      wallet_id: "wallet-1",
      provisioning_signature: "33".repeat(64),
      turnkey_signing_target: { type: "HdWalletAccount", address: ADDRESS },
      allowed_clients: [
        {
          client_key_id: CLIENT_KEY_ID,
          scheme: "p256-sha256",
          allowed_operations: ["BootstrapEd25519", "PrepareWallet", "ShieldSol", "BuildTransfer"],
        },
      ],
    } as unknown as EnclaveBrowserWalletState["walletDescriptor"],
    bootstrap: null,
    checkpoint: null,
    registered: false,
    shieldedBalanceRaw: "0",
    pendingSubmission: null,
    transactions: [],
  };
}

function evidence() {
  return {
    turnkey_app_proofs: [],
    evidence_classification: "CryptographicallyValidButUnbound" as const,
  };
}

function stubClient(overrides: Partial<TvcEnclaveWalletClient> = {}): TvcEnclaveWalletClient {
  return {
    connectAndVerify: vi.fn(),
    createWallet: vi.fn(),
    bootstrapEd25519: vi.fn(async () => ({
      type: "BootstrapEd25519" as const,
      solana_address: ADDRESS,
      shielded_owner_hash: "55".repeat(32),
      shielded_nullifier_public_key: "66".repeat(32),
      shielded_viewing_public_key: `03${"77".repeat(32)}`,
      sealed_wallet_state: checkpoint("1").sealedWalletState,
      state_version: "1",
      state_digest: checkpoint("1").stateDigest,
      turnkey_activity_id: "activity-1",
      ...evidence(),
    })),
    prepareWallet: vi.fn(async () => ({
      type: "PrepareWallet" as const,
      signed_registration_transaction: "aabb",
      registration_signature: "5".repeat(44),
      registration_activity_id: "activity-2",
      registration_app_proofs: [],
      sealed_wallet_state: checkpoint("2").sealedWalletState,
      state_version: "2",
      state_digest: checkpoint("2").stateDigest,
      evidence_classification: "CryptographicallyValidButUnbound" as const,
    })),
    shieldSol: vi.fn(async () => ({
      type: "ShieldSol" as const,
      signed_transaction: "ccdd",
      transaction_signature: "6".repeat(44),
      public_balance_before: "1000",
      shielded_balance_before: "0",
      sealed_wallet_state: checkpoint("3").sealedWalletState,
      state_version: "3",
      state_digest: checkpoint("3").stateDigest,
      turnkey_activity_id: "activity-3",
      ...evidence(),
    })),
    buildTransfer: vi.fn(async () => ({
      type: "BuildTransfer" as const,
      signed_transaction: "eeff",
      transaction_signature: "7".repeat(44),
      shielded_balance_before: "500",
      sealed_wallet_state: checkpoint("4").sealedWalletState,
      state_version: "4",
      state_digest: checkpoint("4").stateDigest,
      turnkey_activity_id: "activity-4",
      ...evidence(),
    })),
    ...overrides,
  } as TvcEnclaveWalletClient;
}

async function makeWallet(state = baseState(), client = stubClient()) {
  const persisted: EnclaveBrowserWalletState[] = [];
  const wallet = await createTvcEnclaveWallet({
    client,
    connection: CONNECTION,
    clientKeyId: CLIENT_KEY_ID,
    state,
    // Every persisted state must satisfy the on-disk schema, so the facade can
    // never write a record it would later refuse to load.
    persistState: async (next) => {
      parseEnclaveBrowserWalletState(next);
      persisted.push(next);
    },
    nowMs: () => 1_750_000_000_000n,
  });
  return { wallet, client, persisted };
}

describe("TvcEnclaveWallet journal", () => {
  it("bootstraps once and adopts the first checkpoint immediately", async () => {
    const { wallet, client, persisted } = await makeWallet();
    expect(client.bootstrapEd25519).toHaveBeenCalledTimes(1);
    expect(wallet.solanaAddress).toBe(ADDRESS);
    expect(wallet.registered).toBe(false);
    expect(persisted.at(-1)?.checkpoint?.stateVersion).toBe("1");
  });

  it("rejects a bootstrap result for a different descriptor address", async () => {
    const client = stubClient({
      bootstrapEd25519: vi.fn(async () => ({
        ...(await stubClient().bootstrapEd25519(CONNECTION)),
        solana_address: "9".repeat(44),
      })),
    });
    await expect(makeWallet(baseState(), client)).rejects.toThrowError("ReleaseBindingMismatch");
  });

  it("journals a registration before it is confirmed and only then registers", async () => {
    const { wallet, persisted } = await makeWallet();
    const pending = await wallet.prepareRegistration(new Uint8Array(32));

    // Journaled, but the checkpoint has not moved and the wallet is not yet
    // registered: the transaction has not landed.
    expect(pending.kind).toBe("PrepareWallet");
    expect(wallet.registered).toBe(false);
    expect(persisted.at(-1)?.checkpoint?.stateVersion).toBe("1");
    expect(persisted.at(-1)?.pendingSubmission?.nextCheckpoint.stateVersion).toBe("2");

    await wallet.settlePending(pending.transactionSignature);
    expect(wallet.registered).toBe(true);
    expect(persisted.at(-1)?.checkpoint?.stateVersion).toBe("2");
    expect(persisted.at(-1)?.pendingSubmission).toBeNull();
  });

  it("keeps the previous checkpoint when a transaction is abandoned", async () => {
    const { wallet, persisted } = await makeWallet();
    const pending = await wallet.prepareRegistration(new Uint8Array(32));
    await wallet.abandonPending(pending.transactionSignature);

    // The whole point of the journal: an expired transaction must leave the
    // wallet able to spend the same inputs again.
    expect(wallet.registered).toBe(false);
    expect(persisted.at(-1)?.checkpoint?.stateVersion).toBe("1");
    expect(persisted.at(-1)?.pendingSubmission).toBeNull();
    expect(wallet.pendingTransaction()).toBeNull();
  });

  it("credits a settled shield and records it in history", async () => {
    const { wallet } = await makeWallet();
    await wallet.settlePending(
      (await wallet.prepareRegistration(new Uint8Array(32))).transactionSignature,
    );
    const shield = await wallet.shieldSol(500n);
    expect(wallet.view().shieldedBalanceRaw).toBe("0");

    await wallet.settlePending(shield.transactionSignature);
    const view = wallet.view();
    expect(view.shieldedBalanceRaw).toBe("500");
    expect(view.transactions[0]).toMatchObject({
      type: "ShieldSol",
      amountRaw: "500",
      balanceAfterRaw: "500",
      recipient: null,
    });
  });

  it("debits a settled transfer from the balance the enclave reported", async () => {
    const { wallet } = await makeWallet();
    await wallet.settlePending(
      (await wallet.prepareRegistration(new Uint8Array(32))).transactionSignature,
    );
    const transfer = await wallet.transfer({
      asset: { type: "Sol" },
      recipient: "8".repeat(44),
      amount: 200n,
      proverProfileId: "prover-1",
    });
    await wallet.settlePending(transfer.transactionSignature);
    expect(wallet.view().shieldedBalanceRaw).toBe("300");
    expect(wallet.view().transactions[0]).toMatchObject({
      type: "BuildTransfer",
      amountRaw: "200",
      balanceAfterRaw: "300",
    });
  });

  it("refuses a transfer larger than the balance the enclave spent from", async () => {
    const { wallet } = await makeWallet();
    await wallet.settlePending(
      (await wallet.prepareRegistration(new Uint8Array(32))).transactionSignature,
    );
    await expect(
      wallet.transfer({
        asset: { type: "Sol" },
        recipient: "8".repeat(44),
        amount: 600n,
        proverProfileId: "prover-1",
      }),
    ).rejects.toThrowError("ReleaseBindingMismatch");
  });

  it("allows only one in-flight transaction at a time", async () => {
    const { wallet } = await makeWallet();
    await wallet.prepareRegistration(new Uint8Array(32));
    await expect(wallet.prepareRegistration(new Uint8Array(32))).rejects.toThrowError(
      "OperationNotAllowed",
    );
  });

  it("refuses to settle a signature it did not journal", async () => {
    const { wallet } = await makeWallet();
    const pending = await wallet.prepareRegistration(new Uint8Array(32));
    await expect(wallet.settlePending("9".repeat(44))).rejects.toThrowError(
      "ReleaseBindingMismatch",
    );
    await expect(wallet.settlePending(pending.transactionSignature)).resolves.toBeUndefined();
  });

  it("refuses spending before registration", async () => {
    const { wallet } = await makeWallet();
    await expect(wallet.shieldSol(1n)).rejects.toThrowError("OperationNotAllowed");
  });

  it("rejects state whose descriptor does not grant this device key", async () => {
    const state = baseState();
    await expect(
      makeWallet({ ...state, clientKeyId: `tvc-browser-p256-${"cd".repeat(16)}` }),
    ).rejects.toThrowError("StorageCorrupted");
  });

  it("resumes a journaled transaction from disk without re-issuing it", async () => {
    const first = await makeWallet();
    const pending = await first.wallet.prepareRegistration(new Uint8Array(32));
    const onDisk = first.persisted.at(-1);
    expect(onDisk).toBeDefined();

    // A reload is the crash case: the transaction may already be on chain, so
    // the facade must surface the same journal rather than bootstrap or
    // re-issue anything.
    const client = stubClient();
    const resumed = await makeWallet(onDisk as EnclaveBrowserWalletState, client);
    expect(client.bootstrapEd25519).not.toHaveBeenCalled();
    expect(client.prepareWallet).not.toHaveBeenCalled();
    expect(resumed.wallet.pendingTransaction()).toEqual(pending);
    expect(resumed.wallet.registered).toBe(false);

    // And settling on the reloaded facade advances exactly as it would have.
    await resumed.wallet.settlePending(pending.transactionSignature);
    expect(resumed.wallet.registered).toBe(true);
    expect(resumed.persisted.at(-1)?.checkpoint?.stateVersion).toBe("2");
  });
});
