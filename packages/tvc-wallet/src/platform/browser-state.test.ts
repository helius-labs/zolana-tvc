import { describe, expect, it } from "vitest";
import { parsePersistentBrowserTvcWalletState } from "./browser-state.js";

const address = "4".repeat(44);
const checkpoint = {
  sealedWalletState: "11".repeat(64),
};
const descriptor = {
  version: 1,
  security_domain_id: "aa".repeat(32),
  environment: "development",
  turnkey_organization_id: "00000000-0000-0000-0000-00000000000b",
  turnkey_wallet_id: "wallet-1",
  address,
  allowed_clients: [],
  provisioning_signature: "33".repeat(64),
};

function baseState() {
  return {
    version: 5,
    clientKeyId: `tvc-browser-p256-${"ab".repeat(16)}`,
    walletDescriptor: descriptor,
    identity: null,
    checkpoint: null,
    registered: false,
  };
}

function readyState() {
  return {
    ...baseState(),
    identity: {
      solanaAddress: address,
      shieldedOwnerHash: "55".repeat(32),
      shieldedNullifierPublicKey: "66".repeat(32),
      shieldedViewingPublicKey: `03${"77".repeat(32)}`,
    },
    checkpoint,
    registered: true,
  };
}

describe("browser wallet state", () => {
  it("accepts descriptor-only and ready states", () => {
    expect(parsePersistentBrowserTvcWalletState(baseState())?.identity).toBeNull();
    expect(parsePersistentBrowserTvcWalletState(readyState())?.checkpoint).toEqual(
      checkpoint,
    );
  });

  it("rejects a half-written identity checkpoint", () => {
    expect(() =>
      parsePersistentBrowserTvcWalletState({ ...readyState(), checkpoint: null }),
    ).toThrowError("StorageCorrupted");
  });

  it("rejects a descriptor carrying any unknown key", () => {
    const widened: Record<string, unknown> = { ...descriptor };
    widened.turnkey_ring_signing_key_id = null;
    expect(() =>
      parsePersistentBrowserTvcWalletState({
        ...baseState(),
        walletDescriptor: widened,
      }),
    ).toThrowError("StorageCorrupted");
  });

  it("rejects application state stored in the wallet record", () => {
    expect(() =>
      parsePersistentBrowserTvcWalletState({
        ...readyState(),
        pendingSubmission: null,
      }),
    ).toThrowError("StorageCorrupted");
  });

  it("rejects an identity that does not match the descriptor address", () => {
    const ready = readyState();
    expect(() =>
      parsePersistentBrowserTvcWalletState({
        ...ready,
        identity: { ...ready.identity, solanaAddress: "5".repeat(44) },
      }),
    ).toThrowError("StorageCorrupted");
  });

  it("rejects a registered flag without an identity", () => {
    expect(() =>
      parsePersistentBrowserTvcWalletState({ ...baseState(), registered: true }),
    ).toThrowError("StorageCorrupted");
  });

  it("passes undefined through as absent state", () => {
    expect(parsePersistentBrowserTvcWalletState(undefined)).toBeNull();
  });
});
