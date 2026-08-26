import {
  ClientEd25519WalletAuthority,
  initializePoseidon,
  type Bytes32,
  type Bytes64,
} from "@heliuslabs/zolana";
import { ed25519DerivationMessage } from "@heliuslabs/zolana/keypair";
import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { beforeAll, describe, expect, it, vi } from "vitest";
import type { TvcWalletClient, VerifiedConnection } from "../client/index.js";
import { encodeLowerHex } from "../protocol/hex.js";
import type { BootstrapClientEd25519Result, WalletDescriptorV1 } from "../protocol/types.js";
import type { PersistentBrowserTvcAuthorizer } from "./browser-authorizer.js";
import type { PersistentBrowserTvcWalletState } from "./browser-state.js";
import { createTvcShieldedWallet } from "./tvc-shielded-wallet.js";

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function encodeBase58(bytes: Uint8Array): string {
  let leadingZeroes = 0;
  while (leadingZeroes < bytes.length && bytes[leadingZeroes] === 0) {
    leadingZeroes += 1;
  }
  if (leadingZeroes === bytes.length) return "1".repeat(leadingZeroes);
  const digits = [0];
  for (let index = leadingZeroes; index < bytes.length; index += 1) {
    let carry = bytes[index] ?? 0;
    for (let digit = 0; digit < digits.length; digit += 1) {
      carry += (digits[digit] ?? 0) * 256;
      digits[digit] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }
  return (
    "1".repeat(leadingZeroes) +
    digits
      .reverse()
      .map((digit) => BASE58_ALPHABET[digit])
      .join("")
  );
}

function browserAuthorizer(): PersistentBrowserTvcAuthorizer {
  const values = new Map<string, Uint8Array>();
  let counter = 0;
  return {
    clientKeyId: `tvc-browser-p256-${"11".repeat(16)}`,
    clientPublicKey: `04${"22".repeat(64)}`,
    authorizer: {
      clientKeyId: `tvc-browser-p256-${"11".repeat(16)}`,
      authorizeTvcRequest: async () => new Uint8Array(64),
    },
    async seal(plaintext) {
      counter += 1;
      const ciphertext = counter.toString(16).padStart(32, "0");
      values.set(ciphertext, plaintext.slice());
      return { version: 1, nonce: "33".repeat(12), ciphertext };
    },
    async open(sealed) {
      const value = values.get(sealed.ciphertext);
      if (!value) throw new Error("missing sealed test value");
      return value.slice();
    },
  };
}

async function fixture() {
  const signingSecret = sha256(new TextEncoder().encode("facade-wallet"));
  const signingPublic = ed25519.getPublicKey(signingSecret);
  const solanaAddress = encodeBase58(signingPublic);
  const derivationSeed = ed25519.sign(ed25519DerivationMessage(signingPublic as Bytes32), signingSecret);
  const authority = ClientEd25519WalletAuthority.fromDerivationSeed({
    solanaPublicKey: solanaAddress as never,
    derivationSeed: derivationSeed as Bytes64,
  });
  const identity = await authority.shieldedAddress();
  const authorizer = browserAuthorizer();
  const descriptor: WalletDescriptorV1 = {
    version: 1,
    wallet_id: "facade-wallet",
    security_domain_id: "44".repeat(32),
    turnkey_parent_organization_id: "parent",
    turnkey_organization_id: "organization",
    turnkey_signing_target: {
      type: "HdWalletAccount",
      turnkey_wallet_id: "turnkey-wallet",
      wallet_account_id: "turnkey-account",
      address: solanaAddress,
      derivation_path: "m/44'/501'/0'/0'",
    },
    turnkey_service_user_id: "service-user",
    turnkey_api_key_id: "api-key",
    expected_ed25519_public_key: encodeLowerHex(signingPublic),
    allowed_clients: [
      {
        client_key_id: authorizer.clientKeyId,
        scheme: "p256-sha256",
        client_public_key: authorizer.clientPublicKey,
        allowed_operations: ["BootstrapClientEd25519", "AuthorizeDefaultRingTransfer"],
        may_rotate_descriptor: false,
      },
    ],
    policy_version: "1",
    previous_descriptor_digest: null,
    environment: "development",
    provisioning_key_id: "provisioner",
    owner_authorization_key: null,
    recovery_binding: null,
    provisioning_signature: "55".repeat(64),
    owner_authorization: null,
    prior_client_authorization: null,
  };
  const result: BootstrapClientEd25519Result = {
    type: "BootstrapClientEd25519",
    solana_address: solanaAddress,
    shielded_owner_hash: encodeLowerHex(identity.ownerHash()),
    shielded_nullifier_public_key: encodeLowerHex(identity.nullifierPublicKey),
    shielded_viewing_public_key: encodeLowerHex(identity.viewingPublicKey.toBytes()),
    derivation_seed: encodeLowerHex(derivationSeed),
    derivation_suite: "zolana-ed25519-role-expansion-v1",
    turnkey_activity_id: "bootstrap-activity",
    turnkey_app_proofs: [],
    evidence_classification: "CryptographicallyValidButUnbound",
  };
  const state: PersistentBrowserTvcWalletState = {
    version: 1,
    clientKeyId: authorizer.clientKeyId,
    turnkeyServicePublicKey: `02${"66".repeat(32)}`,
    walletDescriptor: descriptor,
    bootstrap: null,
    sealedWalletState: null,
    registered: false,
    pendingSubmission: null,
  };
  return { authorizer, result, solanaAddress, state };
}

describe("TvcShieldedWallet facade", () => {
  beforeAll(() => initializePoseidon());

  it("bootstraps once, persists encrypted state, and restores without TVC", async () => {
    const input = await fixture();
    const bootstrapClientEd25519 = vi.fn(async () => input.result);
    const client = {
      connectAndVerify: vi.fn(),
      bootstrapClientEd25519,
      authorizeDefaultRingTransfer: vi.fn(),
    } as unknown as TvcWalletClient;
    let persisted = input.state;
    const persistState = vi.fn(async (state: PersistentBrowserTvcWalletState) => {
      persisted = state;
    });
    const connection = {} as VerifiedConnection;

    const wallet = await createTvcShieldedWallet({
      client,
      connection,
      authorizer: input.authorizer,
      state: input.state,
      zolanaClientConfig: {},
      persistState,
    });
    expect(wallet.solanaAddress).toBe(input.solanaAddress);
    expect(wallet.registered).toBe(false);
    expect(persisted.bootstrap?.sealedDerivationSeed.ciphertext).toBeDefined();
    expect(persisted.sealedWalletState?.ciphertext).toBeDefined();
    expect(bootstrapClientEd25519).toHaveBeenCalledTimes(1);

    await wallet.markRegistered();
    expect(persisted.registered).toBe(true);
    const restored = await createTvcShieldedWallet({
      client,
      connection,
      authorizer: input.authorizer,
      state: persisted,
      zolanaClientConfig: {},
      persistState,
    });
    expect(restored.registered).toBe(true);
    expect(bootstrapClientEd25519).toHaveBeenCalledTimes(1);
    expect("signMessage" in restored).toBe(false);
    expect("signTransaction" in restored).toBe(false);
    expect("nullifierKey" in restored).toBe(false);

    const signedTransaction = "66".repeat(100);
    const transactionSignature = "7".repeat(80);
    const resumed = await createTvcShieldedWallet({
      client,
      connection,
      authorizer: input.authorizer,
      state: {
        ...persisted,
        pendingSubmission: {
          type: "DefaultRingTransfer",
          intentDigest: "77".repeat(32),
          signedTransaction,
          transactionSignature,
          createdAtMs: "1787520000000",
        },
      },
      zolanaClientConfig: {},
      persistState,
    });
    expect(resumed.pendingDefaultRingTransaction()).toEqual({
      kind: "transfer",
      intentDigest: "77".repeat(32),
      signedTransaction: new Uint8Array(100).fill(0x66),
      transactionSignature,
    });
    await expect(resumed.expireDefaultRingTransaction("another-signature")).rejects.toThrowError(
      "ReleaseBindingMismatch",
    );
    await resumed.expireDefaultRingTransaction(transactionSignature);
    expect(persisted.pendingSubmission).toBeNull();
  });

  it("rejects a bootstrap result for another descriptor before persisting", async () => {
    const input = await fixture();
    const persistState = vi.fn();
    const client = {
      bootstrapClientEd25519: vi.fn(async () => ({
        ...input.result,
        solana_address: "4".repeat(44),
      })),
    } as unknown as TvcWalletClient;
    await expect(
      createTvcShieldedWallet({
        client,
        connection: {} as VerifiedConnection,
        authorizer: input.authorizer,
        state: input.state,
        zolanaClientConfig: {},
        persistState,
      }),
    ).rejects.toThrowError("ReleaseBindingMismatch");
    expect(persistState).not.toHaveBeenCalled();
  });
});
