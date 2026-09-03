import {
  keyedWalletSnapshotCipher,
  walletSnapshotKey,
  type Bytes32,
  type WalletStateCipher,
} from "@heliuslabs/zolana";
import { sha256 } from "@noble/hashes/sha256";

import type { TvcKeys } from "./keys.js";

/**
 * The first-nullifier slot of the per-transaction key that keys the snapshot.
 * A nullifier is a BN254 field element, below 0x30..., so a value whose first
 * byte is 0xff is never one, and the key it selects belongs to no transaction.
 */
const SNAPSHOT_KEY_CONTEXT: Bytes32 = (() => {
  const context = sha256(new TextEncoder().encode("zolana-tvc/wallet-snapshot-key/v1"));
  context[0] = 0xff;
  return context as Bytes32;
})();

/**
 * The SDK's sealed snapshot cipher for a wallet the enclave holds. The
 * enclave mints one per-transaction viewing key under a context no
 * transaction can have; that key is the snapshot key's material, so the
 * snapshot opens for anyone who can drive this wallet's enclave operations and
 * for nobody else. The material is wiped once the AES key is imported.
 */
export async function snapshotCipher(keys: TvcKeys): Promise<WalletStateCipher> {
  const [viewingPublicKey] = keys.viewingPublicKeys();
  if (viewingPublicKey === undefined) throw new Error("MissingViewingKey");
  const [transactionKey] = await keys.transactionKeys([
    { viewingPublicKey, firstNullifier: SNAPSHOT_KEY_CONTEXT },
  ]);
  if (transactionKey === undefined) throw new Error("BatchMismatch");
  try {
    return keyedWalletSnapshotCipher(
      keys.address(),
      await walletSnapshotKey(transactionKey.secretBytes()),
    );
  } finally {
    transactionKey.destroy();
  }
}
