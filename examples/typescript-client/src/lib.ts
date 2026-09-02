import "dotenv/config";

import { webcrypto } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";

import {
  address,
  assertIsFullySignedTransaction,
  assertIsTransactionWithinSizeLimit,
  createKeyPairSignerFromBytes,
  getPublicKeyFromAddress,
  getSignatureFromTransaction,
  getTransactionDecoder,
  getTransactionEncoder,
  sendTransactionWithoutConfirmingFactory,
  signTransactionWithSigners,
  verifySignature,
  type Address,
  type Signature,
  type SignatureDictionary,
  type Transaction,
  type TransactionPartialSigner,
} from "@solana/kit";
import {
  createZolanaClient,
  initializePoseidon,
  type ZolanaClientConfig,
} from "@heliuslabs/zolana";
import { Turnkey } from "@turnkey/sdk-server";
import {
  createTvcClient,
  createTvcOperationAuthorizer,
  type BootProofResolver,
  type Checkpoint,
  type QosIdentityPcrs,
  type ShieldedIdentity,
  type TvcClient,
  type WalletDescriptor,
} from "@zolana/tvc-wallet";
import {
  clientKeyIdFor,
  encodeLowerHex,
  type PinnedReleaseAuthorities,
  type SignedReleasePolicy,
} from "@zolana/tvc-wallet/protocol";
import { createLocalTvcClient } from "@zolana/tvc-wallet/testing";

export type Client = Awaited<ReturnType<typeof createZolanaClient>>;

export interface ExampleSetup {
  /** Helius RPC plus the Photon indexer and the prover. */
  readonly zolana: Client;
  /** The enclave: verified before use, then the five key operations. */
  readonly tvc: TvcClient;
  /** The Turnkey wallet that owns the private balance. It pays and signs. */
  readonly signer: TransactionPartialSigner;
  /** Where the public identity and the sealed checkpoint are kept. */
  readonly walletPath: string;
}

export interface ConfirmedTransaction {
  readonly signature: Signature;
  /** Slot the transaction landed in; drives the indexer freshness gates. */
  readonly slot: bigint;
}

/** The two values `bootstrap` returns. Neither is a secret. */
export interface StoredWallet {
  readonly identity: ShieldedIdentity;
  readonly checkpoint: Checkpoint;
}

/** Independently pinned trust material for one TVC release. */
interface TrustMaterial {
  readonly releasePolicy: SignedReleasePolicy;
  readonly releaseAuthorities: PinnedReleaseAuthorities;
  readonly qosIdentityPcrs: QosIdentityPcrs;
}

// Will be exposed through a single devnet URL. Currently exposed as they are.
const RPC_URL = "https://devnet.helius-rpc.com";
const INDEXER_URL =
  "http://zolnet-devnet-1779374825.eu-north-1.elb.amazonaws.com";
const PROVER_URL =
  "http://zolnet-devnet-1779374825.eu-north-1.elb.amazonaws.com:3001";
const TURNKEY_API_URL = "https://api.turnkey.com";
const P256 = { name: "ECDSA", namedCurve: "P-256" } as const;

function env(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`set ${name}`);
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

async function readJson(path: string): Promise<unknown> {
  return JSON.parse(await readFile(path, "utf8")) as unknown;
}

function clientConfigFromEnv(): ZolanaClientConfig {
  const endpoint = process.env["ZOLANA_ENDPOINT"]?.trim();
  const apiKey = process.env["API_KEY"]?.trim();
  const solanaRpcUrl =
    endpoint || (apiKey ? `${RPC_URL}/?api-key=${apiKey}` : undefined);
  if (!solanaRpcUrl) {
    throw new Error("set API_KEY or ZOLANA_ENDPOINT");
  }
  return Object.freeze({
    solanaRpcUrl,
    indexerUrl: process.env["ZOLANA_INDEXER_URL"]?.trim() || INDEXER_URL,
    proverUrl: process.env["ZOLANA_PROVER_URL"]?.trim() || PROVER_URL,
    // The Photon/prover ALB is HTTP. Loopback HTTP is already allowed.
    allowInsecureHttp: true,
  });
}

/**
 * The release policy, its signing authorities, and the enclave PCRs, as the
 * operator published them. The client verifies the policy signatures and the
 * Boot Proof against these values; nothing here is taken from the service.
 */
async function trustMaterial(path: string): Promise<TrustMaterial> {
  const parsed = await readJson(path);
  if (
    !isRecord(parsed) ||
    !isRecord(parsed["releasePolicy"]) ||
    !isRecord(parsed["releaseAuthorities"]) ||
    !isRecord(parsed["qosIdentityPcrs"])
  ) {
    throw new Error(
      `${path} must hold releasePolicy, releaseAuthorities and qosIdentityPcrs`,
    );
  }
  return parsed as unknown as TrustMaterial;
}

/**
 * The P-256 key that signs every operation request. The wallet descriptor
 * lists its public key, so only this key can drive this wallet's enclave
 * operations. On the first run the key is created; the descriptor check then
 * reports the public key to enroll.
 */
async function clientKey(
  path: string,
): Promise<{ privateKey: webcrypto.CryptoKey; publicKey: Uint8Array }> {
  let jwk: webcrypto.JsonWebKey;
  try {
    jwk = (await readJson(path)) as webcrypto.JsonWebKey;
  } catch {
    const pair = await webcrypto.subtle.generateKey(P256, true, ["sign"]);
    jwk = await webcrypto.subtle.exportKey("jwk", pair.privateKey);
    await writeFile(path, JSON.stringify(jwk), { mode: 0o600 });
  }
  const privateKey = await webcrypto.subtle.importKey("jwk", jwk, P256, false, [
    "sign",
  ]);
  const { kty, crv, x, y } = jwk;
  const publicJwk = await webcrypto.subtle.importKey(
    "jwk",
    { kty, crv, x, y },
    P256,
    true,
    ["verify"],
  );
  const publicKey = new Uint8Array(
    await webcrypto.subtle.exportKey("raw", publicJwk),
  );
  return { privateKey, publicKey };
}

/**
 * The descriptor binds the Turnkey wallet, its Solana address, and the
 * client keys allowed to operate it. The operator's provisioning service
 * signs it once per wallet.
 */
async function walletDescriptor(
  path: string,
  clientPublicKey: string,
): Promise<WalletDescriptor> {
  let parsed: unknown;
  try {
    parsed = await readJson(path);
  } catch {
    throw new Error(
      `no wallet descriptor at ${path}. ` +
        `Enroll client public key ${clientPublicKey} and save the descriptor there.`,
    );
  }
  if (!isRecord(parsed) || !Array.isArray(parsed["allowed_clients"])) {
    throw new Error(`${path} is not a wallet descriptor`);
  }
  const descriptor = parsed as unknown as WalletDescriptor;
  const allowed = descriptor.allowed_clients.some(
    (grant) => grant.client_public_key === clientPublicKey,
  );
  if (!allowed) {
    throw new Error(
      `${path} does not list client public key ${clientPublicKey}`,
    );
  }
  return descriptor;
}

/**
 * The Boot Proof is Turnkey evidence for the enclave boot. A client session
 * cannot read it from Turnkey, so a server the operator runs returns the
 * public document; the client still verifies it against its own pins.
 */
function bootProofResolver(url: string): BootProofResolver {
  return async ({ bootProofLookupKey }) => {
    const response = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ephemeralKey: bootProofLookupKey }),
    });
    if (!response.ok) throw new Error(`boot proof: HTTP ${response.status}`);
    return response.json();
  };
}

async function tvcClientFromEnv(): Promise<{
  tvc: TvcClient;
  descriptor: WalletDescriptor;
}> {
  const trust = await trustMaterial(env("TVC_TRUST_PATH"));
  const key = await clientKey(env("TVC_CLIENT_KEY_PATH"));
  const clientPublicKey = encodeLowerHex(key.publicKey);
  const descriptor = await walletDescriptor(
    env("TVC_DESCRIPTOR_PATH"),
    clientPublicKey,
  );
  const authorizer = createTvcOperationAuthorizer({
    clientKeyId: clientKeyIdFor(key.publicKey),
    sign: async (message) =>
      new Uint8Array(
        await webcrypto.subtle.sign(
          { name: "ECDSA", hash: "SHA-256" },
          key.privateKey,
          message,
        ),
      ),
  });
  const tvc = createTvcClient({
    endpoint: new URL(env("TVC_ENDPOINT")),
    releasePolicy: trust.releasePolicy,
    releaseAuthorities: trust.releaseAuthorities,
    qosIdentityPcrs: trust.qosIdentityPcrs,
    resolveBootProof: bootProofResolver(env("TVC_BOOT_PROOF_URL")),
    operations: { walletDescriptor: descriptor, authorizer },
  });
  return { tvc, descriptor };
}

function sameBytes(left: ArrayLike<number>, right: ArrayLike<number>): boolean {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

/**
 * The Turnkey wallet as a `@solana/kit` signer.
 *
 * A private transaction is paid by the wallet's own Solana address; that
 * signature is what authorizes the spend on chain. Turnkey signs a whole
 * serialized transaction and returns it signed. The adapter accepts only the
 * signature it asked for: the message must come back byte for byte, and the
 * signature in this signer's slot must verify against the wallet's public
 * key. In a browser application the signed-in Turnkey session takes the
 * place of the API key.
 */
function turnkeySigner(descriptor: WalletDescriptor): TransactionPartialSigner {
  const turnkey = new Turnkey({
    apiBaseUrl: TURNKEY_API_URL,
    apiPublicKey: env("TURNKEY_API_PUBLIC_KEY"),
    apiPrivateKey: env("TURNKEY_API_PRIVATE_KEY"),
    defaultOrganizationId: descriptor.turnkey_organization_id,
  }).apiClient();
  const signer: Address = address(descriptor.address);
  const publicKey = getPublicKeyFromAddress(signer);
  const encoder = getTransactionEncoder();
  const decoder = getTransactionDecoder();
  return {
    address: signer,
    async signTransactions(
      transactions: readonly Transaction[],
    ): Promise<readonly SignatureDictionary[]> {
      const signatures: SignatureDictionary[] = [];
      for (const transaction of transactions) {
        if (!(signer in transaction.signatures)) {
          throw new Error("SignerNotRequired");
        }
        const { signedTransaction } = await turnkey.signTransaction({
          signWith: descriptor.address,
          unsignedTransaction: Buffer.from(
            encoder.encode(transaction),
          ).toString("hex"),
          type: "TRANSACTION_TYPE_SOLANA",
        });
        const signed = decoder.decode(Buffer.from(signedTransaction, "hex"));
        if (!sameBytes(signed.messageBytes, transaction.messageBytes)) {
          throw new Error("SignedTransactionMismatch");
        }
        const signature = signed.signatures[signer];
        if (!signature) throw new Error("MissingTransactionSignature");
        if (
          !(await verifySignature(
            await publicKey,
            signature,
            transaction.messageBytes,
          ))
        ) {
          throw new Error("InvalidTransactionSignature");
        }
        signatures.push({ [signer]: signature });
      }
      return signatures;
    },
  };
}

/**
 * The local testkit in place of a deployed enclave: the same five operations
 * behind pinned process keys instead of Nitro attestation, and a local Ed25519
 * key instead of Turnkey, so the example runs against `just headless-e2e`'s
 * stack with a plain keypair as the wallet. Loopback only, never for funds.
 */
async function localTestkit(endpoint: string): Promise<{
  tvc: TvcClient;
  signer: TransactionPartialSigner;
}> {
  const secret = JSON.parse(
    await readFile(env("TVC_SOLANA_KEYPAIR_PATH"), "utf8"),
  ) as unknown;
  if (!Array.isArray(secret) || secret.length !== 64) {
    throw new Error("TVC_SOLANA_KEYPAIR_PATH is not a Solana keypair file");
  }
  const signer = await createKeyPairSignerFromBytes(Uint8Array.from(secret));
  const tvc = createLocalTvcClient({
    endpoint: new URL(endpoint),
    solanaAddress: signer.address,
  });
  return { tvc, signer };
}

export async function setup(): Promise<ExampleSetup> {
  await initializePoseidon();
  const zolana = await createZolanaClient(clientConfigFromEnv());
  const walletPath = env("TVC_WALLET_PATH");
  const testkit = process.env["TVC_LOCAL_TESTKIT_ENDPOINT"]?.trim();
  if (testkit) {
    return Object.freeze({ zolana, walletPath, ...(await localTestkit(testkit)) });
  }
  const { tvc, descriptor } = await tvcClientFromEnv();
  return Object.freeze({
    zolana,
    tvc,
    signer: turnkeySigner(descriptor),
    walletPath,
  });
}

/** The stored identity and checkpoint, or `undefined` before the first bootstrap. */
export async function loadWallet(
  path: string,
): Promise<StoredWallet | undefined> {
  let parsed: unknown;
  try {
    parsed = await readJson(path);
  } catch {
    return undefined;
  }
  if (
    !isRecord(parsed) ||
    !isRecord(parsed["identity"]) ||
    typeof parsed["checkpoint"] !== "string"
  ) {
    throw new Error(`${path} is not a stored wallet`);
  }
  return parsed as unknown as StoredWallet;
}

export async function saveWallet(
  path: string,
  wallet: StoredWallet,
): Promise<void> {
  await writeFile(path, JSON.stringify(wallet, null, 2), { mode: 0o600 });
}

/**
 * Sign a transaction the SDK built, send it, and wait for confirmation.
 *
 * The SDK returns compiled transactions and leaves signing and sending to the
 * application. The SDK's `confirmTransaction` is the confirmation, and the
 * status response that confirms also carries the landed slot, which the next
 * `syncWallet` waits for.
 */
export function sendAndConfirmFactory(
  client: Client,
  signer: TransactionPartialSigner,
): (transaction: Transaction) => Promise<ConfirmedTransaction> {
  const sendTransaction = sendTransactionWithoutConfirmingFactory({
    rpc: client.solanaRpc,
  });

  return async function sendAndConfirm(
    transaction: Transaction,
  ): Promise<ConfirmedTransaction> {
    const signed = await signTransactionWithSigners([signer], transaction);
    assertIsFullySignedTransaction(signed);
    assertIsTransactionWithinSizeLimit(signed);
    await sendTransaction(signed, { commitment: client.commitment });
    const signature = getSignatureFromTransaction(signed);
    const slot = await client.confirmTransaction(signature);
    return { signature, slot };
  };
}
