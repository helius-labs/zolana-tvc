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
import type { AssetBalance } from "@heliuslabs/zolana/transaction";
import { DEFAULT_SOLANA_ACCOUNTS, Turnkey } from "@turnkey/sdk-server";
import {
  createTvcClient,
  createTvcOperationAuthorizer,
  type BootProofResolver,
  type SealedSeed,
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
  /** Where the public identity and the sealed seed are kept. */
  readonly walletPath: string;
}

export interface ConfirmedTransaction {
  readonly signature: Signature;
  /** Slot the transaction landed in; drives the indexer freshness gates. */
  readonly slot: bigint;
}

/** The two values `bootstrap` returns. Neither is a secret to the client. */
export interface StoredWallet {
  readonly identity: ShieldedIdentity;
  readonly sealedSeed: SealedSeed;
}

/** Independently pinned trust material for one TVC release. */
interface TrustMaterial {
  readonly releasePolicy: SignedReleasePolicy;
  readonly releaseAuthorities: PinnedReleaseAuthorities;
  readonly qosIdentityPcrs: QosIdentityPcrs;
}

// Will be exposed through a single devnet URL. Currently exposed as they are.
// The client's prover receives only the proofs the SDK builds client-side, the
// custom-ring auditor proof; the enclave proves the rest at its own pinned
// prover. This one serves every circuit, custom-ring included.
const RPC_URL = "https://devnet.helius-rpc.com";
const INDEXER_URL =
  "http://zolnet-devnet-1779374825.eu-north-1.elb.amazonaws.com";
const PROVER_URL = "https://d30sgubc9yxiri.cloudfront.net";
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
    // The Photon ALB is HTTP. Loopback HTTP is already allowed.
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
export async function clientKey(
  path: string,
): Promise<{ privateKey: webcrypto.CryptoKey; publicKey: Uint8Array }> {
  let jwk: webcrypto.JsonWebKey;
  try {
    jwk = (await readJson(path)) as webcrypto.JsonWebKey;
  } catch (error) {
    if (!isRecord(error) || error["code"] !== "ENOENT") throw error;
    const pair = await webcrypto.subtle.generateKey(P256, true, ["sign"]);
    jwk = await webcrypto.subtle.exportKey("jwk", pair.privateKey);
    await writeFile(path, JSON.stringify(jwk), { mode: 0o600, flag: "wx" });
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
 * The Boot Proof is Turnkey evidence for the enclave boot, readable only by a
 * user of the TVC organization. A client whose Turnkey key belongs to that
 * organization (the operator's own test) reads it directly; any other client
 * gets the public document from a server the operator runs
 * (`TVC_BOOT_PROOF_URL`). Either way the client verifies it against its own
 * pins.
 */
async function bootProofResolver(): Promise<BootProofResolver> {
  const url = process.env["TVC_BOOT_PROOF_URL"]?.trim();
  if (url) {
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
  const organizationId = process.env["TVC_ORGANIZATION_ID"]?.trim();
  if (!organizationId) throw new Error("set TVC_BOOT_PROOF_URL or TVC_ORGANIZATION_ID");
  const turnkey = await turnkeyClient(organizationId);
  return async ({ bootProofLookupKey }) =>
    (await turnkey.getBootProof({ organizationId, ephemeralKey: bootProofLookupKey }))
      .bootProof;
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
    resolveBootProof: await bootProofResolver(),
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
 * The Turnkey API key: `TURNKEY_API_PUBLIC_KEY` / `TURNKEY_API_PRIVATE_KEY`, or
 * the file `TURNKEY_API_KEY_PATH` names in Turnkey's API key format
 * (`{"public_key": hex, "private_key": hex}`), as `turnkey` and `tvc login`
 * store it.
 */
async function turnkeyApiKey(): Promise<{ publicKey: string; privateKey: string }> {
  const path = process.env["TURNKEY_API_KEY_PATH"]?.trim();
  if (!path) {
    return {
      publicKey: env("TURNKEY_API_PUBLIC_KEY"),
      privateKey: env("TURNKEY_API_PRIVATE_KEY"),
    };
  }
  const stored = await readJson(path);
  if (
    !isRecord(stored) ||
    typeof stored["public_key"] !== "string" ||
    typeof stored["private_key"] !== "string"
  ) {
    throw new Error(`${path} is not a Turnkey API key file`);
  }
  return { publicKey: stored["public_key"], privateKey: stored["private_key"] };
}

async function turnkeyClient(organizationId: string) {
  const { publicKey, privateKey } = await turnkeyApiKey();
  return new Turnkey({
    apiBaseUrl: TURNKEY_API_URL,
    apiPublicKey: publicKey,
    apiPrivateKey: privateKey,
    defaultOrganizationId: organizationId,
  }).apiClient();
}

/** What the operator needs to sign this client's descriptor. */
export interface Enrollment {
  readonly organizationId: string;
  readonly walletId: string;
  readonly address: string;
  readonly clientPublicKey: string;
  readonly trustPath: string;
}

/**
 * The enclave's request-signing key, compressed, as Turnkey lists an API key.
 * The pinned quorum public key is the encryption point followed by the
 * signing point, both uncompressed; the enclave signs its Turnkey requests
 * with the second.
 */
function enclaveServicePublicKey(quorumPublicKey: string): string {
  if (!/^04[0-9a-f]{128}04[0-9a-f]{128}$/.test(quorumPublicKey)) {
    throw new Error("the pinned quorum public key is not two P-256 points");
  }
  const signing = quorumPublicKey.slice(130);
  const x = signing.slice(2, 66);
  const yIsEven = Number.parseInt(signing.slice(-2), 16) % 2 === 0;
  return `${yIsEven ? "02" : "03"}${x}`;
}

/**
 * Grants the enclave what `bootstrap` needs from the Turnkey organization
 * that holds the wallet: a user whose API key is the enclave's signing key,
 * allowed by one policy to sign raw Ed25519 payloads with the wallet account.
 * Turnkey does not currently expose the raw payload to policy conditions, so
 * this grant cannot enforce a bootstrap-only boundary. Existing grants are
 * reconciled to the pinned quorum user, including after key rotation.
 */
export async function grantEnclaveBootstrap(
  turnkey: Pick<Awaited<ReturnType<typeof turnkeyClient>>,
    "getUsers" | "createUsers" | "getPolicies" | "createPolicy" | "updatePolicy">,
  organizationId: string,
  servicePublicKey: string,
  walletAddress: string,
): Promise<void> {
  const { users } = await turnkey.getUsers({ organizationId });
  let userId = users.find((user) =>
    user.apiKeys.some(
      (apiKey) =>
        apiKey.credential.type === "CREDENTIAL_TYPE_API_KEY_P256" &&
        apiKey.credential.publicKey.replace(/^0x/, "").toLowerCase() ===
          servicePublicKey,
    ),
  )?.userId;
  if (userId === undefined) {
    const created = await turnkey.createUsers({
      organizationId,
      users: [
        {
          userName: "zolana-tvc-wallet-authority",
          apiKeys: [
            {
              apiKeyName: "zolana-tvc-wallet-quorum-key",
              publicKey: servicePublicKey,
              curveType: "API_KEY_CURVE_P256",
            },
          ],
          authenticators: [],
          oauthProviders: [],
          userTags: [],
        },
      ],
    });
    userId = created.userIds[0];
    if (userId === undefined) throw new Error("Turnkey created no user");
    console.log(`created enclave service user ${userId}`);
  }

  const policyName = `zolana-tvc-bootstrap-${walletAddress.slice(0, 12)}`;
  const condition = [
    "activity.type == 'ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2'",
    `wallet_account.address == '${walletAddress}'`,
    "activity.params.encoding == 'PAYLOAD_ENCODING_HEXADECIMAL'",
    "activity.params.hash_function == 'HASH_FUNCTION_NOT_APPLICABLE'",
  ].join(" && ");
  const consensus = `approvers.any(user, user.id == '${userId}')`;
  const notes = "TVC raw Ed25519 signing grant; Turnkey policies cannot currently restrict the payload.";
  const { policies } = await turnkey.getPolicies({ organizationId });
  const existing = policies.filter((policy) => policy.policyName === policyName);
  if (existing.length > 0) {
    for (const policy of existing) {
      if (policy.effect === "EFFECT_ALLOW" && policy.condition === condition && policy.consensus === consensus) continue;
      await turnkey.updatePolicy({
        organizationId,
        policyId: policy.policyId,
        policyName,
        policyEffect: "EFFECT_ALLOW",
        policyCondition: condition,
        policyConsensus: consensus,
        policyNotes: notes,
      });
      console.log(`updated bootstrap policy ${policy.policyId}`);
    }
    return;
  }
  const { policyId } = await turnkey.createPolicy({
    organizationId,
    policyName,
    effect: "EFFECT_ALLOW",
    condition,
    consensus,
    notes,
  });
  console.log(`created bootstrap policy ${policyId}`);
}

/** The Solana wallet account behind `TURNKEY_WALLET_ADDRESS`, or a new wallet when none is named. */
async function walletAccount(
  turnkey: Awaited<ReturnType<typeof turnkeyClient>>,
  organizationId: string,
): Promise<{ walletId: string; address: string }> {
  const named = process.env["TURNKEY_WALLET_ADDRESS"]?.trim();
  if (named) {
    const { accounts } = await turnkey.getWalletAccounts({ organizationId });
    const account = accounts.find((entry) => entry.address === named);
    if (account === undefined) {
      throw new Error(`organization ${organizationId} has no wallet account ${named}`);
    }
    return { walletId: account.walletId, address: named };
  }
  const created = await turnkey.createWallet({
    organizationId,
    walletName: `zolana-tvc-example-${Date.now()}`,
    accounts: DEFAULT_SOLANA_ACCOUNTS,
  });
  const [address] = created.addresses;
  if (address === undefined) throw new Error("Turnkey created a wallet without an address");
  console.log(`created wallet ${created.walletId} with Solana address ${address}`);
  return { walletId: created.walletId, address };
}

/**
 * Prepares one Turnkey wallet for the enclave and this client: creates the
 * client key if needed, finds the wallet behind `TURNKEY_WALLET_ADDRESS` (or
 * creates one when the variable is unset), and installs the enclave's grant in
 * the organization. The descriptor itself is signed by the operator from the
 * returned values.
 */
export async function enroll(): Promise<Enrollment> {
  const trustPath = env("TVC_TRUST_PATH");
  const trust = await trustMaterial(trustPath);
  const key = await clientKey(env("TVC_CLIENT_KEY_PATH"));
  const organizationId = env("TURNKEY_ORGANIZATION_ID");
  const turnkey = await turnkeyClient(organizationId);
  const account = await walletAccount(turnkey, organizationId);
  await grantEnclaveBootstrap(
    turnkey,
    organizationId,
    enclaveServicePublicKey(trust.releasePolicy.policy.quorumPublicKey),
    account.address,
  );
  return Object.freeze({
    organizationId,
    walletId: account.walletId,
    address: account.address,
    clientPublicKey: encodeLowerHex(key.publicKey),
    trustPath,
  });
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
async function turnkeySigner(descriptor: WalletDescriptor): Promise<TransactionPartialSigner> {
  const turnkey = await turnkeyClient(descriptor.turnkey_organization_id);
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
    signer: await turnkeySigner(descriptor),
    walletPath,
  });
}

/** The stored identity and sealed seed, or `undefined` before the first bootstrap. */
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
    !isRecord(parsed["sealedSeed"]) ||
    typeof parsed["sealedSeed"]["sealedSeed"] !== "string"
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

/** The `SPL_*` and `RING_*` inputs are read by the examples that need them. */
export function requiredEnv(name: string): string {
  return env(name);
}

/**
 * Waits for the chain to pass `slot`. A ring transaction is compiled over an
 * address lookup table, and a table's addresses resolve from the slot after
 * the one that wrote them.
 */
export async function awaitSlotAfter(client: Client, slot: bigint): Promise<void> {
  for (let attempt = 0; attempt < 120; attempt += 1) {
    const current = await client.solanaRpc.getSlot({ commitment: client.commitment }).send();
    if (BigInt(current) > slot) return;
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error(`the chain did not pass slot ${slot}`);
}

/** The private balance an example step must have reached, or the step failed. */
export function expectBalance(
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
