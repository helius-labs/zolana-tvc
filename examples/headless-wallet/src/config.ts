import { readFile } from "node:fs/promises";

import type { ShieldedIdentity } from "@zolana/tvc-wallet";

export type LocalE2eConfig = {
  readonly tvcEndpoint: URL;
  readonly solanaRpcUrl: URL;
  readonly indexerUrl: URL;
  readonly proverUrl?: URL;
  readonly allowInsecureHttp: boolean;
  readonly solanaKeypairPath: string;
  readonly solanaKeypairBytes: Uint8Array;
  readonly expectedIdentity?: ShieldedIdentity;
  readonly identityPath?: string;
  readonly requireEmptyPrivateBalance: boolean;
  readonly splMint: string;
  readonly splAssetId: bigint;
  readonly splTokenAccount: string;
  readonly ringAProgramId: string;
  readonly ringBProgramId: string;
  readonly depositLamports: bigint;
  readonly transferLamports: bigint;
  readonly splAmount: bigint;
  readonly ringBridgeLamports: bigint;
  readonly mergeInputLamports: bigint;
  readonly feeReserveLamports: bigint;
  readonly syncTimeoutMs: number;
  readonly syncPollMs: number;
};

export type Environment = Readonly<Record<string, string | undefined>>;

export function required(value: string | undefined, name: string): string {
  if (value === undefined || value.length === 0) {
    throw new Error(`${name} is required; use \`just headless-e2e\` to provision it`);
  }
  return value;
}

async function readJson<T>(path: string): Promise<T> {
  return JSON.parse(await readFile(path, "utf8")) as T;
}

async function optionalJson<T>(path: string | undefined): Promise<T | undefined> {
  if (!path) return undefined;
  try {
    return await readJson<T>(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  }
}

export function parseSolanaKeypair(value: unknown): Uint8Array {
  if (
    !Array.isArray(value) ||
    value.length !== 64 ||
    value.some((byte) => !Number.isInteger(byte) || byte < 0 || byte > 255)
  ) {
    throw new Error("the local Solana keypair must be a JSON array of 64 bytes");
  }
  return Uint8Array.from(value as number[]);
}

export function positiveInteger(
  value: string | undefined,
  fallback: number,
  name: string,
): number {
  if (value === undefined) return fallback;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error(`${name} must be a positive safe integer`);
  }
  return parsed;
}

export function positiveLamports(
  value: string | undefined,
  fallback: bigint,
  name: string,
): bigint {
  if (value === undefined) return fallback;
  if (!/^[1-9][0-9]*$/.test(value)) {
    throw new Error(`${name} must be positive decimal lamports`);
  }
  return BigInt(value);
}

export function validateCycleAmounts(deposit: bigint, transfer: bigint): void {
  if (transfer > deposit) {
    throw new Error("TVC_E2E_TRANSFER_LAMPORTS must not exceed the deposit");
  }
}

export async function loadLocalE2eConfig(
  environment: Environment = process.env,
): Promise<LocalE2eConfig> {
  const depositLamports = positiveLamports(
    environment.TVC_E2E_DEPOSIT_LAMPORTS,
    20_000_000n,
    "TVC_E2E_DEPOSIT_LAMPORTS",
  );
  const transferLamports = positiveLamports(
    environment.TVC_E2E_TRANSFER_LAMPORTS,
    depositLamports,
    "TVC_E2E_TRANSFER_LAMPORTS",
  );
  validateCycleAmounts(depositLamports, transferLamports);

  const solanaKeypairPath = environment.TVC_SOLANA_KEYPAIR_PATH;
  if (!solanaKeypairPath) {
    throw new Error(
      "TVC_SOLANA_KEYPAIR_PATH is required; use `just headless-e2e` for an automatic disposable wallet",
    );
  }
  const identityPath = environment.TVC_IDENTITY_PATH;
  const expectedIdentity = await optionalJson<ShieldedIdentity>(identityPath);
  const proverUrl = new URL(environment.TVC_PROVER_URL ?? "http://127.0.0.1:3201");
  return Object.freeze({
    tvcEndpoint: new URL(environment.TVC_ENDPOINT ?? "http://127.0.0.1:44020"),
    solanaRpcUrl: new URL(environment.TVC_SOLANA_RPC_URL ?? "http://127.0.0.1:9099"),
    indexerUrl: new URL(environment.TVC_INDEXER_URL ?? "http://127.0.0.1:8984"),
    proverUrl,
    allowInsecureHttp: environment.TVC_ALLOW_INSECURE_HTTP !== "0",
    solanaKeypairPath,
    solanaKeypairBytes: parseSolanaKeypair(await readJson<unknown>(solanaKeypairPath)),
    ...(expectedIdentity === undefined ? {} : { expectedIdentity }),
    ...(identityPath === undefined ? {} : { identityPath }),
    requireEmptyPrivateBalance:
      environment.TVC_E2E_REQUIRE_EMPTY_PRIVATE_BALANCE === "1",
    splMint: required(environment.TVC_E2E_SPL_MINT, "TVC_E2E_SPL_MINT"),
    splAssetId: positiveLamports(
      required(environment.TVC_E2E_SPL_ASSET_ID, "TVC_E2E_SPL_ASSET_ID"),
      2n,
      "TVC_E2E_SPL_ASSET_ID",
    ),
    splTokenAccount: required(
      environment.TVC_E2E_SPL_TOKEN_ACCOUNT,
      "TVC_E2E_SPL_TOKEN_ACCOUNT",
    ),
    ringAProgramId: required(
      environment.TVC_E2E_RING_A_PROGRAM_ID,
      "TVC_E2E_RING_A_PROGRAM_ID",
    ),
    ringBProgramId: required(
      environment.TVC_E2E_RING_B_PROGRAM_ID,
      "TVC_E2E_RING_B_PROGRAM_ID",
    ),
    depositLamports,
    transferLamports,
    splAmount: positiveLamports(
      environment.TVC_E2E_SPL_AMOUNT,
      200_000n,
      "TVC_E2E_SPL_AMOUNT",
    ),
    ringBridgeLamports: positiveLamports(
      environment.TVC_E2E_RING_BRIDGE_LAMPORTS,
      30_000_000n,
      "TVC_E2E_RING_BRIDGE_LAMPORTS",
    ),
    mergeInputLamports: positiveLamports(
      environment.TVC_E2E_MERGE_INPUT_LAMPORTS,
      2_000_000n,
      "TVC_E2E_MERGE_INPUT_LAMPORTS",
    ),
    feeReserveLamports: positiveLamports(
      environment.TVC_E2E_FEE_RESERVE_LAMPORTS,
      20_000_000n,
      "TVC_E2E_FEE_RESERVE_LAMPORTS",
    ),
    syncTimeoutMs: positiveInteger(
      environment.TVC_E2E_SYNC_TIMEOUT_MS,
      180_000,
      "TVC_E2E_SYNC_TIMEOUT_MS",
    ),
    syncPollMs: positiveInteger(
      environment.TVC_E2E_SYNC_POLL_MS,
      3_000,
      "TVC_E2E_SYNC_POLL_MS",
    ),
  });
}
