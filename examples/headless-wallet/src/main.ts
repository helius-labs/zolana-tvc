// Headless client for one privacy wallet. Verifies the release, derives the
// shielded identity, and prints the view tags a caller queries the indexer with.
//
// Reading the indexer and submitting transactions stay with the caller, so this
// script needs no chain access.
import { readFile, writeFile } from "node:fs/promises";
import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha256";
import {
  checkpointFromBootstrapResult,
  createTvcOperationAuthorizer,
  createTvcWalletClient,
  shieldedIdentityOf,
  type BootProofResolver,
  type ShieldedIdentity,
} from "@zolana/tvc-wallet";
import { clientKeyIdFor, decodeLowerHex } from "@zolana/tvc-wallet/protocol";
import type {
  PinnedReleaseAuthoritiesV1,
  SignedReleasePolicyV1,
  WalletDescriptorV1,
} from "@zolana/tvc-wallet/protocol";

type BootProof = Awaited<ReturnType<BootProofResolver>>;

/** Absent configuration is a setup error, so it fails before any request. */
function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is not set`);
  return value;
}

async function readJson<T>(path: string): Promise<T> {
  return JSON.parse(await readFile(path, "utf8")) as T;
}

/**
 * The Boot Proof comes from Turnkey under the caller's own session, so this
 * example delegates to an endpoint that already holds one. Never source the
 * expected PCRs from here.
 */
function bootProofResolverFor(url: URL): BootProofResolver {
  return async (input) => {
    const response = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(input),
    });
    if (!response.ok) throw new Error(`boot proof resolver returned ${response.status}`);
    return (await response.json()) as BootProof;
  };
}

/**
 * Signs with a local P-256 key. A browser holds a non-exportable key instead,
 * and the SDK builds the signed message either way.
 */
function localSigner(clientKeyId: string, privateKeyHex: string) {
  const privateKey = Uint8Array.from(Buffer.from(privateKeyHex, "hex"));
  return createTvcOperationAuthorizer({
    clientKeyId,
    async sign(message: Uint8Array) {
      return p256.sign(sha256(message), privateKey).toCompactRawBytes();
    },
  });
}

async function main(): Promise<void> {
  const descriptor = await readJson<WalletDescriptorV1>(required("TVC_DESCRIPTOR_PATH"));
  const grant = descriptor.allowed_clients[0];
  if (!grant) throw new Error("descriptor grants no client");

  const client = createTvcWalletClient({
    endpoint: new URL(required("TVC_ENDPOINT")),
    releasePolicy: await readJson<SignedReleasePolicyV1>(required("TVC_RELEASE_POLICY_PATH")),
    releaseAuthorities: await readJson<PinnedReleaseAuthoritiesV1>(
      required("TVC_RELEASE_AUTHORITIES_PATH"),
    ),
    resolveBootProof: bootProofResolverFor(new URL(required("TVC_BOOT_PROOF_URL"))),
    operations: {
      walletDescriptor: descriptor,
      authorizer: localSigner(
        clientKeyIdFor(decodeLowerHex(grant.client_public_key)),
        required("TVC_CLIENT_PRIVATE_KEY_HEX"),
      ),
    },
  });

  const connection = await client.connectAndVerify();
  console.log(`verified release ${connection.releaseId}`);

  // A recorded identity makes a re-bootstrap refuse to adopt a different
  // wallet, which is the difference between a rotation and a substitution.
  const identityPath = process.env.TVC_IDENTITY_PATH;
  const known = identityPath
    ? await readJson<ShieldedIdentity>(identityPath).catch(() => undefined)
    : undefined;

  const bootstrap = await client.bootstrapKeyholder(connection, { expectedIdentity: known });
  const identity = shieldedIdentityOf(bootstrap);
  console.log(`solana address       ${identity.solanaAddress}`);
  console.log(`shielded owner hash  ${identity.shieldedOwnerHash}`);
  if (identityPath && !known) {
    await writeFile(identityPath, `${JSON.stringify(identity, null, 2)}\n`);
  }

  const checkpoint = checkpointFromBootstrapResult(bootstrap);
  const tags = await client.deriveViewTags(connection, { checkpoint });
  for (const tag of tags.view_tags) console.log(`view tag             ${tag}`);
  console.log(
    "query the indexer with these tags, then pass the ciphertexts to decryptUtxos",
  );
}

await main();
