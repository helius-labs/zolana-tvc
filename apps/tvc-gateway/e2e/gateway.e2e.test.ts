import { ed25519 } from "@noble/curves/ed25519";
import { p256 } from "@noble/curves/p256";
import { getAddressDecoder } from "@solana/kit";
import {
  identityOf,
  sealedSeedOf,
  type BootstrapResult,
  type TvcClient,
  type TvcTransport,
  type VerifiedConnection,
} from "@zolana/tvc-wallet";
import {
  decodeLowerHex,
  encodeLowerHex,
  walletEnrollmentMessage,
  type WalletDescriptor,
} from "@zolana/tvc-wallet/protocol";
import { createLocalTvcClient } from "@zolana/tvc-wallet/testing";
import { beforeAll, describe, expect, inject, it } from "vitest";
import {
  ORGANIZATION_ID,
  PARENT_ORGANIZATION_ID,
  PROJECT_ID,
  TURNKEY_WALLET_ID,
  testkit,
} from "./fixtures.js";

const { gatewayUrl, originAuth, walletSeedHex } = inject("stack");
const privateWallet = `${gatewayUrl}/v1/private-wallet`;
const ownerSeed = decodeLowerHex(walletSeedHex);
const ownerAddress = getAddressDecoder().decode(ed25519.getPublicKey(ownerSeed));
const clientPublicKey = encodeLowerHex(
  p256.getPublicKey(decodeLowerHex(testkit.clientPrivateKeyHex), false),
);

/** The headers gatekeeper adds to every request it forwards. */
function gatekeeperHeaders(project = PROJECT_ID) {
  return {
    authorization: originAuth,
    "x-helius-project-id": project,
    "content-type": "application/json",
  };
}

async function post(path: string, body: unknown, project?: string) {
  const response = await fetch(`${privateWallet}${path}`, {
    method: "POST",
    headers: gatekeeperHeaders(project),
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
  return { status: response.status, body: await response.json() };
}

function enrollment(issuedAtMs = Date.now(), signer = ownerSeed) {
  const fields = {
    parentOrganizationId: PARENT_ORGANIZATION_ID,
    organizationId: ORGANIZATION_ID,
    walletName: "Solana Wallet",
    turnkeyWalletId: TURNKEY_WALLET_ID,
    solanaAddress: ownerAddress,
    clientPublicKey,
    issuedAtMs,
  };
  const message = new TextEncoder().encode(walletEnrollmentMessage(fields));
  return { ...fields, ownerSignature: encodeLowerHex(ed25519.sign(message, signer)) };
}

it("serves health without credentials", async () => {
  expect((await fetch(`${gatewayUrl}/health`)).status).toBe(200);
});

it("serves only /session, /enroll and /operations", async () => {
  for (const path of ["/info", "/ping", "/policy", "/wallet-grant", "/enrollment-challenge"]) {
    expect(await post(path, {}), path).toEqual({ status: 404, body: { error: "NotFound" } });
  }
});

describe("enrollment", () => {
  it("refuses an enrollment older than five minutes", async () => {
    expect(await post("/enroll", enrollment(Date.now() - 6 * 60_000))).toEqual({
      status: 400,
      body: { error: "StaleEnrollment" },
    });
  });

  it("refuses an enrollment another key signed", async () => {
    const intruder = ed25519.utils.randomPrivateKey();
    expect(await post("/enroll", enrollment(Date.now(), intruder))).toEqual({
      status: 400,
      body: { error: "InvalidOwnerEnrollmentSignature" },
    });
  });

  it("refuses an enrollment for another project's sub-organization", async () => {
    expect(await post("/enroll", enrollment(), "other-project")).toEqual({
      status: 403,
      body: { error: "SubOrganizationNotOwned" },
    });
  });

  it("answers the same descriptor for the same enrollment", async () => {
    const signed = enrollment();
    const first = await post("/enroll", signed);
    expect(first.status).toBe(200);
    expect(first.body.descriptor).toMatchObject({
      address: ownerAddress,
      allowed_clients: [{ client_public_key: clientPublicKey }],
    });
    expect(await post("/enroll", signed)).toEqual(first);
  });
});

describe("a wallet enrolled through the gateway", () => {
  const sent: { path: string; body: string }[] = [];
  const transport: TvcTransport = {
    fetch(url, init) {
      sent.push({ path: url.pathname, body: String(init?.body ?? "") });
      return fetch(url, { ...init, headers: gatekeeperHeaders() });
    },
  };
  let descriptor: WalletDescriptor;
  let tvc: TvcClient;
  let connection: VerifiedConnection;
  let bootstrap: BootstrapResult;
  const firstOperation = () => {
    const operation = sent.find(({ path }) => path.endsWith("/operations"));
    if (!operation) throw new Error("no operation was sent");
    return JSON.parse(operation.body) as { descriptor: WalletDescriptor; request: { ciphertext: string } };
  };

  beforeAll(async () => {
    descriptor = (await post("/enroll", enrollment())).body.descriptor;
    tvc = createLocalTvcClient({
      backend: { kind: "gateway", endpoint: new URL(privateWallet) },
      solanaAddress: ownerAddress,
      walletDescriptor: descriptor,
      transport,
    });
    connection = await tvc.connectAndVerify();
    bootstrap = await tvc.bootstrap(connection);
  });

  it("connects with one /session request", () => {
    expect(sent.filter(({ path }) => !path.endsWith("/operations")).map(({ path }) => path)).toEqual([
      "/v1/private-wallet/session",
    ]);
  });

  it("bootstraps through /operations with a grant the gateway adds", () => {
    expect(identityOf(bootstrap).solanaAddress).toBe(ownerAddress);
    expect(firstOperation().request).not.toHaveProperty("wallet_grant");
  });

  it("answers TransactionKeys for the bootstrapped wallet", async () => {
    const identity = identityOf(bootstrap);
    const keys = await tvc.transactionKeys(connection, sealedSeedOf(bootstrap), [
      { viewing_public_key: identity.shieldedViewingPublicKey, first_nullifier: "01".padStart(64, "0") },
    ]);
    expect(keys).toHaveLength(1);
  });

  it("refuses a resent operation", async () => {
    expect(await post("/operations", firstOperation())).toEqual({
      status: 409,
      body: { error: "ReplayedRequest" },
    });
  });

  it("refuses an operation on another project's wallet", async () => {
    const fresh = firstOperation();
    fresh.request.ciphertext = "abcd";
    expect(await post("/operations", fresh, "other-project")).toEqual({
      status: 403,
      body: { error: "SubOrganizationNotOwned" },
    });
  });

  it("refuses a descriptor this gateway did not provision, or none", async () => {
    const tampered = firstOperation();
    tampered.descriptor.turnkey_wallet_id = "3b2c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e";
    expect(await post("/operations", tampered)).toEqual({
      status: 403,
      body: { error: "InvalidDescriptor" },
    });
    expect(await post("/operations", firstOperation().request)).toEqual({
      status: 400,
      body: { error: "InvalidJson" },
    });
  });
});
