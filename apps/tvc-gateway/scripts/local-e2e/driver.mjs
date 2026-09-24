// Drives a private wallet end to end through tvc-gateway, as gatekeeper would
// call it, against the local unattested testkit. Uses the built
// @zolana/tvc-wallet protocol client from packages/tvc-wallet.
import assert from "node:assert/strict";
import { createECDH, createPrivateKey, sign } from "node:crypto";
import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

const gateway = required("GATEWAY_URL");
const originAuth = required("ORIGIN_AUTH");
const projectId = required("PROJECT_ID");
const parentOrganizationId = required("PARENT_ORGANIZATION_ID");
const organizationId = required("ORGANIZATION_ID");
const turnkeyWalletId = required("TURNKEY_WALLET_ID");
const enclaveUrl = required("ENCLAVE_URL");
const dist = required("TVC_WALLET_DIST");

const testkit = JSON.parse(await readFile(required("TESTKIT_FIXTURE"), "utf8"));
const CLIENT_SECRET = Buffer.from(testkit.clientPrivateKeyHex, "hex");
const RENEWAL_DOMAIN = Buffer.from("HELIUS_TVC_GATEWAY_WALLET_GRANT_RENEWAL_V1");

const { createLocalTvcClient } = await import(pathToFileURL(`${dist}/testing.js`).href);
const { sealedSeedOf, identityOf } = await import(pathToFileURL(`${dist}/index.js`).href);
const { descriptorDigest } = await import(pathToFileURL(`${dist}/protocol.js`).href);

function required(name) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function step(name) {
  console.log(`✓ ${name}`);
}

function gatekeeperHeaders(project = projectId) {
  return {
    authorization: originAuth,
    "x-helius-project-id": project,
    "content-type": "application/json",
  };
}

async function call(method, path, body, project) {
  const response = await fetch(`${gateway}/v1/private-wallet${path}`, {
    method,
    headers: gatekeeperHeaders(project),
    ...(body === undefined ? {} : { body: typeof body === "string" ? body : JSON.stringify(body) }),
  });
  const text = await response.text();
  return { status: response.status, body: text ? JSON.parse(text) : undefined };
}

async function solanaKeypair() {
  const bytes = Uint8Array.from(JSON.parse(await readFile(required("WALLET_KEYPAIR"), "utf8")));
  const seed = Buffer.from(bytes.subarray(0, 32));
  const publicKey = Buffer.from(bytes.subarray(32, 64));
  const pkcs8 = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]);
  const privateKey = createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  return { privateKey, address: base58(publicKey) };
}

function base58(bytes) {
  const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let value = BigInt(`0x${Buffer.from(bytes).toString("hex")}`);
  let out = "";
  while (value > 0n) {
    out = alphabet[Number(value % 58n)] + out;
    value /= 58n;
  }
  for (const byte of bytes) {
    if (byte !== 0) break;
    out = `1${out}`;
  }
  return out;
}

function p256Key(secret) {
  const ecdh = createECDH("prime256v1");
  ecdh.setPrivateKey(secret);
  const publicKey = ecdh.getPublicKey();
  const privateKey = createPrivateKey({
    key: {
      kty: "EC",
      crv: "P-256",
      d: secret.toString("base64url"),
      x: publicKey.subarray(1, 33).toString("base64url"),
      y: publicKey.subarray(33, 65).toString("base64url"),
    },
    format: "jwk",
  });
  return { privateKey, publicKeyHex: publicKey.toString("hex") };
}

function renewalSignature(descriptor, issuedAtMs, privateKey) {
  const issuedAt = Buffer.alloc(8);
  issuedAt.writeBigUInt64BE(BigInt(issuedAtMs));
  const message = Buffer.concat([
    RENEWAL_DOMAIN,
    Buffer.from([0]),
    Buffer.from(descriptorDigest(descriptor)),
    issuedAt,
  ]);
  return sign("sha256", message, { key: privateKey, dsaEncoding: "ieee-p1363" }).toString("hex");
}

/** Maps the enclave paths the client calls onto the gateway, adding gatekeeper's headers. */
function gatewayTransport(sentOperations) {
  return {
    async fetch(input, init) {
      const url = new URL(input);
      const suffix = url.pathname.replace(/^.*\/v1\//, "");
      const headers = gatekeeperHeaders();
      if (suffix === "info") return fetch(`${gateway}/v1/private-wallet/info`, { headers });
      if (suffix === "ping" || suffix === "operations") {
        if (suffix === "operations") sentOperations.push(init.body);
        return fetch(`${gateway}/v1/private-wallet/${suffix}`, { method: "POST", headers, body: init.body });
      }
      throw new Error(`unexpected enclave path ${url.pathname}`);
    },
  };
}

const owner = await solanaKeypair();
const client = p256Key(CLIENT_SECRET);

assert.equal((await fetch(`${gateway}/health`)).status, 200);
step("health");

const policy = await call("GET", "/policy");
assert.equal(policy.status, 200);
assert.equal(policy.body.policy.releaseId, "local-unattested-do-not-deploy");
step("policy is served and matches the testkit release");

assert.equal((await call("GET", "/boot-proof/abc")).status, 400);
step("malformed boot-proof key is refused");

const enrollment = {
  parentOrganizationId,
  organizationId,
  walletName: "Solana Wallet",
  turnkeyWalletId,
  solanaAddress: owner.address,
  clientPublicKey: client.publicKeyHex,
};
const challenge = await call("POST", "/enrollment-challenge", enrollment);
assert.equal(challenge.status, 200, JSON.stringify(challenge.body));
const ownerSignature = sign(null, Buffer.from(challenge.body.message), owner.privateKey).toString("hex");
step("enrollment challenge issued and signed by the wallet owner");

const stolen = await call("POST", "/provision-descriptor", { token: challenge.body.token, ownerSignature }, "other-project");
assert.equal(stolen.status, 400);
step("a challenge does not redeem for another project");

const provisioned = await call("POST", "/provision-descriptor", { token: challenge.body.token, ownerSignature });
assert.equal(provisioned.status, 200, JSON.stringify(provisioned.body));
const { descriptor, walletGrant: issued } = provisioned.body;
assert.equal(descriptor.address, owner.address);
assert.equal(descriptor.allowed_clients[0].client_public_key, client.publicKeyHex);
assert.equal(issued.project_id, projectId);
step("descriptor and wallet grant provisioned after the Turnkey ownership check");

const walletGrant = { current: issued };
const sentOperations = [];
const tvc = createLocalTvcClient({
  endpoint: new URL(enclaveUrl),
  solanaAddress: owner.address,
  walletDescriptor: descriptor,
  walletGrant: () => Promise.resolve(walletGrant.current),
  transport: gatewayTransport(sentOperations),
});
const connection = await tvc.connectAndVerify();
step("connected to the enclave through the gateway");

const bootstrap = await tvc.bootstrap(connection);
const identity = identityOf(bootstrap);
assert.equal(identity.solanaAddress, owner.address);
const sealedSeed = sealedSeedOf(bootstrap);
step("bootstrap returned the shielded identity and a sealed seed");

const keys = await tvc.transactionKeys(connection, sealedSeed, [
  { viewing_public_key: identity.shieldedViewingPublicKey, first_nullifier: "01".padStart(64, "0") },
]);
assert.equal(keys.length, 1);
step("TransactionKeys operation answered");

const replay = await fetch(`${gateway}/v1/private-wallet/operations`, {
  method: "POST",
  headers: gatekeeperHeaders(),
  body: sentOperations.at(-1),
});
assert.equal(replay.status, 409);
step("a resent operation is refused");

const foreign = await fetch(`${gateway}/v1/private-wallet/operations`, {
  method: "POST",
  headers: gatekeeperHeaders("other-project"),
  body: sentOperations.at(-1),
});
assert.equal(foreign.status, 401);
step("the wallet grant does not work for another project");

const withoutGrant = JSON.parse(sentOperations.at(-1));
delete withoutGrant.wallet_grant;
const ungranted = await fetch(`${gateway}/v1/private-wallet/operations`, {
  method: "POST",
  headers: gatekeeperHeaders(),
  body: JSON.stringify(withoutGrant),
});
assert.equal(ungranted.status, 401);
step("an operation without a grant is refused");

const issuedAtMs = Date.now();
const renewed = await call("POST", "/wallet-grant", {
  descriptor,
  issuedAtMs,
  signature: renewalSignature(descriptor, issuedAtMs, client.privateKey),
});
assert.equal(renewed.status, 200, JSON.stringify(renewed.body));
walletGrant.current = renewed.body;
const again = await tvc.transactionKeys(connection, sealedSeed, [
  { viewing_public_key: identity.shieldedViewingPublicKey, first_nullifier: "02".padStart(64, "0") },
]);
assert.equal(again.length, 1);
step("wallet grant renewed with the client key and accepted by the enclave");

const intruder = p256Key(Buffer.alloc(32, 0x07));
const forged = await call("POST", "/wallet-grant", {
  descriptor,
  issuedAtMs,
  signature: renewalSignature(descriptor, issuedAtMs, intruder.privateKey),
});
assert.equal(forged.status, 401);
step("a renewal signed by another key is refused");

console.log("local e2e passed");
