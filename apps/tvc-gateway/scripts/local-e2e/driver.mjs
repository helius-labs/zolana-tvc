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

const { createLocalTvcClient } = await import(pathToFileURL(`${dist}/testing.js`).href);
const { sealedSeedOf, identityOf } = await import(pathToFileURL(`${dist}/index.js`).href);
const { walletEnrollmentMessage } = await import(pathToFileURL(`${dist}/protocol.js`).href);

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

/**
 * Serves the local client's enclave calls through the gateway, as a gatekeeper
 * caller would: discovery from the enclave, the ping through `/session`, and
 * each operation through `/operations` with its descriptor and no grant.
 */
function gatewayTransport(descriptor, sentOperations, sessions) {
  return {
    async fetch(input, init) {
      const url = new URL(input);
      const suffix = url.pathname.replace(/^.*\/v1\//, "");
      if (suffix === "info") return fetch(`${enclaveUrl}/v1/info`);
      if (suffix === "ping") {
        const session = await call("POST", "/session", init.body);
        assert.equal(session.status, 200, JSON.stringify(session.body));
        sessions.push(session.body);
        return Response.json(session.body.ping);
      }
      if (suffix === "operations") {
        const request = JSON.parse(init.body);
        delete request.wallet_grant;
        const envelope = JSON.stringify({ descriptor: descriptor.current, request });
        sentOperations.push(envelope);
        const answer = await call("POST", "/operations", envelope);
        if (answer.status !== 200) return Response.json(answer.body, { status: answer.status });
        assert.equal(
          answer.body.bootProof.ephemeralPublicKeyHex,
          answer.body.response.tvc_app_proof.public_key,
        );
        return Response.json(answer.body.response);
      }
      throw new Error(`unexpected enclave path ${url.pathname}`);
    },
  };
}

function enrollmentFor(issuedAtMs, signer = owner.privateKey) {
  const fields = {
    parentOrganizationId,
    organizationId,
    walletName: "Solana Wallet",
    turnkeyWalletId,
    solanaAddress: owner.address,
    clientPublicKey: client.publicKeyHex,
    issuedAtMs,
  };
  const ownerSignature = sign(null, Buffer.from(walletEnrollmentMessage(fields)), signer).toString("hex");
  return { ...fields, ownerSignature };
}

const owner = await solanaKeypair();
const client = p256Key(CLIENT_SECRET);

assert.equal((await fetch(`${gateway}/health`)).status, 200);
step("health");

for (const path of ["/info", "/policy", "/wallet-grant", "/enrollment-challenge"]) {
  assert.equal((await call("POST", path, "{}")).status, 404);
}
step("only /session, /enroll and /operations are served");

const stale = await call("POST", "/enroll", enrollmentFor(Date.now() - 6 * 60_000));
assert.equal(stale.status, 400, JSON.stringify(stale.body));
const intruder = createPrivateKey({
  key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.alloc(32, 9)]),
  format: "der",
  type: "pkcs8",
});
const forgedEnrollment = await call("POST", "/enroll", enrollmentFor(Date.now(), intruder));
assert.equal(forgedEnrollment.status, 400, JSON.stringify(forgedEnrollment.body));
step("a stale enrollment or one signed by another key is refused");

const signedEnrollment = enrollmentFor(Date.now());
const stolen = await call("POST", "/enroll", signedEnrollment, "other-project");
assert.equal(stolen.status, 403, JSON.stringify(stolen.body));
step("an enrollment does not work for another project");

const enrolled = await call("POST", "/enroll", signedEnrollment);
assert.equal(enrolled.status, 200, JSON.stringify(enrolled.body));
const descriptor = { current: enrolled.body.descriptor };
assert.equal(descriptor.current.address, owner.address);
assert.equal(descriptor.current.allowed_clients[0].client_public_key, client.publicKeyHex);
const again = await call("POST", "/enroll", signedEnrollment);
assert.deepEqual(again.body.descriptor, descriptor.current);
step("enrolled in one request after the Turnkey ownership check, and again with the same answer");

const sentOperations = [];
const sessions = [];
const tvc = createLocalTvcClient({
  endpoint: new URL(enclaveUrl),
  solanaAddress: owner.address,
  walletDescriptor: descriptor.current,
  transport: gatewayTransport(descriptor, sentOperations, sessions),
});
const connection = await tvc.connectAndVerify();
assert.equal(sessions.length, 1);
assert.equal(sessions[0].info.release_id, "local-unattested-do-not-deploy");
assert.equal(sessions[0].bootProof.ephemeralPublicKeyHex, sessions[0].ping.tvc_app_proof.public_key);
step("one /session answered discovery, the ping and the answering replica's Boot Proof");

const bootstrap = await tvc.bootstrap(connection);
const identity = identityOf(bootstrap);
assert.equal(identity.solanaAddress, owner.address);
const sealedSeed = sealedSeedOf(bootstrap);
step("bootstrap through /operations, with a grant the gateway added");

const keys = await tvc.transactionKeys(connection, sealedSeed, [
  { viewing_public_key: identity.shieldedViewingPublicKey, first_nullifier: "01".padStart(64, "0") },
]);
assert.equal(keys.length, 1);
step("TransactionKeys answered, with the replica's Boot Proof beside the response");

const replay = await call("POST", "/operations", sentOperations.at(-1));
assert.equal(replay.status, 409);
step("a resent operation is refused");

const fresh = JSON.parse(sentOperations.at(-1));
fresh.request.ciphertext = "abcd";
const foreign = await call("POST", "/operations", JSON.stringify(fresh), "other-project");
assert.equal(foreign.status, 403, JSON.stringify(foreign.body));
step("an operation does not work for another project's wallet");

const tampered = JSON.parse(sentOperations.at(-1));
tampered.descriptor.turnkey_wallet_id = "3b2c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e";
assert.equal((await call("POST", "/operations", JSON.stringify(tampered))).status, 403);
const bare = await call("POST", "/operations", JSON.stringify(fresh.request));
assert.equal(bare.status, 400);
step("an operation needs a descriptor this gateway provisioned");

console.log("local e2e passed");
