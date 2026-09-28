#!/usr/bin/env node
// Creates tvc-gateway's Turnkey API key: a new API-only user with no policies,
// so it can only read, in the organization of a `tvc login`, and writes the key
// into the gateway secret as boot_proof_api_* and waas_api_*:
//
//   node scripts/create-gateway-turnkey-key.mjs <tvc-login> <user-name> <gateway-secret-id> [--region <region>] [--profile <profile>]
//
// The request is stamped with that login's API key. The new private key exists
// only in this process and in the secret; the script prints the user id and
// the public key.

import { execFileSync } from "node:child_process";
import { createECDH, createPrivateKey, sign as signWithKey } from "node:crypto";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

const TURNKEY_API = "https://api.turnkey.com";

function fail(message) {
  console.error(`error: ${message}`);
  process.exit(1);
}

const [login, userName, secretId, ...rest] = process.argv.slice(2);
if (!login || !userName || !secretId || [login, userName, secretId].some((arg) => arg.startsWith("--"))) {
  fail("usage: node scripts/create-gateway-turnkey-key.mjs <tvc-login> <user-name> <gateway-secret-id> [--region <region>] [--profile <profile>]");
}
const flag = (option) => {
  const index = rest.indexOf(option);
  return index === -1 ? [] : [option, rest[index + 1] ?? fail(`${option} needs a value`)];
};
const aws = (args, input) =>
  execFileSync("aws", ["secretsmanager", ...args, ...flag("--region"), ...flag("--profile")], {
    encoding: "utf8",
    input,
    stdio: [input === undefined ? "ignore" : "pipe", "pipe", "inherit"],
  });

/** The organization id and API key `tvc login <login>` stored under ~/.config/turnkey. */
function tvcLogin(name) {
  const turnkeyDir = join(homedir(), ".config/turnkey");
  const config = readFileSync(join(turnkeyDir, "tvc.config.toml"), "utf8");
  const section = config.split(/^\[/m).find((block) => block.startsWith(`orgs.${name}]`));
  const organizationId = section?.match(/^\s*id\s*=\s*"([^"]+)"/m)?.[1] ?? fail(`no tvc login named ${name}`);
  const stored = JSON.parse(readFileSync(join(turnkeyDir, "orgs", name, "api_key.json"), "utf8"));
  return { organizationId, publicKey: stored.public_key, privateKey: stored.private_key };
}

function p256Pair() {
  const ecdh = createECDH("prime256v1");
  ecdh.generateKeys();
  return { secret: ecdh.getPrivateKey(), publicKey: ecdh.getPublicKey("hex", "compressed") };
}

/** One stamped Turnkey submit, sent once: P-256 over SHA-256 of the body, DER in `X-Stamp`. */
async function submit(caller, path, body) {
  const secret = Buffer.from(caller.privateKey, "hex");
  const ecdh = createECDH("prime256v1");
  ecdh.setPrivateKey(secret);
  const point = ecdh.getPublicKey();
  const base64url = (bytes) => Buffer.from(bytes).toString("base64url");
  const key = createPrivateKey({
    format: "jwk",
    key: { kty: "EC", crv: "P-256", d: base64url(secret), x: base64url(point.subarray(1, 33)), y: base64url(point.subarray(33, 65)) },
  });
  secret.fill(0);
  const payload = JSON.stringify(body);
  const signature = signWithKey("sha256", Buffer.from(payload), { key, dsaEncoding: "der" }).toString("hex");
  const stamp = base64url(JSON.stringify({ publicKey: caller.publicKey, scheme: "SIGNATURE_SCHEME_TK_API_P256", signature }));
  const response = await fetch(`${TURNKEY_API}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", "X-Stamp": stamp },
    body: payload,
  });
  const answer = await response.json();
  if (!response.ok) fail(`Turnkey ${path}: HTTP ${response.status} ${JSON.stringify(answer)}`);
  return answer;
}

const caller = tvcLogin(login);
const gatewaySecret = JSON.parse(aws(["get-secret-value", "--secret-id", secretId, "--query", "SecretString", "--output", "text"]));
const { secret, publicKey } = p256Pair();

const answer = await submit(caller, "/public/v1/submit/create_api_only_users", {
  type: "ACTIVITY_TYPE_CREATE_API_ONLY_USERS",
  timestampMs: String(Date.now()),
  organizationId: caller.organizationId,
  parameters: {
    apiOnlyUsers: [{ userName, userTags: [], apiKeys: [{ apiKeyName: userName, publicKey }] }],
  },
});
const activity = answer.activity;
const userId = activity?.result?.createApiOnlyUsersResult?.userIds?.[0];
if (activity?.status !== "ACTIVITY_STATUS_COMPLETED" || !userId) {
  secret.fill(0);
  fail(`activity ${activity?.id} is ${activity?.status}; the secret is unchanged`);
}

const privateKey = secret.toString("hex");
secret.fill(0);
try {
  aws(
    ["put-secret-value", "--secret-id", secretId, "--secret-string", "file:///dev/stdin", "--query", "VersionId", "--output", "text"],
    JSON.stringify({
      ...gatewaySecret,
      boot_proof_api_public_key: publicKey,
      boot_proof_api_private_key: privateKey,
      waas_api_public_key: publicKey,
      waas_api_private_key: privateKey,
    }),
  );
} catch {
  fail(`created Turnkey user ${userId} but could not write ${secretId}; delete that user and run again`);
}
console.log(`created read-only Turnkey user ${userName} (${userId}) in ${caller.organizationId}`);
console.log(`public key: ${publicKey}`);
console.log(`wrote boot_proof_api_* and waas_api_* to ${secretId}`);
