#!/usr/bin/env node
// Releases the privacy wallet in four phases, each resumable on its own:
//
//   build   builds the linux/amd64 image, pushes it, records the deployment
//           descriptor with both digests
//   deploy  creates the TVC deployment, approves it for every operator,
//           provisions it, makes it live, and waits for /v1/info to answer
//           with the new release
//   policy  reads /v1/info, assembles the release policy, signs it with a
//           one-time authority key, and writes the trust material
//   pins    writes the trust material into the wallet-kit demo and enables
//           its signature test
//
//   node scripts/release.mjs <build|deploy|policy|pins|all> <release-id> [--wallet-kit <dir>]
//
// The constants of the deployment live in apps/privacy-wallet/deploy/release.json.
// Docker, the Turnkey `tvc` CLI (logged in for the operators) and cargo are
// used where they are needed; nothing here holds a key longer than one call.

import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";

const ROOT = resolve(import.meta.dirname, "..");
const DEPLOY_DIR = join(ROOT, "apps/privacy-wallet/deploy");
const OPERATIONS = ["Bootstrap", "Decrypt", "Derive", "TransactionKeys", "Prove"];
const HEX64 = /^[0-9a-f]{64}$/;
const HEX = (bytes) => new RegExp(`^[0-9a-f]{${2 * bytes}}$`);
const INFO_TIMEOUT_MS = 20 * 60_000;

function fail(message) {
  console.error(`error: ${message}`);
  process.exit(1);
}

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function writeJson(path, value) {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
  console.log(`wrote ${path}`);
}

/** Runs a command with inherited output; the release stops on the first failure. */
function run(command, args, options = {}) {
  console.log(`$ ${[command, ...args].join(" ")}`);
  const result = spawnSync(command, args, { stdio: "inherit", cwd: ROOT, ...options });
  if (result.status !== 0) fail(`${command} ${args[0] ?? ""} failed`);
}

/** Runs a command and returns its stdout; the command line is still shown. */
function capture(command, args, options = {}) {
  console.log(`$ ${[command, ...args].join(" ")}`);
  try {
    return execFileSync(command, args, { encoding: "utf8", cwd: ROOT, stdio: ["ignore", "pipe", "inherit"], ...options });
  } catch (error) {
    fail(`${command} ${args[0] ?? ""} failed: ${error.message}`);
  }
}

function config() {
  const value = readJson(join(DEPLOY_DIR, "release.json"));
  for (const key of ["appId", "endpoint", "imageRepository", "qosVersion", "securityDomainId", "quorumKeyId", "quorumKeyEpoch"]) {
    if (typeof value[key] !== "string" || value[key] === "") fail(`release.json: ${key} is required`);
  }
  if (!Array.isArray(value.operatorIds) || value.operatorIds.length === 0) fail("release.json: operatorIds is required");
  for (const index of ["0", "1", "2", "3"]) {
    if (!HEX(48).test(value.qosIdentityPcrs?.[index] ?? "")) fail(`release.json: qosIdentityPcrs.${index} must be 48-byte hex`);
  }
  return value;
}

const descriptorPath = (releaseId) => join(DEPLOY_DIR, `privacy-wallet-${releaseId}.deployment.json`);
const deploymentPath = (releaseId) => join(DEPLOY_DIR, `privacy-wallet-${releaseId}.deploy.json`);
const trustPath = (releaseId) => join(DEPLOY_DIR, `privacy-wallet-${releaseId}.trust.json`);
const CURRENT_TRUST = join(DEPLOY_DIR, "privacy-wallet.trust.json");

function build(releaseId, cfg) {
  const tag = `${cfg.imageRepository}:${releaseId}`;
  run("docker", ["build", "--platform", "linux/amd64", "--provenance=false", "-f", "apps/privacy-wallet/Dockerfile", "-t", tag, "."]);
  const pivotDigest = capture("docker", ["run", "--rm", "--platform", "linux/amd64", "--entrypoint", "sha256sum", tag, "/tvc_app"]).split(/\s+/)[0];
  if (!HEX64.test(pivotDigest)) fail(`could not read the /tvc_app digest: ${pivotDigest}`);
  const pushed = capture("docker", ["push", tag]);
  const imageDigest = pushed.match(/digest: (sha256:[0-9a-f]{64})/)?.[1];
  if (!imageDigest) fail("docker push did not report the manifest digest");
  writeJson(descriptorPath(releaseId), {
    appId: cfg.appId,
    qosVersion: cfg.qosVersion,
    pivotContainerImageUrl: `${tag}@${imageDigest}`,
    pivotPath: "/tvc_app",
    pivotArgs: [
      "--host", "0.0.0.0",
      "--port", "3000",
      "--security-domain-id", cfg.securityDomainId,
      "--release-id", releaseId,
      "--quorum-key-id", cfg.quorumKeyId,
      "--quorum-key-epoch", cfg.quorumKeyEpoch,
    ],
    expectedPivotDigest: pivotDigest,
    dangerousDeployDebugMode: false,
    healthCheckType: "TVC_HEALTH_CHECK_TYPE_HTTP",
    healthCheckPort: 3000,
    publicIngressPort: 3000,
  });
}

/** The `tvc` CLI, non-interactive with JSON answers. */
function tvc(args) {
  const output = capture("tvc", ["--non-interactive", "--message-format", "json", ...args]);
  try {
    return JSON.parse(output);
  } catch {
    return output;
  }
}

function deploymentId(answer) {
  const id = answer?.deployId ?? answer?.deploymentId ?? answer?.deployment?.id ?? answer?.id;
  if (typeof id !== "string") fail(`could not find the deployment id in the tvc answer:\n${JSON.stringify(answer, null, 2)}`);
  return id;
}

async function fetchInfo(endpoint) {
  const response = await fetch(new URL("v1/info", `${endpoint}/`));
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.json();
}

/** Waits until the live deployment is the one being released. */
async function awaitRelease(releaseId, cfg, expectedPivotDigest) {
  const deadline = Date.now() + INFO_TIMEOUT_MS;
  for (;;) {
    try {
      const info = await fetchInfo(cfg.endpoint);
      if (info.release_id === releaseId && info.executable_digest === expectedPivotDigest) return info;
      console.log(`live: ${info.release_id} (${info.executable_digest.slice(0, 16)}…), waiting for ${releaseId}`);
    } catch (error) {
      console.log(`/v1/info: ${error.message}, waiting`);
    }
    if (Date.now() > deadline) fail(`${cfg.endpoint} did not serve ${releaseId} within ${INFO_TIMEOUT_MS / 60_000} minutes`);
    await sleep(15_000);
  }
}

async function deploy(releaseId, cfg) {
  const descriptor = readJson(descriptorPath(releaseId));
  const created = tvc(["deploy", "create", "--config-file", descriptorPath(releaseId)]);
  const deployId = deploymentId(created);
  writeJson(deploymentPath(releaseId), { deployId, created });
  // Each operator's approval is a signature over the QOS manifest; the CLI
  // must be logged in with a key that can act for the operator.
  for (const operatorId of cfg.operatorIds) {
    tvc(["deploy", "approve", "--deploy-id", deployId, "--operator-id", operatorId]);
  }
  tvc(["deploy", "provision", "--deploy-id", deployId]);
  tvc(["app", "set-live-deploy", "--app-id", cfg.appId, "--deploy-id", deployId]);
  await awaitRelease(releaseId, cfg, descriptor.expectedPivotDigest);
}

async function policy(releaseId, cfg) {
  const descriptor = readJson(descriptorPath(releaseId));
  const info = await awaitRelease(releaseId, cfg, descriptor.expectedPivotDigest);
  const same = (field, expected) => {
    if (info[field] !== expected) fail(`/v1/info ${field} is ${info[field]}, expected ${expected}`);
  };
  same("environment", "development");
  same("security_domain_id", cfg.securityDomainId);
  same("quorum_key_id", cfg.quorumKeyId);
  same("quorum_key_epoch", cfg.quorumKeyEpoch);
  if (!HEX64.test(info.manifest_digest)) fail("/v1/info manifest_digest is not 32-byte hex");
  if (!HEX(130).test(info.quorum_public_key)) fail("/v1/info quorum_public_key is not a QOS public key");
  if (JSON.stringify([...info.supported_operations].sort()) !== JSON.stringify([...OPERATIONS].sort())) {
    fail(`/v1/info supported_operations are ${info.supported_operations.join(", ")}`);
  }

  const now = Date.now();
  const unsigned = {
    version: 1,
    releaseId,
    environment: "development",
    tvcApplicationId: cfg.appId,
    securityDomainId: cfg.securityDomainId,
    acceptedManifestDigests: [info.manifest_digest],
    acceptedExecutableDigests: [descriptor.expectedPivotDigest],
    quorumKeyId: cfg.quorumKeyId,
    quorumKeyEpoch: cfg.quorumKeyEpoch,
    quorumPublicKey: info.quorum_public_key,
    allowedOperations: OPERATIONS,
    maxEncryptedRequestBytes: Number(info.max_encrypted_request_bytes),
    maxEncryptedResponseBytes: Number(info.max_encrypted_response_bytes),
    turnkeyTrustRootId: cfg.turnkeyTrustRootId,
    turnkeyProofSchemaVersions: cfg.turnkeyProofSchemaVersions,
    revocationEpoch: "0",
    validFromMs: String(now),
    expiresAtMs: String(now + cfg.policyValidityDays * 86_400_000),
  };
  const stamp = new Date(now).toISOString().slice(0, 7);
  const authoritySetId = `${releaseId}-${stamp}`;

  // The authority key is generated inside the signer, used once, and gone
  // when it exits; only the signed policy and the public half come back.
  const scratch = mkdtempSync(join(tmpdir(), "zolana-tvc-release-"));
  let signed;
  try {
    const unsignedPath = join(scratch, "policy.json");
    writeFileSync(unsignedPath, JSON.stringify(unsigned));
    signed = JSON.parse(
      capture("cargo", ["run", "-q", "-p", "zolana-tvc-protocol", "--example", "sign-release-policy", "--", unsignedPath, authoritySetId]),
    );
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
  const trust = {
    releasePolicy: signed.releasePolicy,
    releaseAuthorities: signed.releaseAuthorities,
    qosIdentityPcrs: cfg.qosIdentityPcrs,
  };
  writeJson(trustPath(releaseId), trust);
  writeJson(CURRENT_TRUST, trust);
}

/** A TypeScript object literal in the shape the demo's `tvc-policy.ts` keeps: JSON with bare keys. */
function literal(value) {
  return JSON.stringify(value, null, 2).replace(/^(\s*)"([A-Za-z_$][\w$]*|\d+)":/gm, "$1$2:");
}

function pins(releaseId, walletKit) {
  const trust = readJson(trustPath(releaseId));
  const app = join(walletKit, "examples/privacy-wallet-next-app/src/app");
  const policyFile = join(app, "tvc-policy.ts");
  let source = readFileSync(policyFile, "utf8");
  const replaceConst = (name, type, value) => {
    const pattern = new RegExp(`export const ${name} = \\{[\\s\\S]*?\\n\\} as const satisfies ${type};`);
    if (!pattern.test(source)) fail(`${policyFile}: no \`export const ${name}\` block`);
    source = source.replace(pattern, `export const ${name} = ${literal(value)} as const satisfies ${type};`);
  };
  replaceConst("releasePolicy", "SignedReleasePolicy", trust.releasePolicy);
  replaceConst("releaseAuthorities", "PinnedReleaseAuthorities", trust.releaseAuthorities);
  replaceConst("qosIdentityPcrs", "QosIdentityPcrs", trust.qosIdentityPcrs);
  // The note that carried the demo between the two releases, and the pointer
  // to the ceremony that produced these values.
  source = source
    .replace(/\/\/\n\/\/ PENDING RELEASE:[\s\S]*?\n(?=export const releasePolicy)/, "")
    .replace(/see\n\/\/ `docs\/deployment\.md` in zolana-tvc for the ceremony that produces it\./, "produced\n// by `scripts/release.mjs policy` in zolana-tvc.");
  writeFileSync(policyFile, source);
  console.log(`wrote ${policyFile}`);

  const testFile = join(app, "tvc-policy.test.ts");
  let test = readFileSync(testFile, "utf8");
  test = test
    .replace(/  \/\/ The pinned signature was made over[\s\S]*?\n(?=  it\.skip\()/, "")
    .replace(
      'it.skip("verifies the independent signature (pending the key-primitive release ceremony)"',
      'it("verifies the independent signature"',
    );
  writeFileSync(testFile, test);
  console.log(`wrote ${testFile}`);
}

async function main() {
  const [phase, releaseId, ...rest] = process.argv.slice(2);
  if (!["build", "deploy", "policy", "pins", "all"].includes(phase ?? "") || !releaseId) {
    fail("usage: node scripts/release.mjs <build|deploy|policy|pins|all> <release-id> [--wallet-kit <dir>]");
  }
  if (!/^[a-z0-9][a-z0-9-]{1,63}$/.test(releaseId)) fail("release id: lowercase letters, digits and dashes");
  const walletKitFlag = rest.indexOf("--wallet-kit");
  const walletKit = resolve(ROOT, walletKitFlag === -1 ? "../wallet-kit" : rest[walletKitFlag + 1] ?? fail("--wallet-kit needs a path"));
  const cfg = config();
  const phases = phase === "all" ? ["build", "deploy", "policy", "pins"] : [phase];
  for (const step of phases) {
    console.log(`\n== ${step} ${releaseId}`);
    if (step === "build") build(releaseId, cfg);
    if (step === "deploy") await deploy(releaseId, cfg);
    if (step === "policy") await policy(releaseId, cfg);
    if (step === "pins") pins(releaseId, walletKit);
  }
  console.log(`\n${releaseId}: done. Commit apps/privacy-wallet/deploy and the wallet-kit pins, then run the demo and \`examples/typescript-client\` against ${cfg.endpoint}.`);
}

await main();
