#!/usr/bin/env node
// Signs a prover policy: the TEE prover deployments the enclave may seal a
// proof witness to.
//
//   node scripts/sign-prover-policy.mjs --tee <pin.json> [--valid-days <n>] \
//     [--out <path>] [--prover-policy-key <path>]
//
// `--tee` is a zolana TEE pin (`prover/tee/deployments/*.json`, either
// `{"deployment": {...}}` or the bare policy): the platform, its measurements,
// `gpu` and `max_age_secs`. The policy is valid from now for `--valid-days`
// (default 180). The prover policy key is read from
// TVC_PROVER_POLICY_KEY_JSON or the --prover-policy-key file, both
// `{"private_key": "<hex>"}`, checked against the public key compiled into the
// enclave, used for one signature and wiped.
//
// The signed policy is not a secret. The default output is the devnet policy
// tvc-wallet ships (packages/tvc-wallet/src/devnet-prover-policy.json). It
// needs `pnpm build:ts` for the protocol package it imports.

import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { parseArgs } from "node:util";

const ROOT = resolve(import.meta.dirname, "..");
const DEFAULT_OUT = "packages/tvc-wallet/src/devnet-prover-policy.json";
const DAY_MS = 86_400_000;

function fail(message) {
  console.error(`error: ${message}`);
  process.exit(1);
}

function readText(path) {
  try {
    return readFileSync(path, "utf8");
  } catch (error) {
    fail(`${path}: ${error.message}`);
  }
}

async function protocol() {
  try {
    return await import(resolve(ROOT, "packages/tvc-wallet/dist/protocol.js"));
  } catch {
    fail("packages/tvc-wallet is not built: run `pnpm install && pnpm build:ts` first");
  }
}

const { values } = parseArgs({
  options: {
    tee: { type: "string" },
    "valid-days": { type: "string", default: "180" },
    out: { type: "string", default: DEFAULT_OUT },
    "prover-policy-key": { type: "string" },
  },
});
if (!values.tee) fail("--tee is required");
const validDays = Number(values["valid-days"]);
if (!Number.isInteger(validDays) || validDays <= 0) fail("--valid-days must be a positive integer");

const pin = JSON.parse(readText(values.tee));
const tee = "deployment" in pin ? pin.deployment : pin;
if (tee === null || typeof tee !== "object" || typeof tee.platform !== "string") {
  fail(`${values.tee} pins no deployment`);
}

const keyJson = process.env.TVC_PROVER_POLICY_KEY_JSON;
if (!keyJson && !values["prover-policy-key"]) {
  fail("set TVC_PROVER_POLICY_KEY_JSON or pass --prover-policy-key <path>");
}
const { proverPolicySecret, signProverPolicy } = await protocol();
const secret = proverPolicySecret(keyJson ?? readText(values["prover-policy-key"]));
const now = Date.now();
let signed;
try {
  signed = signProverPolicy(
    {
      version: 1,
      tee,
      validFromMs: String(now),
      expiresAtMs: String(now + validDays * DAY_MS),
    },
    secret,
  );
} finally {
  secret.fill(0);
}
writeFileSync(resolve(ROOT, values.out), `${JSON.stringify(signed, null, 2)}\n`);
console.log(`${values.out}: ${tee.platform} policy valid until ${new Date(now + validDays * DAY_MS).toISOString()}`);
