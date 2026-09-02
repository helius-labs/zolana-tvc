#!/usr/bin/env node
// Signs a wallet descriptor: the operator's grant that lets one client key
// drive the enclave operations of one Turnkey wallet.
//
//   node scripts/provision-descriptor.mjs --organization-id <uuid> --wallet-id <id> \
//     --address <solana address> --client-public-key <65-byte hex> [--out <path>] \
//     [--provisioning-key <path>] [--trust <path>]
//
// The security domain, environment and operation list come from the published
// trust material (apps/privacy-wallet/deploy/privacy-wallet.trust.json), so the
// descriptor names exactly the release the client pins. The provisioning key is
// read from TVC_PROVISIONING_KEY_JSON or the --provisioning-key file, both the
// Turnkey API key format ({"private_key": "<hex>"}), checked against the public
// key compiled into the enclave, used for one signature and wiped.
//
// A descriptor is not a secret: it names public keys and identifiers. Send it
// to the client, which stores it at its TVC_DESCRIPTOR_PATH. It needs
// `pnpm build:ts` for the protocol package it imports.

import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { parseArgs } from "node:util";

import { p256 } from "@noble/curves/p256";

const ROOT = resolve(import.meta.dirname, "..");
const DEFAULT_TRUST = "apps/privacy-wallet/deploy/privacy-wallet.trust.json";
// The development provisioner, as compiled into the enclave (PROVISIONING_PUBLIC
// in apps/privacy-wallet/src/operations/mod.rs). A descriptor signed by any other
// key is refused there, so the mismatch is reported here first.
const PROVISIONING_PUBLIC =
  "0494c61a25e2d50e7e20c8fcd7e2a9394522760478d7e6e7931ac60959db24e0a828389f390f75bf00fbac61638486782b785c40ba8e334e215b476d9d1f223f4f";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SOLANA_ADDRESS = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;

function fail(message) {
  console.error(`error: ${message}`);
  process.exit(1);
}

function readJson(path) {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
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

function provisioningSecret(path) {
  const inline = process.env.TVC_PROVISIONING_KEY_JSON?.trim();
  let stored;
  if (inline) {
    try {
      stored = JSON.parse(inline);
    } catch (error) {
      fail(`TVC_PROVISIONING_KEY_JSON: ${error.message}`);
    }
  } else if (path) {
    stored = readJson(path);
  } else {
    fail("set TVC_PROVISIONING_KEY_JSON or pass --provisioning-key <path>");
  }
  const hex = typeof stored.private_key === "string" ? stored.private_key.replace(/^0x/, "") : "";
  if (!/^[0-9a-f]{64}$/i.test(hex)) fail("the provisioning key file must hold private_key as 32-byte hex");
  const secret = Buffer.from(hex, "hex");
  if (Buffer.from(p256.getPublicKey(secret, false)).toString("hex") !== PROVISIONING_PUBLIC) {
    secret.fill(0);
    fail("this is not the provisioning key the enclave is built with");
  }
  return secret;
}

const { values } = parseArgs({
  options: {
    "organization-id": { type: "string" },
    "wallet-id": { type: "string" },
    address: { type: "string" },
    "client-public-key": { type: "string" },
    out: { type: "string" },
    "provisioning-key": { type: "string" },
    trust: { type: "string", default: DEFAULT_TRUST },
  },
});

for (const name of ["organization-id", "wallet-id", "address", "client-public-key"]) {
  if (!values[name]) fail(`--${name} is required`);
}
const organizationId = values["organization-id"].toLowerCase();
const walletId = values["wallet-id"];
const clientPublicKey = values["client-public-key"].replace(/^0x/, "").toLowerCase();
if (!UUID.test(organizationId)) fail("--organization-id must be a UUID");
if (walletId.length === 0 || walletId.length > 128) fail("--wallet-id must be 1 to 128 characters");
if (!SOLANA_ADDRESS.test(values.address)) fail("--address must be a Solana address");
if (!/^04[0-9a-f]{128}$/.test(clientPublicKey)) {
  fail("--client-public-key must be an uncompressed P-256 point, 65 bytes of hex");
}

const trust = readJson(resolve(ROOT, values.trust));
const policy = trust.releasePolicy?.policy;
if (!policy?.securityDomainId || !Array.isArray(policy.allowedOperations)) {
  fail(`${values.trust} does not hold a release policy`);
}
if (policy.environment !== "development") fail(`the enclave accepts development descriptors only`);

const { descriptorDigest, encodeLowerHex } = await protocol();
const descriptor = {
  version: 1,
  security_domain_id: policy.securityDomainId,
  environment: policy.environment,
  turnkey_organization_id: organizationId,
  turnkey_wallet_id: walletId,
  address: values.address,
  // One grant, listing every operation of the release: the enclave compares
  // the whole list and rejects a descriptor that narrows or reorders it.
  allowed_clients: [{ client_public_key: clientPublicKey, allowed_operations: policy.allowedOperations }],
  provisioning_signature: "",
};

const secret = provisioningSecret(values["provisioning-key"]);
try {
  const signature = p256
    .sign(descriptorDigest(descriptor), secret, { lowS: true, prehash: false })
    .toCompactRawBytes();
  descriptor.provisioning_signature = encodeLowerHex(signature);
} finally {
  secret.fill(0);
}

const json = `${JSON.stringify(descriptor, null, 2)}\n`;
if (values.out) {
  writeFileSync(values.out, json);
  console.log(`wrote ${values.out} for client ${clientPublicKey.slice(0, 18)}… on wallet ${values.address}`);
} else {
  process.stdout.write(json);
}
