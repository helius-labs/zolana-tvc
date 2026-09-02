// Local, read-only checks over a TVC deployment descriptor.
//
// This automates only the mechanical half of the acceptance sequence in
// the deployment section of README.md. It deliberately does not sign, publish, approve, or
// contact any network: independent release-policy signing and the operator
// approval quorum are ceremonies, and a script that performed them would defeat
// the separation they exist to create.

import { readFileSync, readdirSync, realpathSync } from "node:fs";
import { join } from "node:path";

const PROFILES = ["privacy-wallet"];
const HEX64 = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
// Every pivot arg a template leaves blank for a ceremony to fill. Shipping one
// unfilled is the failure mode a copied template actually produces.
const REQUIRED_PIVOT_ARGS = ["--security-domain-id", "--release-id", "--quorum-key-id"];
const REQUIRED_KEYS = [
  "appId",
  "qosVersion",
  "pivotContainerImageUrl",
  "pivotPath",
  "expectedPivotDigest",
  "dangerousDeployDebugMode",
];

function fail(message) {
  throw new Error(message);
}

function parseArgs(argv) {
  const [profile, ...rest] = argv;
  const options = { profile, descriptor: null, pivotDigest: null };
  for (let i = 0; i < rest.length; i += 2) {
    const flag = rest[i];
    const value = rest[i + 1];
    if (value === undefined) fail(`missing value for ${flag}`);
    if (flag === "--descriptor") options.descriptor = value;
    else if (flag === "--pivot-digest") options.pivotDigest = value.replace(/^SHA256=/, "");
    else fail(`unknown flag ${flag}`);
  }
  if (!PROFILES.includes(options.profile)) {
    fail(`profile must be one of ${PROFILES.join(", ")}`);
  }
  if (!options.descriptor) fail("--descriptor <path> is required");
  return options;
}

function readDescriptor(path) {
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(path, "utf8"));
  } catch (error) {
    fail(`cannot read descriptor ${path}: ${error.message}`);
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    fail(`descriptor ${path} is not a JSON object`);
  }
  return parsed;
}

/** Every committed descriptor, so reuse of an identity can be detected. */
function allDescriptors() {
  const out = [];
  for (const profile of PROFILES) {
    const dir = join("apps", profile, "deploy");
    let entries = [];
    try {
      entries = readdirSync(dir);
    } catch {
      continue;
    }
    for (const name of entries.filter((n) => n.endsWith(".deployment.json"))) {
      const path = join(dir, name);
      out.push({ profile, path, descriptor: readDescriptor(path) });
    }
  }
  return out;
}

function pivotArg(descriptor, flag) {
  const args = Array.isArray(descriptor.pivotArgs) ? descriptor.pivotArgs : [];
  const index = args.indexOf(flag);
  return index >= 0 ? args[index + 1] : null;
}

function releaseId(descriptor) {
  return pivotArg(descriptor, "--release-id");
}

function pinnedQosVersion(profile) {
  const manifest = readFileSync(join("apps", profile, "Cargo.toml"), "utf8");
  const match = manifest.match(/qos_core\s*=\s*\{?\s*version\s*=\s*"=?([0-9.]+)"/);
  return match ? match[1] : null;
}

const checks = [];
function check(name, run) {
  try {
    const detail = run();
    checks.push({ name, ok: true, detail: detail ?? "" });
  } catch (error) {
    checks.push({ name, ok: false, detail: error.message });
  }
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  const descriptor = readDescriptor(options.descriptor);
  const descriptorPath = realpathSync(options.descriptor);
  const others = allDescriptors().filter(
    (entry) => realpathSync(entry.path) !== descriptorPath,
  );

  check("descriptor has every required field", () => {
    const missing = REQUIRED_KEYS.filter((key) => !(key in descriptor));
    if (missing.length) fail(`missing: ${missing.join(", ")}`);
    return REQUIRED_KEYS.length + " fields";
  });

  check("appId is a UUID from `tvc app create`", () => {
    const appId = String(descriptor.appId ?? "");
    if (!UUID.test(appId)) {
      fail(`appId must be a lowercase UUID, got "${appId}"`);
    }
    return appId;
  });

  check("no pivot arg was left for a ceremony to fill", () => {
    const unfilled = REQUIRED_PIVOT_ARGS.filter((flag) => {
      const value = pivotArg(descriptor, flag);
      return typeof value !== "string" || value.trim() === "" || value.startsWith("--");
    });
    if (unfilled.length) fail(`empty or missing: ${unfilled.join(", ")}`);
    // The security domain is 32 random bytes; a short value here
    // usually means a placeholder survived the copy.
    const domain = pivotArg(descriptor, "--security-domain-id");
    if (!HEX64.test(domain)) {
      fail(`--security-domain-id must be 64 lowercase hex characters, got "${domain}"`);
    }
    return REQUIRED_PIVOT_ARGS.length + " args";
  });

  check("image is pinned by digest, not a mutable tag", () => {
    const url = String(descriptor.pivotContainerImageUrl ?? "");
    if (!/@sha256:[0-9a-f]{64}$/.test(url)) {
      fail(`pivotContainerImageUrl must end in @sha256:<64 hex>, got "${url}"`);
    }
    return url.slice(url.indexOf("@") + 1);
  });

  check("debug mode is off", () => {
    if (descriptor.dangerousDeployDebugMode !== false) {
      fail("dangerousDeployDebugMode must be false for a release");
    }
    return "false";
  });

  check("expectedPivotDigest is a SHA-256", () => {
    if (!HEX64.test(String(descriptor.expectedPivotDigest ?? ""))) {
      fail("expectedPivotDigest must be 64 lowercase hex characters");
    }
    return descriptor.expectedPivotDigest;
  });

  check("qosVersion matches the profile's pinned qos_core", () => {
    const pinned = pinnedQosVersion(options.profile);
    if (!pinned) fail("could not read qos_core pin from Cargo.toml");
    if (descriptor.qosVersion !== pinned) {
      fail(`descriptor says ${descriptor.qosVersion}, Cargo.toml pins ${pinned}`);
    }
    return pinned;
  });

  check("release id is not reused by another descriptor", () => {
    const id = releaseId(descriptor);
    if (!id) fail("pivotArgs has no --release-id");
    const clash = others.find((entry) => releaseId(entry.descriptor) === id);
    if (clash) fail(`release id "${id}" already used by ${clash.path}`);
    return id;
  });

  check("pivot digest is not reused by another descriptor", () => {
    const clash = others.find(
      (entry) => entry.descriptor.expectedPivotDigest === descriptor.expectedPivotDigest,
    );
    if (clash) fail(`same binary already deployed as ${clash.path}`);
    return "unique";
  });

  if (options.pivotDigest) {
    check("built pivot digest matches the descriptor", () => {
      if (options.pivotDigest !== descriptor.expectedPivotDigest) {
        fail(`built ${options.pivotDigest}, descriptor expects ${descriptor.expectedPivotDigest}`);
      }
      return "match";
    });
  }

  for (const { name, ok, detail } of checks) {
    console.log(`${ok ? "ok  " : "FAIL"}  ${name}${detail ? `  (${detail})` : ""}`);
  }

  const failed = checks.filter((entry) => !entry.ok).length;
  console.log("");
  if (failed) {
    console.log(`${failed} of ${checks.length} checks failed.`);
    process.exit(1);
  }
  console.log(`${checks.length} checks passed.`);
  if (!options.pivotDigest) {
    console.log(
      "Pivot digest not verified. Build the image and re-run with --pivot-digest <hex>\n" +
        "to confirm the descriptor describes the binary you actually built.",
    );
  }
  console.log(
    "\nStill manual, by design: independent release-policy signing, dependency and\n" +
      "runtime-permission review, and the operator approval quorum.",
  );
}

try {
  main();
} catch (error) {
  console.error(`preflight: ${error.message}`);
  process.exit(2);
}
