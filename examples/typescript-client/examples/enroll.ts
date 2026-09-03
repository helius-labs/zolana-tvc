import { enroll } from "../src/lib.js";

// One-time setup of a Turnkey wallet for this client. Creates the client key,
// grants the enclave the bootstrap signature in the wallet's organization, and
// prints the command the operator runs to sign the wallet descriptor.
const enrollment = await enroll();
const descriptorPath = process.env["TVC_DESCRIPTOR_PATH"]?.trim() ?? "tvc-wallet-descriptor.json";

console.log(`wallet ${enrollment.address} (wallet id ${enrollment.walletId}) is ready for the enclave.`);
if (!process.env["TURNKEY_WALLET_ADDRESS"]?.trim()) {
  console.log(`set TURNKEY_WALLET_ADDRESS=${enrollment.address} in .env for later runs.`);
}
console.log(`client public key: ${enrollment.clientPublicKey}`);
console.log("");
console.log("Ask the operator to sign the descriptor, from the zolana-tvc repository root:");
console.log("");
console.log(
  [
    "  node scripts/provision-descriptor.mjs",
    `--organization-id ${enrollment.organizationId}`,
    `--wallet-id ${enrollment.walletId}`,
    `--address ${enrollment.address}`,
    `--client-public-key ${enrollment.clientPublicKey}`,
    "--out <descriptor.json>",
  ].join(" \\\n    "),
);
console.log("");
console.log(`Save the descriptor at ${descriptorPath} and run the example.`);
