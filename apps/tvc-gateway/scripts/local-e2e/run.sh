#!/usr/bin/env bash
# Runs tvc-gateway end to end on loopback: the local unattested testkit
# enclave, a mock Turnkey, the gateway, and a client driving a wallet through
# it the way gatekeeper calls it. Needs cargo and node >= 24.
set -euo pipefail

gateway_dir="$(cd "$(dirname "$0")/../.." && pwd)"
script_dir="$gateway_dir/scripts/local-e2e"
repo_dir="$(git -C "$gateway_dir" rev-parse --show-toplevel)"
testkit_fixture="$repo_dir/packages/tvc-wallet/src/local-testkit.json"

enclave_port="${ENCLAVE_PORT:-44020}"
turnkey_port="${MOCK_TURNKEY_PORT:-18941}"
gateway_port="${GATEWAY_PORT:-18940}"
project_id="local-e2e-project"
parent_organization_id="9b98a0d8-04a4-47a3-9dc3-afa84c686de4"
organization_id="1f0e6b1e-2a4c-4f7e-8d2b-3c4d5e6f7a8b"
turnkey_wallet_id="2a1b3c4d-5e6f-4a8b-9c0d-1e2f3a4b5c6d"
origin_auth="Bearer local-e2e-$(openssl rand -hex 16)"
# Any key but the testkit's makes the enclave refuse every descriptor, or every
# grant, the gateway signs.
provisioning_key="${PROVISIONING_KEY:-$(node -p "require('$testkit_fixture').provisioningPrivateKeyHex")}"
grant_key="${GRANT_KEY:-$(node -p "require('$testkit_fixture').grantPrivateKeyHex")}"

run_dir="$(mktemp -d)"
pids=()
cleanup() {
    for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
    wait 2>/dev/null || true
    rm -rf -- "$run_dir"
}
trap cleanup EXIT

wait_for() {
    local url="$1" name="$2"
    for _ in $(seq 1 180); do
        if curl --fail --silent "$url" >/dev/null; then return 0; fi
        sleep 1
    done
    echo "$name did not come up at $url; logs in $run_dir" >&2
    exit 1
}

p256_public() {
    node -e "const c=require('crypto').createECDH('prime256v1');c.setPrivateKey(Buffer.from(process.argv[1],'hex'));console.log(c.getPublicKey('hex',process.argv[2]))" "$1" "$2"
}

if [ ! -f "$repo_dir/packages/tvc-wallet/dist/testing.js" ]; then
    (cd "$repo_dir" && npx --yes pnpm@9.15.0 install --frozen-lockfile && npx --yes pnpm@9.15.0 build:ts)
fi

node -e '
const { generateKeyPairSync } = require("crypto");
const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const seed = privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32);
const pub = publicKey.export({ format: "der", type: "spki" }).subarray(-32);
process.stdout.write(JSON.stringify([...seed, ...pub]));
' > "$run_dir/wallet.json"
wallet_address="$(node -e '
const bytes = Buffer.from(JSON.parse(require("fs").readFileSync(process.argv[1], "utf8")).slice(32));
const a = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
let v = BigInt("0x" + bytes.toString("hex")), s = "";
while (v > 0n) { s = a[Number(v % 58n)] + s; v /= 58n; }
for (const b of bytes) { if (b !== 0) break; s = "1" + s; }
console.log(s);
' "$run_dir/wallet.json")"

echo "building the testkit enclave and the gateway"
cargo build --quiet --manifest-path "$repo_dir/Cargo.toml" -p zolana-tvc-privacy-wallet \
    --features local-dev --bin zolana-tvc-privacy-wallet-local
cargo build --quiet --manifest-path "$gateway_dir/Cargo.toml" --bin tvc-gateway --example local_release_policy

"$repo_dir/target/debug/zolana-tvc-privacy-wallet-local" \
    --port "$enclave_port" --wallet-keypair "$run_dir/wallet.json" \
    >"$run_dir/enclave.log" 2>&1 &
pids+=($!)

MOCK_TURNKEY_PORT="$turnkey_port" MOCK_PROJECT_ID="$project_id" MOCK_WALLET_ADDRESS="$wallet_address" \
    node "$script_dir/mock-turnkey.mjs" >"$run_dir/turnkey.log" 2>&1 &
pids+=($!)

"$gateway_dir/target/debug/examples/local_release_policy" "$run_dir/policy"
turnkey_key="$(openssl rand -hex 32)"
(
    cd "$gateway_dir"
    export TVC_GATEWAY_LISTEN="127.0.0.1:$gateway_port"
    export TVC_GATEWAY_ORIGIN_AUTH_HEADER="$origin_auth"
    export TVC_GATEWAY_ENCLAVE__BASE_URL="http://127.0.0.1:$enclave_port"
    export TVC_GATEWAY_TURNKEY__API_BASE_URL="http://127.0.0.1:$turnkey_port"
    export TVC_GATEWAY_TURNKEY__WAAS_PARENT_ORGANIZATION_ID="$parent_organization_id"
    export TVC_GATEWAY_TURNKEY__BOOT_PROOF_API_KEY__PRIVATE_KEY="$turnkey_key"
    export TVC_GATEWAY_TURNKEY__BOOT_PROOF_API_KEY__PUBLIC_KEY="$(p256_public "$turnkey_key" compressed)"
    export TVC_GATEWAY_TURNKEY__WAAS_API_KEY__PRIVATE_KEY="$turnkey_key"
    export TVC_GATEWAY_TURNKEY__WAAS_API_KEY__PUBLIC_KEY="$(p256_public "$turnkey_key" compressed)"
    export TVC_GATEWAY_PROVISIONING__PRIVATE_KEY="$provisioning_key"
    export TVC_GATEWAY_PROVISIONING__EXPECTED_PUBLIC_KEY="$(p256_public "$provisioning_key" uncompressed)"
    export TVC_GATEWAY_PROVISIONING__ENROLLMENT_SECRET="$(openssl rand -hex 32)"
    export TVC_GATEWAY_PROVISIONING__RELEASE_POLICY_PATH="$run_dir/policy/release-policy.json"
    export TVC_GATEWAY_PROVISIONING__RELEASE_AUTHORITIES_PATH="$run_dir/policy/release-authorities.json"
    export TVC_GATEWAY_WALLET_GRANT__PRIVATE_KEY="$grant_key"
    export TVC_GATEWAY_WALLET_GRANT__EXPECTED_PUBLIC_KEY="$(p256_public "$grant_key" uncompressed)"
    exec "$gateway_dir/target/debug/tvc-gateway" configs/config.yaml
) >"$run_dir/gateway.log" 2>&1 &
pids+=($!)

wait_for "http://127.0.0.1:$enclave_port/health" "testkit enclave"
wait_for "http://127.0.0.1:$gateway_port/health" "tvc-gateway"

if ! GATEWAY_URL="http://127.0.0.1:$gateway_port" \
    ORIGIN_AUTH="$origin_auth" \
    PROJECT_ID="$project_id" \
    PARENT_ORGANIZATION_ID="$parent_organization_id" \
    ORGANIZATION_ID="$organization_id" \
    TURNKEY_WALLET_ID="$turnkey_wallet_id" \
    ENCLAVE_URL="http://127.0.0.1:$enclave_port" \
    WALLET_KEYPAIR="$run_dir/wallet.json" \
    TVC_WALLET_DIST="$repo_dir/packages/tvc-wallet/dist" \
    TESTKIT_FIXTURE="$testkit_fixture" \
    node "$script_dir/driver.mjs"; then
    for log in enclave turnkey gateway; do
        echo "--- $log.log" >&2
        tail -n 40 "$run_dir/$log.log" >&2
    done
    exit 1
fi
