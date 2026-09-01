#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 4 ]]; then
  echo "usage: start-localnet.sh PORT_OFFSET SOLANA_KEYPAIR FIXTURE_DIR OUTPUT_ENV" >&2
  exit 2
fi

port_offset="$1"
solana_keypair="$2"
fixture_dir="$3"
output_env="$4"

tvc_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
zolana_root="$tvc_root/../zolana"
rpc_port=$((8899 + port_offset))
photon_port=$((8784 + port_offset))
prover_port=$((3001 + port_offset))
rpc_url="http://127.0.0.1:${rpc_port}"
indexer_url="http://127.0.0.1:${photon_port}"
prover_url="http://127.0.0.1:${prover_port}"

if [[ -e "$fixture_dir" ]]; then
  echo "fixture directory must not already exist: $fixture_dir" >&2
  exit 2
fi
mkdir -p "$fixture_dir"
fixture_dir="$(cd "$fixture_dir" && pwd)"
solana_keypair="$(cd "$(dirname "$solana_keypair")" && pwd)/$(basename "$solana_keypair")"
output_env="$(cd "$(dirname "$output_env")" && pwd)/$(basename "$output_env")"

cd "$zolana_root"
ZOLANA_PORT_OFFSET="$port_offset" just \
  build-programs build-prover-server build-cli ensure-photon ensure-custom-ring-live-keys

program_ids="$(cargo run -q -p xtask -- program-ids)"
eval "$program_ids"
: "${SHIELDED_POOL_PROGRAM_ID:?xtask did not emit SHIELDED_POOL_PROGRAM_ID}"
: "${USER_REGISTRY_PROGRAM_ID:?xtask did not emit USER_REGISTRY_PROGRAM_ID}"
: "${DEFAULT_TREE_ADDRESS:?xtask did not emit DEFAULT_TREE_ADDRESS}"

bin="$zolana_root/target/debug/zolana"
accounts_dir="$fixture_dir/accounts"
export ZOLANA_CONFIG_DIR="$fixture_dir/zolana-config"
export ZOLANA_PHOTON_BIN="$zolana_root/target/debug/photon"
export ZOLANA_PROVER_KEYS_DIR="$zolana_root/prover/server/proving-keys"
mkdir -p "$ZOLANA_CONFIG_DIR"

cargo run -q -p xtask -- generate-account-snapshots \
  --deploy-dir target/deploy --accounts-dir "$accounts_dir"

new_ring() {
  local name="$1"
  local ring_dir="$fixture_dir/$name"
  mkdir -p "$ring_dir"
  solana-keygen new --no-bip39-passphrase --silent --force \
    --outfile "$ring_dir/program.json"
  solana-keygen new --no-bip39-passphrase --silent --force \
    --outfile "$ring_dir/authority.json"
}

new_ring ring-a
new_ring ring-b
ring_a_program="$(solana-keygen pubkey "$fixture_dir/ring-a/program.json")"
ring_b_program="$(solana-keygen pubkey "$fixture_dir/ring-b/program.json")"
ring_a_authority="$(solana-keygen pubkey "$fixture_dir/ring-a/authority.json")"
ring_b_authority="$(solana-keygen pubkey "$fixture_dir/ring-b/authority.json")"

"$bin" dev start --no-use-surfpool \
  --rpc-port "$rpc_port" --photon-port "$photon_port" --prover-port "$prover_port" \
  --account-dir "$accounts_dir" --limit-ledger-size 5000000 \
  --sbf-program "$SHIELDED_POOL_PROGRAM_ID" target/deploy/shielded_pool_program.so \
  --sbf-program "$USER_REGISTRY_PROGRAM_ID" target/deploy/zolana_user_registry.so \
  --upgradeable-program "$ring_a_program" target/deploy/custom_ring_program.so \
    "$ring_a_authority" \
  --upgradeable-program "$ring_b_program" target/deploy/custom_ring_program.so \
    "$ring_b_authority" \
  -- --deactivate-feature B8JJXCy5amZyWG9r7EnUYLwzXSXTxG7GZ1qZ1qggo83g

"$bin" config set --rpc-url "$rpc_url" --indexer-url "$indexer_url" \
  --prover-url "$prover_url" >/dev/null

"$bin" wallet new --outfile "$fixture_dir/mint-authority.json" >/dev/null
"$bin" wallet new --outfile "$fixture_dir/headless-wallet.json" \
  --funding-keypair "$solana_keypair" >/dev/null
mint_output="$("$bin" dev pool test-mint \
  --keypair "$fixture_dir/headless-wallet.json" \
  --authority-path "$fixture_dir/mint-authority.json" \
  --airdrop-lamports 20000000000 --amount 1000000)"
spl_mint="$(sed -n 's/^ok test_mint mint=\([^ ]*\).*/\1/p' <<<"$mint_output")"
spl_asset_id="$(sed -n 's/^ok test_mint .* asset_id=\([^ ]*\).*/\1/p' <<<"$mint_output")"
spl_token_account="$(sed -n 's/^ok test_mint .* token_account=\([^ ]*\).*/\1/p' <<<"$mint_output")"
: "${spl_mint:?test-mint did not emit a mint}"
: "${spl_asset_id:?test-mint did not emit an asset id}"
: "${spl_token_account:?test-mint did not emit a token account}"

configure_ring() {
  local name="$1"
  local program_id="$2"
  local ring_dir="$fixture_dir/$name"
  cat >"$ring_dir/ring.toml" <<TOML
name = "headless-${name}"
program_id = "$program_id"
authority_keypair = "$ring_dir/authority.json"
target = "localnet"

[localnet]
rpc = "$rpc_url"
indexer = "$indexer_url"
prover = "$prover_url"
ring_rpc = "http://127.0.0.1:1"

[devnet]
rpc = "$rpc_url"
indexer = "$indexer_url"
prover = "$prover_url"
ring_rpc = "http://127.0.0.1:1"
TOML
  cargo run -q -p zolana-ring-rpc -- keygen --out "$ring_dir/auditor.key"
  cargo run -q -p custom-ring-cli -- --config "$ring_dir/ring.toml" \
    init --local-auditor --auditor-pubkey-file auditor.key.pub
}

configure_ring ring-a "$ring_a_program"
configure_ring ring-b "$ring_b_program"

printf '%s\n' \
  "TVC_E2E_SPL_MINT=$spl_mint" \
  "TVC_E2E_SPL_ASSET_ID=$spl_asset_id" \
  "TVC_E2E_SPL_TOKEN_ACCOUNT=$spl_token_account" \
  "TVC_E2E_RING_A_PROGRAM_ID=$ring_a_program" \
  "TVC_E2E_RING_B_PROGRAM_ID=$ring_b_program" \
  "ZOLANA_TREE=$DEFAULT_TREE_ADDRESS" >"$output_env"

echo
echo "headless local fixture ready"
echo "  rpc       $rpc_url"
echo "  photon    $indexer_url"
echo "  prover    $prover_url"
echo "  SPL mint  $spl_mint (asset $spl_asset_id)"
echo "  ring A    $ring_a_program"
echo "  ring B    $ring_b_program"
