#!/usr/bin/env bash
# Starts a fresh Zolana localnet (validator, Photon, prover) from the sibling
# zolana checkout, mints one SPL test asset and initializes one custom ring for
# the client example; see `just headless-e2e`.
set -euo pipefail

if [[ "$#" -ne 4 ]]; then
  echo "usage: start-localnet.sh PORT_OFFSET SOLANA_KEYPAIR FIXTURE_DIR OUTPUT_ENV" >&2
  exit 2
fi

port_offset="$1"
solana_keypair="$2"
fixture_dir="$3"
output_env="$4"

tvc_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
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
ZOLANA_PORT_OFFSET="$port_offset" just build-programs build-prover-server build-cli ensure-photon \
  ensure-custom-ring-live-keys

eval "$(cargo run -q -p xtask -- program-ids)"
: "${SHIELDED_POOL_PROGRAM_ID:?xtask did not emit SHIELDED_POOL_PROGRAM_ID}"
: "${USER_REGISTRY_PROGRAM_ID:?xtask did not emit USER_REGISTRY_PROGRAM_ID}"
: "${CUSTOM_RING_PROGRAM_ID:?xtask did not emit CUSTOM_RING_PROGRAM_ID}"

bin="$zolana_root/target/debug/zolana"
accounts_dir="$fixture_dir/accounts"
export ZOLANA_CONFIG_DIR="$fixture_dir/zolana-config"
export ZOLANA_PHOTON_BIN="$zolana_root/target/debug/photon"
export ZOLANA_PROVER_KEYS_DIR="$zolana_root/prover/server/proving-keys"
mkdir -p "$ZOLANA_CONFIG_DIR"

cargo run -q -p xtask -- generate-account-snapshots \
  --deploy-dir target/deploy --accounts-dir "$accounts_dir"

# The ring program is loaded upgradeable; only its upgrade authority may
# create the ring config, so the authority is a keypair of this run.
ring_dir="$fixture_dir/ring"
mkdir -p "$ring_dir"
solana-keygen new --no-bip39-passphrase --silent --force -o "$ring_dir/authority.json"
ring_authority="$(solana-keygen pubkey "$ring_dir/authority.json")"

"$bin" dev start --no-use-surfpool \
  --rpc-port "$rpc_port" --photon-port "$photon_port" --prover-port "$prover_port" \
  --account-dir "$accounts_dir" --limit-ledger-size 5000000 \
  --sbf-program "$SHIELDED_POOL_PROGRAM_ID" target/deploy/shielded_pool_program.so \
  --sbf-program "$USER_REGISTRY_PROGRAM_ID" target/deploy/zolana_user_registry.so \
  --upgradeable-program "$CUSTOM_RING_PROGRAM_ID" target/deploy/custom_ring_program.so "$ring_authority" \
  -- --deactivate-feature B8JJXCy5amZyWG9r7EnUYLwzXSXTxG7GZ1qZ1qggo83g

"$bin" config set --rpc-url "$rpc_url" --indexer-url "$indexer_url" \
  --prover-url "$prover_url" >/dev/null

"$bin" wallet new --outfile "$fixture_dir/mint-authority.json" >/dev/null
"$bin" wallet new --outfile "$fixture_dir/mint-wallet.json" \
  --funding-keypair "$solana_keypair" >/dev/null
mint_output="$("$bin" dev pool test-mint \
  --keypair "$fixture_dir/mint-wallet.json" \
  --authority-path "$fixture_dir/mint-authority.json" \
  --airdrop-lamports 20000000000 --amount 1000000)"
spl_mint="$(sed -n 's/^ok test_mint mint=\([^ ]*\).*/\1/p' <<<"$mint_output")"
spl_asset_id="$(sed -n 's/^ok test_mint .* asset_id=\([^ ]*\).*/\1/p' <<<"$mint_output")"
spl_token_account="$(sed -n 's/^ok test_mint .* token_account=\([^ ]*\).*/\1/p' <<<"$mint_output")"
: "${spl_mint:?test-mint did not emit a mint}"
: "${spl_asset_id:?test-mint did not emit an asset id}"
: "${spl_token_account:?test-mint did not emit a token account}"

# One custom ring with a fresh auditor key. Nothing in the example reads as
# the auditor, so the ring RPC is not started; the ring config alone lets the
# pool accept ring deposits, transfers and exits.
cat >"$ring_dir/ring.toml" <<TOML
name = "headless-e2e-ring"
program_id = "$CUSTOM_RING_PROGRAM_ID"
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
  init --auditor-pubkey-file "auditor.key.pub"

printf '%s\n' \
  "SPL_MINT=$spl_mint" \
  "SPL_ASSET_ID=$spl_asset_id" \
  "SPL_TOKEN_ACCOUNT=$spl_token_account" \
  "RING_PROGRAM_ID=$CUSTOM_RING_PROGRAM_ID" >"$output_env"

echo
echo "localnet ready"
echo "  rpc       $rpc_url"
echo "  photon    $indexer_url"
echo "  prover    $prover_url"
echo "  SPL mint  $spl_mint (asset $spl_asset_id)"
echo "  ring      $CUSTOM_RING_PROGRAM_ID"
