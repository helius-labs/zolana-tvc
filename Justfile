set dotenv-load

default:
    @just --list

fmt:
    cargo fmt --all
    cargo fmt --manifest-path crates/boot-proof/Cargo.toml --all

fmt-check:
    cargo fmt --all -- --check
    cargo fmt --manifest-path crates/boot-proof/Cargo.toml --all -- --check

check:
    cargo check --workspace --all-targets --all-features --locked
    cargo check --manifest-path crates/boot-proof/Cargo.toml --all-targets --locked

lint:
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
    cargo clippy --manifest-path crates/boot-proof/Cargo.toml --all-targets --locked -- -D warnings

test:
    cargo test --workspace --all-targets --all-features --locked
    cargo test --manifest-path crates/boot-proof/Cargo.toml --all-targets --locked

regenerate-protocol-fixtures:
    cargo test --test conformance regenerate_content_addressed_fixtures -- --ignored --exact

check-protocol-fixtures:
    #!/usr/bin/env sh
    set -eu
    fixture_status="$(git status --porcelain --untracked-files=all -- crates/protocol/fixtures)"
    if [ -n "$fixture_status" ]; then
        echo "protocol fixtures differ from the committed conformance corpus" >&2
        echo "$fixture_status" >&2
        exit 1
    fi

setup: install-ts

install-ts:
    npx --yes pnpm@9.15.0 install --frozen-lockfile

lint-ts:
    npx --yes pnpm@9.15.0 lint:ts

typecheck-ts:
    npx --yes pnpm@9.15.0 typecheck:ts

test-ts:
    npx --yes pnpm@9.15.0 test:ts

build-ts:
    npx --yes pnpm@9.15.0 build:ts

ci-ts:
    npx --yes pnpm@9.15.0 ci:ts

# Start a fresh Zolana localnet plus the Rust testkit and run the headless example.
headless-e2e port_offset="200": (_local-e2e port_offset "node --experimental-strip-types examples/headless-wallet/src/main.ts")

# The same stack, running the client example against the testkit.
client-example-local port_offset="200": (_local-e2e port_offset "npx --yes pnpm@9.15.0 --filter zolana-tvc-typescript-client-example example examples/deposit_transfer_withdraw.ts")

_local-e2e port_offset runner:
    #!/usr/bin/env bash
    set -euo pipefail
    run_dir="$(mktemp -d)"
    wallet_keypair="${TVC_SOLANA_KEYPAIR_PATH:-$run_dir/wallet.json}"
    identity_path="${TVC_IDENTITY_PATH:-$run_dir/identity.json}"
    fixture_env="$run_dir/fixture.env"
    fixture_dir="$run_dir/fixture"
    if [ -z "${TVC_SOLANA_KEYPAIR_PATH:-}" ]; then
        solana-keygen new --no-bip39-passphrase --silent --outfile "$wallet_keypair"
    else
        test -f "$wallet_keypair" || { echo "missing TVC_SOLANA_KEYPAIR_PATH: $wallet_keypair" >&2; exit 1; }
    fi
    rpc_port=$((8899 + {{port_offset}}))
    photon_port=$((8784 + {{port_offset}}))
    prover_port=$((3001 + {{port_offset}}))
    rpc_url="http://127.0.0.1:${rpc_port}"
    indexer_url="http://127.0.0.1:${photon_port}"
    prover_url="http://127.0.0.1:${prover_port}"
    server_pid=""
    cleanup() {
        if [ -n "$server_pid" ]; then kill "$server_pid" 2>/dev/null || true; fi
        for port in "$rpc_port" "$photon_port" "$prover_port"; do
            lsof -ti "tcp:${port}" 2>/dev/null | xargs kill 2>/dev/null || true
        done
        rm -rf -- "$run_dir"
    }
    trap cleanup EXIT
    npx --yes pnpm@9.15.0 install --frozen-lockfile
    npx --yes pnpm@9.15.0 build:ts
    bash examples/headless-wallet/scripts/start-localnet.sh \
      "{{port_offset}}" "$wallet_keypair" "$fixture_dir" "$fixture_env"
    source "$fixture_env"
    solana airdrop 10 "$(solana address --keypair "$wallet_keypair")" --url "$rpc_url" >/dev/null
    cargo run -p zolana-tvc-privacy-wallet --features local-dev --bin zolana-tvc-privacy-wallet-local -- \
        --wallet-keypair "$wallet_keypair" --prover-url "$prover_url" &
    server_pid=$!
    for _ in $(seq 1 120); do
        if curl --fail --silent http://127.0.0.1:44020/health >/dev/null; then
            break
        fi
        if ! kill -0 "${server_pid}" 2>/dev/null; then
            wait "${server_pid}"
        fi
        sleep 1
    done
    curl --fail --silent http://127.0.0.1:44020/health >/dev/null
    TVC_ENDPOINT="http://127.0.0.1:44020" \
      TVC_SOLANA_KEYPAIR_PATH="$wallet_keypair" TVC_IDENTITY_PATH="$identity_path" \
      TVC_SOLANA_RPC_URL="$rpc_url" TVC_INDEXER_URL="$indexer_url" TVC_PROVER_URL="$prover_url" \
      TVC_E2E_SPL_MINT="$TVC_E2E_SPL_MINT" \
      TVC_E2E_SPL_ASSET_ID="$TVC_E2E_SPL_ASSET_ID" \
      TVC_E2E_SPL_TOKEN_ACCOUNT="$TVC_E2E_SPL_TOKEN_ACCOUNT" \
      TVC_LOCAL_TESTKIT_ENDPOINT="http://127.0.0.1:44020" TVC_WALLET_PATH="$run_dir/wallet-identity.json" \
      ZOLANA_ENDPOINT="$rpc_url" ZOLANA_INDEXER_URL="$indexer_url" ZOLANA_PROVER_URL="$prover_url" \
      {{runner}}

ci: fmt-check lint test check-protocol-fixtures install-ts ci-ts

image-privacy-wallet:
    docker build --platform linux/amd64 --provenance=false -f apps/privacy-wallet/Dockerfile .

# Build, deploy, sign the release policy and pin it in the wallet-kit demo; see scripts/release.mjs.
release release_id wallet_kit="../wallet-kit":
    node scripts/release.mjs all {{release_id}} --wallet-kit {{wallet_kit}}
