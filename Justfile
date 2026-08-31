set dotenv-load

default:
    @just --list

doctor:
    @rustc --version
    @cargo --version
    @just --version
    @node --version
    @npx --yes pnpm@9.15.0 --version

fmt:
    cargo fmt --all
    cargo fmt --manifest-path crates/keypair-turnkey/Cargo.toml --all
    cargo fmt --manifest-path crates/proof-verifier/Cargo.toml --all

fmt-check:
    cargo fmt --all -- --check
    cargo fmt --manifest-path crates/keypair-turnkey/Cargo.toml --all -- --check
    cargo fmt --manifest-path crates/proof-verifier/Cargo.toml --all -- --check

check: check-workspace check-keypair-turnkey check-proof-verifier

check-workspace:
    cargo check --workspace --all-targets --all-features --locked

check-keypair-turnkey:
    cargo check --manifest-path crates/keypair-turnkey/Cargo.toml --all-targets --locked

check-proof-verifier:
    cargo check --manifest-path crates/proof-verifier/Cargo.toml --all-targets --locked

lint: lint-workspace lint-keypair-turnkey lint-proof-verifier

lint-workspace:
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings

lint-keypair-turnkey:
    cargo clippy --manifest-path crates/keypair-turnkey/Cargo.toml --all-targets --locked -- -D warnings

lint-proof-verifier:
    cargo clippy --manifest-path crates/proof-verifier/Cargo.toml --all-targets --locked -- -D warnings

test: test-workspace test-keypair-turnkey test-proof-verifier

test-workspace:
    cargo test --workspace --all-targets --all-features --locked

test-keypair-turnkey:
    cargo test --manifest-path crates/keypair-turnkey/Cargo.toml --all-targets --locked

test-proof-verifier:
    cargo test --manifest-path crates/proof-verifier/Cargo.toml --all-targets --locked

check-private-swap:
    #!/usr/bin/env sh
    set -eu
    if [ ! -d ../zolana/sdk-tests/zk-program-swap ]; then
        echo "check-private-swap requires the sibling zolana checkout" >&2
        exit 1
    fi
    cargo fmt --manifest-path examples/private-swap/Cargo.toml --all -- --check
    cargo clippy --manifest-path examples/private-swap/Cargo.toml --all-targets --locked -- -D warnings
    cargo test --manifest-path examples/private-swap/Cargo.toml --all-targets --locked

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

ci: fmt-check lint test check-protocol-fixtures check-private-swap install-ts ci-ts

# Mechanical pre-deployment checks only. Signing and approval stay manual.
deploy-preflight descriptor *args:
    node scripts/deploy-preflight.mjs privacy-wallet --descriptor {{descriptor}} {{args}}

deploy-check descriptor: ci
    just deploy-preflight {{descriptor}}

image-privacy-wallet:
    docker build --platform linux/amd64 --provenance=false -f apps/privacy-wallet/Dockerfile .

image-privacy-wallet-local:
    docker build --platform linux/amd64 --provenance=false -f apps/privacy-wallet/Dockerfile.local -t zolana-tvc-privacy-wallet-local:dev .
