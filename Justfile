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
    cargo fmt --manifest-path apps/privacy-wallet/Cargo.toml --all
    cargo fmt --manifest-path crates/proof-verifier/Cargo.toml --all

fmt-check:
    cargo fmt --all -- --check
    cargo fmt --manifest-path crates/keypair-turnkey/Cargo.toml --all -- --check
    cargo fmt --manifest-path apps/privacy-wallet/Cargo.toml --all -- --check
    cargo fmt --manifest-path crates/proof-verifier/Cargo.toml --all -- --check

check: check-protocol check-keypair-turnkey check-privacy-wallet check-proof-verifier

check-protocol:
    cargo check --workspace --all-targets --locked

check-keypair-turnkey:
    cargo check --manifest-path crates/keypair-turnkey/Cargo.toml --all-targets --locked

check-privacy-wallet:
    cargo check --manifest-path apps/privacy-wallet/Cargo.toml --all-targets --all-features --locked

check-proof-verifier:
    cargo check --manifest-path crates/proof-verifier/Cargo.toml --all-targets --locked

lint: lint-protocol lint-keypair-turnkey lint-privacy-wallet lint-proof-verifier

lint-protocol:
    cargo clippy --workspace --all-targets --locked -- -D warnings

lint-keypair-turnkey:
    cargo clippy --manifest-path crates/keypair-turnkey/Cargo.toml --all-targets --locked -- -D warnings

lint-privacy-wallet:
    cargo clippy --manifest-path apps/privacy-wallet/Cargo.toml --all-targets --all-features --locked -- -D warnings

lint-proof-verifier:
    cargo clippy --manifest-path crates/proof-verifier/Cargo.toml --all-targets --locked -- -D warnings

test: test-protocol test-keypair-turnkey test-privacy-wallet test-proof-verifier

test-protocol:
    cargo test --workspace --all-targets --locked

test-keypair-turnkey:
    cargo test --manifest-path crates/keypair-turnkey/Cargo.toml --all-targets --locked

test-privacy-wallet:
    cargo test --manifest-path apps/privacy-wallet/Cargo.toml --all-targets --all-features --locked

test-proof-verifier:
    cargo test --manifest-path crates/proof-verifier/Cargo.toml --all-targets --locked

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

ci: fmt-check lint test install-ts ci-ts

# Mechanical pre-deployment checks only. Signing and approval stay manual.
deploy-preflight descriptor *args:
    node scripts/deploy-preflight.mjs privacy-wallet --descriptor {{descriptor}} {{args}}

deploy-check descriptor: ci
    just deploy-preflight {{descriptor}}

image-privacy-wallet:
    docker build --platform linux/amd64 --provenance=false -f apps/privacy-wallet/Dockerfile .

image-privacy-wallet-local:
    docker build --platform linux/amd64 --provenance=false -f apps/privacy-wallet/Dockerfile.local -t zolana-tvc-privacy-wallet-local:dev .
