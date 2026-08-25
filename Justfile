set dotenv-load

default:
    @just --list

# Verify the local toolchain and the sibling Zolana checkout.
doctor:
    @test -f ../zolana/Cargo.toml || { echo "missing sibling ../zolana checkout" >&2; exit 1; }
    @rustc --version
    @cargo --version
    @just --version

# Format every independently locked Rust workspace.
fmt:
    cargo fmt --all
    cargo fmt --manifest-path crates/keypair-turnkey/Cargo.toml --all
    cargo fmt --manifest-path apps/client-wallet/Cargo.toml --all
    cargo fmt --manifest-path apps/enclave-wallet/Cargo.toml --all
    cargo fmt --manifest-path crates/proof-verifier/Cargo.toml --all

# Check formatting without modifying files.
fmt-check:
    cargo fmt --all -- --check
    cargo fmt --manifest-path crates/keypair-turnkey/Cargo.toml --all -- --check
    cargo fmt --manifest-path apps/client-wallet/Cargo.toml --all -- --check
    cargo fmt --manifest-path apps/enclave-wallet/Cargo.toml --all -- --check
    cargo fmt --manifest-path crates/proof-verifier/Cargo.toml --all -- --check

check: check-protocol check-keypair-turnkey check-client-wallet check-enclave-wallet check-proof-verifier

check-protocol:
    cargo check --workspace --all-targets --locked

check-keypair-turnkey:
    cargo check --manifest-path crates/keypair-turnkey/Cargo.toml --all-targets --locked

check-client-wallet:
    cargo check --manifest-path apps/client-wallet/Cargo.toml --all-targets --all-features --locked

check-enclave-wallet:
    cargo check --manifest-path apps/enclave-wallet/Cargo.toml --all-targets --all-features --locked

check-proof-verifier:
    cargo check --manifest-path crates/proof-verifier/Cargo.toml --all-targets --locked

lint: lint-protocol lint-keypair-turnkey lint-client-wallet lint-enclave-wallet lint-proof-verifier

lint-protocol:
    cargo clippy --workspace --all-targets --locked -- -D warnings

lint-keypair-turnkey:
    cargo clippy --manifest-path crates/keypair-turnkey/Cargo.toml --all-targets --locked -- -D warnings

lint-client-wallet:
    cargo clippy --manifest-path apps/client-wallet/Cargo.toml --all-targets --all-features --locked -- -D warnings

lint-enclave-wallet:
    cargo clippy --manifest-path apps/enclave-wallet/Cargo.toml --all-targets --all-features --locked -- -D warnings

lint-proof-verifier:
    cargo clippy --manifest-path crates/proof-verifier/Cargo.toml --all-targets --locked -- -D warnings

test: test-protocol test-keypair-turnkey test-client-wallet test-enclave-wallet test-proof-verifier

test-protocol:
    cargo test --workspace --all-targets --locked

test-keypair-turnkey:
    cargo test --manifest-path crates/keypair-turnkey/Cargo.toml --all-targets --locked

test-client-wallet:
    cargo test --manifest-path apps/client-wallet/Cargo.toml --all-targets --all-features --locked

test-enclave-wallet:
    cargo test --manifest-path apps/enclave-wallet/Cargo.toml --all-targets --all-features --locked

test-proof-verifier:
    cargo test --manifest-path crates/proof-verifier/Cargo.toml --all-targets --locked

# Local CI-equivalent gate; image builds are intentionally separate.
ci: fmt-check lint test

# Build the production-shaped client-owned TVC image.
image-client-wallet:
    docker build --platform linux/amd64 --provenance=false -f apps/client-wallet/Dockerfile ..

# Build the production-shaped enclave-owned TVC image.
image-enclave-wallet:
    docker build --platform linux/amd64 --provenance=false -f apps/enclave-wallet/Dockerfile ..

# Build the unattested disposable client-owned local harness.
image-client-wallet-local:
    docker build --platform linux/amd64 --provenance=false -f apps/client-wallet/Dockerfile.local -t zolana-tvc-client-wallet-local:dev ..

# Build the unattested disposable enclave-owned local harness.
image-enclave-wallet-local:
    docker build --platform linux/amd64 --provenance=false -f apps/enclave-wallet/Dockerfile.local -t zolana-tvc-enclave-wallet-local:dev ..
