FROM stagex/pallet-rust:1.94.0@sha256:4e2d4273a1d5c6d62660968302791f3cf550c3d12629e66314956ff46c97fc0e AS build

ENV RUSTFLAGS='-C target-feature=+crt-static'
ENV CARGOFLAGS='--target x86_64-unknown-linux-musl --locked --release --package zolana-tvc-enclave-wallet --bin zolana-tvc-enclave-wallet'
ENV RELEASE_DIR='/src/apps/enclave-wallet/target/x86_64-unknown-linux-musl/release'

ADD . /src/
WORKDIR /src/apps/enclave-wallet/

RUN cargo fetch --locked
RUN --network=none <<-EOF
    set -eu
    cargo build ${CARGOFLAGS}
    mkdir -p /rootfs
    mv ${RELEASE_DIR}/zolana-tvc-enclave-wallet /rootfs/tvc_app
    sha256sum /rootfs/tvc_app | awk '{print "SHA256=" $1}'
EOF

FROM stagex/core-busybox:1.36.1@sha256:cac5d773db1c69b832d022c469ccf5f52daf223b91166e6866d42d6983a3b374 AS package
COPY --from=build /rootfs/. /

LABEL org.opencontainers.image.title="Zolana TVC Enclave Wallet" \
      org.opencontainers.image.description="Development full enclave-owned private wallet service" \
      org.opencontainers.image.licenses="AGPL-3.0-only"

RUN sha256sum /tvc_app | awk '{print "SHA256=" $1}'
