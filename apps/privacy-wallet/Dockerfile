FROM stagex/pallet-rust:1.94.0@sha256:4e2d4273a1d5c6d62660968302791f3cf550c3d12629e66314956ff46c97fc0e AS build

ENV RUSTFLAGS='-C target-feature=+crt-static'
ENV CARGOFLAGS='--target x86_64-unknown-linux-musl --locked --release --package zolana-tvc-privacy-wallet --bin zolana-tvc-privacy-wallet'
ENV RELEASE_DIR='/src/target/x86_64-unknown-linux-musl/release'

ADD . /src/
WORKDIR /src/

RUN cargo fetch --locked
RUN --network=none <<-EOF
    set -eu
    cargo build ${CARGOFLAGS}
    mkdir -p /rootfs
    mv ${RELEASE_DIR}/zolana-tvc-privacy-wallet /rootfs/tvc_app
    sha256sum /rootfs/tvc_app | awk '{print "SHA256=" $1}'
EOF

FROM stagex/core-busybox:1.36.1@sha256:cac5d773db1c69b832d022c469ccf5f52daf223b91166e6866d42d6983a3b374 AS package
COPY --from=build /rootfs/. /

LABEL org.opencontainers.image.title="Zolana TVC Privacy Wallet" \
      org.opencontainers.image.description="Attested privacy wallet with enclave-held keys and an external-prover spend path" \
      org.opencontainers.image.licenses="AGPL-3.0-only"

RUN sha256sum /tvc_app | awk '{print "SHA256=" $1}'
