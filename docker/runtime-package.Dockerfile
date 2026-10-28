FROM rust:1.96-bookworm AS package-builder
ARG APP_VERSION
ARG DEBIAN_VERSION
ARG TARGETARCH
WORKDIR /build
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 binutils \
    && rm -rf /var/lib/apt/lists/*

# Copy only project sources; local logs, credentials, and Git history do not
# belong in a package build layer.
COPY Cargo.toml Cargo.lock LICENSE ./
COPY src ./src
COPY crates ./crates
COPY examples ./examples
COPY scripts/verify-runtime-package.sh scripts/release-version.sh ./scripts/

RUN cargo test --locked --package ebpf-tracker-agent -- --include-ignored \
    && cargo build --locked --release --package ebpf-tracker-agent --bin ebpf-tracker-agent \
    && test "$(target/release/ebpf-tracker-agent --version)" = "ebpf-tracker-agent ${APP_VERSION}"

RUN set -eu; \
    test "$(dpkg --print-architecture)" = "${TARGETARCH}"; \
    package_root=/tmp/runtime-package; \
    install -D -m 0755 target/release/ebpf-tracker-agent "${package_root}/usr/bin/ebpf-tracker-agent"; \
    install -D -m 0644 LICENSE "${package_root}/usr/share/doc/ebpf-tracker-runtime/copyright"; \
    mkdir -p "${package_root}/DEBIAN" /packages; \
    printf '%s\n' \
      'Package: ebpf-tracker-runtime' \
      "Version: ${DEBIAN_VERSION}" \
      "Architecture: ${TARGETARCH}" \
      'Maintainer: ebpf-tracker contributors <noreply@github.com>' \
      'Section: utils' \
      'Priority: optional' \
      'Depends: bpftrace (>= 0.17), bpftrace (<< 0.18), libc6 (>= 2.36), libgcc-s1 (>= 12)' \
      'Homepage: https://github.com/givtaj/ebpf-tracker' \
      'Description: Native eBPF collector for trusted Debian Bookworm containers' \
      ' Starts an application as an unprivileged user and records scoped JSONL events.' \
      ' Requires a compatible Linux kernel and an explicitly privileged container.' \
      > "${package_root}/DEBIAN/control"; \
    dpkg-deb --root-owner-group --build "${package_root}" "/packages/ebpf-tracker-runtime_${DEBIAN_VERSION}_${TARGETARCH}.deb"; \
    bash scripts/verify-runtime-package.sh \
      --deb "/packages/ebpf-tracker-runtime_${DEBIAN_VERSION}_${TARGETARCH}.deb" \
      --expected-version "${APP_VERSION}" --arch "${TARGETARCH}" --write-checksums

# Test the delivered package in a runtime image with no compiler or source tree.
FROM debian:bookworm-slim AS install-check
ARG APP_VERSION
COPY --from=package-builder /packages /packages
RUN apt-get update \
    && apt-get install -y --no-install-recommends /packages/*.deb \
    && test "$(ebpf-tracker-agent --version)" = "ebpf-tracker-agent ${APP_VERSION}" \
    && ebpf-tracker-agent --help \
    && test -x /usr/bin/bpftrace \
    && ! command -v cargo \
    && ! command -v rustc \
    && rm -rf /var/lib/apt/lists/*

FROM scratch AS package-artifact
COPY --from=install-check /packages/ /
