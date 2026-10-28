FROM rust:1.96-bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --locked --release

FROM debian:bookworm-slim
COPY runtime.deb /tmp/runtime.deb
RUN apt-get update \
    && apt-get install -y --no-install-recommends /tmp/runtime.deb \
    && rm -rf /var/lib/apt/lists/* /tmp/runtime.deb \
    && groupadd --gid 10001 roots \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin roots \
    && mkdir -p /data /traces \
    && chown roots:roots /data
COPY --from=builder /build/target/release/axum-container-fixture /usr/local/bin/axum-fixture
WORKDIR /data
# The tracer starts as root. It drops all app credentials/capabilities before exec.
ENTRYPOINT ["/usr/bin/ebpf-tracker-agent", "--app-user", "roots", "--output", "/traces/events.jsonl", "--"]
CMD ["/usr/local/bin/axum-fixture"]
