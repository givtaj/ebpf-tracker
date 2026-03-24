FROM rust:1-bookworm AS exec-target-builder

COPY scripts/exec-target-from-env.rs /tmp/exec-target-from-env.rs
RUN rustc /tmp/exec-target-from-env.rs -O -o /tmp/exec-target-from-env

FROM node:22-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends bpftrace kmod linux-perf \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

COPY scripts/run-bpftrace-wrap.sh /usr/local/bin/run-bpftrace-wrap.sh
COPY --from=exec-target-builder /tmp/exec-target-from-env /usr/local/bin/exec-target-from-env
RUN chmod +x /usr/local/bin/run-bpftrace-wrap.sh /usr/local/bin/exec-target-from-env

ENTRYPOINT ["/usr/local/bin/run-bpftrace-wrap.sh"]
CMD ["/bin/true"]
