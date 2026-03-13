FROM rust:1-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends bpftrace kmod \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

COPY scripts/run-bpftrace-wrap.sh /usr/local/bin/run-bpftrace-wrap.sh
RUN chmod +x /usr/local/bin/run-bpftrace-wrap.sh

ENTRYPOINT ["/usr/local/bin/run-bpftrace-wrap.sh"]
CMD ["/bin/true"]
