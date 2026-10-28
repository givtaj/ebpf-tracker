Trace a trusted Axum API **inside its own Debian Bookworm Docker image**, save
its process/file/write/connection activity, and replay the JSONL afterward.

The new `ebpf-tracker-runtime_0.2.0~alpha.2_amd64.deb` installs a precompiled
`ebpf-tracker-agent` and declares its Bookworm bpftrace dependencies. Use the
agent as the entrypoint, select your existing non-root application user, and
apply the development tracing configuration. No Rust compiler, Node viewer,
Docker socket, or Axum source changes are needed inside the application image.

```dockerfile
USER root
COPY vendor/ebpf-tracker-runtime.deb /tmp/tracker.deb
RUN apt-get update \
 && apt-get install -y --no-install-recommends /tmp/tracker.deb \
 && rm /tmp/tracker.deb \
 && rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["ebpf-tracker-agent", "--app-user", "app", "--output", "/traces/events.jsonl", "--"]
CMD ["your-api"]
```

Replace `app` with your existing non-root user and `your-api` with your server
command. Read the [complete Dockerfile/Compose/CI guide](https://github.com/givtaj/ebpf-tracker/blob/v0.2.0-alpha.2/docs/in-container.md)
before running: the first alpha requires a privileged container and host PID
namespace on an isolated, trusted development or disposable CI host. It is not
for production, shared runners, or untrusted workloads. Dropping app
capabilities and filtering events do not create a security sandbox.

The known-bad `7.0.0-1017-azure` host kernel is rejected because it silently
drops syscall events outside one CPU. Live GitHub release gates use Ubuntu
22.04 while [the upstream runner regression](https://github.com/actions/runner-images/issues/15003)
remains unresolved. Changing the application image cannot fix a host kernel.

The launcher waits for tracing readiness, drops application privileges,
keeps stdout/stderr in Docker logs, forwards shutdown signals, and preserves
workload exit status. Each run requires a new output file. Stopping the traced
container stops the API and flushes its capture; existing-container attachment
is not part of this integration.

Downloads include the Bookworm amd64 runtime package, Linux x86_64 and Intel
macOS host-CLI archives, and `SHA256SUMS`. The host CLI provides offline replay:

```bash
ebpf-tracker replay traces/events.jsonl
```

Replay needs host Node.js and does not start Docker. Arm64 runtime packages can
be built from source; they are not included in this release's amd64 package
support promise. No crates.io publication is provided.

The release gates install the actual package in a clean Bookworm image and
exercise a synthetic Axum/PostgreSQL stack, including HTTP responses,
non-root identity, capabilities, trace isolation, shutdown, and failure cases.
Roots informed the Docker layout but its application integration has not been
accepted; no Roots files, services, or data were changed.

Events describe syscall attempts, not successful I/O, remote addresses,
HTTP routes, request IDs, database contents, throughput, or request latency.
APIs and formats may change during alpha. Cloud attachment, host monitoring,
perf, AI analysis, datasets, and OTLP remain experimental extras outside this
focused release.

See the [alpha scope](https://github.com/givtaj/ebpf-tracker/blob/v0.2.0-alpha.2/docs/alpha-scope.md),
[CLI guide](https://github.com/givtaj/ebpf-tracker/blob/v0.2.0-alpha.2/docs/cli.md),
and [security policy](https://github.com/givtaj/ebpf-tracker/blob/v0.2.0-alpha.2/SECURITY.md).
