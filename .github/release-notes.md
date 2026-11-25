Alpha.3 adds a native **ARM64 Bookworm runtime package** alongside amd64. Install
`ebpf-tracker-agent` inside your trusted Axum API image, record its process-tree
activity during a development or CI session, then replay the saved JSONL.

Choose the runtime package matching the application image and native Docker
host:

- `ebpf-tracker-runtime_0.2.0-alpha.3_amd64.deb`
- `ebpf-tracker-runtime_0.2.0-alpha.3_arm64.deb`

Both use Debian package version `0.2.0~alpha.3`; release filenames use a hyphen
because GitHub rewrites `~`. Verify the download against the original
`SHA256SUMS` before installing. The
[Dockerfile/Compose/CI guide](https://github.com/givtaj/ebpf-tracker/blob/v0.2.0-alpha.3/docs/in-container.md)
provides architecture selection, checksum verification, installation and
shutdown commands.

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

Replace `app` and `your-api` with the existing non-root user and server command.
The API image needs neither Rust tooling nor a Node viewer. The agent waits for
tracing readiness, drops the API's capabilities, preserves its stdout/stderr,
forwards shutdown signals, and writes a new JSONL capture. Stopping the traced
container stops the API and flushes the capture; this does not attach to an
already-running server.

Publication requires **both native architecture gates**: clean Bookworm
installation, synthetic Axum/PostgreSQL HTTP checks, application identity,
scoped events, isolation, shutdown/failure cases, and offline replay of the
actual capture. A cross-build or the earlier source-built Roots pilot does not
substitute for those gates. The existing alpha.2 release is unchanged.

The host CLI archives remain **Linux x86_64 and Intel macOS**. There is no
ARM64 host CLI archive in this release; source installation remains available.
Replay needs host Node.js and does not start Docker:

```bash
ebpf-tracker replay traces/events.jsonl
```

Use only a trusted, isolated development or disposable CI host with privileged
Docker and the host PID namespace. Production, shared runners, untrusted
workloads, rootless Docker, and emulated live tracing are outside this alpha's
validated boundary. Workload filtering and privilege dropping do not make the
container a sandbox. The known-bad `7.0.0-1017-azure` host kernel remains rejected;
changing the application image cannot repair its kernel tracing regression.

Events describe syscall attempts, not successful I/O, remote addresses, HTTP
bodies/routes, request IDs, SQL, throughput, latency, or request-to-syscall
causality. APIs and formats may change during alpha. Cloud attachment, host
monitoring, perf, AI analysis, datasets and OTLP remain experimental extras
outside this focused release.

See the [alpha scope](https://github.com/givtaj/ebpf-tracker/blob/v0.2.0-alpha.3/docs/alpha-scope.md),
[CLI guide](https://github.com/givtaj/ebpf-tracker/blob/v0.2.0-alpha.3/docs/cli.md),
[verification record](https://github.com/givtaj/ebpf-tracker/blob/v0.2.0-alpha.3/docs/alpha-validation.md),
and [security policy](https://github.com/givtaj/ebpf-tracker/blob/v0.2.0-alpha.3/SECURITY.md).
