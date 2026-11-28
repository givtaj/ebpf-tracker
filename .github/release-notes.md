Alpha.4 makes a missing-file failure in a Dockerized Axum API visible in a
saved capture. The in-container agent pairs `openat` entry and exit by thread
ID and records the return value and errno. Replay shows the failed path,
process and error, with a bounded failure list and separate successful, failed
and unknown counts. Older captures retain unknown outcomes.

The [synthetic Axum walkthrough](https://github.com/givtaj/ebpf-tracker/blob/v0.2.0-alpha.4/examples/axum-container/README.md)
reproduces HTTP 500 from `/missing-file`, checks four captured `ENOENT` failures
and successful control opens, then replays the saved JSONL. It uses no Roots
source, services or data.

Choose the runtime package matching the application image and native Docker
host:

- `ebpf-tracker-runtime_0.2.0-alpha.4_amd64.deb`
- `ebpf-tracker-runtime_0.2.0-alpha.4_arm64.deb`

Both use Debian package version `0.2.0~alpha.4`; release filenames use a hyphen
because GitHub rewrites `~`. Verify the download against the original
`SHA256SUMS` before installing. The
[Dockerfile/Compose/CI guide](https://github.com/givtaj/ebpf-tracker/blob/v0.2.0-alpha.4/docs/in-container.md)
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
scoped events, missing-file failure and successful-open controls, isolation,
shutdown/failure cases, and offline replay of the actual capture. A cross-build
or an earlier Roots pilot does not substitute for those gates. Earlier release
tags remain unchanged.

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

Only the in-container `open_at` events add completion results. A successful
open does not establish a successful read or write. The other three event kinds
and generic command tracing retain syscall-attempt semantics. Captures do not
report remote addresses, HTTP bodies/routes, request IDs, SQL, throughput,
latency, or request-to-syscall causality. APIs and formats may change during
alpha. Cloud attachment, host monitoring, perf, AI analysis, datasets and OTLP
remain experimental extras outside this focused release.

See the [alpha scope](https://github.com/givtaj/ebpf-tracker/blob/v0.2.0-alpha.4/docs/alpha-scope.md),
[CLI guide](https://github.com/givtaj/ebpf-tracker/blob/v0.2.0-alpha.4/docs/cli.md),
[verification record](https://github.com/givtaj/ebpf-tracker/blob/v0.2.0-alpha.4/docs/alpha-validation.md),
and [security policy](https://github.com/givtaj/ebpf-tracker/blob/v0.2.0-alpha.4/SECURITY.md).
