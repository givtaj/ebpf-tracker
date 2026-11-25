# Axum In-Container Alpha

Development candidate: `0.2.0-alpha.4`; published release: `0.2.0-alpha.3`.
The selected workflow installs a
native tracing agent inside an existing Bookworm application image and starts
the Axum API through that agent. Roots supplied the reference Docker layout;
release gates use a separate synthetic fixture. A separately authorized local
[Roots pilot](./roots-pilot-2026-11-25.md) provides bounded source-built evidence.

## Product Outcome

Inspect one trusted development API process tree during a bounded HTTP test
session, save its syscall observations, and replay the capture locally. The
API uses its existing environment, Docker network, ports, and PostgreSQL
connection. A versioned Debian package supplies the agent and declares its
bpftrace runtime dependencies. The image needs no Rust compiler or Node viewer.

Recording follows the launched API's lifetime. Stopping the traced container
stops the API gracefully and flushes the capture. This alpha does not attach
to an already-running API or stop collection independently of the server.

## Supported Boundary

- Debian 12 Bookworm runtime images and Bookworm bpftrace 0.17.
- Linux Docker hosts with working eBPF/tracefs and the documented privileged,
  host-PID development configuration. The actual kernel support is tested at
  startup; missing tracing support is an error, not a silently empty capture.
- The known-bad `7.0.0-1017-azure` host kernel is rejected; see
  [the upstream regression](https://github.com/actions/runner-images/issues/15003).
  Live release gates use native Ubuntu 22.04 runners for each architecture.
- An existing non-root application user, with UID/GID/groups and capabilities
  managed by the launcher. The image's default Docker user remains root for
  the collector; healthcheck and exec identity must be handled explicitly.
- Four fixed process-tree syscall kinds: `execve`, `openat`, `write`, and `connect`.
  In alpha.4, the in-container agent pairs `openat` entry and exit by Linux
  thread ID and records the return value and errno. The other three event
  kinds, generic command tracing and older captures retain entry-only semantics.
- Application stdout/stderr separate from a newly created JSONL output file.
- Bookworm runtime packages for native amd64 and arm64 Linux Docker hosts.
  The alpha.3 workflow requires separate native installed-package and live
  acceptance gates for both architectures before publication. Emulated live
  tracing is outside the validated boundary.

Use only trusted workloads on isolated development or disposable CI hosts.
The privileged container has broad host access. Workload filtering and dropping
API capabilities are not a security sandbox. See [SECURITY.md](../SECURITY.md).

## Delivery

Follow the [Dockerfile, Compose, and CI installation guide](./in-container.md).
The repository supplies a standalone synthetic Axum/PostgreSQL example and a
smoke test that installs the actual runtime package. The existing host CLI
provides replay. Its prebuilt archives target Linux x86_64 and Intel macOS;
ARM64 runtime-package support does not add an ARM64 host CLI archive.
`attach docker` remains a scaffold and is not used here.

## Acceptance Required Before Publication

- Install the real package in a clean Bookworm runtime image with no compiler.
- Start a separate PostgreSQL service and the instrumented Axum API; assert
  health and a controlled route through HTTP against that actual container.
- Verify the app's non-root identity, cleared capabilities, and no_new_privs.
- Capture app-specific file/write/connection activity and all four event kinds;
  exclude concurrent activity from an unrelated process/container.
- For alpha.4, require the synthetic missing-file HTTP failure and a matching
  completed file-open record with `return_value: -2` and `errno: 2`, plus a
  successful file-open control. Replay must expose the path, process and error
  while keeping legacy unknown outcomes distinct from success.
- Keep API stdout/stderr out of the normalized JSONL, preserving Docker logs.
- Forward SIGTERM, let the app finish its shutdown work, flush capture, and
  preserve ordinary failure status (including exit 23).
- Reject missing commands, missing tracing privileges, and existing output
  files. Collector failure must not leave an untraced workload running.
- Pass workspace regression checks, offline replay, and the strict Linux
  release gates; verify runtime package metadata, architecture, and checksums.

Current publication status and exact-artifact evidence are recorded in
[alpha validation](./alpha-validation.md) and TASKLOG.md. The earlier
[source-built ARM64 Roots pilot](./roots-pilot-2026-11-25.md) established health,
scoped process activity, shutdown and replay for that local setup. It does not
replace alpha.3's tagged-package gates or establish HTTP request attribution.

## Evidence Limits

Alpha.4 in-container `open_at` events record completed opens, including a
signed return value and numeric errno (zero on success). They do not establish
that file contents were read, or which HTTP request caused the operation.
Older captures and other collectors omit these fields: their outcomes are
unknown. Other event kinds still record syscall entry. Write counts are
requested bytes, not throughput. Connections contain a file descriptor, not a
destination. There is no HTTP method, route, request ID, duration, SQL statement,
or per-request causal relationship. Timestamps reflect parser receipt; long
or whitespace-containing paths retain shared parser limits. Async workloads
may use pooled connections or other syscalls outside these four probes.

Do not market this alpha as complete network visibility, request tracing,
latency profiling, production monitoring, or a least-privilege integration.

## Deferred

Existing-container attachment, arbitrary base distributions, production and
shared-host deployment, private PID namespaces, Kubernetes, EKS/ECS,
serverless/Workers, general host monitoring, AI analysis, and new transports
are deferred. Existing experimental CLI paths remain available but do not
expand the alpha contract.
