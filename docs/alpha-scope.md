# Axum In-Container Alpha

Release line: `0.2.0-alpha.1`. The selected workflow installs a
native tracing agent inside an existing Bookworm application image and starts
the Axum API through that agent. Roots supplied the reference Docker layout;
no Roots files, services, credentials, or data are changed.

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
- An existing non-root application user, with UID/GID/groups and capabilities
  managed by the launcher. The image's default Docker user remains root for
  the collector; healthcheck and exec identity must be handled explicitly.
- Four fixed process-tree probes: `execve`, `openat`, `write`, and `connect`.
- Application stdout/stderr separate from a newly created JSONL output file.
- Native package builds for amd64 and arm64. The release workflow gates and
  publishes amd64; architecture-specific live evidence is required before
  claiming another architecture as a verified release artifact.

Use only trusted workloads on isolated development or disposable CI hosts.
The privileged container has broad host access. Workload filtering and dropping
API capabilities are not a security sandbox. See [SECURITY.md](../SECURITY.md).

## Delivery

Follow the [Dockerfile, Compose, and CI installation guide](./in-container.md).
The repository supplies a standalone synthetic Axum/PostgreSQL example and a
smoke test that installs the actual runtime package. The existing host CLI
provides replay. `attach docker` remains a scaffold and is not used here.

## Acceptance Required Before Publication

- Install the real package in a clean Bookworm runtime image with no compiler.
- Start a separate PostgreSQL service and the instrumented Axum API; assert
  health and a controlled route through HTTP against that actual container.
- Verify the app's non-root identity, cleared capabilities, and no_new_privs.
- Capture app-specific file/write/connection activity and all four event kinds;
  exclude concurrent activity from an unrelated process/container.
- Keep API stdout/stderr out of the normalized JSONL, preserving Docker logs.
- Forward SIGTERM, let the app finish its shutdown work, flush capture, and
  preserve ordinary failure status (including exit 23).
- Reject missing commands, missing tracing privileges, and existing output
  files. Collector failure must not leave an untraced workload running.
- Pass workspace regression checks, offline replay, and the strict Linux
  release gates; verify runtime package metadata, architecture, and checksums.

Current evidence is recorded in [alpha validation](./alpha-validation.md) and TASKLOG.md.
A fixture passing does not establish real Roots acceptance or HTTP request
tracing. Roots application integration remains a separate opt-in task.

## Evidence Limits

Events record syscall entry, not successful completion. Write counts are
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
