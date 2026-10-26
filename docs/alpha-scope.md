# Axum On Docker Alpha

Candidate: `0.2.0-alpha.1`, unpublished. The target is a Rust Axum API running
in Linux Docker, with Roots as the reference application. The generic tracing
and replay work is a foundation; it does not establish Axum-container acceptance.

## Product Outcome

Inspect one development API service during a bounded test session, save its
process and I/O observations, and replay the capture locally. Use this to
investigate startup/database connectivity and activity around a controlled set
of HTTP requests.

The alpha should select one container unambiguously, keep unrelated container
activity out of the capture, and finish capture without disrupting the API or
its database. Collect process and syscall metadata, not HTTP bodies, cookies,
credentials, or database contents.

## Reference Application

The Roots source inspected on 2026-10-26 uses Axum 0.8 and Tokio. Its
`roots-dev-api` Compose service runs a prebuilt `roots-api` binary as a non-root
user in Debian Bookworm, listens on container port 4301, and connects to the
separate PostgreSQL service on port 4302. `/api/health` checks database access;
`/api/hello` provides a small public HTTP request. The API handles SIGINT and
SIGTERM with a bounded graceful shutdown.

This was a source inspection of a working checkout with unrelated changes,
not a running-system test. No Roots code, configuration, credentials, database,
or service was changed.

## Integration Decision

Recommended: record the existing API container, preserving its application
image, environment, network, and lifecycle. The alternative is launching a
separate disposable API under the tracker. The user has been asked to choose;
container integration implementation and publication await that decision.

The current `attach docker` path only prints a scaffold plan. It is not a
working recording command. Managed `run` starts its own privileged container;
it does not automatically reuse Roots's network, environment, or port mappings.

## Acceptance Required Before Publication

- Identify the chosen API container and reject missing, ambiguous, stopped,
  or unsupported targets without observing another workload.
- Record a bounded session while a disposable Axum/PostgreSQL fixture serves
  health and greeting requests; retain real application response assertions.
- Observe relevant API activity with evidence sufficient for the advertised
  use case. The current four probes alone may miss steady-state Axum requests
  using pooled connections and vectored I/O.
- Exclude concurrent activity from an unrelated container.
- Stop recording without stopping or restarting the API/PostgreSQL services;
  produce valid JSONL and replay the saved records with Docker unavailable.
- Verify the selected workflow against an isolated Roots test instance with
  synthetic data before claiming Roots compatibility.
- Pass the strict Linux gate, both archive builds, installed Linux checks, and
  checksum validation on the exact release source. Publish as a prerelease.

Axum/container acceptance is **NOT RUN** and container attachment is
**NOT IMPLEMENTED**. Existing generic command, replay, isolation, and packaging
checks remain useful regressions; they cannot substitute for these scenarios.

## Evidence Limits

The current events record syscall entry, not successful completion. Write
counts are requested bytes, not throughput. Connection events contain a file
descriptor, not a destination. There is no HTTP method, route, request ID,
request duration, SQL statement, or per-request causal relationship. Timestamps
reflect parser receipt. File paths containing whitespace have parser limits.

Do not market this alpha as HTTP request tracing, latency profiling, complete
network visibility, or production monitoring without implementing and testing
those capabilities. Preserve the [security boundary](../SECURITY.md): privileged
collection is for trusted workloads on an isolated development host.

## Deferred

Kubernetes, EKS/ECS, serverless/Workers, general host monitoring, Node.js workload
support as a product focus, perf, AI analysis, datasets, OTLP, and new OS targets
are deferred. Host Node.js remains a viewer dependency. Existing experimental
commands remain available, but the next feature work should serve the one
Axum-on-Docker workflow above.
