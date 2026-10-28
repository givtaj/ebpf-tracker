# In-container alpha validation — 2026-10-28

The local arm64 runtime package passed a real installation and capture test.
This records the synthetic fixture result, not acceptance against Roots.

## Package and environment

- Version: `0.2.0-alpha.1` (`0.2.0~alpha.1` in Debian package metadata).
- Package: `ebpf-tracker-runtime_0.2.0~alpha.1_arm64.deb`.
- SHA-256: `f4c9b193fa22900b230461bff85c7efcf22c7423ce54456ea2b479447255c05c`.
- Builder: `rust:1.96-bookworm`; runtime: `debian:bookworm-slim` and bpftrace 0.17.0.
- Docker Desktop Linux arm64 VM, kernel `7.0.14-linuxkit`.
- Installation checked in a clean runtime image without Cargo or rustc.
- Package payload contains the precompiled agent and license, with no install hooks.

## Results

| Check | Observed result |
| --- | --- |
| Workspace tests on macOS | 133 passed |
| Linux agent tests in package builder, including privilege test | 11 passed, none ignored |
| HTTP exercise | Axum route returned the expected PostgreSQL query result and file/descendant markers |
| Application identity | All UIDs/GIDs 10001, supplementary groups cleared, all capability sets zero, NoNewPrivs=1 |
| Real capture | 36 JSONL records, including 35 syscall records across all four kinds |
| Isolation | Concurrent unrelated-container process/file markers absent |
| Logs | Application stdout/stderr retained separately from JSONL |
| Graceful SIGTERM | Shutdown marker retained, exit 0 |
| Application failure | Exit 23 preserved |
| Missing executable | Exit 127 |
| Missing privileges / nonroot collector / existing capture | Exit 125; workload did not start; existing output preserved |
| App ignores TERM | Forced shutdown after its configured one-second grace, exit 137, process reaped |
| SIGINT | Application handler ran, exit 0, process reaped |
| Collector killed | Capture failed with 125, application received TERM and was reaped |
| Offline replay | Actual API capture and original filtered demo replay passed with Docker invocation blocked |

The full fixture was run using `scripts/in-container-smoke.sh`. Local evidence
is retained under `target/in-container-evidence-arm64/`, including HTTP
responses, process status, JSONL, logs, package identity, and lifecycle results.
The package and checksum manifest are under `dist/runtime/`.

Release/version/archive regressions, four command-resolution cases, and eleven
existing bpftrace exit-status cases also passed. The package check caught and
fixed a Bash 3 versus Bash 5 tilde-expansion difference in Debian prerelease
version conversion. Package and fixture builders are pinned to Rust 1.96.

## Release status and limits

The candidate is unpublished at this checkpoint. Native amd64 CI and release
artifact verification are required before publication. The workflows retain
the tested package and evidence; they also replay the actual API capture.

The fixture uses synthetic data and a separate PostgreSQL 17 container. No
Roots files, service configuration, databases, or running services were used
or changed. This result does not establish real Roots compatibility, HTTP
request attribution, production suitability, private-PID-namespace support,
or a least-privilege Docker configuration.
