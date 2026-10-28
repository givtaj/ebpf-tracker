# In-container alpha validation — 2026-10-28

Both local arm64 and native amd64 runtime packages passed real installation
and capture tests. These results use the synthetic fixture and do not establish
acceptance against Roots. The first section records the earlier arm64 build.

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

## Native amd64 investigation

Initial native amd64 runs built and installed the package, but the real capture
gate rejected missing application events. Bounded diagnostics showed that
process-tree membership remained correct while syscall callbacks disappeared.
This matches the confirmed Ubuntu 24.04 Azure kernel regression in
[actions/runner-images#15003](https://github.com/actions/runner-images/issues/15003).
The release gates now use the recommended Ubuntu 22.04 runner, and both the
native agent and managed command runtime reject the known-bad
`7.0.0-1017-azure` kernel before starting a workload. Temporary diagnostics were
removed; primary-process startup and fast-exit capture assertions remain.

## Native amd64 acceptance

[CI run 40717437051](https://github.com/givtaj/ebpf-tracker/actions/runs/40717437051)
passed all four jobs on commit `c8db19926e43853447d2949390d8bbeb774e3796`.
The live jobs used Ubuntu 22.04, kernel `6.8.0-1064-azure`, and native amd64
Bookworm containers. The real installed package passed all 13 Linux agent
tests, the Axum/PostgreSQL fixture, and offline replay of its actual capture.

The capture contained 37 JSONL records, including 36 syscall records and all
four kinds. Primary-process exec and startup file/write activity were present,
as were the API route and descendant markers. UID/GID 10001, zero capability
sets, NoNewPrivs, concurrent-noise exclusion, separate logs, graceful exit 0,
exit 23, missing-command/permission/output checks, SIGINT, forced shutdown 137,
and collector-failure 125 all passed. Every lifecycle app was reaped.

The CI candidate package was
`ebpf-tracker-runtime_0.2.0~alpha.1_amd64.deb`, with SHA-256
`9246fee645c223a0aea55d4a7682c94dc90ea9d22aa39930f9b58bcb15a9c1ca`.
The downloaded bytes were checked against that manifest. CI retains the
`runtime-candidate-amd64` and `in-container-alpha-evidence` artifacts.

## Tagged artifact gate

The `v0.2.0-alpha.1` [release run 40719860865](https://github.com/givtaj/ebpf-tracker/actions/runs/40719860865)
passed strict validation, both platform builds, installed runtime acceptance,
and all installed Linux archive checks. That final check traced the Rust and
Node fixtures and replayed embedded viewer assets outside the checkout.
Cleanup then failed on a root-owned synthetic fixture file, so publication was
withheld. The public tag is preserved. Version `0.2.0-alpha.2` carries the
scoped cleanup repair and must pass the entire workflow before publication.
A disposable Bookworm container verified the actual cleanup function with
root-owned output files and an unprivileged caller: success 0, original failure
23, cleanup failure 1, original-plus-cleanup failure 23, SIGINT 130, and SIGTERM
143. Cleanup needs no privilege escalation, and the success message is emitted
only after cleanup completes.

The alpha.2 [non-publishing release run 40723398161](https://github.com/givtaj/ebpf-tracker/actions/runs/40723398161)
then passed every validation, build, runtime, installed-archive, cleanup, and
asset-assembly job. A parallel main run exposed an unrelated fixture race: a
noise marker snapshot was empty between truncation and rewrite. Both noise
writers now publish by atomic rename; 4,000 concurrent read assertions passed
without changing the capture or exclusion requirements. Final main and tag
gates remain required for publication.

## Release status and limits

Publication is separately gated by tagged release validation, clean platform
archive builds, installed-archive acceptance, runtime-package acceptance, and
checksum assembly. The release rebuilds its packages; use the final
[release assets and SHA256SUMS](https://github.com/givtaj/ebpf-tracker/releases)
for installation. A package version or this pre-release evidence alone does
not establish that publication completed.

The fixture uses synthetic data and a separate PostgreSQL 17 container. No
Roots files, service configuration, databases, or running services were used
or changed. This result does not establish real Roots compatibility, HTTP
request attribution, production suitability, private-PID-namespace support,
or a least-privilege Docker configuration.
