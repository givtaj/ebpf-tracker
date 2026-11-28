# In-container alpha validation

## Alpha.4 release preparation — 2026-11-28

The implementation at `d4f3af65b4fe55cd0ff3c707c86f78485dff2002`
passed all five jobs in [PR #5 CI](https://github.com/givtaj/ebpf-tracker/actions/runs/46054321614)
on the first attempt: workspace checks, smoke, strict Linux release validation,
and native Bookworm amd64/ARM64 package acceptance. Both native jobs built and
installed the actual package, exercised the synthetic Axum missing-file scenario,
verified isolation/lifecycle, and replayed the saved capture without Docker.
The [branch push run](https://github.com/givtaj/ebpf-tracker/actions/runs/46054264661)
also passed its applicable checks; its native and strict jobs were intentionally
delegated to the PR run.

Release-facing documentation is prepared for `v0.2.0-alpha.4`. Merged-main CI,
exact-tag validation/publication, and fresh public artifact verification remain
pending until recorded separately. Earlier local-only amd64/CI gaps below are
closed by the PR run for the stated implementation head. Roots and its database
remain outside this release validation.

## Alpha.4 development candidate — 2026-11-25

**PASS for local native ARM64 implementation acceptance; not published.** The
synthetic Axum missing-file scenario records completed file-open results and
shows readable failure evidence in replay. Roots source, services and its
database were not accessed or changed by this work.

| Check | Result |
| --- | --- |
| Workspace | 138 tests PASS; workspace build and formatting PASS |
| Bookworm ARM64 package | Built and installed in a clean runtime image without Cargo/rustc; 14 Linux agent tests PASS |
| Host | Native Docker ARM64, Linux `7.0.14-linuxkit`, Bookworm bpftrace 0.17 |
| Missing-file reproduction | Four concurrent HTTP requests returned the expected 500/ENOENT response; four independent captured opens of `/data/fixture-missing-input.txt` had `return_value: -2`, `errno: 2` |
| Successful control | Five opens of `/data/file-open-control.txt` succeeded with nonnegative return values and zero errno |
| Capture | 50 JSONL records: 49 syscall records, including 29 completed opens (4 failed, 25 succeeded); unrelated container activity excluded |
| Lifecycle | Graceful exit 0; failure 23, missing command 127, denied prerequisites 125, forced shutdown 137, SIGINT 0 and collector failure 125 all verified; owned processes reaped |
| Replay | Source-built alpha.4 CLI replayed the actual saved capture from an external directory with Docker blocked; legacy captures retained unknown outcomes |
| Viewer | Four tests cover outcomes, escaping, bounded retention, reset, journey labels and failure rendering; actual browser display shows full path, ENOENT, process/PID and return value |
| Cleanup | Both fixture runs removed their own containers and Compose networks; no containers remained running, matching the initial state |

Runtime package SHA-256:
`3fff3d080b05a676d4e920eaa3a84a353cbade0ee78602d2c99b08c244589c85`.
The first live run captured the correct outcomes but failed a validator's
assumed Tokio worker name. The example now explicitly names its workers
`axum-worker`; a fresh installed-package run passed. Both receipts are retained
locally under `output/alpha4-validation/`.

The evidence establishes concurrent requests, not distinct overlapping Linux
thread IDs or per-request attribution. The missing-file route only reads
synthetic files; the separate existing exercise uses its disposable PostgreSQL
fixture. No Roots data is used. Native amd64 alpha.4 execution, remote CI,
exact-tag/public-download validation and independent developer acceptance are
**NOT RUN**. Existing native amd64/arm64 CI and release jobs run the strengthened
package and replay gates before publication.

## Published alpha.3 — 2026-11-25

**PASS:** [v0.2.0-alpha.3](https://github.com/givtaj/ebpf-tracker/releases/tag/v0.2.0-alpha.3)
is a published prerelease with native Bookworm amd64 and ARM64 runtime packages,
Linux x86_64 and Intel macOS host CLI archives, and the original `SHA256SUMS`.
The earlier alpha.2 release remains unchanged.

- Source: `b85756709ef42ea66f7af70cbf2a3c2774182aff`, merged through
  [PR #4](https://github.com/givtaj/ebpf-tracker/pull/4). Its tree matches the
  reviewed candidate `9b1bdd55f64cb1577663e7a1606f2d73b5b3e61f`.
- Annotated tag object: `ca41ac56bde38656053f94c84eed2be8c6126ffe`.
- [PR CI](https://github.com/givtaj/ebpf-tracker/actions/runs/45604813419),
  [non-publishing rehearsal](https://github.com/givtaj/ebpf-tracker/actions/runs/45604832084),
  and [merged main CI](https://github.com/givtaj/ebpf-tracker/actions/runs/45606042337): PASS.
- [Exact-tag release workflow](https://github.com/givtaj/ebpf-tracker/actions/runs/45606627217):
  all seven jobs passed on the first attempt, including publication. Both native
  runtime gates used Linux `6.8.0-1070-azure`, with matching host and Docker
  architectures on `ubuntu-22.04` and `ubuntu-22.04-arm`.
- Published at `2026-11-25T11:49:45Z`; release ID `458041355`.

### Public acquisition and installation

All five assets were downloaded afresh through anonymous HTTPS requests.
Every digest matched GitHub's asset metadata; all four binary digests matched
the unmodified downloaded manifest. Both runtime packages passed the tagged
metadata, dependency, payload, install-hook and ELF-architecture verifier.
Both CLI archives passed the tagged archive-content verifier.

The exact download recipe in the tagged [Docker/CI guide](in-container.md)
passed for both `runtime_arch=amd64` and `runtime_arch=arm64`, including the
copy into `vendor/ebpf-tracker-runtime.deb`. These runs selected `sha256sum`;
the macOS `shasum` fallback passed separate focused recipe checks before
publication. No instruction changes or checksum regeneration were needed.

| Gate | Observed result |
| --- | --- |
| Native amd64 package | Tagged CI: clean Bookworm installation, live Axum/PostgreSQL capture, isolation, application identity, lifecycle and actual-capture replay PASS |
| Native ARM64 package | Same tagged CI gates PASS; fresh public package also installed and exercised locally on Docker Desktop ARM64, Linux `7.0.14-linuxkit` |
| Fresh ARM64 HTTP exercise | Health `{"ok":true}`; expected PostgreSQL answer 42, synthetic marker, file write and descendant completion |
| Fresh ARM64 application identity | UID/GID 10001, all capabilities zero, NoNewPrivs enabled |
| Fresh ARM64 capture | 38 JSONL records, 37 syscall attempts across execve, open_at, write and connect; unrelated container noise excluded |
| Shutdown and failures | Graceful exit 0; workload failure 23; missing command 127; invalid privileges/user/existing output 125; forced shutdown 137; SIGINT 0; collector failure 125; lifecycle processes reaped |
| Fresh downloaded CLI | Intel macOS archive reports `0.2.0-alpha.3`; actual ARM64 capture replay PASS on Apple Silicon macOS 26.0.1 with Node 22.20.0, embedded viewer outside checkout and Docker invocation blocked |
| Cleanup | Fixture containers, labelled network and volumes absent after scoped cleanup |

The local fixture used the unmodified scripts exported from the alpha.3 tag.
The agent and its dependencies were installed into a clean Bookworm runtime
layer; existing build/dependency caches were available. No Roots workload was
used in publication verification. Local receipts are retained under
`output/alpha3-public-verification/` and are not release assets.

### Public asset digests

| Asset | SHA-256 |
| --- | --- |
| `ebpf-tracker-runtime_0.2.0-alpha.3_amd64.deb` | `d029e5017bdc73ceebc5c33e29404a14207aba02e719bfc968aa2030ec02c0c1` |
| `ebpf-tracker-runtime_0.2.0-alpha.3_arm64.deb` | `c902b2027e16383929caed3af31bd78241bf93dd95a964df9d84d399f286603b` |
| `ebpf-tracker-v0.2.0-alpha.3-x86_64-apple-darwin.tar.gz` | `5f8a5223ddb2afa0daf33ea6d8e39eb43c010dc500950fac1b1a77d6577afb01` |
| `ebpf-tracker-v0.2.0-alpha.3-x86_64-unknown-linux-gnu.tar.gz` | `e37b2857b69b8511bb776d3e264f87f03cfca8885b04bc4cd3ddb09a47419526` |
| `SHA256SUMS` | `ca341a8cf367b096f48737a1d752de746353868b627b4bbcc7536b41808ddf60` |

These checks bind the downloaded bytes to the exact-tag workflow's release
assets and its original manifest. They establish distribution consistency;
no detached publisher-signature verification is claimed. The fresh local live
run covers ARM64; amd64 live acceptance is from native tagged CI. There is no
ARM64 host CLI archive, production acceptance or HTTP request attribution.
The earlier Roots pilot remains separately scoped, source-built alpha.2 evidence.

## Later published-package Roots pilot — 2026-11-25

The separately requested [existing Roots development pilot](roots-pilot-2026-11-25.md)
passed with the freshly downloaded ARM64 alpha.3 runtime and public replay CLI.
Read-only health returned HTTP 200; scoped capture, clean shutdown and offline
replay passed. Recorded files and Git edits were unchanged, logical database
schema/data/ownership/ACL hashes matched, and the initial stopped service state
was restored. The linked receipt records the scope and explains the default
bridge recreation caused by Docker Desktop waking from Resource Saver mode.
No checkout copy or Roots source/configuration edits were made.

## Historical alpha.1/alpha.2 validation — 2026-10-28

Both local arm64 and native amd64 runtime packages passed real installation
and capture tests. These results use the synthetic fixture and do not establish
acceptance against Roots. The first section records the earlier arm64 build.

### Package and environment

- Version: `0.2.0-alpha.1` (`0.2.0~alpha.1` in Debian package metadata).
- Package: `ebpf-tracker-runtime_0.2.0~alpha.1_arm64.deb`.
- SHA-256: `f4c9b193fa22900b230461bff85c7efcf22c7423ce54456ea2b479447255c05c`.
- Builder: `rust:1.96-bookworm`; runtime: `debian:bookworm-slim` and bpftrace 0.17.0.
- Docker Desktop Linux arm64 VM, kernel `7.0.14-linuxkit`.
- Installation checked in a clean runtime image without Cargo or rustc.
- Package payload contains the precompiled agent and license, with no install hooks.

### Results

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

### Native amd64 investigation

Initial native amd64 runs built and installed the package, but the real capture
gate rejected missing application events. Bounded diagnostics showed that
process-tree membership remained correct while syscall callbacks disappeared.
This matches the confirmed Ubuntu 24.04 Azure kernel regression in
[actions/runner-images#15003](https://github.com/actions/runner-images/issues/15003).
The release gates now use the recommended Ubuntu 22.04 runner, and both the
native agent and managed command runtime reject the known-bad
`7.0.0-1017-azure` kernel before starting a workload. Temporary diagnostics were
removed; primary-process startup and fast-exit capture assertions remain.

### Native amd64 acceptance

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

### Tagged artifact gate

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
without changing the capture or exclusion requirements. Final main and tag gates passed as recorded below.

### Published release

[v0.2.0-alpha.2](https://github.com/givtaj/ebpf-tracker/releases/tag/v0.2.0-alpha.2)
is published as a GitHub prerelease from annotated tag commit
`b7606456d532cc4f71ba8815a35491a2217d9fee`. Main CI
[40725691152](https://github.com/givtaj/ebpf-tracker/actions/runs/40725691152)
and every job in the tagged
[release run 40726471342](https://github.com/givtaj/ebpf-tracker/actions/runs/40726471342)
passed, including installed-archive cleanup and publication.

All three public binary assets were downloaded afresh and checked against the
published `SHA256SUMS`. Both CLI archives also passed structural verification.
The guide's direct `curl` download URLs and `sha256sum --check --ignore-missing`
command passed. The runtime package digest is
`d107b5a22e698b588db56f8a068a56f834dc6667a074d2ba4255cdafd5afc872`.

GitHub rewrites `~` in uploaded filenames. The runtime public filename is now
`ebpf-tracker-runtime_0.2.0-alpha.2_amd64.deb`; its internal Debian version stays
`0.2.0~alpha.2`. The public asset name and matching checksum entry were repaired
without changing any binary bytes. Future release assembly applies this name
before hashing and upload. The original alpha.1 tag remains unchanged.

### Release status and limits

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

## Later local Roots pilot — 2026-11-25

The separately authorized [existing-checkout Roots pilot](roots-pilot-2026-11-25.md)
passed with a native ARM64 runtime built from the exact alpha.2 tag. It verified
read-only health HTTP 200, all four scoped syscall kinds, graceful shutdown,
process reaping, offline replay, matching logical database hashes and restoration
of the initial development-service state. This closes the local health-workflow
integration gate for that source-built route. The published alpha.2 runtime is
amd64-only; this historical pilot does not replace the native ARM64 package
gate introduced for alpha.3.

## Alpha.3 release gates

The alpha.3 release pipeline requires separate native amd64 (`ubuntu-22.04`)
and ARM64 (`ubuntu-22.04-arm`) builds. Each installs its actual Bookworm package,
runs the full synthetic Axum/PostgreSQL acceptance and replays that capture
offline. Architecture-specific manifests remain separate until both packages
have passed; assembly verifies their original checksums and emits public
filenames with one combined manifest covering both runtime packages and the
two existing host CLI archives. No emulated live run substitutes for either
native gate. The complete tagged workflow passed; the public acquisition and
installation results are recorded above.
