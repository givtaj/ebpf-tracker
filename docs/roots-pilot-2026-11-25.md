# Native ARM64 Roots pilot — 2026-11-25

A bounded local integration pilot passed using `ebpf-tracker-agent` built from
`v0.2.0-alpha.2` (`b7606456d532cc4f71ba8815a35491a2217d9fee`). The launcher
recorded Roots process activity while a read-only health request returned HTTP
200. The API shut down cleanly and the saved capture replayed offline.

This was a **source-built ARM64 runtime**, not a published ARM64 package. The
published alpha.2 runtime is amd64-only. The alpha.3 release adds separate
native architecture gates; this pilot does not replace their package validation.

## Scope and environment

The pilot used the existing Roots development checkout and database, without
creating another checkout or editing application source or persistent Compose
configuration. Roots is an Axum API with a Debian Bookworm runtime and a
separate PostgreSQL 17 service. The Docker host was ARM64 with Linux kernel
`7.0.14-linuxkit`. The normal `roots-api` command ran after the documented
launcher `--`, using the existing non-root application account.

A temporary image and Compose override supplied the runtime package,
`HOME=/home/roots`, privileged mode, the host PID namespace, and a fresh capture
directory. Only the API and its existing database dependency were started.
Raw traces, credentials, sensitive environment values, database contents and local
operational receipts are not part of this public report.

## Results

| Check | Observed result |
| --- | --- |
| Tagged ARM64 runtime build | 13 Linux agent tests passed; clean Bookworm installation, version/help and bpftrace 0.17 verified |
| Read-only health request | HTTP 200 with exactly `{"status":"ok"}` |
| Application identity | UID 10001, existing primary GID 999, no supplementary groups, all capability sets zero, NoNewPrivs=1 |
| Scoped JSONL | 36 records, including 35 syscall attempts: 2 execve, 14 open_at, 15 write, 4 connect |
| Isolation | All syscall records belonged to the API process and its threads; PostgreSQL and independently launched curl were excluded |
| Shutdown and flush | API exit 0, no OOM, complete JSONL; original API, collector, helper and supervisor processes reaped |
| Offline replay | Actual capture replayed with the published alpha.2 macOS host CLI, embedded viewer outside the checkout, Docker invocation blocked |
| Logical data preservation | Matching streamed schema/data dump hashes before and after the instrumented API run; dump contents were not saved |
| Source and configuration | All 104 hashed API build/configuration inputs unchanged |
| Service restoration | Pilot-created containers and its labelled network removed; initial development service state restored |

The source-built runtime package was
`ebpf-tracker-runtime_0.2.0~alpha.2_arm64.deb`, SHA-256
`6464e214ee2483d96e8a51fd42e2d7a497ee524c8f95d190fcb3a2dc421810f3`.
This identifies the historical pilot build; use the selected release's public
assets and checksum manifest for installation.

## Adjustments and preservation limits

Two original Dockerfile builds failed because Debian repository HTTP
connections were refused or timed out. The temporary recipe used HTTPS and a
CA bundle from the same Rust builder image, with TLS verification enabled.
The application Dockerfile was left unchanged. The package build itself used
the unchanged alpha.2 source and recipe.

The existing PostgreSQL image skipped initialization and performed ordinary
crash recovery of its previously uncleanly stopped cluster. The logical
comparison starts **after startup/recovery**, before the instrumented API, and
ends after the API stops. It covers schema/data, excluding ownership and ACL
statements. Normal startup, recovery and shutdown changed physical database
files; byte-identical storage is not claimed. No manual repair, migration,
seed, reset or restore was performed.

Other Roots work updated a release report concurrently. Those edits and
unrelated verification containers were preserved. The API input hashes and
service restoration passed; an unchanged entire checkout is not claimed.

This verifies one local health workflow. It does not establish HTTP capture,
request-to-syscall attribution, other application routes, production suitability,
or public ARM64 distribution. See the [in-container guide](in-container.md)
and [release validation record](alpha-validation.md) for the supported contract
and separately verified release artifacts.
