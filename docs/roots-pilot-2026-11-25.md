# Roots development pilots — 2026-11-25

## Published alpha.3 package: PASS

The published ARM64 `v0.2.0-alpha.3` package passed a new pilot on the existing
Roots development checkout and database. No checkout copy was made. The current
Roots Dockerfile build instructions were used directly, with the package install
and launcher added only to an external temporary image recipe. Roots source,
Dockerfile, Compose configuration and normal image tags were unchanged.

The runtime and macOS replay CLI were freshly downloaded from the public release.
Their digests matched the original manifest and GitHub asset metadata. The runtime
SHA-256 is `c902b2027e16383929caed3af31bd78241bf93dd95a964df9d84d399f286603b`.
The installed agent reported `0.2.0-alpha.3`; this run used the published bytes,
not the earlier source-built alpha.2 package.

| Check | Observed result |
| --- | --- |
| Normal API command | `roots-api` through the documented launcher; existing non-root identity, capabilities dropped |
| Read-only health | HTTP 200 and exactly `{"status":"ok"}` |
| Capture | 36 JSONL records, 35 syscall attempts: execve 2, open_at 14, write 15, connect 4 |
| Isolation | Only the API process and threads; independent curl and PostgreSQL excluded |
| Shutdown | Exit 0; API, collector, helper and supervisor process identities reaped; complete JSONL flush |
| Offline replay | Actual Roots capture passed with the fresh public alpha.3 CLI and embedded viewer outside the checkout, Docker blocked |
| Existing edits | All 2,259 recorded tracked/untracked file hashes, 104 API/config inputs, Git HEAD, index and staged/unstaged diffs unchanged |
| Database | Streamed schema/data dumps, including ownership and ACL statements, matched before API startup and after shutdown; contents were never saved |
| Restoration | Existing database cleanly shut down before and after; initial absence of dev containers restored; normal image tags and volumes retained |

The unchanged guide worked without a transport workaround. A temporary Compose
override selected the existing project, database bind and application account,
with privileged mode, host PID namespace and a fresh trace directory. Only the
pilot-owned containers and new labelled network were removed. No migrations,
seeds, resets, restores or modifying application requests ran.

Database preservation means logical schema/data/ownership/ACL equality across
the API run; normal PostgreSQL startup and shutdown update physical storage.
A follow-up read-only investigation explained the default bridge ID change during
preparation. Docker Desktop had stopped its VM in
[Resource Saver mode](https://docs.docker.com/desktop/use-desktop/resource-saver/),
and served the baseline network listing from its cache. The read-only database
control-inspection container woke the VM; the exact daemon's
[startup code](https://github.com/moby/moby/blob/464cd50c3d9e92877d56940ea160de6fca7bea23/daemon/daemon_unix.go#L877)
recreated the default bridge before the image build or Roots startup. No API
request deleted the default bridge. The initial network-ID mismatch is retained;
the network set immediately before and after the live run matched. No network
repair or changes to Roots/database were made during the investigation.

This closes published-package acceptance for the bounded Roots health workflow.
Other application routes and HTTP request-to-syscall attribution were not tested.
Private operational evidence and raw traces stay local under
`output/roots-alpha3-pilot-2026-11-25/`; no Roots data is included here.

## Earlier source-built alpha.2 pilot

A bounded local integration pilot passed using `ebpf-tracker-agent` built from
`v0.2.0-alpha.2` (`b7606456d532cc4f71ba8815a35491a2217d9fee`). The launcher
recorded Roots process activity while a read-only health request returned HTTP
200. The API shut down cleanly and the saved capture replayed offline.

This was a **source-built ARM64 runtime**, not a published ARM64 package. The
published alpha.2 runtime is amd64-only. The alpha.3 release adds separate
native architecture gates; this pilot does not replace their package validation.

### Scope and environment

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

### Results

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

### Adjustments and preservation limits

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
