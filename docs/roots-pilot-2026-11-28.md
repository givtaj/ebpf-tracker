# Published alpha.4 Roots development pilot — 2026-11-28

**PASS for the read-only health workflow.** The published ARM64
[v0.2.0-alpha.4](https://github.com/givtaj/ebpf-tracker/releases/tag/v0.2.0-alpha.4)
runtime ran Roots' normal `roots-api` command from the existing development
checkout and database. No checkout copy was made. Existing Roots source,
configuration and Git edits were preserved, and the original stopped service
state was restored.

## Public artifacts and integration

The runtime, Intel macOS replay CLI and original `SHA256SUMS` were downloaded
afresh through anonymous HTTPS. Both binary digests matched the unmodified
manifest and GitHub's asset metadata. The runtime's package metadata, dependency
constraints, exact payload, absence of install hooks and ARM64 ELF architecture
were inspected before execution. The CLI archive payload was also checked.

- Runtime SHA-256: `cda11292aeec6d255644d87f2d5fe71caa52b792b6a87ceebf51fd0d5a43f47d`.
- Replay archive SHA-256: `d83b6d86513c1f6547a63042fa45b967f32947dcc234407775fdfe6c01814312`.
- Installed runtime: `0.2.0~alpha.4`; agent reports `0.2.0-alpha.4`;
  Bookworm bpftrace `0.17.0-1`.
- Host: native Docker ARM64, Linux `7.0.14-linuxkit`.

An external temporary Dockerfile used the current Roots checkout directly as
its build context, then installed the public package and added the documented
launcher. Roots' Dockerfile and normal image tags were unchanged. The external
recipe used HTTPS Debian mirrors and a CA bundle from the same Rust builder
image because HTTP mirror requests had timed out during verification on this
host. TLS and Debian signature verification remained enabled.

A temporary Compose override selected the existing project, PostgreSQL image
and database bind. It supplied the privileged collector, host PID namespace,
existing non-root application account, `HOME`, and a fresh external capture
directory. Only the database and API were started; no migration, seed, reset,
restore or modifying application request ran.

## Observed results

| Check | Result |
| --- | --- |
| Read-only health | HTTP 200 and exactly `{"status":"ok"}` |
| Application identity | Normal `roots-api` executable; UID 10001, existing GID, no supplementary groups, zero capabilities, NoNewPrivs enabled |
| Capture and flush | 38 complete JSONL records, including 37 syscall records: 2 execve, 14 open_at, 17 write and 4 connect |
| Alpha.4 open results | All 14 opens had integer return values and consistent errno; 14 succeeded, zero failed or unknown |
| Isolation | Only the Roots API process and threads; PostgreSQL and independently launched curl excluded |
| Shutdown | API exit 0; all four recorded API/collector/supervisor process identities reaped |
| Offline replay | Actual capture passed with the fresh public alpha.4 CLI, embedded viewer outside the checkout, and Docker invocation blocked |
| Files and Git | All 2,285 recorded file hashes, 104 API/configuration inputs, HEAD, index and staged/unstaged diffs unchanged |
| Database | Streamed logical schema/data/ownership/ACL hashes matched before API startup and after shutdown; dump contents were never saved |
| Restoration | Same database storage and cluster identity, cleanly shut down before and after; original Roots containers absent again; pilot-owned containers and new network removed |
| Other Docker state | Normal image IDs, network IDs and volume names unchanged; concurrent unrelated containers were left untouched |

The file snapshot covers tracked and nonignored untracked files, plus explicitly
included root environment files and application registration configuration.
Logical database comparison starts after normal PostgreSQL startup and ends
after the API stops. It does not claim byte-identical physical storage or
cluster-wide role equality; PostgreSQL startup and shutdown update physical
files. The database was cleanly stopped at both boundaries.

This verifies the existing Roots health workflow and alpha.4 completed-open
results. No deliberate missing-file fault or other application route was tested
in Roots, and no HTTP request-to-syscall attribution is claimed. The separate
synthetic missing-file release acceptance remains documented in the
[release validation](https://github.com/givtaj/ebpf-tracker/blob/e4f6069fa79ce984ac64bfb8373d1b7e5bda7674/docs/alpha-validation.md) record.

Private operational evidence, raw traces and detailed preservation receipts
remain local under `output/roots-alpha4-pilot-2026-11-28/`. No database contents
or credentials are included in this report.
