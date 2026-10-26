# Focused Alpha

Candidate: `0.2.0-alpha.1`. This is a development scope and acceptance contract;
publication status is recorded in [RELEASE.md](../RELEASE.md).

## Product Promise

Run one trusted development command in the managed Linux Docker runtime,
inspect selected syscall activity from that command and its descendants,
and reopen the saved trace locally.

The intended user is a developer investigating or explaining a Rust or Node.js
command on an isolated development machine. The first workflow is the bundled
`session-io-demo`; the second is one command from the user's own project.

## Included

- `bpftrace` collection on an eBPF-capable Linux Docker host.
- Rust and Node.js commands compatible with the bundled Bookworm images.
- `execve`, `openat`, `write`, and `connect` probes, enabled explicitly by config
  when all four are needed; the no-config default remains `execve` only.
- Workload and descendant filtering, application exit status, JSONL capture,
  and saved logs.
- Local dashboard and offline `ebpf-tracker replay <file>` using host Node.js.
- One CLI binary, version identification, source installation, and verified
  Linux x86_64 / Intel macOS archives. The macOS binary is a launcher; live
  tracing still depends on its Linux Docker VM and is compatibility-dependent.

## Deferred Work

Cloud and Kubernetes attachment, ECS/EKS expansion, host monitoring, the `perf`
transport, AI explanations, dataset analysis, and OTLP integration receive no
new feature work during this alpha. Existing commands remain experimental.
Windows, Apple Silicon binary archives, always-on collection, production
deployment, and a stable event API are outside this release contract.

## What The Trace Means

Events record syscall entry, not successful completion. Write counts are
requested bytes, not throughput. Connection events identify the process and
file descriptor, not the destination. Process events do not supply a complete
command line. Timestamps reflect receipt by the parser, not precise kernel
timing. File paths containing whitespace have parser limitations.

This is a selective session recorder. It does not establish a complete audit
trail, detect threats, profile CPU time, or isolate untrusted code. Live tracing
uses a privileged container, the host PID namespace, and a writable project
mount; the [security boundary](../SECURITY.md) remains part of the contract.

## Acceptance Before Publication

1. The candidate identifies its version and exposes useful help from a clean
   installation outside the checkout.
2. The installed demo emits valid JSONL with process, file, write, and
   connection events. Application output stays separate.
3. A trusted user project runs from its own directory, preserves its exit
   status, and produces a capture that can be reopened.
4. Descendants are captured and concurrent unrelated host activity is excluded.
5. The installed binary replays a saved capture without invoking Docker;
   browser controls and process filtering remain usable.
6. The strict Linux release gate, both archive builds, archive verification,
   and checksums pass for the release commit. Existing dataset/customer checks
   remain regression gates even though those features are deferred.
7. GitHub marks the version as a prerelease. Notes list prerequisites and
   limitations; publication must not proceed from skipped or failed gates.

## Next Development Order

1. Finish and verify installation, capture, and replay for this candidate.
2. Improve first-run diagnostics and trace readability using feedback from
   real Rust and Node.js development sessions.
3. Choose one recurring debugging task from that feedback before adding a
   new collector, platform, or integration.

A proposed feature belongs in this alpha only if it helps a developer finish
the capture-and-replay workflow or fixes its reliability, correctness, or
security. Keep other ideas in the deferred backlog until this loop is useful
and repeatable.
