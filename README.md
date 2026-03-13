# eBPF_tracker

`eBPF_tracker` is a Rust CLI that wraps a command like `cargo run`, starts a Linux runtime with Docker, and attaches `bpftrace` for the lifetime of that command.
The public GitHub repo is `cargo-ebpf-tracker`:
[cargo-ebpf-tracker](https://github.com/givtaj/cargo-ebpf-tracker)

## Current Product

- Installable as a Cargo binary.
- Runs the wrapped command inside a privileged Docker Linux runtime.
- Uses `bpftrace` by default and now supports a `perf trace` transport.
- Default built-in probe is `execve.bt`.
- Supports config-driven generated probes for `exec`, `write`, `open`, and `connect`.
- Can mirror terminal output into `./logs`.

## What It Means In Practice

When you run:

```bash
eBPF_tracker cargo run
```

you are tracing the full wrapped command session. That means you will often see `cargo`, `rustc`, linkers, and then your app. This is current behavior, not a bug.

## Release Scope

For v0.1, the product contract is:

- install with Cargo
- run `eBPF_tracker cargo run` from a Rust project
- execute that command inside a Docker-backed Linux runtime
- attach `bpftrace` for the lifetime of the wrapped command
- show useful kernel-level events for that command session

## Requirements

- Rust toolchain
- Docker Desktop or another Docker engine that supports privileged containers

## Install

Local install:

```bash
cargo install --path .
```

Install from GitHub:

```bash
cargo install --git https://github.com/givtaj/cargo-ebpf-tracker
```

After install:

```bash
eBPF_tracker --help
eBPF_tracker cargo run
```

Runtime assets are materialized under `~/.cache/ebpf-tracker` by default.

Override that location with:

```bash
EBPF_TRACKER_CACHE_DIR=/your/path
```

## Usage

Run without installing:

```bash
cargo run --bin eBPF_tracker -- cargo run
```

Other common commands:

```bash
eBPF_tracker cargo test
eBPF_tracker cargo check
eBPF_tracker --log-enable cargo run
eBPF_tracker --emit jsonl cargo run
eBPF_tracker --transport perf cargo run
```

Built-in probe by name:

```bash
eBPF_tracker --probe execve.bt cargo run
```

Project-local probe file:

```bash
eBPF_tracker --probe ./probes/custom.bt cargo run
```

## Event Stream

`eBPF_tracker` can reserve `stdout` for a machine-readable event stream:

```bash
eBPF_tracker --emit jsonl cargo run
```

In `jsonl` mode:

- `stdout` emits newline-delimited JSON syscall and aggregate events
- `stderr` keeps normal build output, app output, and runtime errors human-readable
- without `--emit`, the default mode is `raw`
- without `--transport`, the default transport is `bpftrace`

That makes it easy to pipe the trace stream into another tool that renders a UI,
stores the events, or applies custom filtering.

The JSONL event contract now lives in the shared workspace crate
`crates/ebpf-tracker-events`, so future consumers can reuse the same parsing and
record schema without embedding CLI-specific code.

You can stream those records into the built-in OTLP consumer:

```bash
eBPF_tracker --emit jsonl cargo run | cargo otel --target jaeger --service-name session-io-demo
```

That path groups raw records into a session span plus per-process spans, then
exports them over OTLP to Jaeger or another collector.

Hardened exporter controls:

```bash
eBPF_tracker --emit jsonl cargo run | cargo otel --target otlp --endpoint http://127.0.0.1:4318 --timeout-seconds 15 --header authorization=Bearer-token
```

The exporter now:

- validates endpoint URLs and normalizes bare collector URLs to `/v1/traces`
- rejects empty service names and zero timeouts
- applies an explicit OTLP request timeout
- surfaces collector-side partial rejections and warnings on `stderr`

Local Jaeger flow:

```bash
cargo jaeger up
eBPF_tracker --emit jsonl cargo run | cargo otel --target jaeger --service-name session-io-demo
```

Then open `http://127.0.0.1:16686`.

Alternate runtime transport:

```bash
eBPF_tracker --transport perf --emit jsonl cargo run
```

That uses Linux `perf trace` inside the same Docker runtime and normalizes the
result into the same JSONL contract. Today the `perf` path is strongest for
`execve`, `write`, `connect`, and aggregate counts; file-path arguments are
best-effort because plain `perf trace` does not always decode userspace string
pointers.

## Config

If `ebpf-tracker.toml` exists in the current project, it is picked up automatically.
You can also pass it explicitly:

```bash
eBPF_tracker --config ebpf-tracker.toml cargo run
```

`--probe` takes precedence over config-generated probes.

Example config:

```toml
[probe]
exec = true
write = true
open = false
connect = false

[runtime]
cpus = 2.0
memory = "4g"
cpuset = "0-3"
pids_limit = 512
```

Available flags:

- `probe.exec`: trace `execve`
- `probe.write`: trace `write`
- `probe.open`: trace `openat`
- `probe.connect`: trace `connect`
- `runtime.cpus`: Docker CPU quota for the runtime container
- `runtime.memory`: Docker memory limit like `512m` or `4g`
- `runtime.cpuset`: Docker CPU set string like `0-3` or `0,1`
- `runtime.pids_limit`: Docker PID limit, or `-1` for unlimited

See `ebpf-tracker.toml.example`.

## First Example

The first example worth running is
[`examples/session-io-demo`](./examples/session-io-demo/README.md).

All examples are indexed in
[`examples/README.md`](./examples/README.md), including the Cargo-based way to
run them.

It shows why session-based tracing is useful:

- `build.rs` reads and generates files during `cargo run`
- the app reads a file, opens a local TCP connection, and writes a summary file
- one `eBPF_tracker` run surfaces all of that activity without changing app code

Run it with:

```bash
cargo demo
```

Structured stream version:

```bash
cargo demo --emit jsonl session-io-demo
```

Same example with the `perf` transport:

```bash
cargo demo --transport perf --emit jsonl session-io-demo
```

Trace UI version:

```bash
cargo jaeger up
cargo demo --emit jsonl session-io-demo | cargo otel --target jaeger --service-name session-io-demo
```

## Local Checks

Smoke check:

```bash
cargo run --bin eBPF_tracker -- /bin/true
```

Installed-binary check from a Rust project:

```bash
eBPF_tracker cargo run
```

Config-driven check:

```bash
cp ebpf-tracker.toml.example ebpf-tracker.toml
eBPF_tracker cargo run
```

Expected today:

- first run may build the Docker image
- default probe output shows `execve ...`
- config-driven `write/open/connect` output can still be noisy because tracing is per command session, not target-only

## Current Limitations

- No Aya/native Rust eBPF probes yet
- OTLP export currently derives coarse session and process spans from the raw stream
- No Kubernetes mode
- No process-tree-only or target-only filtering
- No direct perf-event-array or ringbuf capture path yet; the current alternate transport is Linux `perf trace`
- In `--transport perf` mode, file-path fields are best-effort and may be absent when `perf trace` cannot decode userspace string arguments
- No stable profile system like `minimal/default/full`

## Next TODOs

- Add process-tree-only and target-only filtering so the stream can focus on the app and its children instead of the whole wrapped session
- Add stable stream profiles like `minimal`, `default`, and `full`
- Add a separate viewer crate that reads JSONL from `stdin` and renders a first trace-focused TUI on top of the stream
- Improve the OTel mapping with parent/child process relationships and better span/event semantics for Jaeger and other collectors
- Add direct perf-event-array or ringbuf transport after the event model and stream UX are stable

## Workspace Direction

This repo stays as one workspace, but the boundaries are now explicit:

- the root package is the installable CLI that runs Docker + `bpftrace`
- `crates/ebpf-tracker-events` owns the event parsing and JSONL stream schema
- `crates/ebpf-tracker-otel` maps the JSONL stream into OTLP traces and can manage a local Jaeger collector
- `crates/ebpf-tracker-perf` normalizes Linux `perf trace` output today and holds the future perf-event-array/ringbuf work
- future viewers or other consumers should be added as separate crates under
  `crates/`
- `examples/` stays reserved for runnable demo apps, not product code

That keeps the core Unix contract clear: `eBPF_tracker` emits events, and other
tools decide how to render, store, or forward them.

## Repo Layout

- `Cargo.toml`: workspace manifest plus installable CLI package metadata
- `src/lib.rs`: installable CLI logic
- `src/main.rs`: thin binary wrapper for the CLI crate
- `crates/ebpf-tracker-events`: shared event schema and JSONL parsing crate
- `crates/ebpf-tracker-otel`: OTLP exporter plus local Jaeger helper commands
- `crates/ebpf-tracker-perf`: `perf trace` normalization plus future perf/ringbuf transport work
- `ebpf-tracker.toml.example`: example config
- `docker-compose.bpftrace.yml`: runtime definition
- `docker/bpftrace-rust.Dockerfile`: runtime image
- `scripts/run-bpftrace-wrap.sh`: container entry wrapper
- `probes/execve.bt`: built-in default probe
