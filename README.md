# eBPF_tracker

`eBPF_tracker` is a Rust CLI that wraps a command like `cargo run`, starts a Linux runtime with Docker, and attaches `bpftrace` for the lifetime of that command.
The public GitHub repo is `cargo-ebpf-tracker`:
[cargo-ebpf-tracker](https://github.com/givtaj/cargo-ebpf-tracker)

## Current Product

- Installable as a Cargo binary.
- Runs the wrapped command inside a privileged Docker Linux runtime.
- Uses `bpftrace`, not Aya, for the first release.
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

That makes it easy to pipe the trace stream into another tool that renders a UI,
stores the events, or applies custom filtering.

The JSONL event contract now lives in the shared workspace crate
`crates/ebpf-tracker-events`, so future consumers can reuse the same parsing and
record schema without embedding CLI-specific code.

The first downstream scaffold now also exists:

```bash
eBPF_tracker --emit jsonl cargo run | cargo run -p ebpf-tracker-otel -- --target jaeger --service-name session-io-demo
```

That consumer currently validates and summarizes the stream for future OTLP and
Jaeger export work. It is intentionally scaffold-only for now.

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
```

Available flags:

- `probe.exec`: trace `execve`
- `probe.write`: trace `write`
- `probe.open`: trace `openat`
- `probe.connect`: trace `connect`

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
- No live OTLP export pipeline yet; `crates/ebpf-tracker-otel` is scaffold-only
- No Kubernetes mode
- No process-tree-only or target-only filtering
- No native perf/ringbuf capture path yet; `crates/ebpf-tracker-perf` is a plan scaffold
- No stable profile system like `minimal/default/full`

## Workspace Direction

This repo stays as one workspace, but the boundaries are now explicit:

- the root package is the installable CLI that runs Docker + `bpftrace`
- `crates/ebpf-tracker-events` owns the event parsing and JSONL stream schema
- `crates/ebpf-tracker-otel` is the OTLP and Jaeger-oriented consumer scaffold
- `crates/ebpf-tracker-perf` holds the future perf and ring buffer transport plan
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
- `crates/ebpf-tracker-otel`: scaffold consumer for OTLP and Jaeger export
- `crates/ebpf-tracker-perf`: scaffold for future perf/ringbuf transport work
- `ebpf-tracker.toml.example`: example config
- `docker-compose.bpftrace.yml`: runtime definition
- `docker/bpftrace-rust.Dockerfile`: runtime image
- `scripts/run-bpftrace-wrap.sh`: container entry wrapper
- `probes/execve.bt`: built-in default probe
