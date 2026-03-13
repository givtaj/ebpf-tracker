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
```

Built-in probe by name:

```bash
eBPF_tracker --probe execve.bt cargo run
```

Project-local probe file:

```bash
eBPF_tracker --probe ./probes/custom.bt cargo run
```

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
- No OTLP export pipeline
- No Kubernetes mode
- No process-tree-only or target-only filtering
- No stable profile system like `minimal/default/full`

## Repo Layout

- `Cargo.toml` and `src/main.rs`: Rust CLI
- `ebpf-tracker.toml.example`: example config
- `docker-compose.bpftrace.yml`: runtime definition
- `docker/bpftrace-rust.Dockerfile`: runtime image
- `scripts/run-bpftrace-wrap.sh`: container entry wrapper
- `probes/execve.bt`: built-in default probe
