# CLI Guide

This page holds the detailed usage notes for the root `ebpf-tracker` CLI. The
main [`README.md`](../README.md) stays intentionally short and points here for
the root-package behavior that does not belong to the extension crates.

## Requirements

- Rust toolchain
- Docker Desktop or another Docker engine that supports privileged containers
- Node.js on the host only if you want the repo-local dashboard/viewer flow

## Install

Install from a local clone:

```bash
cargo install --path . --locked
```

Install from GitHub:

```bash
cargo install --git https://github.com/givtaj/ebpf-tracker --locked
```

The first public release is GitHub-release-first. Use `cargo install --git ...`
or a tagged source checkout; the workspace crates are not published to
crates.io yet.

After install, the smallest useful checks are:

```bash
ebpf-tracker --help
ebpf-tracker /bin/true
ebpf-tracker cargo run
ebpf-tracker npm run dev
```

`ebpf-tracker /bin/true` is the smallest real tracer smoke test and still
requires Docker support. The `cargo demo`, `cargo see`, `cargo dataset`,
`cargo otel`, `cargo jaeger`, and `cargo viewer` helpers remain Cargo aliases
for people working from a clone of this repository.

Runtime assets are materialized under `~/.cache/ebpf-tracker` by default. Set
`EBPF_TRACKER_CACHE_DIR=/your/path` to override that location.

## Run Mode

Run without installing:

```bash
cargo run --bin ebpf-tracker -- cargo run
```

Common commands:

```bash
ebpf-tracker cargo run
ebpf-tracker cargo test
ebpf-tracker cargo check
ebpf-tracker npm run dev
ebpf-tracker npm test
ebpf-tracker --log-enable cargo run
ebpf-tracker --emit jsonl cargo run
ebpf-tracker --transport perf cargo run
ebpf-tracker --runtime node /bin/sh -lc "npm run dev"
```

The tracer follows the full wrapped command session. In practice that means
Rust sessions often include `cargo`, `rustc`, linkers, and then the final app.
Node sessions often include `npm`, `node`, package scripts, and subprocesses.

## Runtime Selection

Runtime selection is modular:

- Rust commands use the Rust runtime image
- Node commands such as `node`, `npm`, `npx`, `pnpm`, and `yarn` use the Node runtime image
- `--runtime rust` or `--runtime node` overrides auto-detection when the wrapped command goes through a shell
- Node support uses a dedicated Node image, not `nvm` inside the tracing container

## Event Stream

The CLI can reserve `stdout` for a machine-readable event stream:

```bash
ebpf-tracker --emit jsonl cargo run
```

In `jsonl` mode:

- `stdout` emits newline-delimited JSON records
- `stderr` keeps normal build output, app output, and runtime errors readable
- without `--emit`, the default mode is `raw`
- without `--transport`, the default transport is `bpftrace`

That makes it easy to pipe the trace into downstream tools such as:

```bash
ebpf-tracker --emit jsonl cargo run | cargo dataset --test-name cargo-run-smoke
ebpf-tracker --emit jsonl cargo run | cargo otel --target jaeger --service-name session-io-demo
```

The shared JSONL record schema lives in
[`crates/ebpf-tracker-events`](../crates/ebpf-tracker-events/README.md).

## Dashboard, Demo, And See

Repo-local dashboard examples:

```bash
./target/debug/ebpf-tracker --dashboard cargo run
./target/debug/ebpf-tracker --dashboard npm run dev
./target/debug/ebpf-tracker --dashboard node
./target/debug/ebpf-tracker demo --dashboard session-io-demo
./target/debug/ebpf-tracker see
```

`see` is a shortcut for the repo-local dashboard demo experience. You can also
target a specific example:

```bash
./target/debug/ebpf-tracker see postcard-generator-rust
cargo see postcard-generator-rust
```

Dashboard mode forces `--emit jsonl` for the viewer stream and also enables
`--log-enable` so replay logs are preserved for later review.

Log locations:

- regular `run` sessions write under the current project's `./logs`
- `demo` and `see` sessions write under `examples/<demo-name>/logs/`

Replay example:

```bash
cargo viewer --replay examples/session-io-demo/logs/ebpf-tracker-YYYYMMDD-HHMMSS.log
```

Fastest deterministic viewer preview for frontend work:

```bash
bash scripts/dashboard-smoke.sh
bash scripts/dashboard-smoke.sh --no-open
```

That uses a bundled replay fixture instead of starting a fresh trace.

The interactive Node REPL path keeps a real terminal attached while the viewer
stays live, so `./target/debug/ebpf-tracker --dashboard node` works for
side-by-side typing plus dashboard review. Pure in-memory expressions will not
produce much trace data, so use file, network, or subprocess commands in the
REPL if you want richer viewer output.

## Config

If `ebpf-tracker.toml` exists in the current project, it is picked up
automatically. You can also pass it explicitly:

```bash
ebpf-tracker --config ebpf-tracker.toml cargo run
```

`--probe` takes precedence over config-generated probes.

Example:

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

See [`ebpf-tracker.toml.example`](../ebpf-tracker.toml.example).

## Attach Mode (Experimental Scaffold)

`attach` is intentionally surfaced here as an experimental scaffold rather
than a finished tracer path. It validates the target you named, prints the
planned integration path, and records the follow-up tasks, but it does not
start tracing yet.

Current scaffold examples:

```bash
ebpf-tracker attach k8s --selector app=payments
ebpf-tracker attach aws-eks --cluster prod --region us-east-1 --selector app=payments
ebpf-tracker attach aws-ecs --cluster prod --service api
ebpf-tracker attach docker --container payments-api
```

Current first-wave scope:

- `inspektor-gadget` is the first backend for `k8s` and `aws-eks`
- `tetragon` is the next backend for long-running cluster attach on `k8s` and `aws-eks`
- AWS-first scope stays on EKS clusters backed by EC2 nodes
- `aws-ecs` remains planned work after the EKS path is stable
- `aws-eks` Fargate and `aws-ecs` Fargate stay out of first-wave scope because the attach model depends on host-level eBPF access

## Local Checks

Smoke check:

```bash
cargo run --bin ebpf-tracker -- /bin/true
```

Installed-binary check from a Rust project:

```bash
ebpf-tracker cargo run
```

Config-driven check:

```bash
cp ebpf-tracker.toml.example ebpf-tracker.toml
ebpf-tracker cargo run
```

Repository demo check:

```bash
ebpf-tracker demo --list
```

Expected today:

- the first run may build the Docker image
- the default probe output shows `execve ...`
- config-driven `write/open/connect` output can still be noisy because tracing is per full session, not target-only

## Related Pages

- [`README.md`](../README.md)
- [`examples/README.md`](../examples/README.md)
- [`crates/ebpf-tracker-events/README.md`](../crates/ebpf-tracker-events/README.md)
- [`crates/ebpf-tracker-dataset/README.md`](../crates/ebpf-tracker-dataset/README.md)
- [`crates/ebpf-tracker-otel/README.md`](../crates/ebpf-tracker-otel/README.md)
- [`crates/ebpf-tracker-perf/README.md`](../crates/ebpf-tracker-perf/README.md)
- [`crates/ebpf-tracker-viewer/README.md`](../crates/ebpf-tracker-viewer/README.md)
