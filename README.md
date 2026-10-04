# ebpf-tracker

> **Experimental alpha.** `ebpf-tracker` is useful today as a hackable,
> session-level syscall recorder for trusted Rust and Node.js development
> workflows. It is not a production observability agent, security sandbox, or
> general-purpose application profiler.

The CLI wraps a command such as `cargo run` or `npm run`, executes it in a
Linux Docker runtime, and records selected syscall activity for the wrapped
session. The result can be streamed as JSONL, saved for replay, opened in the
browser dashboard, converted into a dataset, or exported over OTLP.

For Rust apps, trace `cargo run` when build and dependency activity is part of
the session you want to inspect. When the goal is app-only behavior, build the
Linux binary first and run `ebpf-tracker ./target/release/<binary> ...` so the
trace is not dominated by Cargo, compiler, or registry-cache activity. On macOS,
that app binary must still be built for Linux, for example on a remote Linux
host or inside a compatible container.

## Read This Before Running It

The local tracing runtime currently starts a **privileged** container, joins
the Docker host's **PID namespace**, and mounts the selected project
**read-write** at `/workspace`. Consequently:

- code in the wrapped command can modify the mounted project;
- the tracing container has broad access to the Docker host or Docker Desktop
  VM; and
- trace output can include activity outside the intended workload when the
  selected probe or transport observes it.

**Do not use `ebpf-tracker` to run untrusted repositories, dependencies,
commands, or test fixtures.** Use it only on a trusted development machine or,
preferably, a disposable Linux VM/droplet with no sensitive neighboring
workloads. Do not deploy the run-mode container on a shared or production
host. Built-in/config-generated probes are workload-filtered, but any other
custom bpftrace `--probe` fails closed unless the operator supplies
`--allow-host-wide-probe`. That flag acknowledges potential host-wide
observation; it does not add containment. See [SECURITY.md](./SECURITY.md) for
the full trust and data boundary.

## Golden Workflow

From a source checkout, the bundled `session-io-demo` is the best-supported
way to see the product's current value:

```bash
cargo demo --emit jsonl session-io-demo > /tmp/ebpf-tracker-demo.jsonl
```

Prerequisites are a Rust toolchain, a running Docker engine that permits
privileged containers, and a Linux/eBPF-capable Docker host or VM. The first
run builds the runtime image. Application and build output remains visible on
`stderr`; normalized trace records go to the JSONL file.

Expect records shaped like these (timestamps, PIDs, ordering, and surrounding
build-tool events vary):

```json
{"type":"session","timestamp_unix_ms":1774500000000,"demo_name":"session-io-demo","product_name":"ebpf-tracker"}
{"type":"syscall","timestamp_unix_ms":1774500000100,"kind":"execve","comm":"cargo","pid":1008}
{"type":"syscall","timestamp_unix_ms":1774500000200,"kind":"open_at","comm":"session-io-demo","pid":1012,"file":"input/message.txt"}
{"type":"syscall","timestamp_unix_ms":1774500000300,"kind":"connect","comm":"session-io-demo","pid":1012,"fd":3}
```

The raw probe spelling is `openat`; the normalized JSON enum value is
`open_at`; aggregate metric names use `openat`. See the
[event contract](./crates/ebpf-tracker-events/README.md) before building a
consumer.

For the browser experience, run this separately:

```bash
ebpf-tracker demo --dashboard session-io-demo
```

## Current Scope

The useful path is deliberately narrow:

- **Workloads:** trusted Rust and Node.js projects whose commands work in the
  bundled Debian Bookworm runtime images (`rust:1-bookworm` and
  `node:22-bookworm`). Host-installed tools and native dependencies are not
  automatically available in those containers.
- **Collection:** `bpftrace` by default; `perf trace` is an alternate,
  best-effort transport.
- **Events:** `execve`, `openat`, `write`, and `connect`, with `execve` as the
  default when no config enables additional probes.
- **Scope:** the complete wrapped session, so build tools and child processes
  are expected. This is not app-only profiling.
- **Platforms:** Docker must expose the required Linux kernel tracing features.
  Native non-Linux execution is not supported; Docker Desktop behavior depends
  on its Linux VM and Docker configuration.
- **Packaging:** the root package and workspace crates are `publish = false`;
  install from a checkout or Git tag rather than crates.io.

The terminal monitor is a separate, read-only host snapshot:

```bash
ebpf-tracker monitor --once --no-clear
```

It does not start the privileged tracing runtime. See
[Host Monitoring](./docs/host-monitoring.md).

## Attach Status

`attach` is experimental and has two materially different behaviors:

| Target and backend | Behavior today |
| --- | --- |
| `k8s` + `inspektor-gadget` | Live `kubectl gadget` execution |
| `aws-eks` + `inspektor-gadget` | Live EKS kubeconfig update plus `kubectl gadget` execution; EC2-backed nodes only |
| `k8s`/`aws-eks` + `tetragon` | Scaffold: prints a plan and does not attach |
| `docker`/`aws-ecs` + `inspektor-gadget` | Scaffold: prints a plan and does not attach |
| `docker`/`aws-ecs` + `tetragon` | Rejected as unsupported |

A scaffold command may exit successfully after printing its plan; that is not
evidence that tracing occurred. The exact prerequisites and commands are in
the [CLI guide](./docs/cli.md#attach-mode-experimental).

## Workspace Map

- **Root CLI (`ebpf-tracker`)**: runtime orchestration, terminal `monitor`,
  config loading, demos, dashboard launch, and experimental attach.
- **[`ebpf-tracker-events`](./crates/ebpf-tracker-events/README.md)**: shared
  parser, JSONL schema, and session aggregation.
- **[`ebpf-tracker-dataset`](./crates/ebpf-tracker-dataset/README.md)**:
  per-run dataset bundles and optional analysis.
- **[`ebpf-tracker-otel`](./crates/ebpf-tracker-otel/README.md)**: OTLP exporter
  and local Jaeger helpers.
- **[`ebpf-tracker-perf`](./crates/ebpf-tracker-perf/README.md)**: `perf trace`
  normalization for the alternate collector path.
- **[`ebpf-tracker-viewer`](./crates/ebpf-tracker-viewer/README.md)**: browser
  dashboard and replay viewer.

See [Architecture](./architecture.md) for the data flow and trust boundaries.

## More Workflows

Detailed install, run, config, dashboard, and attach behavior belongs in the
[CLI guide](./docs/cli.md). Additional runnable examples are indexed under
[`examples/`](./examples/README.md), including:

- [`session-io-demo`](./examples/session-io-demo/README.md): build-time and
  runtime file, network, and output activity;
- [`postcard-generator-rust`](./examples/postcard-generator-rust/README.md);
  and
- [`postcard-generator-node`](./examples/postcard-generator-node/README.md).

Maintainer-facing customer journeys are specified in
[Customer UX E2E](./docs/customer-ux-e2e.md). A real external-project example
is documented in [Trace `payment-engine`](./docs/trace-payment-engine.md).

## Project Policies

- [Contributing](./CONTRIBUTING.md)
- [Security](./SECURITY.md)
- [Release process](./RELEASE.md)
