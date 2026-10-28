# ebpf-tracker

> **Axum-on-Docker alpha: `0.2.0-alpha.1`.** Trace one trusted Rust API
> service by installing an agent inside its existing Bookworm image.
> See [release downloads](https://github.com/givtaj/ebpf-tracker/releases),
> the [installation guide](./docs/in-container.md), and [alpha scope](./docs/alpha-scope.md).

The in-container `ebpf-tracker-agent` starts your API, records selected syscall
activity from its process tree, and writes replayable JSONL. Install the
Bookworm runtime package, set the agent as the entrypoint, and enable the
tracing Compose override. Your API keeps its image's libraries, network,
environment, ports, and database connections. The collector runs as root;
the agent starts the API as its existing non-root user with capabilities dropped.

The alpha records one API process lifetime during a bounded development or CI
test session, then saves its capture for local replay. Stopping the traced
container stops the API and flushes the capture. The current probes do not
provide HTTP route, request ID, latency, or per-request attribution. The example
uses a separate synthetic Axum/PostgreSQL stack; Roots itself is unchanged.

The existing host `ebpf-tracker` CLI also wraps commands in its own managed
Docker runtime and provides offline replay. `attach docker` remains a scaffold;
it is not used by the in-container integration.

New cloud-attach, host-monitoring, general Node.js workload, perf, AI, dataset,
and OTLP feature work is deferred while this Axum workflow is refined.
Existing commands remain available for experimentation.

For Rust apps, trace `cargo run` when build and dependency activity is part of
the session you want to inspect. When the goal is app-only behavior, build the
Linux binary first and run `ebpf-tracker ./target/release/<binary> ...` so the
trace is not dominated by Cargo, compiler, or registry-cache activity. On macOS,
that app binary must still be built for Linux, for example on a remote Linux
host or inside a compatible container.

## Read This Before Running It

The host CLI's managed runtime starts a **privileged** container, joins
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

For the focused API-container workflow, follow the
[Dockerfile, Compose, and CI installation guide](./docs/in-container.md).
Build the runtime package and run its isolated live acceptance example:

```bash
bash scripts/build-runtime-deb.sh --platform linux/amd64 --output-dir dist/runtime
bash scripts/in-container-smoke.sh \
  --package dist/runtime/ebpf-tracker-runtime_0.2.0~alpha.1_amd64.deb
```

For a native arm64 Docker engine, use `linux/arm64` and the `_arm64.deb` package.
Both paths require compatible Linux kernel tracing facilities. See the
[alpha scope](./docs/alpha-scope.md) for the current verification evidence.

The original command-tracing and replay workflow is also available.
Build the host CLI from this checkout:

```bash
cargo install --path . --locked
ebpf-tracker --version
```

Then record the bundled demo and replay it:

```bash
ebpf-tracker demo --emit jsonl session-io-demo > trace.jsonl
ebpf-tracker replay trace.jsonl
```

Source installation needs Rust (plus `pkg-config` and OpenSSL development
headers on Linux). Recording needs a running Docker engine with privileged
containers and Linux/eBPF support. The first recording builds the runtime
image. The bundled Rust demos also require Cargo on the host for their cleanup
step, including when using a downloaded binary. Replay and the dashboard need
Node.js on the host; replay does not start Docker. Application and build output stays on `stderr`; normalized
trace records go to the JSONL file. The demo enables all four probes.

For your own project, copy [`ebpf-tracker.toml.example`](./ebpf-tracker.toml.example)
to `ebpf-tracker.toml`, then run:

```bash
ebpf-tracker --config ebpf-tracker.toml --emit jsonl cargo run > trace.jsonl
# Or: ebpf-tracker --config ebpf-tracker.toml --emit jsonl npm test > trace.jsonl
ebpf-tracker replay trace.jsonl
```

Without a config, only `execve` is enabled. These are syscall attempts: the
trace does not prove I/O success, report remote connection addresses, or
measure application latency.

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

The focused alpha supports the in-container Bookworm package described above.
The original command-mode behavior remains available:

- **Workloads:** trusted Rust and Node.js projects whose commands work in the
  bundled Debian Bookworm runtime images (`rust:1-bookworm` and
  `node:22-bookworm`). Host-installed tools and native dependencies are not
  automatically available in those containers.
- **Collection:** `bpftrace` for the alpha workflow; `perf trace` remains an
  experimental alternate transport outside the alpha contract.
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

- **`ebpf-tracker-agent`**: native Linux in-container supervisor, privilege
  dropping, scoped bpftrace capture, and JSONL output; packaged as a Bookworm `.deb`.
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
