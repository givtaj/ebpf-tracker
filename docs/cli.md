# CLI Guide

`ebpf-tracker` is an experimental alpha for trusted Rust and Node.js development
workflows. The most mature behavior is local command-session tracing and
replay. It is not a production agent, security sandbox, or full profiler.
The `0.2.0-alpha.1` target is the [Axum-on-Docker workflow](./alpha-scope.md).
Container integration and Axum acceptance remain pending; the commands below
describe the implemented tracing and replay foundations.
Other commands remain experimental and outside the alpha feature-development scope.

## Requirements And Compatibility

For live run/demo tracing you need:

- a Rust toolchain to build or install the CLI;
- Docker Desktop or another Docker engine that permits privileged containers;
- Linux kernel/eBPF features exposed to that Docker host or VM; and
- `pkg-config` plus OpenSSL development headers for Linux source builds
  (`pkg-config` and `libssl-dev` on Debian/Ubuntu).

Bundled Rust demos also run their Cargo cleanup step on the host, so those
demos require host Cargo even with a downloaded CLI binary.

Node.js on the host is needed for all dashboard and replay workflows, including
the installed binary. Offline replay needs neither Docker nor an eBPF host. The
traced workload itself runs in a bundled Debian Bookworm image:

| Runtime selection | Image family | Auto-selected commands |
| --- | --- | --- |
| Rust | `rust:1-bookworm` | `cargo`, Rust-oriented defaults |
| Node.js | `node:22-bookworm` | `node`, `npm`, `npx`, `pnpm`, `yarn` |

Host-installed tools and native libraries are not automatically available in
the container. Use `--runtime rust` or `--runtime node` when a shell wrapper
prevents reliable auto-detection.

## Security Boundary

Live run/demo mode starts a container with `privileged: true`, `pid: host`, and
a read-write bind mount of the selected project at `/workspace`. The wrapped
command can change that project, and the tracer has broad visibility into the
Docker host or Docker Desktop VM.

Never trace an untrusted repository, dependency, command, fixture, or probe.
Use a disposable development VM/droplet with no sensitive neighboring
workloads. Workload filtering reduces collected events; it does not reduce the
container privilege. Read [SECURITY.md](../SECURITY.md) before live use.

The `monitor` subcommand is different: it performs bounded read-only host checks
and does not start the privileged tracing runtime.

## Install

Install from a reviewed local checkout:

```bash
cargo install --path . --locked
```

Or install the current Git revision directly:

```bash
cargo install --git https://github.com/givtaj/ebpf-tracker --locked
```

The root package and workspace crates use `publish = false`; they are not
available from crates.io. Pin a Git tag or commit when repeatability matters.
Runtime assets are materialized under `~/.cache/ebpf-tracker` by default. Set
`EBPF_TRACKER_CACHE_DIR=/your/path` to use a different cache root.

## Golden Workflow

Use the bundled demo first, including from an installed binary:

```bash
ebpf-tracker demo --emit jsonl session-io-demo > trace.jsonl
ebpf-tracker replay trace.jsonl
```

From a source checkout, `cargo demo --emit jsonl session-io-demo` is equivalent
to the capture command. The demo config enables all four probes. For another
project, copy `ebpf-tracker.toml.example` to `ebpf-tracker.toml` and pass
`--config ebpf-tracker.toml`; without a config only `execve` is enabled.

`ebpf-tracker replay --help` lists replay controls. `ebpf-tracker --version`
identifies the installed candidate. Replay uses the viewer embedded in that
same binary and does not start a new trace.

The first run may build/pull the Docker image. Cargo and application output
remain on `stderr`; valid `StreamRecord` JSON lines go to the file. Expect a
session record and a mixture of Cargo/toolchain and app events, including
records shaped like:

```json
{"type":"syscall","timestamp_unix_ms":1774500000200,"kind":"open_at","comm":"session-io-demo","pid":1012,"file":"input/message.txt"}
```

Timestamps, PIDs, order, and volume vary. The demo's important app-level signal
is file access to `input/message.txt`, a loopback `connect`, and output writes.

The smallest installed-binary runtime check is:

```bash
ebpf-tracker /bin/true
```

It proves orchestration, not rich application signal.

## Run Mode

Common commands:

```bash
ebpf-tracker cargo run
ebpf-tracker cargo test
ebpf-tracker npm run dev
ebpf-tracker npm test
ebpf-tracker --emit jsonl cargo run
ebpf-tracker --transport perf --emit jsonl cargo run
ebpf-tracker --runtime node /bin/sh -lc "npm run dev"
```

Without installing from a checkout:

```bash
cargo run --bin ebpf-tracker -- cargo run
```

The tracer follows the complete wrapped process tree. Rust sessions therefore
include `cargo`, `rustc`, linkers, and the app; Node sessions can include `npm`,
`node`, package scripts, and their children. This is expected session signal,
not app-only profiling. The wrapper preserves the underlying command's exit
status.

Rust runs cache both `CARGO_HOME` and `CARGO_TARGET_DIR` in Docker volumes keyed
by the project path. That keeps registry downloads and build artifacts out of
the project checkout while making later traced `cargo` sessions substantially
warmer than the first run.

For app-level behavior, build first and trace the produced Linux binary instead
of tracing `cargo run`:

```bash
cargo build --release
ebpf-tracker ./target/release/my-app --flag value
```

That keeps the trace focused on the application process and its runtime child
threads. Use `ebpf-tracker cargo run` when you intentionally want build-tool,
compiler, dependency, and application activity in one session trace.
The binary must be runnable inside the Linux tracing runtime. On macOS, build
for Linux in a compatible container or remote Linux host before using this
direct-binary path.

### Workload Scoping

The default `/probes/execve.bt` and probes generated from
`ebpf-tracker.toml` are workload-scoped. They seed a bpftrace map from `cpid`,
track descendant thread IDs with `sched_process_fork`, and clean entries on
process exit. Their syscall handlers emit events only for IDs in that map.

This filtering is intended to keep unrelated Docker-host processes out of the
stream. It is not a security boundary, and it does not change `privileged` or
`pid: host`. `bpftrace -c` provides the initial command PID; it does not by
itself filter every probe.

`perf trace` command mode follows the wrapped command and its children. It is
best-effort: `openat` paths may be absent when perf cannot decode userspace
string pointers.

### Custom Bpftrace Probes

An arbitrary custom probe cannot be safely rewritten or externally scoped by
the CLI. Any explicit probe other than the shipped scoped default fails closed
unless you make the host-wide risk acknowledgement:

```bash
ebpf-tracker --allow-host-wide-probe --probe ./probes/custom.bt cargo run
```

`--allow-host-wide-probe` means the program may observe unrelated processes in
the Docker host PID namespace. Review the probe yourself and use an isolated
host. The equivalent acknowledgement for direct use of the runtime wrapper is
`EBPF_TRACKER_ALLOW_HOST_WIDE_PROBE=1`; normal CLI users should use the flag.

`--probe` is supported only with `--transport bpftrace` and takes precedence
over a config-generated probe.

## Event Stream

The default output mode is `raw`, and the default transport is `bpftrace`.
Reserve `stdout` for machine-readable records with:

```bash
ebpf-tracker --emit jsonl cargo run
```

In JSONL mode, build output, application output, warnings, and runtime errors
remain on `stderr`. Downstream examples from a source checkout:

```bash
ebpf-tracker --emit jsonl cargo run | cargo dataset --test-name cargo-run-smoke
ebpf-tracker --emit jsonl cargo run | cargo otel --target jaeger --service-name my-service
```

The event-name layers differ:

| Layer | Open syscall spelling |
| --- | --- |
| Raw bpftrace/perf-normalizer line | `openat` |
| `StreamRecord` JSON `kind` | `open_at` |
| Aggregate metric | `openat` |

Other JSON kinds are `execve`, `write`, and `connect`. The authoritative schema
is in [`ebpf-tracker-events`](../crates/ebpf-tracker-events/README.md).

## Config

The CLI automatically reads `ebpf-tracker.toml` from the selected project, or
accepts an explicit path:

```bash
ebpf-tracker --config ebpf-tracker.toml cargo run
```

Example:

```toml
[probe]
exec = true
write = true
open = true
connect = false

[runtime]
cpus = 2.0
memory = "4g"
cpuset = "0-3"
pids_limit = 512
```

Probe fields:

- `probe.exec`: raw `execve`, JSON `execve`
- `probe.write`: raw/JSON `write`
- `probe.open`: raw `openat`, JSON `open_at`
- `probe.connect`: raw/JSON `connect`

Runtime limits constrain resource use but do not remove privilege or host PID
visibility. See [`ebpf-tracker.toml.example`](../ebpf-tracker.toml.example).

## Dashboard, Demo, And Replay

Trace a trusted project and open the loopback-bound dashboard:

```bash
ebpf-tracker --dashboard cargo run
ebpf-tracker --dashboard npm run dev
```

Product-first demo entry points:

```bash
ebpf-tracker demo --dashboard session-io-demo
ebpf-tracker see
```

`see` is a dashboard-demo shortcut. Dashboard mode forces JSONL and enables
logging so the session can be replayed. Regular run logs are written under the
project's `./logs`; demo/see logs are written under
`examples/<demo-name>/logs/` when using a checkout. Embedded demo assets are
materialized into the cache when a checkout is unavailable.

Clone-local deterministic replay:

```bash
cargo viewer --replay examples/session-io-demo/logs/ebpf-tracker-YYYYMMDD-HHMMSS.log
bash scripts/dashboard-smoke.sh --no-open
```

Replay does not require a new privileged trace. The viewer binds to
`127.0.0.1` by default. If you deliberately bind it to another interface, treat
it as an unauthenticated development server and control network exposure.

The interactive Node REPL path keeps a terminal attached while the viewer is
live. Pure in-memory expressions produce little syscall signal; use file,
network, or subprocess activity for a meaningful trace.

## Terminal Monitor

For an SSH-first host snapshot:

```bash
ebpf-tracker monitor
ebpf-tracker monitor --once --no-clear
ebpf-tracker monitor --interval-ms 1000 --samples 5
```

The monitor reads Linux `/proc`, uses `df` for disk space, and adds Docker and
eBPF health when the relevant commands are available. It does not install
packages, start a daemon, open a browser, or enter the tracing container.
Unavailable Docker or `bpftool` metadata is reported without interactive sudo.
See [Host Monitoring](./host-monitoring.md).

## Attach Mode (Experimental)

Attach support is not one uniform feature:

| Target and backend | Behavior today |
| --- | --- |
| `k8s` + `inspektor-gadget` | **Live:** runs local `kubectl gadget` commands |
| `aws-eks` + `inspektor-gadget` | **Live:** updates/accesses kubeconfig, then runs `kubectl gadget`; EC2-backed nodes only |
| `k8s`/`aws-eks` + `tetragon` | **Scaffold:** prints a plan; no tracing starts |
| `docker`/`aws-ecs` + `inspektor-gadget` | **Scaffold:** prints a plan; no tracing starts |
| `docker`/`aws-ecs` + `tetragon` | Rejected as unsupported |

Representative commands:

```bash
ebpf-tracker attach k8s --selector app=payments
ebpf-tracker attach aws-eks --cluster prod --region us-east-1 --selector app=payments
ebpf-tracker attach docker --container payments-api
ebpf-tracker attach aws-ecs --cluster prod --service api
```

The live Kubernetes path requires a working `kubectl` client and
`kubectl gadget` plugin plus authorization for the selected workload. The EKS
path also uses the local AWS CLI and credentials to update kubeconfig for the
named cluster. Review the active account, cluster, namespace, selector/pod, and
region first.

The Inspektor Gadget adapter tries the available `exec`, `open`, `write`, and
`tcpconnect` trace subcommands. Missing subcommands are skipped; if none are
available, attach fails with a setup error. Override their order/set with:

```bash
EBPF_TRACKER_ATTACH_INSPEKTOR_GADGET_TRACE_SET=exec,open,write,connect \
  ebpf-tracker attach k8s --selector app=payments
```

A scaffold prints `attach scaffold`, explicitly states that no live backend
execution occurred, and may exit zero after producing the plan. That zero means
"plan rendered," not "workload traced." EKS Fargate and ECS Fargate are out of
scope because the planned model depends on host-level eBPF access.

## Local And Release Checks

Non-privileged checks:

```bash
cargo run --bin ebpf-tracker -- --help
cargo demo --list
cargo test --all --locked
```

Privileged live smoke on an isolated compatible host:

```bash
bash scripts/runtime-smoke.sh
```

Customer-journey suite:

```bash
bash scripts/customer-ux-check.sh
bash scripts/customer-ux-check.sh --strict-prereqs
bash scripts/customer-ux-check.sh --fail-on-skip
bash scripts/release-check.sh --with-customer-ux
```

By default, missing Docker or loopback capabilities can produce `SKIP`. Use the
strict controls when a skipped live journey must fail the gate. A non-skipped
runtime smoke is required before claiming that live tracing works on the tested
host. `scripts/attach-smoke.sh` validates scaffold/rejection behavior; it is not
proof of live Kubernetes/EKS attachment.

## Related Pages

- [Project status and golden workflow](../README.md)
- [Security policy](../SECURITY.md)
- [Architecture and trust boundaries](../architecture.md)
- [Customer UX E2E contract](./customer-ux-e2e.md)
- [External `payment-engine` example](./trace-payment-engine.md)
- [Examples](../examples/README.md)
- [Event schema](../crates/ebpf-tracker-events/README.md)
- [Dataset crate](../crates/ebpf-tracker-dataset/README.md)
- [OTel crate](../crates/ebpf-tracker-otel/README.md)
- [Perf crate](../crates/ebpf-tracker-perf/README.md)
- [Viewer crate](../crates/ebpf-tracker-viewer/README.md)
