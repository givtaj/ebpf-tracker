# Customer UX E2E Spec

This document defines the customer outcomes protected by the end-to-end suite.
For the current experimental alpha, the goal is not broad platform coverage. It
is one honest, repeatable workflow for a trusted Rust or Node.js project, plus
clear failure and support boundaries.

A passing check must never imply that `ebpf-tracker` is a security sandbox,
production agent, or safe runner for untrusted code.

## Safety And Test Host

Live run/demo journeys start a privileged Docker container, join the Docker
host PID namespace, and mount the selected project read-write. Run them only on
an isolated host with trusted inputs and no sensitive neighboring workloads.
Replay-only viewer and dataset checks should be preferred when a live trace is
not required.

A custom bpftrace `--probe` is potentially host-wide and is outside the normal
customer journey. The supported golden path uses built-in/config-generated
workload-scoped probes. That filtering limits collected data; it does not reduce
container privilege.

## Suite Controls

Journey scripts report `SKIP` for missing host capabilities by default. A skip
is useful diagnostic output, not a pass.

- `bash scripts/customer-ux-check.sh --strict-prereqs` turns Docker and
  loopback capability gaps into failures.
- `bash scripts/customer-ux-check.sh --fail-on-skip` fails the umbrella runner
  if any journey reports `SKIP`.
- `EBPF_TRACKER_E2E_STRICT_PREREQS=1` enables strict behavior for individual
  journey scripts.
- `bash scripts/customer-data-e2e.sh --analyze-endpoint <url>` uses an external
  OpenAI-compatible endpoint instead of the local loopback mock. Only use an
  endpoint approved for the trace data being sent.

Release evidence should state which journeys passed, failed, and skipped.

## 1. Golden Demo Stream

User goal: see useful build-time and runtime syscall activity through the
best-supported path.

Prerequisites:

- a source checkout and Rust toolchain;
- Docker with privileged-container and Linux/eBPF support; and
- an isolated host suitable for trusted test code.

Command:

```bash
cargo demo --emit jsonl session-io-demo > /tmp/ebpf-tracker-demo.jsonl
```

Expected observable outcome:

- the wrapped demo builds, runs, and returns its real exit status;
- build/application output stays readable on `stderr`;
- `stdout` is valid newline-delimited `StreamRecord` JSON;
- the stream includes the session plus useful `execve`, `open_at`, `write`, and
  `connect` activity when the corresponding demo probes are supported; and
- app-level events can be distinguished from expected Cargo/toolchain events.

The raw probe name is `openat`; the JSON event kind is `open_at`; aggregate
metric names use `openat`.

Failure signals:

- a zero exit with no evidence that the wrapped command ran;
- malformed or mixed JSONL on `stdout`;
- hidden underlying command failure;
- unrelated host activity appearing in the built-in scoped-probe stream; or
- Docker/runtime startup failure reported as a successful trace.

## 2. Minimal Installed CLI

User goal: confirm an installed binary reaches the real tracing runtime.

Command:

```bash
ebpf-tracker /bin/true
```

Expected observable outcome:

- the command starts the runtime, executes `/bin/true`, and exits `0`;
- the user sees trace/session completion rather than only a help screen; and
- failures name the missing Docker/kernel prerequisite.

This proves orchestration only. It does not prove rich app signal or broad
platform compatibility.

## 3. Trace A Trusted Project

User goal: run a normal Rust or Node.js command and observe the complete
session, including build tools and child processes.

Commands:

```bash
ebpf-tracker cargo run
ebpf-tracker npm test
```

Expected observable outcome:

- the command works in the bundled Debian Bookworm Rust/Node runtime;
- the wrapper preserves command output and exit status;
- built-in/config-generated probes stay scoped to the wrapped process tree;
  and
- the session can produce JSONL or a replay log for later inspection.

Failure signals include promising access to host-installed dependencies,
hiding build-tool events, describing the stream as app-only, or accepting an
arbitrary custom probe without an explicit host-wide acknowledgement.

## 4. Product-First Dashboard And Replay

User goal: see the product quickly and reopen a stored session.

Commands:

```bash
ebpf-tracker demo --dashboard session-io-demo
cargo viewer --replay examples/session-io-demo/logs/ebpf-tracker-YYYYMMDD-HHMMSS.log
```

Expected observable outcome:

- dashboard mode opens or clearly prints its URL;
- the demo session is recognizable and its replay artifact is preserved;
- replay works without a live privileged trace;
- play, pause, step, speed, and jump controls affect playback; and
- bind/port failures are explicit rather than yielding an empty page.

The browser dashboard is a local development surface, not an authenticated
multi-user service. Binding it beyond loopback requires an intentional review
of exposure.

## 5. Dataset And Optional Analysis

User goal: convert an existing JSONL stream into an inspectable local bundle
and, only when requested, send derived context to a configured analysis
endpoint.

Commands:

```bash
ebpf-tracker --emit jsonl cargo run | cargo dataset --test-name cargo-run-smoke
cargo dataset --replay crates/ebpf-tracker-viewer/demo-library/session-io-demo.jsonl
```

Expected observable outcome:

- `run.json`, `events.jsonl`, `processes.json`, `aggregates.json`, and
  `features.json` are written under one run directory;
- invalid input lines are counted rather than silently presented as events;
- the bundle remains local unless the user explicitly chooses analysis/export;
  and
- optional model unavailability does not break the base trace/dataset path.

Treat file paths, process names, command metadata, and derived summaries as
potentially sensitive.

## 6. Attach Boundary

User goal: know before execution whether `attach` will run a live backend,
print a plan, or reject the combination.

| Target and backend | Required outcome |
| --- | --- |
| `k8s` + `inspektor-gadget` | Run the live `kubectl gadget` path or fail its preflight explicitly |
| `aws-eks` + `inspektor-gadget` | Update/access the named EC2-backed EKS cluster, then run the live gadget path, or fail explicitly |
| `k8s`/`aws-eks` + `tetragon` | Print `attach scaffold` and state that no tracing started |
| `docker`/`aws-ecs` + `inspektor-gadget` | Print `attach scaffold` and state that no tracing started |
| `docker`/`aws-ecs` + `tetragon` | Reject as unsupported |

Commands used to verify representative boundaries:

```bash
ebpf-tracker attach k8s --selector app=payments
ebpf-tracker attach aws-eks --cluster prod --region us-east-1 --selector app=payments
ebpf-tracker attach docker --container payments-api
ebpf-tracker attach aws-ecs --cluster prod --service api
```

An exit code of zero from a scaffold is a successful plan render, not a
successful attach. Fargate is out of scope because these designs require
host-level eBPF access.

## Script Mapping

- `scripts/customer-cli-e2e.sh`: installed/root CLI journey
- `scripts/customer-viewer-e2e.sh`: dashboard and replay journey
- `scripts/customer-data-e2e.sh`: dataset and optional analysis journey
- `scripts/customer-ux-check.sh`: umbrella runner
- `scripts/runtime-smoke.sh`: privileged live runtime coverage
- `scripts/attach-smoke.sh`: scaffold/rejection coverage, not live attach proof

## CI And Release Integration

- `bash scripts/release-check.sh --with-customer-ux` opts into the customer
  journey suite.
- Generic `fmt`, `test`, and `build` gates remain cheaper and do not establish
  that privileged live tracing worked.
- A release claim about live tracing requires a non-skipped live runtime check
  on a compatible isolated host.
- A release claim about live Kubernetes/EKS attach requires separate backend
  evidence; the scaffold smoke is insufficient.
