# Droplet Host eBPF Plan

Status: host capability Gates A and A.5 and terminal-monitor Gate A.6 are
complete. On 2026-08-15, the repo-build prerequisite gate was approved and
installed `pkg-config` plus `libssl-dev`; no kernel, native eBPF development,
convenience tracing, or persistent-agent package gate has been approved.

## Goal

Make the DigitalOcean droplet useful for host-wide eBPF observation first:
processes, files, network connections, containers, and shared host resources.
The repo's Docker-based tracing runtime is a secondary goal and should be
validated after the host can trace itself cleanly.

## Repo Findings

- `ebpf-tracker` wraps commands and runs them inside a Linux Docker runtime.
- The default transport is `bpftrace`; `perf trace` is the alternate transport.
- `docker/bpftrace-rust.Dockerfile` and `docker/bpftrace-node.Dockerfile`
  install `bpftrace`, `kmod`, and `linux-perf` inside Debian Bookworm images.
- `docker-compose.bpftrace.yml` and `docker-compose.bpftrace.node.yml` run the
  tracing container with `privileged: true` and `pid: host`.
- `scripts/run-bpftrace-wrap.sh` mounts `debugfs` when possible, then runs either
  `bpftrace <probe> -c /usr/local/bin/exec-target-from-env` or
  `perf trace -e <events> -- <command>`.
- `docs/cli.md` lists host requirements as Rust, Linux OpenSSL build metadata,
  and a Docker engine that supports privileged containers. Node is only needed
  for repo-local viewer and dashboard flows.
- `.cargo/config.toml` defines clone-local helpers: `cargo demo`, `cargo see`,
  `cargo viewer`, `cargo dataset`, `cargo otel`, `cargo jaeger`, and
  `cargo monitor`.

Important implication: the repo currently installs most eBPF runtime tools in
containers, not on the host. For whole-droplet visibility, host packages and
host privilege checks matter more than the repo Dockerfiles.

## Observed Droplet Baseline

Refreshed on 2026-08-15:

- OS: Ubuntu 24.04.4 LTS
- Kernel: `6.8.0-136-generic`
- Architecture: `x86_64`
- Rust: `cargo 1.96.0`, `rustc 1.96.0`
- Docker client: `29.6.0`
- Docker Compose: `v5.1.4`
- Docker daemon: reachable from the current development session
- Present eBPF/tracing tools: `bpftrace`, `perf`, `bpftool`, BCC tools,
  `trace-cmd`, `kmod`, matching `linux-tools-6.8.0-136-generic`, and matching
  `linux-headers-6.8.0-136-generic`
- Present general tools: `gcc`, `make`, `curl`, `python3`, Node/npm from
  `/usr/local`
- Present repo-build packages: `pkg-config`, `libssl-dev`, and `zlib1g-dev`
- Missing optional native eBPF development packages: `clang`, `llvm`, `lld`,
  `libbpf-dev`, `libbpf-tools`, `libelf-dev`, and `dwarves`
- Kernel BTF is readable; `bpftool` can read programs and maps with
  non-interactive sudo

## Principles

- Do not install broad observability stacks before the host tracing path is
  proven.
- Prefer Ubuntu packages for kernel/eBPF tooling so upgrades remain manageable.
- Keep the first install phase small and reversible in concept: meta packages
  and build dependencies before any always-on agents.
- Treat host-wide tracing as sensitive. It can expose process names, command
  arguments, file paths, network destinations, and container activity.
- Use short-lived probes first. Add persistent services only after we know which
  signals are worth keeping.

## Phase 0: Verify Existing Host Capability

No package installs.

Suggested checks:

```bash
sudo bpftool prog show
sudo bpftool map show
test -r /sys/kernel/btf/vmlinux && echo "kernel BTF available"
sudo bpftrace -e 'tracepoint:syscalls:sys_enter_execve { printf("%s pid=%d\n", comm, pid); exit(); }' -c /bin/true
sudo perf trace -e execve -- /bin/true
```

Success means the host can already attach eBPF programs, read kernel BTF, and
capture a minimal process event.

Gate A result on 2026-06-27:

- Passed: `/sys/kernel/btf/vmlinux` is readable, so kernel BTF is available.
- Passed: `sudo bpftool prog show` listed active BPF programs.
- Passed: `sudo bpftool map show` listed active BPF maps.
- Passed: `sudo bpftrace` attached to `tracepoint:syscalls:sys_enter_execve`
  and captured a short exec event.
- Passed: `sudo perf trace -e execve -- /bin/true` produced the execve line
  shape expected by `ebpf-tracker-perf`.
- Note: `kernel.perf_event_paranoid = 4`, so host perf tracing should be treated
  as a sudo/root operation on this droplet.


## Gate A.5: Host-Wide Signal Map

No package installs. This gate checks whether the already-installed host tools can
show the signals we care about without dumping raw command arguments or every
file path. Start with count-only captures grouped by process name.

| Signal | First check | Why it matters |
| --- | --- | --- |
| Process starts | `sys_enter_execve` count by `comm` | Shows command/session churn across the whole droplet. |
| File opens | `sys_enter_openat` count by `comm` | Shows file activity pressure before capturing paths. |
| Writes | `sys_enter_write` count by `comm` | Shows noisy writers and shared-output pressure. |
| Network connects | `sys_enter_connect` count by `comm` | Shows outbound connection attempts. |
| Containers | read-only `docker ps` snapshot | Names container context for host events. |
| Ownership filters | process name first, cgroup/container later | Prevents noisy global traces from becoming unusable. |

Suggested count-only captures:

```bash
sudo bpftrace -e 'tracepoint:syscalls:sys_enter_execve { @[comm] = count(); } interval:s:5 { exit(); } END { print(@); clear(@); }'
sudo bpftrace -e 'tracepoint:syscalls:sys_enter_openat { @[comm] = count(); } interval:s:5 { exit(); } END { print(@); clear(@); }'
sudo bpftrace -e 'tracepoint:syscalls:sys_enter_write { @[comm] = count(); } interval:s:5 { exit(); } END { print(@); clear(@); }'
sudo bpftrace -e 'tracepoint:syscalls:sys_enter_connect { @[comm] = count(); } interval:s:5 { exit(); } END { print(@); clear(@); }'
sudo docker ps --format "{{.ID}} {{.Names}} {{.Status}}"
```

Gate A.5 result on 2026-06-27:

- Passed: process-start, file-open, and write counts all reported activity
  grouped by process name without capturing arguments or paths.
- Passed: network-connect capture attached cleanly; no connect events occurred
  during the five-second sample.
- Passed: the read-only container snapshot found three running containers.

Next decision: keep using count-only host probes until filters are clear. The
next useful no-install experiment is a filtered capture for one target process or
container, then only consider Phase 1 or Phase 2 packages if we need build-time
eBPF development tools rather than runtime observation.


## Gate A.6: Terminal Droplet Monitor

The monitor itself performs no package installs. This gate turns the proven
host signals into an SSH-first terminal UI instead of a browser dashboard.

Command shape:

```bash
ebpf-tracker monitor
ebpf-tracker monitor --once --no-clear
ebpf-tracker monitor --interval-ms 1000 --samples 5
cargo monitor --once --no-clear
```

Gate A.6 final result on 2026-08-15:

- Added `ebpf-tracker monitor` as a terminal-first droplet overview.
- Added the repo-local `cargo monitor` alias.
- The monitor renders CPU, memory, swap, disk, uptime, load, process count,
  active containers, eBPF BTF/program/map health, `perf_event_paranoid`, and top
  CPU/memory processes.
- Installed the minimal repo-build prerequisite set, `pkg-config` and
  `libssl-dev`, after explicit approval; no eBPF development packages or
  services were added.
- Passed `cargo test --all --locked` across the full workspace (120 tests).
- Passed `cargo monitor --once --no-clear` against the real host with readable
  system, eBPF, container, and process panels.
- Bounded external `df`, `bpftool`, and Docker reads, derived RSS from the host
  page size, and sanitized control characters in host-derived terminal text.

Next decision: keep the monitor read-only and terminal-first. The next useful
slice is adding optional short eBPF event-rate panels for `execve`, `openat`,
`write`, and `connect`, gated behind an explicit flag so normal monitor refreshes
stay light.

## Phase 1: Kernel Tooling Stability

Install only if Phase 0 passes or shows that kernel meta packages are the
remaining gap.

Purpose: keep `perf`, headers, and kernel helper tools aligned across future
kernel upgrades.

Proposed package set:
```bash
sudo apt-get install -y --no-install-recommends \
  linux-tools-generic \
  linux-cloud-tools-generic \
  linux-headers-generic
```

Expected value:

- keeps future generic kernel headers available
- keeps future generic kernel perf/tools packages available
- reduces breakage after droplet kernel updates

## Phase 2: Native eBPF Development Layer

Install when we want to build or compile host eBPF programs directly on the
droplet, especially libbpf/CO-RE or Rust eBPF experiments.

Proposed package set:

```bash
sudo apt-get install -y --no-install-recommends \
  clang \
  llvm \
  lld \
  libbpf-dev \
  libelf-dev \
  dwarves
```

Expected value:

- `clang`/`llvm` compile BPF object code
- `libbpf-dev`, `libelf-dev`, and `zlib1g-dev` support native libbpf builds
- `dwarves` provides `pahole`, useful for BTF-oriented development
- existing host packages already provide `pkg-config` and `zlib1g-dev`

## Phase 3: Host-Wide Tracing Convenience Tools

Install only after deciding that prebuilt host tools are useful enough to keep.

Proposed package set:

```bash
sudo apt-get install -y --no-install-recommends \
  libbpf-tools
```

Already installed and should not need reinstalling:

```bash
bpftrace
kmod
bpftool
bpfcc-tools
python3-bpfcc
trace-cmd
```

Expected value:

- adds prebuilt libbpf-based tools for common host observations
- complements existing BCC tools without introducing a daemon

## Phase 4: Repo Docker Runtime

Secondary goal. Do this after host-wide eBPF checks are healthy.

Current Docker note:

- the daemon is reachable from the current development session
- group membership and socket access should still be rechecked on a clean host

Suggested checks:

```bash
docker info
cargo run --locked --quiet --bin ebpf-tracker -- --emit jsonl /bin/true
bash scripts/runtime-smoke.sh
```

Success means the repo can build its privileged tracing image and run the
minimal `bpftrace` path.

## Hold For Later

Do not install these until there is a clear need:

- Kubernetes/eBPF attach tools such as Inspektor Gadget or Tetragon
- Prometheus, Grafana, Jaeger, or other always-on observability stacks
- kernel upgrades solely for tracing experiments
- custom systemd services for persistent capture
- language-specific eBPF frameworks beyond the repo's current requirements

## Approval Gates

Before changing the droplet, choose one gate:

- Gate P: install only the repo-build prerequisites (`pkg-config`, `libssl-dev`)
- Gate A: run Phase 0 verification only
- Gate A.5: run no-install count-only host-wide signal mapping
- Gate B: install Phase 1 kernel meta packages only
- Gate C: install Phase 1 and Phase 2 for full host eBPF development
- Gate D: install Phase 1, Phase 2, and Phase 3 for host tracing convenience
- Gate E: skip host packages and fix/test the repo Docker runtime only

Gate P, Gate A, Gate A.5, and Gate A.6 are complete. The recommended next step
is a no-install filtered target capture for one process or container. Do not
install optional kernel or eBPF development packages unless that reveals a
specific build-time or kernel-tooling gap.
