# Host Monitoring

`ebpf-tracker monitor` is the SSH-first overview for Linux hosts and droplets.
It is intentionally separate from the browser dashboard: use it when the server
itself is the thing you want to inspect from a terminal.

## When To Use It

Use the monitor when you want to answer questions such as:

- is this development box healthy right now?
- are Docker containers running?
- is kernel eBPF support visible?
- which processes are using CPU or memory?
- can I get a quick status snapshot without starting a web UI?

It is read-only. It does not install packages, start a daemon, open a browser,
or attach long-running probes.

## Quick Start

```bash
ebpf-tracker monitor
```

For copyable output in an SSH session:

```bash
ebpf-tracker monitor --once --no-clear
```

The snapshot includes the hostname plus process and container names. Review and
redact it before pasting into an issue, chat, or other shared location.

For a bounded live sample:

```bash
ebpf-tracker monitor --interval-ms 1000 --samples 5 --no-clear
```

From a repository checkout, the alias is:

```bash
cargo monitor --once --no-clear
```

For a deeper no-install readiness inventory before adding packages:

```bash
bash scripts/host-ebpf-readiness.sh
```

## Panels

The monitor shows:

- host, uptime, load average, process count, and container count
- CPU, memory, swap, and root disk pressure
- kernel BTF availability, BPF program count, BPF map count, and `perf_event_paranoid`
- running Docker containers when Docker metadata is readable
- top CPU and memory processes for the current sample

Some panels are best effort. On hardened hosts, Docker or `bpftool` may need
root access. The monitor gives external reads short deadlines, uses
non-interactive checks, and reports unavailable panels instead of blocking for
a password. Host-derived text is stripped of terminal control characters, but
the names themselves can still be sensitive.

## Relationship To Tracing

`monitor` is a host overview. It is not the same as wrapping a command with
`ebpf-tracker cargo run` or `ebpf-tracker --emit jsonl ...`.

Use both together:

1. Run `ebpf-tracker monitor --once --no-clear` to understand host state.
2. Run `ebpf-tracker <command>` to trace one project command through the managed
   runtime.
3. Use `--dashboard` or replay logs when you want session-level event detail.

## Clean-Host Practice

On new droplets, verify existing capability before installing dependencies:

```bash
ebpf-tracker monitor --once --no-clear
bash scripts/host-ebpf-readiness.sh
test -r /sys/kernel/btf/vmlinux && echo "kernel BTF available"
sudo -n bpftool prog show >/dev/null && echo "bpftool can read programs"
sudo -n perf trace -e execve -- /bin/true
```

Only add kernel/eBPF development packages after you know whether the missing
piece is runtime visibility, native build tooling, or convenience tools.
