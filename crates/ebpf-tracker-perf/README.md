# `ebpf-tracker-perf`

> Experimental workspace crate. It is `publish = false`; the current
> `perf trace` adapter should not be confused with a native ring-buffer
> transport or a stable public library API.

This crate normalizes Linux `perf trace` output into the shared
`ebpf_tracker_events::StreamRecord` model and keeps the alternate transport
logic outside the root CLI.

## What Works Today

- The root CLI accepts `--transport perf`.
- `parse_perf_trace_line` accepts the project-specific shape
  `timestamp: comm/pid syscall(args) = return`.
- Supported raw syscall names are `execve`, `openat`, `write`, and `connect`.
- `stream_record_for_perf_trace_line_at` creates `StreamRecord::Syscall`
  values for supported lines.
- `PerfTraceSession` emits aggregate metrics named `execve`, `openat`,
  `writes`, and `connects`.
- `default_perf_event_kinds()` returns only `execve`, matching the CLI default
  when no config enables more probes.
- `default_transport_plan()` describes the split between shipped bpftrace,
  current `perf trace`, and future native transport work.

Example from a source checkout:

```bash
ebpf-tracker --transport perf --emit jsonl cargo run
```

Perf command mode follows the wrapped command and child processes. It is still
executed through the project's privileged Docker runtime; choosing perf does
not remove `privileged`, the host PID namespace, or the read-write project
mount.

## Event Naming

The collector/parser recognizes raw `openat`, but `EventKind::OpenAt` is
serialized by Serde as JSON `"kind":"open_at"`. Aggregate metrics retain the
name `openat`. Consumers should use the
[`ebpf-tracker-events` contract](../ebpf-tracker-events/README.md), not raw perf
spellings.

## Limits

- File paths are best-effort and can be absent when `perf trace` cannot decode
  userspace string pointers.
- `write` and `connect` retain only fields normalized today: byte count and file
  descriptor.
- Unsupported syscalls and malformed lines are ignored rather than partially
  decoded.
- This crate does not provide perf-event-array or eBPF ring-buffer capture.
- Syscall counts vary with host, cache state, dependencies, and command; they
  are not performance benchmarks.
- Process names, PIDs, paths, and descriptors are potentially sensitive trace
  metadata.

## Future Work, Not Current Capability

- direct perf-event-array transport;
- ring-buffer transport; and
- richer argument decoding than plain `perf trace` can provide.
