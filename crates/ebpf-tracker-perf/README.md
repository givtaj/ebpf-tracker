# ebpf-tracker-perf

Transport crate for the non-default `perf` runtime path and future native
kernel-to-userspace transport work.

Current purpose:

- normalize Linux `perf trace` output into `StreamRecord` values
- define the planned transport boundary after the default `bpftrace` + stdout path
- keep perf-event-array and ring-buffer decisions outside the CLI crate
- give future native probes a home without muddying the current release path

Current status:

- the root CLI can now run with `--transport perf`
- this crate parses `perf trace` syscall lines for `execve`, `openat`, `write`,
  and `connect`
- this crate also synthesizes aggregate counts so the JSONL contract stays
  compatible with downstream consumers

Current limitation:

- in plain `perf trace` mode, file-path arguments are best-effort and may be
  omitted when `perf trace` cannot decode userspace string pointers

Future work here:

- direct perf-event-array transport
- ring buffer transport
- richer syscall argument decoding than plain `perf trace` can provide
