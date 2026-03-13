# ebpf-tracker-perf

Scaffold crate for future native kernel-to-userspace transport work.

Current purpose:

- define the planned transport boundary after the `bpftrace` + stdout phase
- keep perf-event-array and ring-buffer decisions outside the CLI crate
- give future native probes a home without muddying the current release path

Today this crate contains the transport plan only. It does not capture live events yet.
