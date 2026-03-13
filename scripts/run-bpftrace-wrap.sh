#!/usr/bin/env bash
set -euo pipefail

mount -t debugfs nodev /sys/kernel/debug >/dev/null 2>&1 || true

transport="${EBPF_TRACKER_TRANSPORT:-bpftrace}"

if [ "$#" -eq 0 ]; then
  set -- /bin/true
fi

case "${transport}" in
  bpftrace)
    probe_file="${EBPF_TRACKER_PROBE:-/probes/execve.bt}"
    if [ ! -f "${probe_file}" ]; then
      echo "probe file not found: ${probe_file}" >&2
      exit 2
    fi

    printf -v cmd "%q " "$@"
    cmd="${cmd% }"

    exec bpftrace "${probe_file}" -c "$cmd"
    ;;
  perf)
    perf_events="${EBPF_TRACKER_PERF_EVENTS:-execve}"
    exec perf trace -e "${perf_events}" -- "$@"
    ;;
  *)
    echo "unsupported transport: ${transport}" >&2
    exit 2
    ;;
esac
