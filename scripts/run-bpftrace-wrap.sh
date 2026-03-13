#!/usr/bin/env bash
set -euo pipefail

mount -t debugfs nodev /sys/kernel/debug >/dev/null 2>&1 || true

probe_file="${EBPF_TRACKER_PROBE:-/probes/execve.bt}"
if [ ! -f "${probe_file}" ]; then
  echo "probe file not found: ${probe_file}" >&2
  exit 2
fi

if [ "$#" -eq 0 ]; then
  set -- /bin/true
fi

printf -v cmd "%q " "$@"
cmd="${cmd% }"

exec bpftrace "${probe_file}" -c "$cmd"
