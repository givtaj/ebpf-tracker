#!/usr/bin/env bash
set -euo pipefail

mount -t debugfs nodev /sys/kernel/debug >/dev/null 2>&1 || true

transport="${EBPF_TRACKER_TRANSPORT:-bpftrace}"

if [ "$#" -eq 0 ]; then
  set -- /bin/true
fi

if [[ "$1" != */* ]]; then
  resolved_command="$(command -v -- "$1" || true)"
  if [ -z "${resolved_command}" ]; then
    echo "command not found in PATH: $1" >&2
    exit 127
  fi
  set -- "${resolved_command}" "${@:2}"
fi

case "${transport}" in
  bpftrace)
    probe_file="${EBPF_TRACKER_PROBE:-/probes/execve.bt}"
    if [ ! -f "${probe_file}" ]; then
      echo "probe file not found: ${probe_file}" >&2
      exit 2
    fi

    export EBPF_TRACKER_ARG_COUNT="$#"
    index=1
    for arg in "$@"; do
      export "EBPF_TRACKER_ARG_${index}=${arg}"
      index=$((index + 1))
    done

    bpftrace "${probe_file}" -c /usr/local/bin/exec-target-from-env
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
