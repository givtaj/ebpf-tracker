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

    case "${probe_file}" in
      /probes/execve.bt|/probes/generated-config.bt)
        ;;
      *)
        if [ "${EBPF_TRACKER_ALLOW_HOST_WIDE_PROBE:-0}" != "1" ]; then
          echo "custom bpftrace probe ${probe_file} is not automatically workload-scoped and may observe host-wide events" >&2
          echo "rerun with --allow-host-wide-probe to acknowledge that risk" >&2
          exit 2
        fi
        ;;
    esac

    export EBPF_TRACKER_ARG_COUNT="$#"
    index=1
    for arg in "$@"; do
      export "EBPF_TRACKER_ARG_${index}=${arg}"
      index=$((index + 1))
    done

    # Bookworm's bpftrace does not propagate the exit status of its -c child.
    # Keep a private handoff outside the mounted project so a successful tracer
    # cannot make a failed workload look successful.
    status_dir="$(mktemp -d "${TMPDIR:-/tmp}/ebpf-tracker-status.XXXXXX")"
    trap 'rm -rf -- "${status_dir}"' EXIT
    export EBPF_TRACKER_STATUS_FILE="${status_dir}/workload-status"

    if bpftrace "${probe_file}" -c /usr/local/bin/exec-target-from-env; then
      tracer_status=0
    else
      tracer_status=$?
    fi
    if [[ "${tracer_status}" -ne 0 ]]; then
      exit "${tracer_status}"
    fi

    if [[ ! -f "${EBPF_TRACKER_STATUS_FILE}" ]] || ! workload_status="$(cat -- "${EBPF_TRACKER_STATUS_FILE}")"; then
      echo "tracer completed without a workload exit status" >&2
      exit 125
    fi
    if [[ ! "${workload_status}" =~ ^(0|[1-9][0-9]{0,2})$ ]] || [[ "${workload_status}" -gt 255 ]]; then
      echo "tracer recorded an invalid workload exit status" >&2
      exit 125
    fi
    exit "${workload_status}"
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
