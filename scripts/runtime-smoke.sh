#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"
run_perf_smoke=0
run_demo_smoke=0

fail() {
  printf 'runtime smoke: %s\n' "$1" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage: bash scripts/runtime-smoke.sh [--with-perf-smoke] [--with-demo-smoke]

The default path runs the standard bpftrace-backed JSONL smoke and verifies
that a wrapped command's nonzero exit status is preserved.
Use --with-perf-smoke to additionally exercise the perf transport path.
Use --with-demo-smoke to verify all four event kinds and session metadata
from the session-io-demo workload.
Set EBPF_TRACKER_TEST_BINARY to validate a specific built executable.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --with-perf-smoke)
      run_perf_smoke=1
      shift
      ;;
    --with-demo-smoke)
      run_demo_smoke=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'runtime smoke: unknown option: %s\n' "$1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

tracker_cmd=()
if [[ -n "${EBPF_TRACKER_TEST_BINARY:-}" ]]; then
  tracker_binary="$(command -v "${EBPF_TRACKER_TEST_BINARY}")" || fail "test binary was not found: ${EBPF_TRACKER_TEST_BINARY}"
  [[ -x "${tracker_binary}" && ! -d "${tracker_binary}" ]] || fail "test binary is not executable: ${tracker_binary}"
  tracker_binary="$(cd -- "$(dirname -- "${tracker_binary}")" && pwd)/$(basename -- "${tracker_binary}")"
  tracker_cmd=("${tracker_binary}")
else
  cargo_binary="$(command -v cargo)" || fail "cargo is required"
  cargo_binary="$(cd -- "$(dirname -- "${cargo_binary}")" && pwd)/$(basename -- "${cargo_binary}")"
  tracker_cmd=("${cargo_binary}" run --manifest-path "${repo_root}/Cargo.toml" --locked --quiet --bin ebpf-tracker --)
fi
command -v python3 >/dev/null 2>&1 || fail "python3 is required to validate JSONL"
command -v docker >/dev/null 2>&1 || fail "docker is required"
docker info >/dev/null 2>&1 || fail "docker daemon is not available; start Docker and retry"

tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/ebpf-tracker-runtime-smoke.XXXXXX")"
default_output_file="${tmp_root}/trace-default.jsonl"
perf_output_file="${tmp_root}/trace-perf.jsonl"

cleanup() {
  rm -rf "${tmp_root}"
}

trap cleanup EXIT INT TERM

cd "${repo_root}"

validate_jsonl() {
  python3 - "$1" "${2:-}" <<'PY'
import json
import sys

path, demo_name = sys.argv[1:]
count = 0
kinds = set()
session_found = False
with open(path, encoding="utf-8") as stream:
    for number, line in enumerate(stream, 1):
        try:
            record = json.loads(line)
        except ValueError as error:
            sys.exit(f"runtime smoke: invalid JSONL at line {number}: {error}")
        if not isinstance(record, dict) or record.get("type") not in {"session", "syscall", "aggregate"}:
            sys.exit(f"runtime smoke: invalid stream record at line {number}")
        count += 1
        if record["type"] == "syscall":
            kind = record.get("kind")
            if not isinstance(kind, str) or kind not in {"execve", "open_at", "write", "connect"}:
                sys.exit(f"runtime smoke: invalid syscall kind at line {number}")
            kinds.add(kind)
        if record["type"] == "session" and record.get("demo_name") == demo_name and record.get("product_name") == "ebpf-tracker":
            session_found = True
if not kinds:
    sys.exit("runtime smoke: no syscall records in JSONL")
if demo_name:
    missing = {"execve", "open_at", "write", "connect"} - kinds
    if missing:
        sys.exit(f"runtime smoke: demo missing syscall kinds: {', '.join(sorted(missing))}")
    if not session_found:
        sys.exit(f"runtime smoke: missing session metadata for {demo_name}")
print(f"[runtime-smoke] validated {count} JSONL records; kinds: {', '.join(sorted(kinds))}")
PY
}

run_jsonl_smoke() {
  local label="$1"
  local output_file="$2"
  shift 2

  printf '[runtime-smoke] running minimal traced session with /bin/true (%s)\n' "${label}"

  if ! "${tracker_cmd[@]}" "$@" --emit jsonl /bin/true >"${output_file}"; then
    fail "minimal traced session failed for ${label}"
  fi

  validate_jsonl "${output_file}"
}

run_jsonl_smoke "bpftrace" "${default_output_file}"

printf '[runtime-smoke] checking wrapped nonzero exit status\n'
if "${tracker_cmd[@]}" --emit jsonl /bin/sh -c 'exit 23' >"${tmp_root}/trace-exit.jsonl"; then
  workload_status=0
else
  workload_status=$?
fi
[[ "${workload_status}" -eq 23 ]] || fail "expected wrapped exit status 23, got ${workload_status}"
validate_jsonl "${tmp_root}/trace-exit.jsonl"
printf '[runtime-smoke] wrapped exit status 23 preserved\n'

if [[ "${run_perf_smoke}" -eq 1 ]]; then
  run_jsonl_smoke "perf" "${perf_output_file}" --transport perf
fi

if [[ "${run_demo_smoke}" -eq 1 ]]; then
  demo_output_file="${tmp_root}/trace-demo.jsonl"
  printf '[runtime-smoke] running traced Rust demo command (session-io-demo)\n'

  if ! "${tracker_cmd[@]}" demo --emit jsonl session-io-demo >"${demo_output_file}"; then
    fail "traced Rust demo command failed"
  fi

  validate_jsonl "${demo_output_file}" session-io-demo
fi

printf '[runtime-smoke] tracer path looks healthy\n'
