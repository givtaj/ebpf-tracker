#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"
run_perf_smoke=0

fail() {
  printf 'runtime smoke: %s\n' "$1" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage: bash scripts/runtime-smoke.sh [--with-perf-smoke]

The default path runs the standard bpftrace-backed JSONL smoke.
Use --with-perf-smoke to additionally exercise the perf transport path.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --with-perf-smoke)
      run_perf_smoke=1
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

command -v cargo >/dev/null 2>&1 || fail "cargo is required"
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

run_jsonl_smoke() {
  local label="$1"
  local output_file="$2"
  shift 2

  printf '[runtime-smoke] running minimal traced session with /bin/true (%s)\n' "${label}"

  if ! cargo run --locked --quiet --bin ebpf-tracker -- "$@" --emit jsonl /bin/true >"${output_file}"; then
    fail "minimal traced session failed for ${label}"
  fi

  if [[ ! -s "${output_file}" ]]; then
    fail "no JSONL records were emitted for ${label}"
  fi

  if ! grep -q '"type":"syscall"' "${output_file}"; then
    fail "smoke run completed but did not emit syscall records for ${label}"
  fi

  record_count="$(wc -l < "${output_file}" | tr -d '[:space:]')"
  printf '[runtime-smoke] captured %s JSONL record(s) for %s\n' "${record_count}" "${label}"
}

run_jsonl_smoke "bpftrace" "${default_output_file}"

if [[ "${run_perf_smoke}" -eq 1 ]]; then
  run_jsonl_smoke "perf" "${perf_output_file}" --transport perf
fi

printf '[runtime-smoke] tracer path looks healthy\n'
