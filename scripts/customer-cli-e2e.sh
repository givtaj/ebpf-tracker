#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"
keep_artifacts=0
tracker_override=""
strict_prereqs="${EBPF_TRACKER_E2E_STRICT_PREREQS:-0}"
skip_exit_code="${EBPF_TRACKER_E2E_SKIP_EXIT_CODE:-42}"

usage() {
  cat <<'EOF'
Usage: bash scripts/customer-cli-e2e.sh [--tracker <path-or-command>] [--keep-artifacts]

Customer journey coverage:
- First run: ebpf-tracker /bin/true
- Trace your app: ebpf-tracker --emit jsonl --log-enable cargo run

Options:
- --tracker <path-or-command>  Override tracker command (default: ebpf-tracker on PATH,
                               then ./target/debug/ebpf-tracker, then cargo run --bin ebpf-tracker)
- --keep-artifacts             Keep temp artifacts instead of cleaning them up
- --strict-prereqs             Treat missing host capabilities as failures instead of skips
- -h, --help                   Show this help
EOF
}

fail() {
  printf 'customer-cli-e2e: FAIL: %s\n' "$1" >&2
  exit 1
}

skip() {
  printf 'customer-cli-e2e: SKIP: %s\n' "$1" >&2
  exit "${skip_exit_code}"
}

require_or_skip() {
  local message="$1"
  if [[ "${strict_prereqs}" == "1" ]]; then
    fail "${message}"
  fi
  skip "${message}"
}

info() {
  printf 'customer-cli-e2e: %s\n' "$1"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tracker)
      shift
      [[ $# -gt 0 ]] || fail "--tracker requires a value"
      tracker_override="$1"
      shift
      ;;
    --keep-artifacts)
      keep_artifacts=1
      shift
      ;;
    --strict-prereqs)
      strict_prereqs=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'customer-cli-e2e: unknown option: %s\n' "$1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

command -v docker >/dev/null 2>&1 || require_or_skip "docker is required"
docker info >/dev/null 2>&1 || require_or_skip "docker daemon is not available; start Docker and retry"
command -v cargo >/dev/null 2>&1 || require_or_skip "cargo is required"
[[ -x /bin/true ]] || require_or_skip "/bin/true is required"

tracker_cmd=()
if [[ -n "${tracker_override}" ]]; then
  tracker_cmd=("${tracker_override}")
elif command -v ebpf-tracker >/dev/null 2>&1; then
  tracker_cmd=("ebpf-tracker")
elif [[ -x "${repo_root}/target/debug/ebpf-tracker" ]]; then
  tracker_cmd=("${repo_root}/target/debug/ebpf-tracker")
else
  command -v cargo >/dev/null 2>&1 || require_or_skip "cargo is required to build ebpf-tracker fallback command"
  tracker_cmd=("cargo" "run" "--locked" "--quiet" "--bin" "ebpf-tracker" "--")
fi

tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/ebpf-tracker-customer-cli-e2e.XXXXXX")"
app_dir="${tmp_root}/customer-rust-app"
first_run_output="${tmp_root}/first-run.out"
trace_jsonl="${tmp_root}/trace-app.jsonl"
trace_stderr="${tmp_root}/trace-app.stderr"

cleanup() {
  if [[ "${keep_artifacts}" -eq 0 ]]; then
    rm -rf "${tmp_root}"
  else
    info "artifacts kept at ${tmp_root}"
  fi
}
trap cleanup EXIT INT TERM

run_tracker() {
  "${tracker_cmd[@]}" "$@"
}

assert_has_trace_signal() {
  local file="$1"
  if grep -Eq 'execve|"type":"syscall"|"kind":"exec"' "${file}"; then
    return 0
  fi
  fail "expected trace signal not found in ${file}"
}

info "using tracker command: ${tracker_cmd[*]}"

info "journey 1/2: first run (ebpf-tracker /bin/true)"
if ! run_tracker /bin/true >"${first_run_output}" 2>&1; then
  fail "first-run command failed"
fi

[[ -s "${first_run_output}" ]] || fail "first-run output is empty"
assert_has_trace_signal "${first_run_output}"
info "first-run path passed"

info "preparing a real Rust app to represent customer workload"
cargo init --name customer_rust_app --bin "${app_dir}" >/dev/null

info "journey 2/2: trace your app (cargo run in a real project)"
(
  cd "${app_dir}"
  if ! run_tracker --emit jsonl --log-enable cargo run >"${trace_jsonl}" 2>"${trace_stderr}"; then
    fail "trace-your-app command failed"
  fi
)

[[ -s "${trace_jsonl}" ]] || fail "trace-your-app JSONL stream is empty"
grep -q '"type":"syscall"' "${trace_jsonl}" || fail "trace-your-app did not emit syscall records"
assert_has_trace_signal "${trace_jsonl}"

logs_dir="${app_dir}/logs"
[[ -d "${logs_dir}" ]] || fail "trace-your-app did not create logs/ directory"
log_file_count="$(find "${logs_dir}" -maxdepth 1 -type f -name 'ebpf-tracker-*.log' | wc -l | tr -d '[:space:]')"
[[ "${log_file_count}" != "0" ]] || fail "trace-your-app did not produce any ebpf-tracker log artifact"

record_count="$(wc -l < "${trace_jsonl}" | tr -d '[:space:]')"
info "trace-your-app path passed (${record_count} JSONL records, ${log_file_count} log artifact(s))"

info "PASS: core customer CLI/runtime journey is healthy"
