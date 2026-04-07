#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"
strict_prereqs="${EBPF_TRACKER_E2E_STRICT_PREREQS:-0}"
skip_exit_code="${EBPF_TRACKER_E2E_SKIP_EXIT_CODE:-42}"
analyze_endpoint="${EBPF_TRACKER_CUSTOMER_DATA_ANALYZE_ENDPOINT:-}"
analyze_model="${EBPF_TRACKER_CUSTOMER_DATA_ANALYZE_MODEL:-customer-e2e-model}"
keep_artifacts=0

fail() {
  printf 'customer-data-e2e: FAIL: %s\n' "$1" >&2
  exit 1
}

skip() {
  printf 'customer-data-e2e: SKIP: %s\n' "$1" >&2
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
  printf 'customer-data-e2e: %s\n' "$1"
}

usage() {
  cat <<'EOF'
Usage: bash scripts/customer-data-e2e.sh [--analyze-endpoint <url>] [--analyze-model <name>] [--strict-prereqs] [--keep-artifacts]

Black-box customer journey check for dataset/intelligence:
- ingest replay data into a dataset bundle
- verify ingest artifacts exist (always)
- verify analyze artifacts via:
  1) `--analyze-endpoint` (OpenAI-compatible, no local mock server), or
  2) `scripts/dataset-smoke.sh` (local mock server path)

Environment overrides:
  EBPF_TRACKER_CUSTOMER_DATA_ANALYZE_ENDPOINT
  EBPF_TRACKER_CUSTOMER_DATA_ANALYZE_MODEL
  EBPF_TRACKER_E2E_STRICT_PREREQS=1
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --analyze-endpoint)
      shift
      [[ $# -gt 0 ]] || fail "--analyze-endpoint requires a value"
      analyze_endpoint="$1"
      shift
      ;;
    --analyze-model)
      shift
      [[ $# -gt 0 ]] || fail "--analyze-model requires a value"
      analyze_model="$1"
      shift
      ;;
    --strict-prereqs)
      strict_prereqs=1
      shift
      ;;
    --keep-artifacts)
      keep_artifacts=1
      shift
      ;;
    *)
      printf 'customer-data-e2e: unknown option: %s\n' "$1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

command -v cargo >/dev/null 2>&1 || require_or_skip "cargo is required"
replay_file="${repo_root}/crates/ebpf-tracker-viewer/demo-library/session-io-demo.jsonl"
[[ -f "${replay_file}" ]] || fail "bundled replay fixture not found at ${replay_file}"
if [[ -z "${analyze_endpoint}" ]]; then
  [[ -f "${repo_root}/scripts/dataset-smoke.sh" ]] || fail "missing required helper script: scripts/dataset-smoke.sh"
fi

tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/ebpf-tracker-customer-data-e2e.XXXXXX")"
dataset_root="${tmp_root}/datasets"
run_id="customer-data-e2e"
dataset_run_dir="${dataset_root}/${run_id}"

cleanup() {
  if [[ "${keep_artifacts}" -eq 0 ]]; then
    rm -rf "${tmp_root}"
  else
    info "artifacts kept at ${tmp_root}"
  fi
}

trap cleanup EXIT INT TERM

cd "${repo_root}"

info "ingesting replay fixture into dataset bundle"
if ! cargo dataset --replay "${replay_file}" --output "${dataset_root}" --run-id "${run_id}" --test-name customer-data-e2e >"${tmp_root}/ingest.log"; then
  fail "dataset ingest command failed"
fi

[[ -s "${dataset_run_dir}/run.json" ]] || fail "missing run metadata: ${dataset_run_dir}/run.json"
[[ -s "${dataset_run_dir}/events.jsonl" ]] || fail "missing event stream: ${dataset_run_dir}/events.jsonl"
[[ -s "${dataset_run_dir}/features.json" ]] || fail "missing derived features: ${dataset_run_dir}/features.json"

analysis_dir="${dataset_run_dir}/analysis"

if [[ -n "${analyze_endpoint}" ]]; then
  info "validating analyze path via external endpoint: ${analyze_endpoint}"
  if ! cargo dataset analyze --run "${dataset_run_dir}" --provider openai-compatible --endpoint "${analyze_endpoint}" --model "${analyze_model}" --live-logs >"${tmp_root}/analyze.log"; then
    fail "dataset analyze failed against external endpoint"
  fi
  shopt -s nullglob
  analysis_md=("${analysis_dir}"/*.md)
  analysis_json=("${analysis_dir}"/*.json)
  analysis_live=("${analysis_dir}"/*.live.log)
  shopt -u nullglob
  [[ "${#analysis_md[@]}" -gt 0 ]] || fail "analysis markdown output was not written"
  [[ "${#analysis_json[@]}" -gt 0 ]] || fail "analysis json output was not written"
  [[ "${#analysis_live[@]}" -gt 0 ]] || fail "analysis live log was not written"
  info "PASS run=${run_id} ingest=run.json,events.jsonl,features.json analyze=external-endpoint"
  exit 0
fi

info "validating analyze path via scripts/dataset-smoke.sh"
command -v python3 >/dev/null 2>&1 || require_or_skip "python3 is required for dataset-smoke analyze path"
# The dataset smoke path uses a local mock OpenAI-compatible HTTP server.
if ! python3 - <<'PY' >/dev/null 2>&1
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
s.close()
PY
then
  require_or_skip "local loopback TCP bind is unavailable; use --analyze-endpoint <url> or run on a host with 127.0.0.1 listener support"
fi

if ! bash "${repo_root}/scripts/dataset-smoke.sh" >"${tmp_root}/dataset-smoke.log"; then
  fail "dataset analyze smoke path failed"
fi

info "PASS run=${run_id} ingest=run.json,events.jsonl,features.json analyze=dataset-smoke"
