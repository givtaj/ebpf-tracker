#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"

fail() {
  printf 'dataset smoke: %s\n' "$1" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage: bash scripts/dataset-smoke.sh

Validates the dataset ingest and analyze path against bundled replay fixtures
and a local mock OpenAI-compatible endpoint.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'dataset smoke: unknown option: %s\n' "$1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

command -v cargo >/dev/null 2>&1 || fail "cargo is required"
command -v python3 >/dev/null 2>&1 || fail "python3 is required"

replay_file="${repo_root}/crates/ebpf-tracker-viewer/demo-library/session-io-demo.jsonl"
[[ -f "${replay_file}" ]] || fail "bundled replay fixture not found at ${replay_file}"

tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/ebpf-tracker-dataset-smoke.XXXXXX")"
dataset_root="${tmp_root}/datasets"
dataset_run_dir="${dataset_root}/release-smoke"
server_state_file="${tmp_root}/server-port"
server_log_file="${tmp_root}/mock-openai.log"
analysis_dir="${dataset_run_dir}/analysis"

cleanup() {
  if [[ -n "${mock_server_pid:-}" ]] && kill -0 "${mock_server_pid}" >/dev/null 2>&1; then
    kill "${mock_server_pid}" >/dev/null 2>&1 || true
    wait "${mock_server_pid}" >/dev/null 2>&1 || true
  fi
  rm -rf "${tmp_root}"
}

trap cleanup EXIT INT TERM

cd "${repo_root}"

printf '[dataset-smoke] ingesting bundled replay fixture into %s\n' "${dataset_run_dir}"
if ! cargo dataset --replay "${replay_file}" --output "${dataset_root}" --run-id release-smoke --test-name release-smoke >"${tmp_root}/ingest.log"; then
  fail "dataset ingest failed"
fi

[[ -s "${dataset_run_dir}/run.json" ]] || fail "dataset run metadata was not written"
[[ -s "${dataset_run_dir}/events.jsonl" ]] || fail "dataset events were not written"

python3 -u - "${server_state_file}" >"${server_log_file}" 2>&1 <<'PY' &
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

state_path = sys.argv[1]


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", "0"))
        if content_length:
            _ = self.rfile.read(content_length)

        payload = {
            "choices": [
                {
                    "message": {
                        "content": "release smoke analysis"
                    }
                }
            ]
        }
        body = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


server = HTTPServer(("127.0.0.1", 0), Handler)
with open(state_path, "w", encoding="utf-8") as handle:
    handle.write(str(server.server_port))
    handle.flush()

server.serve_forever()
PY
mock_server_pid=$!

for _ in $(seq 1 100); do
  if [[ -s "${server_state_file}" ]]; then
    break
  fi
  if ! kill -0 "${mock_server_pid}" >/dev/null 2>&1; then
    fail "mock analysis server exited before reporting a port"
  fi
  sleep 0.1
done

mock_server_port="$(cat "${server_state_file}")"
printf '[dataset-smoke] analyzing dataset run via mock OpenAI-compatible endpoint on port %s\n' "${mock_server_port}"
if ! cargo dataset analyze --run "${dataset_run_dir}" --provider openai-compatible --endpoint "http://127.0.0.1:${mock_server_port}" --model smoke-model --live-logs >"${tmp_root}/analyze.log"; then
  fail "dataset analyze failed"
fi

analysis_markdown="${analysis_dir}/openai-compatible--smoke-model.md"
analysis_json="${analysis_dir}/openai-compatible--smoke-model.json"
analysis_live_log="${analysis_dir}/openai-compatible--smoke-model.live.log"

[[ -s "${analysis_markdown}" ]] || fail "analysis markdown was not written"
[[ -s "${analysis_json}" ]] || fail "analysis JSON was not written"
[[ -s "${analysis_live_log}" ]] || fail "analysis live log was not written"

grep -q 'release smoke analysis' "${analysis_markdown}" || fail "analysis markdown did not include the mock model response"
grep -q 'release smoke analysis' "${analysis_json}" || fail "analysis JSON did not include the mock model response"

printf '[dataset-smoke] dataset ingest and analyze path looks healthy\n'
