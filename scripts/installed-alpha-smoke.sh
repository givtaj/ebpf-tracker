#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"
source "${script_dir}/release-version.sh"
archive=""
expected_version=""

fail() { printf 'installed-alpha-smoke: %s\n' "$1" >&2; exit 1; }
usage() {
  echo 'Usage: bash scripts/installed-alpha-smoke.sh --archive <verified-linux.tar.gz> --expected-version <VERSION>'
  echo 'Run the verified Linux archive outside the checkout with fresh embedded assets.'
  echo 'Requires Linux, Docker/eBPF, Rust/Cargo, Node.js, Python 3, and GNU timeout.'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --archive|--expected-version)
      [[ $# -ge 2 ]] || fail "$1 requires a value"
      if [[ "$1" == --archive ]]; then archive="$2"; else expected_version="$2"; fi
      shift 2
      ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; fail "unknown option: $1" ;;
  esac
done

is_release_version "${expected_version}" || fail 'a valid --expected-version is required'
[[ -f "${archive}" ]] || fail 'a verified --archive is required'
archive_root="ebpf-tracker-v${expected_version}-x86_64-unknown-linux-gnu"
[[ "$(basename -- "${archive}")" == "${archive_root}.tar.gz" ]] || fail 'archive name does not match the expected Linux release'
archive="$(cd -- "$(dirname -- "${archive}")" && pwd)/$(basename -- "${archive}")"
[[ "$(uname -s)" == Linux ]] || fail 'the installed live gate requires Linux'
for prerequisite in docker cargo node python3 timeout tar; do
  command -v "${prerequisite}" >/dev/null 2>&1 || fail "${prerequisite} is required"
done
docker info >/dev/null 2>&1 || fail 'Docker daemon is unavailable'

tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/ebpf-tracker-installed-alpha.XXXXXX")"
trap 'rm -rf "${tmp_root}"' EXIT INT TERM
mkdir -p "${tmp_root}/install" "${tmp_root}/work" "${tmp_root}/node-app"
tar -xzf "${archive}" -C "${tmp_root}/install"
tracker="${tmp_root}/install/${archive_root}/ebpf-tracker"
[[ -x "${tracker}" ]] || fail 'archive lacks an executable tracker'
export EBPF_TRACKER_CACHE_DIR="${tmp_root}/cache"
export EBPF_TRACKER_INTERACTIVE_PTY=0
unset EBPF_TRACKER_COMPOSE_FILE EBPF_TRACKER_VIEWER_SCRIPT

run_capture() {
  local label="$1"
  local output="$2"
  shift 2
  if timeout --signal=TERM --kill-after=15s 1200s "$@" > "${output}" 2> "${tmp_root}/${label}.stderr"; then
    return
  else
    local status=$?
    tail -n 60 "${tmp_root}/${label}.stderr" >&2
    fail "${label} failed with status ${status}"
  fi
}

cd "${tmp_root}/work"
[[ "$("${tracker}" --version)" == "ebpf-tracker ${expected_version}" ]] || fail 'installed binary version mismatch'
"${tracker}" demo --list > "${tmp_root}/demos.txt"
grep -Fxq session-io-demo "${tmp_root}/demos.txt" || fail 'installed demo discovery failed'
[[ -f "${EBPF_TRACKER_CACHE_DIR}/demo-workspace-v${expected_version}/examples/session-io-demo/Cargo.toml" ]] || fail 'demo did not materialize embedded assets'
run_capture rust-demo "${tmp_root}/rust.jsonl" "${tracker}" demo --emit jsonl session-io-demo
[[ -f "${EBPF_TRACKER_CACHE_DIR}/runtime-v${expected_version}/docker-compose.bpftrace.yml" ]] || fail 'capture did not materialize embedded runtime assets'

cp "${repo_root}/ebpf-tracker.toml.example" "${tmp_root}/node-app/ebpf-tracker.toml"
printf 'installed alpha Node fixture\n' > "${tmp_root}/node-app/input.txt"
cat > "${tmp_root}/node-app/fixture.js" <<'JS'
const fs = require('fs');
fs.writeFileSync('output.txt', fs.readFileSync('input.txt'));
console.log('installed Node fixture completed');
JS
cd "${tmp_root}/node-app"
run_capture node-app "${tmp_root}/node.jsonl" "${tracker}" --runtime node --config ebpf-tracker.toml --emit jsonl node fixture.js
cmp input.txt output.txt || fail 'Node workload output did not match its input'

python3 - "${tmp_root}/rust.jsonl" "${tmp_root}/node.jsonl" <<'PY'
import json
import sys

for source, filename in zip(('rust', 'node'), sys.argv[1:]):
    with open(filename, encoding='utf-8') as stream:
        records = [json.loads(line) for line in stream]
    assert records and all(isinstance(record, dict) and record.get('type') in {'session', 'syscall', 'aggregate'} for record in records), f'{source}: invalid stream records'
    events = [record for record in records if record['type'] == 'syscall']
    kinds = {record.get('kind') for record in events}
    required = {'execve', 'open_at', 'write', 'connect'} if source == 'rust' else {'execve', 'open_at', 'write'}
    assert required <= kinds, f'{source}: missing event kinds {required - kinds}'
    comm = 'session-io-demo' if source == 'rust' else 'node'
    app_events = [record for record in events if record.get('comm') == comm]
    expected_file = 'input/message.txt' if source == 'rust' else 'input.txt'
    assert any(record.get('kind') == 'open_at' and record.get('file') == expected_file for record in app_events), f'{source}: missing application file access'
    assert any(record.get('kind') == 'write' for record in app_events), f'{source}: missing application write'
    if source == 'rust':
        assert any(record.get('type') == 'session' and record.get('demo_name') == 'session-io-demo' and record.get('product_name') == 'ebpf-tracker' for record in records), 'rust: missing demo metadata'
        assert any(record.get('kind') == 'connect' for record in app_events), 'rust: missing application connection'
    print(f'[installed-alpha-smoke] validated {source} capture: {len(records)} records')
PY

bash "${script_dir}/replay-smoke.sh" --tracker "${tracker}" --trace "${tmp_root}/rust.jsonl" --require-embedded
printf '[installed-alpha-smoke] PASS: Linux archive, embedded demo/runtime/viewer, Rust and Node capture, offline replay\n'
