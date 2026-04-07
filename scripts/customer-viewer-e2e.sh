#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"

live_port="${EBPF_TRACKER_VIEWER_E2E_LIVE_PORT:-43215}"
replay_port="${EBPF_TRACKER_VIEWER_E2E_REPLAY_PORT:-43216}"
demo_name="${EBPF_TRACKER_VIEWER_E2E_DEMO:-session-io-demo}"
timeout_seconds="${EBPF_TRACKER_VIEWER_E2E_TIMEOUT_SECONDS:-180}"
host="127.0.0.1"
strict_prereqs="${EBPF_TRACKER_E2E_STRICT_PREREQS:-0}"
skip_exit_code="${EBPF_TRACKER_E2E_SKIP_EXIT_CODE:-42}"

live_pid=""
replay_pid=""
tmp_root=""

fail() {
  printf 'customer-viewer-e2e: FAIL: %s\n' "$1" >&2
  exit 1
}

skip() {
  printf 'customer-viewer-e2e: SKIP: %s\n' "$1" >&2
  exit "${skip_exit_code}"
}

require_or_skip() {
  local message="$1"
  if [[ "${strict_prereqs}" == "1" ]]; then
    fail "${message}"
  fi
  skip "${message}"
}

usage() {
  cat <<'EOF'
Usage: bash scripts/customer-viewer-e2e.sh [--demo <name>] [--live-port <port>] [--replay-port <port>] [--timeout-seconds <n>] [--strict-prereqs]

Customer-facing end-to-end checks for product-first UX:
1) `ebpf-tracker see` launches the demo viewer and becomes reachable.
2) Replay mode becomes reachable and reports replay snapshot state.

Environment overrides:
  EBPF_TRACKER_VIEWER_E2E_DEMO
  EBPF_TRACKER_VIEWER_E2E_LIVE_PORT
  EBPF_TRACKER_VIEWER_E2E_REPLAY_PORT
  EBPF_TRACKER_VIEWER_E2E_TIMEOUT_SECONDS
  EBPF_TRACKER_E2E_STRICT_PREREQS=1
EOF
}

show_log_tail() {
  local label="$1"
  local file="$2"
  if [[ -f "$file" ]]; then
    printf '--- %s (tail) ---\n' "$label" >&2
    tail -n 40 "$file" >&2 || true
  fi
}

cleanup() {
  if [[ -n "${live_pid}" ]] && kill -0 "${live_pid}" >/dev/null 2>&1; then
    kill "${live_pid}" >/dev/null 2>&1 || true
    wait "${live_pid}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${replay_pid}" ]] && kill -0 "${replay_pid}" >/dev/null 2>&1; then
    kill "${replay_pid}" >/dev/null 2>&1 || true
    wait "${replay_pid}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${tmp_root}" ]] && [[ -d "${tmp_root}" ]]; then
    rm -rf "${tmp_root}"
  fi
}

wait_for_snapshot() {
  local mode_label="$1"
  local url="$2"
  local pid="$3"
  local log_file="$4"
  local attempts=$((timeout_seconds * 5))
  local snapshot=""

  for _ in $(seq 1 "${attempts}"); do
    if snapshot="$(curl -fsS "${url}/snapshot" 2>/dev/null)"; then
      printf '%s\n' "${snapshot}"
      return 0
    fi

    if ! kill -0 "${pid}" >/dev/null 2>&1; then
      wait "${pid}" || true
      show_log_tail "${mode_label}" "${log_file}"
      fail "${mode_label} process exited before viewer became reachable at ${url}"
    fi
    sleep 0.2
  done

  show_log_tail "${mode_label}" "${log_file}"
  fail "${mode_label} viewer did not become reachable within ${timeout_seconds}s (${url})"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --demo)
      [[ $# -ge 2 ]] || fail "missing value for --demo"
      demo_name="$2"
      shift 2
      ;;
    --live-port)
      [[ $# -ge 2 ]] || fail "missing value for --live-port"
      live_port="$2"
      shift 2
      ;;
    --replay-port)
      [[ $# -ge 2 ]] || fail "missing value for --replay-port"
      replay_port="$2"
      shift 2
      ;;
    --timeout-seconds)
      [[ $# -ge 2 ]] || fail "missing value for --timeout-seconds"
      timeout_seconds="$2"
      shift 2
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
      fail "unknown option: $1"
      ;;
  esac
done

[[ "${live_port}" =~ ^[0-9]+$ ]] || fail "--live-port must be numeric"
[[ "${replay_port}" =~ ^[0-9]+$ ]] || fail "--replay-port must be numeric"
[[ "${timeout_seconds}" =~ ^[0-9]+$ ]] || fail "--timeout-seconds must be numeric"

command -v curl >/dev/null 2>&1 || require_or_skip "curl is required"
command -v docker >/dev/null 2>&1 || require_or_skip "docker is required for the live demo path"
docker info >/dev/null 2>&1 || require_or_skip "docker daemon is not available; start Docker and retry"
[[ -f "${repo_root}/scripts/dashboard-smoke.sh" ]] || fail "scripts/dashboard-smoke.sh not found"

tracker_cmd=()
if command -v ebpf-tracker >/dev/null 2>&1; then
  tracker_cmd=(ebpf-tracker)
else
  command -v cargo >/dev/null 2>&1 || require_or_skip "either ebpf-tracker or cargo is required"
  tracker_cmd=(cargo run --locked --quiet --bin ebpf-tracker --)
fi

tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/ebpf-tracker-customer-viewer-e2e.XXXXXX")"
trap cleanup EXIT INT TERM

shim_dir="${tmp_root}/bin"
mkdir -p "${shim_dir}"

# Keep E2E checks non-interactive by shadowing browser launch commands.
printf '#!/usr/bin/env bash\nexit 1\n' >"${shim_dir}/open"
printf '#!/usr/bin/env bash\nexit 1\n' >"${shim_dir}/xdg-open"
chmod +x "${shim_dir}/open" "${shim_dir}/xdg-open"
export PATH="${shim_dir}:${PATH}"

live_log="${tmp_root}/live-see.log"
replay_log="${tmp_root}/replay.log"

live_url="http://${host}:${live_port}"
replay_url="http://${host}:${replay_port}"

printf '[customer-viewer-e2e] launching product demo via `see` on %s\n' "${live_url}"
(
  cd "${repo_root}"
  "${tracker_cmd[@]}" see --port "${live_port}" "${demo_name}"
) >"${live_log}" 2>&1 &
live_pid=$!

live_snapshot="$(wait_for_snapshot "live-see" "${live_url}" "${live_pid}" "${live_log}")"
if [[ "${live_snapshot}" != *'"mode":"live"'* ]]; then
  show_log_tail "live-see" "${live_log}"
  fail "live snapshot did not report mode=live"
fi
if ! grep -q "live trace viewer on ${live_url}" "${live_log}"; then
  show_log_tail "live-see" "${live_log}"
  fail "live viewer did not emit expected ready message"
fi
if [[ "${live_snapshot}" != *'"command"'* ]]; then
  show_log_tail "live-see" "${live_log}"
  fail "live snapshot did not include command metadata"
fi

kill "${live_pid}" >/dev/null 2>&1 || true
wait "${live_pid}" >/dev/null 2>&1 || true
live_pid=""

printf '[customer-viewer-e2e] launching replay UX via dashboard-smoke on %s\n' "${replay_url}"
(
  cd "${repo_root}"
  bash scripts/dashboard-smoke.sh "${demo_name}" --port "${replay_port}" --no-open
) >"${replay_log}" 2>&1 &
replay_pid=$!

replay_snapshot="$(wait_for_snapshot "replay" "${replay_url}" "${replay_pid}" "${replay_log}")"
if [[ "${replay_snapshot}" != *'"mode":"replay"'* ]]; then
  show_log_tail "replay" "${replay_log}"
  fail "replay snapshot did not report mode=replay"
fi
if [[ "${replay_snapshot}" != *"${demo_name}"* ]]; then
  show_log_tail "replay" "${replay_log}"
  fail "replay snapshot did not include expected demo identifier (${demo_name})"
fi
if ! grep -q "dashboard smoke: ready at ${replay_url}" "${replay_log}"; then
  show_log_tail "replay" "${replay_log}"
  fail "replay flow did not emit expected readiness message"
fi

kill "${replay_pid}" >/dev/null 2>&1 || true
wait "${replay_pid}" >/dev/null 2>&1 || true
replay_pid=""

printf '[customer-viewer-e2e] PASS: live demo launch, viewer readiness, and replay UX look healthy\n'
