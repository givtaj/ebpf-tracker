#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VIEWER_SCRIPT="$ROOT_DIR/crates/ebpf-tracker-viewer/assets/live-trace-matrix.js"
DEMO_LIBRARY_DIR="$ROOT_DIR/crates/ebpf-tracker-viewer/demo-library"
HOST="${EBPF_TRACKER_VIEWER_HOST:-127.0.0.1}"
PORT="${EBPF_TRACKER_VIEWER_PORT:-43118}"
DEMO_NAME="session-io-demo"
OPEN_BROWSER=1
EXIT_AFTER_READY=0

if [[ ! -t 1 || "${CI:-}" == "true" ]]; then
  OPEN_BROWSER=0
fi

usage() {
  cat <<'EOF'
Usage: bash scripts/dashboard-smoke.sh [demo-name] [--port <port>] [--open|--no-open] [--check] [--list]

Deterministic viewer preview for frontend checks. Uses bundled replay fixtures so
the UI can be reviewed without tracing infrastructure, Docker, or a fresh log.

Examples:
  bash scripts/dashboard-smoke.sh
  bash scripts/dashboard-smoke.sh postcard-generator-node
  bash scripts/dashboard-smoke.sh --port 43119 --no-open
  bash scripts/dashboard-smoke.sh --check

Available demos:
  session-io-demo
  postcard-generator-rust
  postcard-generator-node
EOF
}

list_demos() {
  printf '%s\n' \
    "session-io-demo" \
    "postcard-generator-rust" \
    "postcard-generator-node"
}

fail() {
  printf 'dashboard smoke: %s\n' "$1" >&2
  exit 1
}

resolve_replay_file() {
  local demo_name="$1"
  local replay_file="$DEMO_LIBRARY_DIR/$demo_name.jsonl"
  [[ -f "$replay_file" ]] || fail "unknown demo '$demo_name' (use --list)"
  printf '%s\n' "$replay_file"
}

open_url() {
  local url="$1"
  if command -v open >/dev/null 2>&1; then
    open "$url" >/dev/null 2>&1 || true
    return
  fi
  if command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$url" >/dev/null 2>&1 || true
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --port)
      [[ $# -ge 2 ]] || fail "missing value for --port"
      PORT="$2"
      shift 2
      ;;
    --open)
      OPEN_BROWSER=1
      shift
      ;;
    --no-open)
      OPEN_BROWSER=0
      shift
      ;;
    --check)
      OPEN_BROWSER=0
      EXIT_AFTER_READY=1
      shift
      ;;
    --list)
      list_demos
      exit 0
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    -*)
      fail "unknown option '$1'"
      ;;
    *)
      if [[ "$DEMO_NAME" != "session-io-demo" ]]; then
        fail "only one demo name can be provided"
      fi
      DEMO_NAME="$1"
      shift
      ;;
  esac
done

command -v node >/dev/null 2>&1 || fail "node is required to preview the dashboard"
command -v curl >/dev/null 2>&1 || fail "curl is required to detect viewer readiness"
[[ -f "$VIEWER_SCRIPT" ]] || fail "viewer script not found at $VIEWER_SCRIPT"

REPLAY_FILE="$(resolve_replay_file "$DEMO_NAME")"
URL="http://$HOST:$PORT"

printf 'dashboard smoke: replay=%s\n' "$DEMO_NAME"
printf 'dashboard smoke: source=%s\n' "$REPLAY_FILE"
printf 'dashboard smoke: waiting for %s\n' "$URL"

node "$VIEWER_SCRIPT" --host "$HOST" --port "$PORT" --replay "$REPLAY_FILE" &
VIEWER_PID=$!

cleanup() {
  if kill -0 "$VIEWER_PID" >/dev/null 2>&1; then
    kill "$VIEWER_PID" >/dev/null 2>&1 || true
    wait "$VIEWER_PID" >/dev/null 2>&1 || true
  fi
}

trap cleanup EXIT INT TERM

for _ in $(seq 1 100); do
  if curl -fsS "$URL/snapshot" >/dev/null 2>&1; then
    printf 'dashboard smoke: ready at %s\n' "$URL"
    if [[ "$OPEN_BROWSER" -eq 1 ]]; then
      open_url "$URL"
    fi
    if [[ "$EXIT_AFTER_READY" -eq 1 ]]; then
      exit 0
    fi
    wait "$VIEWER_PID"
    exit $?
  fi

  if ! kill -0 "$VIEWER_PID" >/dev/null 2>&1; then
    wait "$VIEWER_PID"
    exit $?
  fi

  sleep 0.2
done

fail "viewer did not become ready within 20 seconds"
