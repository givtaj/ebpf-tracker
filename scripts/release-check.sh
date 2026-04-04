#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"
run_runtime_smoke=0
run_perf_smoke=0
run_attach_smoke=0

usage() {
  cat <<'EOF'
Usage: bash scripts/release-check.sh [--with-runtime-smoke] [--with-perf-smoke] [--with-attach-smoke]

Default behavior runs the fast generic release checks that are suitable for
GitHub-hosted CI.

Use --with-runtime-smoke on a maintainer machine to also run the Docker-backed
tracing smoke path.

Use --with-perf-smoke to additionally exercise the perf transport path during
runtime smoke.

Use --with-attach-smoke to run the lightweight attach validation smoke.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --with-runtime-smoke)
      run_runtime_smoke=1
      shift
      ;;
    --with-perf-smoke)
      run_runtime_smoke=1
      run_perf_smoke=1
      shift
      ;;
    --with-attach-smoke)
      run_attach_smoke=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'release-check: unknown option: %s\n' "$1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

cd "${repo_root}"

echo "[release-check] cargo fmt --all --check"
cargo fmt --all --check

echo "[release-check] cargo test --all --locked"
cargo test --all --locked

echo "[release-check] cargo build --workspace --locked"
cargo build --workspace --locked

echo "[release-check] cargo build --release --locked --bin ebpf-tracker"
cargo build --release --locked --bin ebpf-tracker

echo "[release-check] cargo run --locked --bin ebpf-tracker -- --help"
cargo run --locked --bin ebpf-tracker -- --help

echo "[release-check] cargo run --locked --bin ebpf-tracker -- demo --list"
cargo run --locked --bin ebpf-tracker -- demo --list

if [[ "${run_runtime_smoke}" -eq 1 ]]; then
  echo "[release-check] bash scripts/runtime-smoke.sh"
  if [[ "${run_perf_smoke}" -eq 1 ]]; then
    bash scripts/runtime-smoke.sh --with-perf-smoke
  else
    bash scripts/runtime-smoke.sh
  fi
else
  echo "[release-check] runtime smoke skipped; run bash scripts/release-check.sh --with-runtime-smoke before tagging on a Docker-capable maintainer machine"
fi

if [[ "${run_attach_smoke}" -eq 1 ]]; then
  echo "[release-check] bash scripts/attach-smoke.sh"
  bash scripts/attach-smoke.sh
else
  echo "[release-check] attach smoke skipped; run bash scripts/release-check.sh --with-attach-smoke to validate the scaffolded attach path"
fi
