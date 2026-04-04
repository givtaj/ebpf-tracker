#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"

fail() {
  printf 'attach smoke: %s\n' "$1" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage: bash scripts/attach-smoke.sh

Validates the scaffolded attach CLI path without starting real tracing.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'attach smoke: unknown option: %s\n' "$1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

command -v cargo >/dev/null 2>&1 || fail "cargo is required"

tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/ebpf-tracker-attach-smoke.XXXXXX")"
valid_output_file="${tmp_root}/attach-valid.txt"
invalid_output_file="${tmp_root}/attach-invalid.txt"

cleanup() {
  rm -rf "${tmp_root}"
}

trap cleanup EXIT INT TERM

cd "${repo_root}"

printf '[attach-smoke] validating scaffolded docker attach plan\n'
if ! cargo run --locked --quiet --bin eBPF_tracker -- attach docker --container runtime-smoke-demo >"${valid_output_file}"; then
  fail "scaffolded docker attach plan failed"
fi

grep -q '^attach scaffold$' "${valid_output_file}" || fail "attach scaffold header missing"
grep -q '^status: experimental scaffold/plan mode; no live backend execution yet$' "${valid_output_file}" || fail "attach scaffold status missing"
grep -q '^this command prints a plan only and does not start tracing yet$' "${valid_output_file}" || fail "attach plan-only note missing"
grep -q '^platform: docker$' "${valid_output_file}" || fail "attach platform missing"
grep -q '^backend: inspektor-gadget$' "${valid_output_file}" || fail "attach backend missing"
grep -q '^target: container runtime-smoke-demo$' "${valid_output_file}" || fail "attach target missing"

printf '[attach-smoke] validating attach rejection path\n'
if cargo run --locked --quiet --bin eBPF_tracker -- attach docker --backend tetragon --container runtime-smoke-demo >"${invalid_output_file}" 2>&1; then
  fail "invalid docker+tetragon attach unexpectedly succeeded"
fi

grep -q 'docker attach currently only scaffolds the inspektor-gadget backend' "${invalid_output_file}" || fail "attach rejection message missing"

printf '[attach-smoke] attach validation path looks healthy\n'
