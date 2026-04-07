#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"
skip_exit_code="${EBPF_TRACKER_E2E_SKIP_EXIT_CODE:-42}"
strict_prereqs="${EBPF_TRACKER_E2E_STRICT_PREREQS:-0}"
fail_on_skip=0

fail() {
  printf 'customer-ux-check: FAIL: %s\n' "$1" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage: bash scripts/customer-ux-check.sh

Runs the customer UX end-to-end suite in this exact order:
1) scripts/customer-cli-e2e.sh
2) scripts/customer-viewer-e2e.sh
3) scripts/customer-data-e2e.sh

Default behavior:
- continues past `SKIP` (missing host capability) results
- fails on hard regressions

Options:
- --strict-prereqs  Treat missing host capabilities as failures (passes through to sub-scripts)
- --fail-on-skip    Return non-zero if any script exits with SKIP
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --strict-prereqs)
      strict_prereqs=1
      shift
      ;;
    --fail-on-skip)
      fail_on_skip=1
      shift
      ;;
    *)
      printf 'customer-ux-check: unknown option: %s\n' "$1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

scripts=(
  "scripts/customer-cli-e2e.sh"
  "scripts/customer-viewer-e2e.sh"
  "scripts/customer-data-e2e.sh"
)

for relative_path in "${scripts[@]}"; do
  absolute_path="${repo_root}/${relative_path}"
  [[ -f "${absolute_path}" ]] || fail "required script is missing: ${relative_path}"
done

started_at="$(date +%s)"
passed=()
skipped=()

for relative_path in "${scripts[@]}"; do
  printf '[customer-ux-check] running %s\n' "${relative_path}"
  if EBPF_TRACKER_E2E_STRICT_PREREQS="${strict_prereqs}" bash "${repo_root}/${relative_path}"; then
    passed+=("${relative_path}")
    continue
  else
    script_code=$?
    if [[ "${script_code}" -eq "${skip_exit_code}" ]]; then
      printf '[customer-ux-check] skip %s (exit=%s)\n' "${relative_path}" "${script_code}"
      skipped+=("${relative_path}")
      continue
    fi
    fail "script failed: ${relative_path} (exit=${script_code})"
  fi
done

ended_at="$(date +%s)"
elapsed="$((ended_at - started_at))"

result="pass"
if [[ "${#skipped[@]}" -gt 0 ]]; then
  result="pass_with_skips"
fi

printf '[customer-ux-check] RESULT=%s passed=%s skipped=%s duration=%ss\n' "${result}" "${#passed[@]}" "${#skipped[@]}" "${elapsed}"
if [[ "${#passed[@]}" -gt 0 ]]; then
  for relative_path in "${passed[@]}"; do
    printf '[customer-ux-check] ok %s\n' "${relative_path}"
  done
fi
if [[ "${#skipped[@]}" -gt 0 ]]; then
  for relative_path in "${skipped[@]}"; do
    printf '[customer-ux-check] skipped %s\n' "${relative_path}"
  done
fi

if [[ "${fail_on_skip}" -eq 1 ]] && [[ "${#skipped[@]}" -gt 0 ]]; then
  fail "one or more scripts were skipped and --fail-on-skip is enabled"
fi
