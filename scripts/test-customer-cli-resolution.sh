#!/usr/bin/env bash
set -euo pipefail

# Regression checks for command resolution only. Stubs deliberately avoid Docker
# and tracing; a pass here is not evidence of a working eBPF runtime.
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/ebpf-tracker-cli-resolution.XXXXXX")"
tmp_root="$(cd -- "${tmp_root}" && pwd)"
trap 'rm -rf "${tmp_root}"' EXIT INT TERM

fixture_repo="${tmp_root}/fixture repo"
caller_dir="${tmp_root}/caller"
mkdir -p "${fixture_repo}/scripts" "${caller_dir}/bin"
cp "${script_dir}/customer-cli-e2e.sh" "${fixture_repo}/scripts/"
touch "${fixture_repo}/Cargo.toml"
export FIXTURE_MANIFEST="${fixture_repo}/Cargo.toml"
export FIXTURE_TRACKER="${tmp_root}/tracker"
export FIXTURE_CALLS="${tmp_root}/calls"

cat > "${caller_dir}/bin/docker" <<'EOF'
#!/bin/bash
[[ "$1" == info ]]
EOF

cat > "${caller_dir}/bin/cargo" <<'EOF'
#!/bin/bash
set -euo pipefail
case "$1" in
  init)
    app_dir="${@: -1}"
    mkdir -p "${app_dir}"
    touch "${app_dir}/Cargo.toml"
    ;;
  run)
    shift
    [[ "$1" == --manifest-path && "$2" == "${FIXTURE_MANIFEST}" ]] || {
      echo 'wrong Cargo manifest after changing working directory' >&2
      exit 21
    }
    while [[ "$1" != -- ]]; do shift; done
    shift
    exec "${FIXTURE_TRACKER}" "$@"
    ;;
  *) exit 22 ;;
esac
EOF

cat > "${FIXTURE_TRACKER}" <<'EOF'
#!/bin/bash
set -euo pipefail
printf '%s\n' "${PWD}" >> "${FIXTURE_CALLS}"
if [[ "$1" == /bin/true ]]; then
  printf 'execve comm=fixture pid=123\n'
elif [[ "$*" == '--emit jsonl --log-enable cargo run' ]]; then
  [[ -f Cargo.toml && "${PWD}" == */customer-rust-app ]]
  if [[ "${FIXTURE_FAIL:-0}" == 1 ]]; then
    printf 'fixture trace diagnostic\n' >&2
    exit 23
  fi
  mkdir -p logs
  printf 'execve fixture\n' > logs/ebpf-tracker-fixture.log
  printf '{"type":"syscall","kind":"execve","pid":123}\n'
else
  exit 24
fi
EOF

chmod +x "${caller_dir}/bin/docker" "${caller_dir}/bin/cargo" "${FIXTURE_TRACKER}"
cp "${FIXTURE_TRACKER}" "${caller_dir}/bin/custom-tracker"

run_case() {
  local label="$1"
  shift
  : > "${FIXTURE_CALLS}"
  (
    cd "${caller_dir}"
    # A relative PATH also verifies that Cargo itself remains resolvable after cd.
    PATH="bin:/usr/bin:/bin" /bin/bash "${fixture_repo}/scripts/customer-cli-e2e.sh" --strict-prereqs "$@"
  ) > "${tmp_root}/output" 2>&1 || {
    cat "${tmp_root}/output" >&2
    printf 'test-customer-cli-resolution: FAIL: %s\n' "${label}" >&2
    exit 1
  }
  [[ "$(wc -l < "${FIXTURE_CALLS}" | tr -d '[:space:]')" == 2 ]]
  grep -Fx "${caller_dir}" "${FIXTURE_CALLS}" >/dev/null
  tail -n 1 "${FIXTURE_CALLS}" | grep -E '/customer-rust-app$' >/dev/null
  printf 'test-customer-cli-resolution: PASS: %s\n' "${label}"
}

run_case 'Cargo fallback pins the repository manifest across cwd changes'
run_case 'relative tracker override survives cwd changes' --tracker ./bin/custom-tracker
cp "${FIXTURE_TRACKER}" "${caller_dir}/bin/ebpf-tracker"
run_case 'tracker found through relative PATH survives cwd changes'

if (
  cd "${caller_dir}"
  FIXTURE_FAIL=1 PATH="bin:/usr/bin:/bin" /bin/bash "${fixture_repo}/scripts/customer-cli-e2e.sh" --strict-prereqs
) > "${tmp_root}/failure" 2>&1; then
  printf 'test-customer-cli-resolution: FAIL: failing tracer was accepted\n' >&2
  exit 1
fi
grep -F 'fixture trace diagnostic' "${tmp_root}/failure" >/dev/null
grep -F 'trace-your-app command failed' "${tmp_root}/failure" >/dev/null
printf 'test-customer-cli-resolution: PASS: tracer failures retain diagnostics\n'
