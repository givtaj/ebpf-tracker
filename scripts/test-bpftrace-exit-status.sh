#!/usr/bin/env bash
set -euo pipefail

# Exercise the real supervisor and wrapper without eBPF or Docker. The fake
# bpftrace intentionally swallows child exit status like Bookworm bpftrace 0.17.
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/ebpf-tracker-exit-status.XXXXXX")"
trap 'rm -rf "${tmp_root}"' EXIT INT TERM
mkdir -p "${tmp_root}/bin" "${tmp_root}/handoffs"
rustc "${script_dir}/exec-target-from-env.rs" -o "${tmp_root}/exec-target-from-env"
rustc --test "${script_dir}/exec-target-from-env.rs" -o "${tmp_root}/helper-tests"
"${tmp_root}/helper-tests"

cat > "${tmp_root}/bin/mount" <<'EOF'
#!/bin/sh
exit 0
EOF
cat > "${tmp_root}/bin/bpftrace" <<'EOF'
#!/bin/sh
[ "$2" = -c ] && [ "$3" = /usr/local/bin/exec-target-from-env ] || exit 91
case "${FIXTURE_TRACER_MODE:-run}" in
  no-status) exit 0 ;;
  invalid-status) printf 'invalid\n' > "${EBPF_TRACKER_STATUS_FILE}"; exit 0 ;;
  out-of-range-status) printf '256\n' > "${EBPF_TRACKER_STATUS_FILE}"; exit 0 ;;
  tracer-failure) exit 41 ;;
esac
"${FIXTURE_HELPER}"
# Deliberately ignore the supervisor's exit status.
if [ "${FIXTURE_TRACER_MODE:-run}" = after-failure ]; then exit 42; fi
exit 0
EOF
cat > "${tmp_root}/argument-check" <<'EOF'
#!/bin/bash
[[ "$#" -eq 4 && "$1" == '' && "$2" == 'two words' && "$3" == "single'quote" && "$4" == '$(exit 77)' ]]
EOF
chmod +x "${tmp_root}/bin/mount" "${tmp_root}/bin/bpftrace"
touch "${tmp_root}/probe.bt"
export FIXTURE_HELPER="${tmp_root}/exec-target-from-env"
export EBPF_TRACKER_PROBE="${tmp_root}/probe.bt"
export EBPF_TRACKER_ALLOW_HOST_WIDE_PROBE=1
export EBPF_TRACKER_TRANSPORT=bpftrace
export EBPF_TRACKER_INTERACTIVE_PTY=0
export PATH="${tmp_root}/bin:${PATH}"
export TMPDIR="${tmp_root}/handoffs"

run_case() {
  local name="$1" expected="$2" mode="$3" actual
  shift 3
  if FIXTURE_TRACER_MODE="${mode}" bash "${script_dir}/run-bpftrace-wrap.sh" "$@" >"${tmp_root}/stdout" 2>"${tmp_root}/stderr"; then
    actual=0
  else
    actual=$?
  fi
  if [[ "${actual}" -ne "${expected}" ]]; then
    cat "${tmp_root}/stderr" >&2
    printf 'test-bpftrace-exit-status: FAIL: %s expected %s, got %s\n' "${name}" "${expected}" "${actual}" >&2
    exit 1
  fi
  [[ -z "$(find "${TMPDIR}" -mindepth 1 -maxdepth 1 -print)" ]] || {
    printf 'test-bpftrace-exit-status: FAIL: status handoff was not cleaned up\n' >&2
    exit 1
  }
  printf 'test-bpftrace-exit-status: PASS: %s\n' "${name}"
}

run_case 'success' 0 run /bin/sh -c 'exit 0'
run_case 'nonzero workload status' 23 run /bin/sh -c 'exit 23'
run_case 'missing executable' 127 run "${tmp_root}/does-not-exist"
run_case 'terminated workload' 143 run /bin/sh -c 'kill -TERM $$'
run_case 'tracer failure before workload' 41 tracer-failure /bin/sh -c 'exit 0'
run_case 'tracer failure takes precedence' 42 after-failure /bin/sh -c 'exit 23'
run_case 'missing status fails closed' 125 no-status /bin/sh -c 'exit 0'
run_case 'invalid status fails closed' 125 invalid-status /bin/sh -c 'exit 0'
run_case 'out-of-range status fails closed' 125 out-of-range-status /bin/sh -c 'exit 0'
run_case 'status handoff is absent from workload environment' 0 run /bin/sh -c 'test "${EBPF_TRACKER_STATUS_FILE+set}" != set'
run_case 'argument boundaries and literals survive' 0 run /bin/bash "${tmp_root}/argument-check" '' 'two words' "single'quote" '$(exit 77)'

if script --version 2>/dev/null | grep -q 'util-linux'; then
  EBPF_TRACKER_INTERACTIVE_PTY=1 run_case 'PTY workload status' 23 run /bin/sh -c 'exit 23'
else
  printf 'test-bpftrace-exit-status: PTY integration not run (requires Linux util-linux script); quoting unit test passed\n'
fi
