#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"

fail() {
  printf 'runtime isolation smoke: %s\n' "$1" >&2
  exit 1
}

tracker_cmd=()
if [[ -n "${EBPF_TRACKER_TEST_BINARY:-}" ]]; then
  tracker_binary="$(command -v "${EBPF_TRACKER_TEST_BINARY}")" || fail "test binary was not found: ${EBPF_TRACKER_TEST_BINARY}"
  [[ -x "${tracker_binary}" && ! -d "${tracker_binary}" ]] || fail "test binary is not executable: ${tracker_binary}"
  tracker_binary="$(cd -- "$(dirname -- "${tracker_binary}")" && pwd)/$(basename -- "${tracker_binary}")"
  tracker_cmd=("${tracker_binary}")
else
  cargo_binary="$(command -v cargo)" || fail "cargo is required"
  cargo_binary="$(cd -- "$(dirname -- "${cargo_binary}")" && pwd)/$(basename -- "${cargo_binary}")"
  tracker_cmd=("${cargo_binary}" run --manifest-path "${repo_root}/Cargo.toml" --locked --quiet --bin ebpf-tracker --)
fi
command -v docker >/dev/null 2>&1 || fail "docker is required"
docker info >/dev/null 2>&1 || fail "docker daemon is not available; start Docker and retry"

mkdir -p "${repo_root}/target"
tracked_root="$(mktemp -d "${repo_root}/target/ebpf-tracker-isolation.XXXXXX")"
outside_root="$(mktemp -d "${TMPDIR:-/tmp}/ebpf-tracker-outside.XXXXXX")"
output_file="${tracked_root}/trace.out"
stop_file="${outside_root}/stop"
noise_pid=""

cleanup() {
  touch "${stop_file}" 2>/dev/null || true
  if [[ -n "${noise_pid}" ]]; then
    wait "${noise_pid}" 2>/dev/null || true
  fi
  rm -rf "${tracked_root}" "${outside_root}"
}
trap cleanup EXIT INT TERM

ln -s /bin/sh "${tracked_root}/tracked-parent"
ln -s /bin/sh "${tracked_root}/tracked-child"
ln -s /bin/sh "${outside_root}/outside-noise"

(
  while [[ ! -e "${stop_file}" ]]; do
    "${outside_root}/outside-noise" -c 'exec /bin/true'
    sleep 0.01
  done
) &
noise_pid="$!"

tracked_relative="${tracked_root#"${repo_root}/"}"
cd "${repo_root}"
"${tracker_cmd[@]}" \
  --emit raw \
  "/workspace/${tracked_relative}/tracked-parent" \
  -c "exec /workspace/${tracked_relative}/tracked-child -c 'exec /bin/true'" \
  >"${output_file}"

touch "${stop_file}"
wait "${noise_pid}"
noise_pid=""

grep -Fq 'execve comm=tracked-parent' "${output_file}" \
  || fail "wrapped parent exec was not captured"
grep -Fq 'execve comm=tracked-child' "${output_file}" \
  || fail "wrapped descendant exec was not captured"

if grep -Fq 'execve comm=outside-noise' "${output_file}"; then
  fail "unrelated host exec leaked into the wrapped workload trace"
fi

printf 'runtime isolation smoke: wrapped descendants captured; unrelated host exec excluded\n'
