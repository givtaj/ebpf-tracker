#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"
fixture_dir="${repo_root}/examples/axum-container"
package=""
output_dir=""

fail() { printf 'in-container smoke: FAIL: %s\n' "$1" >&2; exit 1; }
usage() {
  cat <<'EOF'
Usage: bash scripts/in-container-smoke.sh --package <runtime.deb> [--output-dir <evidence>]

Installs the actual package in an isolated Bookworm Axum app container and
checks HTTP/PostgreSQL activity, tracing, app privilege drop, shutdown, exit
status and scope. Requires a trusted Linux Docker host with privileged and
host-PID containers. No existing workloads or Docker cache are removed.
Evidence is retained; --deb is an alias for --package.
EOF
}
while [[ $# -gt 0 ]]; do
  case "$1" in
    --package|--deb) [[ $# -ge 2 ]] || fail "$1 requires a value"; package="$2"; shift 2 ;;
    --output-dir) [[ $# -ge 2 ]] || fail "$1 requires a value"; output_dir="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown argument: $1" ;;
  esac
done
[[ -f "${package}" ]] || fail "--package must name an existing .deb"
for command_name in docker python3 curl; do command -v "${command_name}" >/dev/null || fail "${command_name} is required"; done
docker info >/dev/null 2>&1 || fail "Docker is unavailable"
docker compose version >/dev/null || fail "Docker Compose is required"
package="$(cd -- "$(dirname -- "${package}")" && pwd)/$(basename -- "${package}")"
if [[ -z "${output_dir}" ]]; then
  output_dir="$(mktemp -d "${TMPDIR:-/tmp}/ebpf-container-evidence.XXXXXX")"
else
  [[ ! -e "${output_dir}" ]] || fail "output directory already exists; choose a fresh evidence directory"
  mkdir -p "${output_dir}"
fi
output_dir="$(cd -- "${output_dir}" && pwd)"
context_dir="$(mktemp -d "${TMPDIR:-/tmp}/ebpf-container-context.XXXXXX")"
project="ebpf-alpha-$(date +%s)-$$"
export FIXTURE_CONTEXT="${context_dir}" FIXTURE_OUTPUT="${output_dir}" FIXTURE_IMAGE="${project}:fixture"
compose=(docker compose -p "${project}" -f "${fixture_dir}/compose.yaml")
host_noise_pid=""
app_id=""

cleanup() {
  result=$?
  trap - EXIT INT TERM
  if [[ -n "${host_noise_pid}" ]]; then
    touch "${output_dir}/stop-host-noise"
    wait "${host_noise_pid}" 2>/dev/null || true
  fi
  if [[ -n "${app_id}" ]]; then
    docker stop --time 15 "${app_id}" >/dev/null 2>&1 || true
    docker logs "${app_id}" >"${output_dir}/app.stdout.log" 2>"${output_dir}/app.stderr.log" || true
    docker cp "${app_id}:/traces/events.jsonl" "${output_dir}/events.jsonl" >/dev/null 2>&1 || true
  fi
  for name in exit23 missing-command missing-permission nonroot-agent existing-output; do
    docker rm -f "${project}-${name}" >/dev/null 2>&1 || true
  done
  "${compose[@]}" logs --no-color >"${output_dir}/compose.log" 2>&1 || true
  "${compose[@]}" down --volumes --remove-orphans >"${output_dir}/cleanup.log" 2>&1 || true
  rm -rf "${context_dir}"
  printf 'in-container smoke: evidence retained at %s\n' "${output_dir}"
  exit "${result}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

uname -a >"${output_dir}/host-uname.txt"
docker info --format '{{.KernelVersion}}' >"${output_dir}/docker-kernel.txt"
cp "${fixture_dir}/Cargo.toml" "${fixture_dir}/Cargo.lock" "${fixture_dir}/Dockerfile" "${context_dir}/"
cp -R "${fixture_dir}/src" "${context_dir}/src"
cp "${package}" "${context_dir}/runtime.deb"
mkdir -p "${output_dir}/data" "${output_dir}/traces"
# Disposable synthetic-data bind mounts must be writable by UID 10001.
chmod 0777 "${output_dir}/data" "${output_dir}/traces"
printf 'in-container smoke: building fixture with %s\n' "$(basename -- "${package}")"
"${compose[@]}" build app >"${output_dir}/build.log" 2>&1 || { tail -n 80 "${output_dir}/build.log" >&2; fail "fixture build failed"; }
docker image inspect "${FIXTURE_IMAGE}" --format '{{.Os}}/{{.Architecture}} {{.Id}}' >"${output_dir}/image.txt"
docker run --rm --entrypoint /usr/bin/dpkg-query "${FIXTURE_IMAGE}" -W ebpf-tracker-runtime >"${output_dir}/package.txt"
docker run --rm --entrypoint /usr/bin/ebpf-tracker-agent "${FIXTURE_IMAGE}" --version >"${output_dir}/agent-version.txt"
docker run --rm --entrypoint /usr/bin/uname "${FIXTURE_IMAGE}" -a >"${output_dir}/container-uname.txt"
if docker run --rm --privileged --pid host --entrypoint /usr/bin/bpftrace "${FIXTURE_IMAGE}" --info >"${output_dir}/bpftrace-info.txt" 2>&1; then
  printf '0\n' >"${output_dir}/bpftrace-info-exit-code.txt"
else
  printf '%s\n' "$?" >"${output_dir}/bpftrace-info-exit-code.txt"
fi
"${compose[@]}" up -d postgres noise app
app_id="$("${compose[@]}" ps -q app)"
[[ -n "${app_id}" ]] || fail "app container was not created"
endpoint="$("${compose[@]}" port app 8080)"
[[ "${endpoint}" == 127.0.0.1:* ]] || fail "expected loopback-only HTTP binding, got ${endpoint}"

if [[ "$(uname -s)" == Linux ]]; then
  ln -s /bin/sh "${output_dir}/host-noise"
  (
    while [[ ! -e "${output_dir}/stop-host-noise" ]]; do
      "${output_dir}/host-noise" -c 'printf unrelated > "$1"' _ "${output_dir}/host-noise-marker"
      sleep 0.05
    done
  ) &
  host_noise_pid=$!
fi

ready=0
for attempt in $(seq 1 90); do
  if curl --silent --show-error --fail --max-time 2 "http://${endpoint}/health" >"${output_dir}/health.json" 2>"${output_dir}/http-error.log"; then ready=1; break; fi
  [[ "$(docker inspect --format '{{.State.Running}}' "${app_id}")" == true ]] || fail "app container exited before readiness"
  sleep 1
done
[[ "${ready}" -eq 1 ]] || fail "HTTP health route did not become ready"
curl --silent --show-error --fail --max-time 10 "http://${endpoint}/identity" >"${output_dir}/identity.json"
curl --silent --show-error --fail --max-time 20 "http://${endpoint}/exercise" >"${output_dir}/exercise.json"
noise_id="$("${compose[@]}" ps -q noise)"
[[ -n "${noise_id}" && "$(docker inspect --format '{{.State.Running}}' "${noise_id}")" == true ]] || fail "unrelated noise container is not running"
"${compose[@]}" exec -T noise /bin/sh -c 'test -s /tmp/unrelated-noise-marker && cat /tmp/unrelated-noise-marker' >"${output_dir}/noise-proof.txt"
if [[ -n "${host_noise_pid}" ]]; then [[ -s "${output_dir}/host-noise-marker" ]] || fail "host noise did not execute"; fi
# Keep the independent noise process alive across request and shutdown tracing.
docker stop --time 20 "${app_id}" >/dev/null
docker inspect --format '{{.State.ExitCode}}' "${app_id}" >"${output_dir}/stop-exit-code.txt"
docker logs "${app_id}" >"${output_dir}/app.stdout.log" 2>"${output_dir}/app.stderr.log"
docker cp "${app_id}:/traces/events.jsonl" "${output_dir}/events.jsonl" >/dev/null

run_case() {
  local name="$1" expected="$2" actual
  shift 2
  local case_dir="${output_dir}/${name}"
  mkdir -p "${case_dir}/traces" "${case_dir}/data"
  chmod 0777 "${case_dir}/traces" "${case_dir}/data"
  if [[ "${name}" == existing-output ]]; then printf 'preserve-existing-capture\n' >"${case_dir}/traces/events.jsonl"; fi
  if python3 -c 'import subprocess, sys
try:
    sys.exit(subprocess.run(sys.argv[1:], timeout=90).returncode)
except subprocess.TimeoutExpired:
    print("in-container smoke: Docker case exceeded 90 seconds", file=sys.stderr)
    sys.exit(124)' docker run --rm --name "${project}-${name}" \
    --mount "type=bind,src=${case_dir}/traces,dst=/traces" \
    --mount "type=bind,src=${case_dir}/data,dst=/data" \
    "$@" >"${case_dir}/stdout.log" 2>"${case_dir}/stderr.log"; then actual=0; else actual=$?; fi
  [[ "${actual}" -eq "${expected}" ]] || { cat "${case_dir}/stderr.log" >&2; fail "${name}: expected exit ${expected}, got ${actual}"; }
  [[ ! -e "${case_dir}/data/should-not-run" ]] || fail "${name}: workload ran despite failed preflight"
  if [[ "${name}" == existing-output ]]; then
    [[ "$(cat "${case_dir}/traces/events.jsonl")" == preserve-existing-capture ]] || fail "existing capture was overwritten"
  fi
  if [[ "${name}" == exit23 ]]; then
    python3 - "${case_dir}" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
pid = int((root / "data/app.pid").read_text())
if (root / "data/exit23-marker.txt").read_text() != "fixture-exit23-marker\n":
    raise SystemExit("in-container smoke: FAIL: exit23 marker missing")
records = [json.loads(line) for line in (root / "traces/events.jsonl").read_text().splitlines()]
events = [record for record in records if record.get("type") == "syscall" and record.get("pid") == pid]
if not {"execve", "open_at", "write"} <= {record.get("kind") for record in events}:
    raise SystemExit("in-container smoke: FAIL: exit23 primary process exec/open/write missing")
if not any(record.get("kind") == "open_at" and record.get("file") == "/data/exit23-marker.txt" for record in events):
    raise SystemExit("in-container smoke: FAIL: exit23 primary process marker open missing")
PY
  fi
  printf '%s %s\n' "${name}" "${actual}" >>"${output_dir}/negative-cases.txt"
}
run_case exit23 23 --privileged --pid host "${FIXTURE_IMAGE}" /bin/sh -c 'printf "%s\n" "$$" > /data/app.pid; printf "fixture-exit23-marker\n" > /data/exit23-marker.txt; exit 23'
run_case missing-command 127 --privileged --pid host "${FIXTURE_IMAGE}" /no-such-fixture-command
run_case missing-permission 125 --cap-drop ALL --security-opt no-new-privileges "${FIXTURE_IMAGE}" /bin/sh -c 'touch /data/should-not-run'
run_case nonroot-agent 125 --user 10001:10001 "${FIXTURE_IMAGE}" /bin/sh -c 'touch /data/should-not-run'
run_case existing-output 125 --privileged --pid host "${FIXTURE_IMAGE}" /bin/sh -c 'touch /data/should-not-run'
python3 - "${output_dir}" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
cases = dict(line.split() for line in (root / "negative-cases.txt").read_text().splitlines())
(root / "negative-cases.json").write_text(json.dumps({key: int(value) for key, value in cases.items()}) + "\n")
PY
bash "${script_dir}/test-agent-lifecycle.sh" --image "${FIXTURE_IMAGE}" --output-dir "${output_dir}/lifecycle"
python3 "${fixture_dir}/validate.py" "${output_dir}"
printf 'in-container smoke: PASS: real package, Axum/PostgreSQL, trace isolation, privilege drop and lifecycle\n'
