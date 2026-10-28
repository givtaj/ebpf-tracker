#!/usr/bin/env bash
set -euo pipefail

# Real installed-package lifecycle tests. Requires an image produced by the
# Axum fixture Dockerfile; this never replaces bpftrace with a test backend.
image=""
output_dir=""
fail() { printf 'agent lifecycle: FAIL: %s\n' "$1" >&2; exit 1; }
while [[ $# -gt 0 ]]; do
  case "$1" in
    --image|--output-dir)
      option="$1"; [[ $# -ge 2 ]] || fail "${option} requires a value"
      if [[ "${option}" == --image ]]; then image="$2"; else output_dir="$2"; fi
      shift 2 ;;
    -h|--help)
      printf 'Usage: bash scripts/test-agent-lifecycle.sh --image <installed-fixture-image> --output-dir <new-directory>\n'
      exit 0 ;;
    *) fail "unknown argument: $1" ;;
  esac
done
[[ -n "${image}" && -n "${output_dir}" && ! -e "${output_dir}" ]] || fail "an image and new output directory are required"
mkdir -p "${output_dir}"
output_dir="$(cd -- "${output_dir}" && pwd)"
prefix="ebpf-lifecycle-$(date +%s)-$$"
active_container=""
active_dir=""

collect_logs() {
  [[ -n "${active_container}" ]] || return 0
  docker logs "${active_container}" >"${active_dir}/stdout.log" 2>"${active_dir}/stderr.log" || true
  docker cp "${active_container}:/traces/events.jsonl" "${active_dir}/events.jsonl" >/dev/null 2>&1 || true
}
cleanup() {
  result=$?
  trap - EXIT INT TERM
  collect_logs
  if [[ -n "${active_container}" ]]; then docker rm -f "${active_container}" >/dev/null 2>&1 || true; fi
  exit "${result}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

run_case() {
  local name="$1" expected="$2" signal="$3" ready=0
  active_dir="${output_dir}/${name}"
  mkdir -p "${active_dir}/data" "${active_dir}/traces"
  chmod 0777 "${active_dir}/data" "${active_dir}/traces"
  case "${name}" in
    ignore-term) printf "trap '' TERM\n" >"${active_dir}/data/workload.sh" ;;
    sigint) printf "trap 'printf received-INT > /data/signal-marker; exit 0' INT\n" >"${active_dir}/data/workload.sh" ;;
    collector-failure) printf "trap 'printf received-TERM > /data/signal-marker; exit 0' TERM\n" >"${active_dir}/data/workload.sh" ;;
  esac
  cat >>"${active_dir}/data/workload.sh" <<'EOF'
cat /proc/$$/stat > /data/app.stat
printf '%s\n' "$$" > /data/app.pid
while :; do sleep 0.1; done
EOF
  active_container="${prefix}-${name}"
  docker run -d --name "${active_container}" --privileged --pid host \
    --mount "type=bind,src=${active_dir}/data,dst=/data" \
    --mount "type=bind,src=${active_dir}/traces,dst=/traces" \
    --entrypoint /usr/bin/ebpf-tracker-agent "${image}" \
    --app-user roots --output /traces/events.jsonl --shutdown-timeout 1 -- /bin/sh /data/workload.sh >"${active_dir}/container-id.txt"
  for attempt in $(seq 1 100); do
    if [[ -s "${active_dir}/data/app.pid" ]]; then ready=1; break; fi
    [[ "$(docker inspect --format '{{.State.Running}}' "${active_container}")" == true ]] || { collect_logs; cat "${active_dir}/stderr.log" >&2; fail "${name}: app exited before readiness"; }
    sleep 0.2
  done
  [[ "${ready}" -eq 1 ]] || fail "${name}: app readiness exceeded 20 seconds"
  app_pid="$(cat "${active_dir}/data/app.pid")"
  agent_pid="$(docker inspect --format '{{.State.Pid}}' "${active_container}")"
  started="$(python3 -c 'import time; print(time.monotonic())')"
  if [[ "${name}" == collector-failure ]]; then
    # Target only bpftrace directly parented by this test's inspected agent.
    docker exec "${active_container}" /bin/sh -c '
      for pid in $(cat "/proc/$1/task/$1/children"); do
        IFS= read -r comm < "/proc/$pid/comm" || continue
        if [ "$comm" = bpftrace ]; then printf "%s\n" "$pid"; kill -KILL "$pid"; exit 0; fi
      done
      exit 1
    ' _ "${agent_pid}" >"${active_dir}/killed-collector-pid.txt" || fail "could not identify the owned collector"
  else
    # Use docker kill's signal-only mode: Docker must not supply the timeout KILL.
    docker kill --signal "${signal}" "${active_container}" >/dev/null
  fi
  python3 - "${active_container}" "${started}" "${active_dir}/stop-elapsed.txt" <<'PY'
import pathlib, subprocess, sys, time
started = float(sys.argv[2])
while time.monotonic() - started < 12:
    result = subprocess.run(["docker", "inspect", "--format", "{{.State.Running}}", sys.argv[1]], capture_output=True, text=True, timeout=3)
    if result.returncode != 0:
        raise SystemExit("agent lifecycle: cannot inspect owned container")
    if result.stdout.strip() == "false":
        elapsed = time.monotonic() - started
        if elapsed > 12:
            raise SystemExit("agent lifecycle: supervisor exceeded its 12-second stop deadline")
        pathlib.Path(sys.argv[3]).write_text(str(round(elapsed, 3)))
        break
    time.sleep(0.2)
else:
    raise SystemExit("agent lifecycle: supervisor did not stop within 12 seconds")
PY
  actual="$(docker inspect --format '{{.State.ExitCode}}' "${active_container}")"
  printf '%s\n' "${actual}" >"${active_dir}/exit-code.txt"
  collect_logs
  [[ "${actual}" -eq "${expected}" ]] || { cat "${active_dir}/stderr.log" >&2; fail "${name}: expected exit ${expected}, got ${actual}"; }
  case "${name}" in
    sigint) [[ "$(cat "${active_dir}/data/signal-marker")" == received-INT ]] || fail "SIGINT did not reach app" ;;
    collector-failure) [[ "$(cat "${active_dir}/data/signal-marker")" == received-TERM ]] || fail "collector failure did not terminate app gracefully" ;;
  esac
  # Compare kernel start time as well as PID, so PID reuse cannot cause a false
  # survivor report. This verifier shares the host PID namespace but is unprivileged.
  docker run --rm --pid host --user 10001:10001 --cap-drop ALL --security-opt no-new-privileges \
    --entrypoint /bin/sh "${image}" -c 'if [ -d "/proc/$1" ]; then cat "/proc/$1/stat" || test ! -d "/proc/$1"; fi' _ "${app_pid}" >"${active_dir}/after.stat"
  python3 - "${active_dir}" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
before = (root / "data/app.stat").read_text()
after = (root / "after.stat").read_text()
if after and before.rsplit(")", 1)[1].split()[19] == after.rsplit(")", 1)[1].split()[19]:
    raise SystemExit("agent lifecycle: application survived supervisor shutdown")
events = [json.loads(line) for line in (root / "events.jsonl").read_text().splitlines()]
if not any(event.get("type") == "syscall" for event in events):
    raise SystemExit("agent lifecycle: missing syscall records in retained capture")
stop_elapsed = float((root / "stop-elapsed.txt").read_text())
if root.name == "ignore-term" and stop_elapsed < 0.8:
    raise SystemExit("agent lifecycle: TERM-ignoring app was killed before its grace period")
(root / "result.json").write_text(json.dumps({"exit_code": int((root / "exit-code.txt").read_text()), "stop_elapsed_seconds": stop_elapsed, "app_reaped": True, "capture_records": len(events)}) + "\n")
PY
  docker rm "${active_container}" >/dev/null
  active_container=""
  printf 'agent lifecycle: PASS: %s (exit %s)\n' "${name}" "${actual}"
}

run_case ignore-term 137 TERM
run_case sigint 0 INT
run_case collector-failure 125 unused
python3 - "${output_dir}" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
summary = {name: json.loads((root / name / "result.json").read_text()) for name in ["ignore-term", "sigint", "collector-failure"]}
(root / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
PY
