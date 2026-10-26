#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"
source "${script_dir}/release-version.sh"
run_runtime_smoke=0
run_demo_smoke=0
run_dashboard_smoke=0
run_dataset_smoke=0
run_perf_smoke=0
run_attach_smoke=0
run_customer_ux=0
run_isolation_smoke=0
expected_version=""

usage() {
  cat <<'EOF'
Usage: bash scripts/release-check.sh [--expected-version <VERSION>] [--with-runtime-smoke] [--with-demo-smoke] [--with-isolation-smoke] [--with-dashboard-smoke] [--with-dataset-smoke] [--with-perf-smoke] [--with-attach-smoke] [--with-customer-ux]

Default behavior runs the fast generic release checks that are suitable for
GitHub-hosted CI. It is not sufficient by itself to approve a release tag.

Use --expected-version to require an exact match with [workspace.package].version.
Versions may be MAJOR.MINOR.PATCH or MAJOR.MINOR.PATCH-{alpha,beta,rc}.N.

Use --with-runtime-smoke on a maintainer machine to also run the Docker-backed
tracing smoke path.

Use --with-demo-smoke to additionally trace a real Rust demo command during
the runtime smoke step.

Use --with-isolation-smoke to prove wrapped descendants are captured while
unrelated host exec noise is excluded.

Use --with-dashboard-smoke to run the bundled replay viewer check.

Use --with-dataset-smoke to validate dataset ingest and analyze against a
bundled replay plus a local mock model endpoint.

Use --with-perf-smoke to additionally exercise the perf transport path during
runtime smoke.

Use --with-attach-smoke to run the lightweight attach validation smoke.

Use --with-customer-ux to run the full customer journey end-to-end suite via
scripts/customer-ux-check.sh. This flag is strict and fails on missing
prerequisites or skipped journeys.
EOF
}


while [[ $# -gt 0 ]]; do
  case "$1" in
    --expected-version)
      shift
      [[ $# -gt 0 ]] || { printf 'release-check: --expected-version requires a value\n' >&2; exit 1; }
      expected_version="$1"
      shift
      ;;
    --with-runtime-smoke)
      run_runtime_smoke=1
      shift
      ;;
    --with-demo-smoke)
      run_runtime_smoke=1
      run_demo_smoke=1
      shift
      ;;
    --with-isolation-smoke)
      run_isolation_smoke=1
      shift
      ;;
    --with-dashboard-smoke)
      run_dashboard_smoke=1
      shift
      ;;
    --with-dataset-smoke)
      run_dataset_smoke=1
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
    --with-customer-ux)
      run_customer_ux=1
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


workspace_version="$(
  awk '
    $0 == "[workspace.package]" { in_workspace_package = 1; next }
    /^\[/ { in_workspace_package = 0 }
    in_workspace_package && $1 == "version" {
      gsub(/"/, "", $3)
      print $3
      exit
    }
  ' Cargo.toml
)"
[[ -n "${workspace_version}" ]] || { printf 'release-check: could not read workspace version\n' >&2; exit 1; }
is_release_version "${workspace_version}" || { printf 'release-check: invalid workspace release version\n' >&2; exit 1; }
printf '[release-check] workspace version %s\n' "${workspace_version}"
if [[ -n "${expected_version}" ]]; then
  is_release_version "${expected_version}" || { printf 'release-check: expected version must be MAJOR.MINOR.PATCH or MAJOR.MINOR.PATCH-{alpha,beta,rc}.N\n' >&2; exit 1; }
  [[ "${workspace_version}" == "${expected_version}" ]] || { printf 'release-check: workspace version %s does not match expected %s\n' "${workspace_version}" "${expected_version}" >&2; exit 1; }
fi
echo "[release-check] bash scripts/release-tooling-test.sh"
bash scripts/release-tooling-test.sh
echo "[release-check] bash scripts/test-customer-cli-resolution.sh"
bash scripts/test-customer-cli-resolution.sh
echo "[release-check] helper format and workload exit-status regression checks"
rustfmt --check scripts/exec-target-from-env.rs
bash scripts/test-bpftrace-exit-status.sh

echo "[release-check] cargo fmt --all --check"
cargo fmt --all --check

echo "[release-check] cargo test --all --locked"
cargo test --all --locked

echo "[release-check] cargo build --workspace --locked"
cargo build --workspace --locked

echo "[release-check] cargo build --release --locked --bin ebpf-tracker"
cargo build --release --locked --bin ebpf-tracker --target-dir "${repo_root}/target"

# Customer journey scripts prefer PATH; force them to use this release candidate.
export PATH="${repo_root}/target/release:${PATH}"
tracker_binary="${repo_root}/target/release/ebpf-tracker"
export EBPF_TRACKER_TEST_BINARY="${tracker_binary}"
actual_version="$("${tracker_binary}" --version)"
[[ "${actual_version}" == "ebpf-tracker ${workspace_version}" ]] || { printf 'release-check: built binary version mismatch: %s\n' "${actual_version}" >&2; exit 1; }

echo "[release-check] built release binary --help / replay --help / demo --list"
"${tracker_binary}" --help
"${tracker_binary}" replay --help
"${tracker_binary}" demo --list

if [[ "${run_customer_ux}" -eq 1 || "${run_dashboard_smoke}" -eq 1 ]]; then
  echo "[release-check] root CLI offline replay smoke"
  bash scripts/replay-smoke.sh --tracker "${tracker_binary}"
fi

if [[ "${run_runtime_smoke}" -eq 1 ]]; then
  echo "[release-check] bash scripts/runtime-smoke.sh"
  if [[ "${run_perf_smoke}" -eq 1 ]]; then
    if [[ "${run_demo_smoke}" -eq 1 ]]; then
      bash scripts/runtime-smoke.sh --with-perf-smoke --with-demo-smoke
    else
      bash scripts/runtime-smoke.sh --with-perf-smoke
    fi
  else
    if [[ "${run_demo_smoke}" -eq 1 ]]; then
      bash scripts/runtime-smoke.sh --with-demo-smoke
    else
      bash scripts/runtime-smoke.sh
    fi
  fi
else
  echo "[release-check] runtime smoke skipped; run bash scripts/release-check.sh --with-runtime-smoke before tagging on a Docker-capable maintainer machine"
fi

if [[ "${run_isolation_smoke}" -eq 1 ]]; then
  [[ -f scripts/runtime-isolation-smoke.sh ]] || { printf 'release-check: scripts/runtime-isolation-smoke.sh is missing\n' >&2; exit 1; }
  echo "[release-check] bash scripts/runtime-isolation-smoke.sh"
  bash scripts/runtime-isolation-smoke.sh
else
  echo "[release-check] isolation smoke skipped; run bash scripts/release-check.sh --with-isolation-smoke before tagging"
fi

if [[ "${run_dashboard_smoke}" -eq 1 ]]; then
  echo "[release-check] bash scripts/dashboard-smoke.sh --check"
  bash scripts/dashboard-smoke.sh --check
else
  echo "[release-check] dashboard smoke skipped; run bash scripts/release-check.sh --with-dashboard-smoke to validate the viewer surface"
fi

if [[ "${run_dataset_smoke}" -eq 1 ]]; then
  echo "[release-check] bash scripts/dataset-smoke.sh"
  bash scripts/dataset-smoke.sh
else
  echo "[release-check] dataset smoke skipped; run bash scripts/release-check.sh --with-dataset-smoke to validate dataset ingest/analyze"
fi

if [[ "${run_attach_smoke}" -eq 1 ]]; then
  echo "[release-check] bash scripts/attach-smoke.sh"
  bash scripts/attach-smoke.sh
else
  echo "[release-check] attach smoke skipped; run bash scripts/release-check.sh --with-attach-smoke to validate the scaffolded attach path"
fi

if [[ "${run_customer_ux}" -eq 1 ]]; then
  [[ -f scripts/customer-ux-check.sh ]] || { printf 'release-check: scripts/customer-ux-check.sh is missing\n' >&2; exit 1; }
  echo "[release-check] bash scripts/customer-ux-check.sh --strict-prereqs --fail-on-skip"
  bash scripts/customer-ux-check.sh --strict-prereqs --fail-on-skip
else
  echo "[release-check] customer UX suite skipped; run bash scripts/release-check.sh --with-customer-ux to validate end-to-end customer journeys"
fi

echo "[release-check] PASS"
