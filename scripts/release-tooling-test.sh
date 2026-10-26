#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "${script_dir}/release-version.sh"

fail() {
  printf 'release-tooling-test: %s\n' "$1" >&2
  exit 1
}

for version in 0.1.1 1.2.3 0.2.0-alpha.1 1.0.0-beta.2 2.0.0-rc.0; do
  is_release_version "${version}" || fail "rejected supported version ${version}"
  is_release_tag "v${version}" || fail "rejected supported tag v${version}"
done

for version in '' v0.1.1 01.2.3 1.02.3 1.2.03 1.2 1.2.3-alpha 1.2.3-alpha.01 1.2.3-preview.1 1.2.3-rc.1.2 1.2.3+build; do
  if is_release_version "${version}"; then
    fail "accepted unsupported version ${version}"
  fi
done

tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/ebpf-tracker-release-tooling.XXXXXX")"
trap 'rm -rf "${tmp_root}"' EXIT INT TERM

make_archive() {
  local tag="$1"
  local target="$2"
  local archive_root="ebpf-tracker-${tag}-${target}"
  mkdir -p "${tmp_root}/staging/${archive_root}"
  printf '#!/bin/sh\nexit 0\n' > "${tmp_root}/staging/${archive_root}/ebpf-tracker"
  chmod +x "${tmp_root}/staging/${archive_root}/ebpf-tracker"
  printf 'Test license\n' > "${tmp_root}/staging/${archive_root}/LICENSE"
  printf 'Test readme\n' > "${tmp_root}/staging/${archive_root}/README.md"
  COPYFILE_DISABLE=1 tar -czf "${tmp_root}/dist/${archive_root}.tar.gz" -C "${tmp_root}/staging" "${archive_root}"
}

mkdir -p "${tmp_root}/dist"
for tag in v0.1.1 v0.2.0-alpha.1; do
  make_archive "${tag}" x86_64-unknown-linux-gnu
  if bash "${script_dir}/verify-release-artifacts.sh" --dist "${tmp_root}/dist" --tag "${tag}" > "${tmp_root}/output" 2>&1; then
    fail "accepted incomplete platform set for ${tag}"
  fi
  make_archive "${tag}" x86_64-apple-darwin
  bash "${script_dir}/verify-release-artifacts.sh" --dist "${tmp_root}/dist" --tag "${tag}"
done

alpha_root="ebpf-tracker-v0.2.0-alpha.1-x86_64-unknown-linux-gnu"
chmod -x "${tmp_root}/staging/${alpha_root}/ebpf-tracker"
COPYFILE_DISABLE=1 tar -czf "${tmp_root}/dist/${alpha_root}.tar.gz" -C "${tmp_root}/staging" "${alpha_root}"
if bash "${script_dir}/verify-release-artifacts.sh" --dist "${tmp_root}/dist" --tag v0.2.0-alpha.1 > "${tmp_root}/output" 2>&1; then
  fail "accepted a non-executable binary"
fi
make_archive v0.2.0-alpha.1 x86_64-unknown-linux-gnu
printf 'unexpected\n' > "${tmp_root}/staging/${alpha_root}/extra"
COPYFILE_DISABLE=1 tar -czf "${tmp_root}/dist/${alpha_root}.tar.gz" -C "${tmp_root}/staging" "${alpha_root}"
if bash "${script_dir}/verify-release-artifacts.sh" --dist "${tmp_root}/dist" --tag v0.2.0-alpha.1 > "${tmp_root}/output" 2>&1; then
  fail "accepted unexpected archive content"
fi

if bash "${script_dir}/release-check.sh" --expected-version 0.2.0-alpha.01 > "${tmp_root}/output" 2>&1; then
  fail "release gate accepted a malformed prerelease version"
fi
grep -q 'expected version must be' "${tmp_root}/output" || fail "release gate failed for an unexpected reason"

printf '[release-tooling-test] PASS: versions, complete platform sets, executable binaries, and archive contents\n'
