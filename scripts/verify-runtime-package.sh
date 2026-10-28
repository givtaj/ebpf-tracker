#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "${script_dir}/release-version.sh"
package=""
version=""
arch=""
write_checksums=0
fail() { printf 'verify-runtime-package: %s\n' "$1" >&2; exit 1; }
usage() {
  cat <<'EOF'
Usage: bash scripts/verify-runtime-package.sh --deb FILE --expected-version VERSION --arch amd64|arm64 [--write-checksums]

Checks package name, version, architecture, dependencies, exact payload, and ELF
architecture. Requires Debian dpkg-deb, Python 3, and readelf. Does not execute the
agent or trace the host. --write-checksums writes adjacent SHA256SUMS.runtime.
Accepts the local Debian-version filename (~) or public SemVer filename (-).
The package's internal Version must always use the Debian version.
EOF
}
while [[ $# -gt 0 ]]; do
  case "$1" in
    --deb|--expected-version|--arch)
      option="$1"; shift
      [[ $# -gt 0 ]] || fail "${option} requires a value"
      case "${option}" in --deb) package="$1" ;; --expected-version) version="$1" ;; --arch) arch="$1" ;; esac
      shift ;;
    --write-checksums) write_checksums=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown option: $1" ;;
  esac
done
is_release_version "${version}" || fail "--expected-version must be a supported release version"
case "${arch}" in amd64|arm64) ;; *) fail "--arch must be amd64 or arm64" ;; esac
[[ -s "${package}" ]] || fail "package does not exist or is empty: ${package}"
debian_version="$(debian_release_version "${version}")"
local_name="ebpf-tracker-runtime_${debian_version}_${arch}.deb"
public_name="ebpf-tracker-runtime_${version}_${arch}.deb"
package_name="$(basename -- "${package}")"
[[ "${package_name}" == "${local_name}" || "${package_name}" == "${public_name}" ]] || fail "unexpected package filename"
for tool in dpkg-deb python3 readelf; do command -v "${tool}" >/dev/null 2>&1 || fail "${tool} is required"; done
[[ "$(dpkg-deb -f "${package}" Package)" == ebpf-tracker-runtime ]] || fail "unexpected Package field"
[[ "$(dpkg-deb -f "${package}" Version)" == "${debian_version}" ]] || fail "unexpected Version field"
[[ "$(dpkg-deb -f "${package}" Architecture)" == "${arch}" ]] || fail "unexpected Architecture field"
[[ "$(dpkg-deb -f "${package}" Depends)" == 'bpftrace (>= 0.17), bpftrace (<< 0.18), libc6 (>= 2.36), libgcc-s1 (>= 12)' ]] || fail "unexpected runtime dependencies"
tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/ebpf-tracker-runtime-verify.XXXXXX")"
trap 'rm -rf "${tmp_root}"' EXIT
dpkg-deb --fsys-tarfile "${package}" > "${tmp_root}/payload.tar"
dpkg-deb --ctrl-tarfile "${package}" > "${tmp_root}/control.tar"
python3 - "${tmp_root}" <<'PY'
import pathlib
import sys
import tarfile

root = pathlib.Path(sys.argv[1])
expected = {
    "usr/bin/ebpf-tracker-agent": 0o755,
    "usr/share/doc/ebpf-tracker-runtime/copyright": 0o644,
}
with tarfile.open(root / "payload.tar") as archive:
    seen = set()
    for member in archive:
        if member.isdir() and member.name in (".", "./"):
            continue
        name = member.name.removeprefix("./").rstrip("/")
        if member.isdir():
            if name not in (".", "usr", "usr/bin", "usr/share", "usr/share/doc", "usr/share/doc/ebpf-tracker-runtime"):
                raise SystemExit(f"unexpected package directory: {name}")
            continue
        if name not in expected or name in seen or not member.isfile():
            raise SystemExit(f"unexpected package entry: {name}")
        if member.mode != expected[name] or member.uid != 0 or member.gid != 0 or member.size == 0:
            raise SystemExit(f"invalid package permissions, owner, or size: {name}")
        seen.add(name)
        if name == "usr/bin/ebpf-tracker-agent":
            (root / "agent").write_bytes(archive.extractfile(member).read())
    if seen != set(expected):
        raise SystemExit("package payload is incomplete")
with tarfile.open(root / "control.tar") as archive:
    entries = [m for m in archive if not m.isdir()]
    if len(entries) != 1 or entries[0].name.removeprefix("./") != "control" or not entries[0].isfile():
        raise SystemExit("package must contain only control metadata, with no install hooks")
PY
case "${arch}" in amd64) machine='Advanced Micro Devices X86-64' ;; arm64) machine='AArch64' ;; esac
readelf -h "${tmp_root}/agent" | grep -Eq "Machine:[[:space:]]+${machine}$" || fail "ELF architecture differs from package architecture"
if [[ "${write_checksums}" -eq 1 ]]; then
  command -v sha256sum >/dev/null 2>&1 || fail "sha256sum is required"
  (cd -- "$(dirname -- "${package}")" && sha256sum "${package_name}" > SHA256SUMS.runtime)
fi
printf '[verify-runtime-package] verified %s\n' "${package_name}"
