#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"
source "${script_dir}/release-version.sh"
platform="linux/amd64"
output_dir="${repo_root}/dist/runtime"

fail() { printf 'build-runtime-deb: %s\n' "$1" >&2; exit 1; }
usage() {
  cat <<'EOF'
Usage: bash scripts/build-runtime-deb.sh [--platform linux/amd64|linux/arm64] [--output-dir DIRECTORY]

Builds and install-checks ebpf-tracker-runtime in Debian Bookworm using Docker
Buildx. The package contains a precompiled agent; the runtime needs no Rust tools.
Defaults: linux/amd64, repository dist/runtime. Cross-architecture builds require
Docker emulation. A successful build does not prove live kernel tracing.
Outputs: ebpf-tracker-runtime_VERSION_ARCH.deb and SHA256SUMS.runtime.
Debian prerelease versions use ~ (for example 0.2.0~alpha.1).
EOF
}
while [[ $# -gt 0 ]]; do
  case "$1" in
    --platform|--output-dir)
      option="$1"; shift
      [[ $# -gt 0 ]] || fail "${option} requires a value"
      if [[ "${option}" == --platform ]]; then platform="$1"; else output_dir="$1"; fi
      shift ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown option: $1" ;;
  esac
done
case "${platform}" in
  linux/amd64) arch=amd64 ;;
  linux/arm64) arch=arm64 ;;
  *) fail "--platform must be linux/amd64 or linux/arm64" ;;
esac
version="$(awk '/^\[workspace.package\]$/ { section=1; next } /^\[/ { section=0 } section && $1 == "version" { gsub(/"/, "", $3); print $3; exit }' "${repo_root}/Cargo.toml")"
is_release_version "${version}" || fail "unsupported workspace version: ${version}"
debian_version="$(debian_release_version "${version}")"
package_name="ebpf-tracker-runtime_${debian_version}_${arch}.deb"
command -v docker >/dev/null 2>&1 || fail "Docker with Buildx is required"
docker buildx version >/dev/null 2>&1 || fail "Docker Buildx is required"
mkdir -p "${output_dir}"
output_dir="$(cd -- "${output_dir}" && pwd)"
tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/ebpf-tracker-runtime-package.XXXXXX")"
trap 'rm -rf "${tmp_root}"' EXIT

docker buildx build \
  --platform "${platform}" \
  --file "${repo_root}/docker/runtime-package.Dockerfile" \
  --target package-artifact \
  --build-arg "APP_VERSION=${version}" \
  --build-arg "DEBIAN_VERSION=${debian_version}" \
  --output "type=local,dest=${tmp_root}/artifacts" \
  "${repo_root}"
[[ -s "${tmp_root}/artifacts/${package_name}" ]] || fail "builder did not export ${package_name}"
cp "${tmp_root}/artifacts/${package_name}" "${output_dir}/${package_name}"
cp "${tmp_root}/artifacts/SHA256SUMS.runtime" "${output_dir}/SHA256SUMS.runtime"
printf '[build-runtime-deb] built and install-checked %s/%s\n' "${output_dir}" "${package_name}"
