#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "${script_dir}/release-version.sh"

dist_dir="dist"
release_tag=""
write_checksums=0

fail() {
  printf 'verify-release-artifacts: %s\n' "$1" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage: bash scripts/verify-release-artifacts.sh --tag <vVERSION> [--dist <directory>] [--write-checksums]

Verifies that the complete Linux/macOS release archive set exists, that every
archive contains only the expected binary, license, and README, and that the
binary is executable. --write-checksums creates <directory>/SHA256SUMS.
VERSION may be MAJOR.MINOR.PATCH or MAJOR.MINOR.PATCH-{alpha,beta,rc}.N.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dist)
      shift
      [[ $# -gt 0 ]] || fail "--dist requires a value"
      dist_dir="$1"
      shift
      ;;
    --tag)
      shift
      [[ $# -gt 0 ]] || fail "--tag requires a value"
      release_tag="$1"
      shift
      ;;
    --write-checksums)
      write_checksums=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'verify-release-artifacts: unknown option: %s\n' "$1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

is_release_tag "${release_tag}" || fail "--tag must be vMAJOR.MINOR.PATCH or vMAJOR.MINOR.PATCH-{alpha,beta,rc}.N"
[[ -d "${dist_dir}" ]] || fail "artifact directory does not exist: ${dist_dir}"
command -v tar >/dev/null 2>&1 || fail "tar is required"
if [[ "${write_checksums}" -eq 1 ]]; then
  command -v sha256sum >/dev/null 2>&1 || fail "sha256sum is required to write checksums"
fi

expected_targets=(
  x86_64-unknown-linux-gnu
  x86_64-apple-darwin
)

shopt -s nullglob
archives=("${dist_dir}"/ebpf-tracker-"${release_tag}"-*.tar.gz)
shopt -u nullglob

if [[ "${#archives[@]}" -ne "${#expected_targets[@]}" ]]; then
  fail "expected ${#expected_targets[@]} platform archives, found ${#archives[@]}"
fi

tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/ebpf-tracker-release-assets.XXXXXX")"
cleanup() {
  rm -rf "${tmp_root}"
}
trap cleanup EXIT INT TERM

archive_names=()
for target in "${expected_targets[@]}"; do
  archive_name="ebpf-tracker-${release_tag}-${target}.tar.gz"
  archive_path="${dist_dir}/${archive_name}"
  archive_root="ebpf-tracker-${release_tag}-${target}"
  [[ -s "${archive_path}" ]] || fail "missing or empty archive: ${archive_path}"

  entries=()
  while IFS= read -r entry; do
    entries+=("${entry}")
  done < <(tar -tzf "${archive_path}")
  [[ "${#entries[@]}" -eq 4 ]] || fail "${archive_name} must contain one directory and exactly three files"
  for entry in "${entries[@]}"; do
    normalized_entry="${entry%/}"
    case "${normalized_entry}" in
      "${archive_root}"|"${archive_root}/ebpf-tracker"|"${archive_root}/LICENSE"|"${archive_root}/README.md")
        ;;
      *)
        fail "unexpected archive entry in ${archive_name}: ${entry}"
        ;;
    esac
  done

  extract_dir="${tmp_root}/${target}"
  mkdir -p "${extract_dir}"
  tar -xzf "${archive_path}" -C "${extract_dir}"
  [[ -x "${extract_dir}/${archive_root}/ebpf-tracker" ]] || fail "binary is missing or not executable in ${archive_name}"
  [[ -s "${extract_dir}/${archive_root}/LICENSE" ]] || fail "LICENSE is missing or empty in ${archive_name}"
  [[ -s "${extract_dir}/${archive_root}/README.md" ]] || fail "README.md is missing or empty in ${archive_name}"

  archive_names+=("${archive_name}")
  printf '[verify-release-artifacts] verified %s\n' "${archive_name}"
done

if [[ "${write_checksums}" -eq 1 ]]; then
  checksums_file="${dist_dir}/SHA256SUMS"
  : > "${checksums_file}"
  for archive_name in "${archive_names[@]}"; do
    (
      cd "${dist_dir}"
      sha256sum "${archive_name}"
    ) >> "${checksums_file}"
  done
  [[ -s "${checksums_file}" ]] || fail "checksum manifest was not written"
  printf '[verify-release-artifacts] wrote %s\n' "${checksums_file}"
fi

printf '[verify-release-artifacts] release asset set is complete\n'
