#!/usr/bin/env bash
set -u

print_section() {
  printf '\n== %s ==\n' "$1"
}

run_optional() {
  local label="$1"
  shift
  printf '%s: ' "$label"
  local output
  if output="$("$@" 2>&1)"; then
    if [ -n "$output" ]; then
      printf '%s\n' "$output"
    else
      printf 'ok\n'
    fi
  else
    local status=$?
    output="$(printf '%s' "$output" | tr '\n' ' ' | sed 's/[[:space:]]*$//')"
    printf 'unavailable (exit %s%s%s)\n' "$status" "${output:+: }" "$output"
  fi
}

run_sudo_optional() {
  local label="$1"
  shift
  if sudo -n true >/dev/null 2>&1; then
    run_optional "$label" sudo -n "$@"
  else
    printf '%s: unavailable (sudo -n not available)\n' "$label"
  fi
}

count_numbered_rows() {
  awk -F: '$1 ~ /^[0-9]+$/ { count += 1 } END { print count + 0 }'
}

run_count_optional() {
  local label="$1"
  shift
  printf '%s: ' "$label"
  local output
  if output="$("$@" 2>&1)"; then
    printf '%s\n' "$(printf '%s\n' "$output" | count_numbered_rows)"
  else
    local status=$?
    output="$(printf '%s' "$output" | tr '\n' ' ' | sed 's/[[:space:]]*$//')"
    printf 'unavailable (exit %s%s%s)\n' "$status" "${output:+: }" "$output"
  fi
}

run_sudo_count_optional() {
  local label="$1"
  shift
  if sudo -n true >/dev/null 2>&1; then
    run_count_optional "$label" sudo -n "$@"
  else
    printf '%s: unavailable (sudo -n not available)\n' "$label"
  fi
}

print_section "host"
printf 'user: '; whoami
printf 'hostname: '; hostname
printf 'kernel: '; uname -r
printf 'arch: '; uname -m
if [ -r /etc/os-release ]; then
  . /etc/os-release
  printf 'os: %s\n' "${PRETTY_NAME:-unknown}"
fi
printf 'btf: '
if [ -r /sys/kernel/btf/vmlinux ]; then
  printf 'available\n'
else
  printf 'missing\n'
fi

print_section "sysctl"
for key in kernel.perf_event_paranoid kernel.kptr_restrict kernel.unprivileged_bpf_disabled; do
  sysctl_path="/proc/sys/${key//./\/}"
  if [ -r "$sysctl_path" ]; then
    printf '%s: %s\n' "$key" "$(cat "$sysctl_path")"
  else
    printf '%s: unavailable\n' "$key"
  fi
done

print_section "tools"
for tool in bpftrace bpftool perf clang llvm-config llc pahole gcc make pkg-config docker; do
  if command -v "$tool" >/dev/null 2>&1; then
    printf '%s: %s\n' "$tool" "$(command -v "$tool")"
  else
    printf '%s: missing\n' "$tool"
  fi
done

print_section "eBPF objects"
run_sudo_count_optional "bpftool programs" bpftool prog show
run_sudo_count_optional "bpftool maps" bpftool map show

print_section "docker"
run_optional "docker version" docker --version
run_optional "docker daemon" docker info --format 'server={{.ServerVersion}}'
run_sudo_optional "docker daemon via sudo" docker info --format 'server={{.ServerVersion}}'

print_section "ubuntu packages"
if command -v dpkg-query >/dev/null 2>&1; then
  for pkg in bpftrace bpftool bpfcc-tools python3-bpfcc trace-cmd linux-tools-common "linux-tools-$(uname -r)" "linux-headers-$(uname -r)" linux-tools-generic linux-cloud-tools-generic linux-headers-generic clang llvm lld libbpf-dev libbpf-tools libelf-dev zlib1g-dev dwarves pkg-config libssl-dev; do
    if package_record="$(dpkg-query -W -f='${binary:Package}\t${Version}\n' "$pkg" 2>/dev/null)"; then
      printf 'installed %s\n' "$package_record"
    else
      printf 'missing %s\n' "$pkg"
    fi
  done
else
  printf 'dpkg-query unavailable; adapt package inventory to this distribution\n'
fi

print_section "next"
printf 'Do not install from this script. Use results to write approval gates first.\n'
