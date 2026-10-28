#!/usr/bin/env bash

# Release channels deliberately exclude arbitrary SemVer identifiers and metadata.
is_release_version() {
  [[ "$1" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-(alpha|beta|rc)\.(0|[1-9][0-9]*))?$ ]]
}

is_release_tag() {
  [[ "$1" == v* ]] && is_release_version "${1#v}"
}

debian_release_version() {
  is_release_version "$1" || return 1
  # Bash versions differ in whether an unescaped replacement ~ expands HOME.
  printf '%s\n' "$1" | tr '-' '~'
}
