# Release Runbook

This is the maintainer checklist for public releases of `ebpf-tracker`.
Releases are GitHub-first: workspace crates remain `publish = false`, so the
tagged source tree and attached binary archives are the public artifacts.

## Release Line

The unpublished `0.2.0-alpha.4` candidate follows the
[Axum-on-Docker alpha contract](./docs/alpha-scope.md), using Roots as the
reference service. The selected integration installs the native agent inside
the API image. The isolated Axum/PostgreSQL acceptance must pass against the
actual amd64 and arm64 Debian packages on their native Linux architectures;
generic command/replay checks do not approve this release. A workspace version
does not establish publication. Both runtime gates, both host CLI archives,
asset assembly and checksums must pass before publication. Record the exact
tag, workflow and downloaded-artifact results in [alpha validation](./docs/alpha-validation.md).

## Versioning

- Keep the workspace version in [Cargo.toml](./Cargo.toml) on the release line.
- Use annotated `vMAJOR.MINOR.PATCH` tags, or prereleases such as
  `v0.2.0-alpha.4`. Supported prerelease channels are `alpha.N`, `beta.N`, and
  `rc.N`, with no leading zeroes in numeric components.
- Prerelease tags are marked as prereleases on GitHub; do not promote an alpha
  to a stable release.
- Bump the version and finalize [CHANGELOG.md](./CHANGELOG.md) before tagging.
- Leave internal workspace crates unpublished unless the release plan changes.

## Pre-Release Checklist

1. Move all shipped changes from `Unreleased` into a dated version section in [CHANGELOG.md](./CHANGELOG.md).
   Update [.github/release-notes.md](./.github/release-notes.md), including its
   version-pinned links, for the release being published.
2. Confirm the support and trust boundaries in [README.md](./README.md), [SECURITY.md](./SECURITY.md), and [docs/cli.md](./docs/cli.md) still match the implementation.
3. Confirm example docs still point to runnable commands in [examples/README.md](./examples/README.md).
4. Verify GitHub private vulnerability reporting or the documented security contact is available.
5. Verify the worktree contains only intentional release edits.

## Required Verification

The default check is useful during development, but is not sufficient to
approve a release tag:

```bash
bash scripts/release-check.sh
```

Before tagging, run the complete gate on a Linux maintainer host with Docker,
privileged container support, host PID access, eBPF support, and a bindable
loopback interface:

```bash
bash scripts/release-check.sh \
  --expected-version 0.2.0-alpha.4 \
  --with-runtime-smoke \
  --with-demo-smoke \
  --with-isolation-smoke \
  --with-customer-ux
```

Replace `0.2.0-alpha.4` with the version being released. This gate verifies formatting,
the locked workspace tests and builds, CLI discovery, a real traced workload,
descendant capture and unrelated-process exclusion, and all supported customer
journeys. `--with-customer-ux` is strict: a missing prerequisite or skipped
journey fails the release check.

Run these runtime checks on each architecture's native Docker host, setting
`runtime_arch` to match. Cross-building a package does not replace native live
acceptance:

```bash
runtime_arch=amd64 # Set arm64 on the native ARM64 host.
case "$runtime_arch" in amd64|arm64) ;; *) exit 1 ;; esac
bash scripts/build-runtime-deb.sh --platform "linux/$runtime_arch" --output-dir dist/runtime
bash scripts/in-container-smoke.sh \
  --package "dist/runtime/ebpf-tracker-runtime_0.2.0~alpha.4_${runtime_arch}.deb"
```

Both architecture gates are mandatory for alpha.4. Each runtime package must
be built on Bookworm, installed in a clean image without Cargo, and pass live
capture and offline replay, including the missing-file HTTP failure, kernel
`ENOENT` result and successful-open control. CI uses native `ubuntu-22.04` amd64 and
`ubuntu-22.04-arm` arm64 runners. Publication waits for both; do not replace a
missing or failed native gate with an emulated run.

Other focused checks remain available for maintainers:

```bash
bash scripts/dashboard-smoke.sh --check
bash scripts/dataset-smoke.sh
bash scripts/customer-ux-check.sh --strict-prereqs --fail-on-skip
```

Use `bash scripts/customer-data-e2e.sh --analyze-endpoint <url>` to verify the
dataset path against an external OpenAI-compatible endpoint instead of the
bundled local mock endpoint.

The tag workflow applies the same strict gate. It does not substitute lighter
checks when the runner lacks required capabilities: release validation must
succeed before any platform archives can be built or published.

Before publication, asset assembly also unpacks the Linux archive on a fresh
runner whose checkout is at a different path. It verifies embedded demo,
runtime, and viewer assets, real Rust and Node captures, and offline replay
through the installed binary. Any failure prevents publication.

Pull requests and `main` run the strict Linux gate as well. The release
workflow also supports manual dispatch on a selected revision: it validates,
builds both runtime packages and both CLI archives, and assembles checksums as
Actions artifacts without publishing. Only an annotated release-tag push starts
publication.

## Tag And Release

1. Update the workspace version, internal dependency requirements, and lockfile.
2. Finalize the dated changelog entry.
3. Run the complete required verification above.
4. Commit and push the release preparation to `main`; wait for CI to pass.
5. Create and push an annotated tag:

```bash
git tag -a vX.Y.Z -m "ebpf-tracker vX.Y.Z"
git push origin vX.Y.Z
```

For this candidate use `v0.2.0-alpha.4` in place of `vX.Y.Z`.

6. Wait for every `release` workflow job to pass: strict validation, both native runtime-package gates, both CLI platform builds, asset assembly, and publication.
7. Download the public assets afresh, verify their checksums, and confirm the release notes describe the exact supported architectures.

Do not publish a partial release or manually bypass a failed workflow. Fix the
problem and cut a new patch version if a public tag is already wrong.

## Artifact Sanity Checks

The workflow requires both CLI archives, both Bookworm runtime packages, and
`SHA256SUMS` (five public assets):

- `x86_64-unknown-linux-gnu`
- `x86_64-apple-darwin`
- `ebpf-tracker-runtime_0.2.0-alpha.4_amd64.deb`
- `ebpf-tracker-runtime_0.2.0-alpha.4_arm64.deb`

The CLI targets remain Linux x86_64 and Intel macOS. An ARM64 runtime `.deb`
does not establish availability of an ARM64 host CLI archive.

Each archive must contain one top-level directory with the executable
`ebpf-tracker` binary, `LICENSE`, and `README.md`. To validate downloaded or
locally assembled assets without replacing the supplied checksums:

```bash
bash scripts/verify-release-artifacts.sh \
  --dist dist \
  --tag v0.2.0-alpha.4
for runtime_arch in amd64 arm64; do
  bash scripts/verify-runtime-package.sh \
    --deb "dist/ebpf-tracker-runtime_0.2.0-alpha.4_${runtime_arch}.deb" \
    --expected-version 0.2.0-alpha.4 --arch "$runtime_arch"
done
(cd dist && sha256sum -c SHA256SUMS)
```

Also confirm the tagged source matches the release-preparation commit, the
binary prints useful help, and the documented install path remains accurate.
Release assets use the SemVer hyphen in their filenames; local Debian-package
builds and internal package versions use `~`. Assembly renames each package
before generating the combined manifest. Never regenerate a downloaded
`SHA256SUMS` before checking it.

## Post-Release Follow-Up

- Install or run the release from a clean throwaway checkout.
- Verify the public tag, generated notes, both CLI archives, both runtime packages, and the original checksum file.
- Restore an empty `Unreleased` section for the next cycle.
- Record release problems in [TASKLOG.md](./TASKLOG.md).

## Rollback

Do not rewrite a public tag. Correct the issue, cut a follow-up patch release,
and mark the faulty release as superseded where appropriate.
