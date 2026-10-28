# Release Runbook

This is the maintainer checklist for public releases of `ebpf-tracker`.
Releases are GitHub-first: workspace crates remain `publish = false`, so the
tagged source tree and attached binary archives are the public artifacts.

## Release Line

`0.2.0-alpha.2` follows the
[Axum-on-Docker alpha contract](./docs/alpha-scope.md), using Roots as the
reference service. The selected integration installs the native agent inside
the API image. The isolated Axum/PostgreSQL acceptance must pass against the
actual Debian package; generic command/replay checks do not approve this
release. It is not published merely because the workspace has this version. Runtime gates, the Debian package, both platform archives, and
checksums must pass before publication.

## Versioning

- Keep the workspace version in [Cargo.toml](./Cargo.toml) on the release line.
- Use annotated `vMAJOR.MINOR.PATCH` tags, or prereleases such as
  `v0.2.0-alpha.2`. Supported prerelease channels are `alpha.N`, `beta.N`, and
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
  --expected-version 0.2.0-alpha.2 \
  --with-runtime-smoke \
  --with-demo-smoke \
  --with-isolation-smoke \
  --with-customer-ux
```

Replace `0.2.0-alpha.2` with the version being released. This gate verifies formatting,
the locked workspace tests and builds, CLI discovery, a real traced workload,
descendant capture and unrelated-process exclusion, and all supported customer
journeys. `--with-customer-ux` is strict: a missing prerequisite or skipped
journey fails the release check.

Optional focused checks remain available for maintainers:

```bash
bash scripts/build-runtime-deb.sh --platform linux/amd64 --output-dir dist/runtime
bash scripts/in-container-smoke.sh \
  --package dist/runtime/ebpf-tracker-runtime_0.2.0~alpha.2_amd64.deb
bash scripts/dashboard-smoke.sh --check
bash scripts/dataset-smoke.sh
bash scripts/customer-ux-check.sh --strict-prereqs --fail-on-skip
```

The first two checks are mandatory for the in-container alpha. Use the matching
arm64 platform/package when validating a native arm64 development host. The
runtime package must be built on Bookworm, installed in a clean image without
Cargo, and pass its live architecture-specific gate. The published runtime
package is amd64 until another architecture has its own release gate.

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
builds both archives, and assembles checksums as Actions artifacts without
publishing. Manual dispatch becomes available once that workflow change is on
the default branch. Only an annotated release-tag push starts publication.

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

For this candidate use `v0.2.0-alpha.2` in place of `vX.Y.Z`.

6. Wait for every `release` workflow job to pass: strict validation, both platform builds, asset assembly, and publication.
7. Verify the release notes, archives, and checksums on the GitHub release page.

Do not publish a partial release or manually bypass a failed workflow. Fix the
problem and cut a new patch version if a public tag is already wrong.

## Artifact Sanity Checks

The workflow requires both of these CLI archives, the Bookworm amd64 runtime
package, and `SHA256SUMS`:

- `x86_64-unknown-linux-gnu`
- `x86_64-apple-darwin`
- `ebpf-tracker-runtime_0.2.0~alpha.2_amd64.deb`

Each archive must contain one top-level directory with the executable
`ebpf-tracker` binary, `LICENSE`, and `README.md`. To validate downloaded or
locally assembled assets without replacing the supplied checksums:

```bash
bash scripts/verify-release-artifacts.sh \
  --dist dist \
  --tag v0.2.0-alpha.2
bash scripts/verify-runtime-package.sh \
  --deb dist/ebpf-tracker-runtime_0.2.0~alpha.2_amd64.deb \
  --expected-version 0.2.0-alpha.2 --arch amd64
(cd dist && sha256sum -c SHA256SUMS)
```

Also confirm the tagged source matches the release-preparation commit, the
binary prints useful help, and the documented install path remains accurate.

## Post-Release Follow-Up

- Install or run the release from a clean throwaway checkout.
- Verify the public tag, generated notes, both platform archives, and checksum file.
- Restore an empty `Unreleased` section for the next cycle.
- Record release problems in [TASKLOG.md](./TASKLOG.md).

## Rollback

Do not rewrite a public tag. Correct the issue, cut a follow-up patch release,
and mark the faulty release as superseded where appropriate.
