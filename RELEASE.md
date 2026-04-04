# Release Runbook

This is the maintainer checklist for a first public release of `ebpf-tracker`.
It assumes a GitHub-release-first flow. The workspace crates are marked
`publish = false`, so the release artifact is the tagged source tree and any
binary assets you choose to attach, not a crates.io publish.

## Versioning

- Keep the workspace version in [Cargo.toml](./Cargo.toml) on the release line.
- Use a `vMAJOR.MINOR.PATCH` tag for GitHub releases.
- Bump versions before tagging, then update the changelog entry to match the new release.
- Leave internal workspace crates unpublished unless the release plan explicitly changes.

## Pre-Release Checklist

1. Review [CHANGELOG.md](./CHANGELOG.md) and make sure all user-facing changes are captured under `Unreleased` or moved into the new release section.
2. Confirm the root install story still matches [README.md](./README.md) and [docs/cli.md](./docs/cli.md).
3. Check that example docs still point to runnable commands in [examples/README.md](./examples/README.md).
4. Verify the workspace is clean except for intentional release edits.

## Verification

Run the fast generic gate first:

```bash
bash scripts/release-check.sh
```

That script is the same generic check set used in GitHub-hosted automation:

```bash
cargo fmt --all --check
cargo test --all --locked
cargo build --workspace --locked
cargo build --release --locked --bin ebpf-tracker
cargo run --locked --bin ebpf-tracker -- --help
cargo run --locked --bin ebpf-tracker -- demo --list
```

Before tagging, also run the real tracer smoke path on a maintainer machine
with Docker support:

```bash
bash scripts/release-check.sh --with-runtime-smoke
```

That extra step is intentionally local for now. The project is still early and
the GitHub-hosted workflow does not try to pretend it proves privileged
Docker-backed tracing.

If you are validating the repo-local viewer surface, include:

```bash
bash scripts/dashboard-smoke.sh
```

## Tag And Release

1. Update the version in [Cargo.toml](./Cargo.toml).
2. Update [CHANGELOG.md](./CHANGELOG.md) with the release notes.
3. Run the verification commands above.
4. Commit the release prep.
5. Create and push the tag:

```bash
git tag vX.Y.Z
git push origin vX.Y.Z
```

6. Push the tag and wait for the release workflow to publish the GitHub release.
7. Verify the generated release notes and attached binary artifacts. Create the release manually only if the workflow fails.

## Artifact Sanity Checks

- Confirm the tagged source matches the committed release prep.
- Confirm the release notes mention the supported install path:
  - `cargo install --path . --locked` for local clones
  - `cargo install --git https://github.com/givtaj/ebpf-tracker --locked` for GitHub installs
- Confirm the root CLI still prints useful help and the binary name remains `ebpf-tracker`.
- If artifacts are attached, verify their filenames include the release version and platform.

## Post-Release Follow-Up

- Verify the GitHub release page looks correct and the tag is visible.
- Smoke the install path from a fresh checkout or throwaway directory.
- Update the `Unreleased` section so it is ready for the next cycle.
- Record any release issues in `TASKLOG.md` if follow-up work is needed.

## Rollback

If the release is wrong but the tag is already public, do not rewrite history.
Cut a follow-up patch release, update the changelog, and supersede the bad release with a corrected tag.
