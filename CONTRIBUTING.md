# Contributing

This repository is entering its first public release. Contributions should keep
the current command surface, docs, examples, and tests aligned so a new user can
clone the repo, run the examples, and understand the limits without guessing.

## Local Setup

1. Install the Rust toolchain and Docker Desktop or another Docker engine that
   supports privileged containers.
2. Clone the repository and work from the root.
3. Build the workspace once so Cargo fetches dependencies and verifies the
   local environment:

```bash
cargo build --workspace
```

If you are working on the repo-local dashboard/viewer or the Node example flow,
also make sure Node.js is available on the host.

## Verify Changes

Use the smallest command set that proves your change:

```bash
cargo fmt --all --check
cargo test --all --locked
cargo build --workspace --locked
```

For release-readiness changes, run the generic gate:

```bash
bash scripts/release-check.sh
```

If your change touches the CLI run path, Docker/runtime orchestration, demos, or
release packaging, also run the real tracer smoke path on a machine with Docker:

```bash
bash scripts/runtime-smoke.sh
```

For CLI or example changes, also run a focused command that exercises the path
you touched. Useful examples from this repo include:

```bash
cargo run --bin ebpf-tracker -- --help
cargo run --bin ebpf-tracker -- /bin/true
cargo demo --list
cargo demo session-io-demo
bash scripts/dashboard-smoke.sh
```

If your change affects a particular example or viewer flow, run that example or
smoke script directly instead of relying only on the full workspace test run.

## Commit And PR Expectations

- Keep each change focused on one main behavior or documentation topic.
- Write commit messages and PR titles that describe the user-facing effect.
- Include tests or the reasoning for why tests are not needed when behavior
  changes.
- Avoid mixing unrelated refactors with feature work.
- Do not commit generated artifacts or logs unless the change is specifically
  about those assets.

## Keep Docs Current

This repo has multiple user-facing entry points:

- [`README.md`](./README.md) for the high-level product summary
- [`docs/cli.md`](./docs/cli.md) for detailed CLI behavior
- [`examples/README.md`](./examples/README.md) for runnable demo guidance
- crate-level READMEs for package-specific behavior

When you change a command, flag, example, or runtime assumption, update the
relevant docs in the same change. If the behavior is visible in an example,
update that example's README and any linked smoke command or sample output.

Examples should stay runnable from a local clone. If you change a demo manifest,
its inputs, or its generated outputs, make sure the example README still shows
the correct invocation and expected result.

## Notes For First-Time Maintainers

- Keep the workspace checks green before merging.
- Prefer updating the docs alongside the code rather than after the fact.
- If a change introduces a new repo-local command or alias, document it in the
  root README and the relevant detail page.
- If you add or change a release note, keep `CHANGELOG.md` in sync with the
  user-visible change.
