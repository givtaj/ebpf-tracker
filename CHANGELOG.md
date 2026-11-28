# Changelog

This file tracks notable repo changes in progress on this branch.

## Unreleased

### Verification

- Verify the published alpha.4 ARM64 package on the existing Roots development setup: read-only health, completed-open capture, shutdown and public-CLI replay PASS; recorded files/Git edits and logical database contents preserved, initial Roots service state restored. Record the external HTTPS mirror adjustment and concurrent unrelated Docker activity in the [pilot receipt](docs/roots-pilot-2026-11-28.md).

## v0.2.0-alpha.4 - 2026-11-28

### Added

- Add missing-file debugging for the synthetic Axum Docker example: completed `openat` results and errno in the in-container capture, a deterministic missing-file HTTP scenario, and readable failure evidence in offline replay. Legacy captures retain unknown outcomes; other syscall kinds remain entry-only observations.

### Documentation

- Record alpha.4 exact-tag publication, all five public asset digests, both download recipes and fresh ARM64 missing-file capture/replay acceptance, including the local Debian HTTP timeout and fixture-only HTTPS retry.
- Retain the alpha.4 implementation reviews and local ARM64 capture/replay acceptance notes, including the corrected worker-name assertion and viewer labels.
- Update the release notes and architecture-specific download guide for alpha.4 while retaining the trusted development/CI and whole-session evidence limits.

### Verification

- Explain the pilot's default Docker bridge ID change: the read-only preparation container woke Docker Desktop from Resource Saver mode, and daemon startup recreated its default bridge; no Roots/database or network changes were made during investigation.

- Verify the published alpha.3 ARM64 runtime on the existing Roots development setup: read-only health, capture, shutdown and public-CLI replay pass; current edits and logical database contents are preserved, with initial service state restored. See the [pilot receipt](docs/roots-pilot-2026-11-25.md).

## v0.2.0-alpha.3 - 2026-11-25

### Added

- Add a Bookworm ARM64 runtime package alongside amd64, with native architecture-specific package installation, Axum/PostgreSQL capture, isolation, lifecycle and offline replay gates in CI and releases.

### Changed

- Verify each architecture's original package manifest separately, then assemble both GitHub-safe runtime filenames and the two existing host CLI archives into one complete checksum manifest before publication.
- Update Docker installation instructions to select amd64 or ARM64 explicitly while retaining the trusted development/CI, privileged-container and host-PID requirements.

### Documentation

- Record alpha.3 exact-tag publication, original public asset digests, both copy-paste download recipes and fresh ARM64 installed-package capture/replay acceptance in the release validation receipt.
- Record the [existing Roots development pilot](docs/roots-pilot-2026-11-25.md): an ARM64 build from the alpha.2 tag passed read-only health verification, scoped process capture, shutdown and offline replay. Logical database hashes matched and the initial service state was restored; the public report excludes local operational details and raw traces.

## v0.2.0-alpha.2 - 2026-10-28

### Fixed

- Use GitHub-safe public runtime filenames and matching checksum entries while retaining Debian prerelease metadata; published alpha.2 binary bytes are unchanged.

- Publish synthetic noise markers atomically so the isolation test cannot read an empty file between truncation and write; retain the full capture and noise-exclusion assertions.

- Clean up root-owned files from the installed-archive acceptance fixture without changing application captures or swallowing failures. The alpha.1 tag passed its product checks but publication was withheld when fixture cleanup failed; the tag remains unchanged.

## v0.2.0-alpha.1 - 2026-10-28

### Added

- Added a native Linux `ebpf-tracker-agent` entrypoint for an existing Bookworm API image, with non-root workload execution, separate JSONL capture, graceful shutdown, and workload exit-status preservation.
- Added a Bookworm runtime Debian package, checksum/installation verification, and an isolated Axum/PostgreSQL container acceptance fixture, verified on native amd64 CI and a local arm64 Linux VM.
- Added Dockerfile, Compose, and CI installation instructions for the same-container workflow. Roots remains a reference only; no Roots source, configuration, services, or data are changed.
- Added `ebpf-tracker replay <file>` to reopen saved JSONL or raw logs from the installed CLI using the bundled viewer, without starting Docker.
- Added `--version` and `-V` to identify the installed release candidate.
- Added release-tooling and customer-command resolution regression checks.
- Added an installed Linux archive gate covering embedded assets, Rust and Node capture, and offline replay before publication.

### Fixed

- Strengthened native Linux acceptance to require application-leader startup and fast-exit capture.
- Pinned live CI/release gates to Ubuntu 22.04 and reject the known-bad `7.0.0-1017-azure` host kernel, which silently drops syscall events on other CPUs (actions/runner-images#15003).
- Fixed customer CLI validation resolving the tracker from a temporary application's Cargo manifest after changing directories; failures now include bounded diagnostics.
- Accepted explicit alpha, beta, and release-candidate tags and marked them as GitHub prereleases.
- Pinned release customer checks to the freshly built candidate and made archive verification compatible with macOS Bash.
- Preserve the wrapped workload's exit status when bpftrace reports its own successful completion.
- Preserved downloaded release checksums during artifact sanity checks, including the runtime package.
- Wait for both viewer HTTP readiness and launcher readiness logs in customer checks, avoiding a race on fast-starting viewers.

### Changed

- Focused the alpha on launching an API inside its existing Bookworm container and recording its process lifetime. Added synthetic Axum/PostgreSQL acceptance; existing-container attachment and real Roots acceptance remain separate. Deferred cloud, monitoring, general Node.js workload, perf, AI, dataset, and OTLP feature expansion.
- Made the sample config enable all four supported probes and clarified host Node requirements and syscall-attempt limitations.
- Added strict Linux release validation on pull requests and a manual release-workflow path that builds verified archives without publishing.
- Added a persisted Rust `CARGO_HOME` cache to the managed tracing runtime and documented the build-first direct-binary workflow for app-level Rust traces.

## v0.1.1 - 2026-09-27

### Security

- Scoped the built-in and generated bpftrace probes to the wrapped process tree, including descendants, while excluding unrelated host activity.
- Made arbitrary custom probes fail closed unless the operator explicitly accepts host-wide tracing with `--allow-host-wide-probe`.
- Documented that the privileged, host-PID, read-write-mounted runtime is only for trusted workloads and that workload filtering is not a security boundary.

### Added

- Added a terminal-first `ebpf-tracker monitor` droplet overview with `/proc`, bounded Docker/eBPF health reads, sanitized host-derived text, and host-readiness docs for clean Linux development boxes.
- Added a live runtime-isolation smoke test covering parent and descendant capture plus concurrent host-noise exclusion.
- Added deterministic Linux and Intel macOS release archives, verified archive contents, executable-bit checks, and `SHA256SUMS`.

### Fixed

- Fixed the customer viewer E2E diagnostic so strict public CI no longer fails because `printf` parses the divider as an option.
- Switched the tag-driven release workflow to the current `macos-15-intel` hosted runner label.
- Fixed repo-local `cargo demo` and `cargo see` aliases to use the current `ebpf-tracker` binary name.

### Changed

- Positioned the project as an experimental alpha for trusted Rust and Node.js workloads rather than a general production observability tool.
- Added a supported-surface matrix and a golden `session-io-demo` workflow, and aligned docs on `openat` probe names versus the `open_at` JSON event kind.
- Made CI and tagged releases fail on missing scripts, skipped customer journeys, runtime isolation regressions, or incomplete platform artifacts instead of publishing a partial fallback release.
- Refreshed the root onboarding copy, CLI help, and example docs so installed-binary tracing is separated cleanly from checkout-only `demo` and `see` flows.
- Reworked the live trace viewer layout and replay controls, including clearer status grouping, replay-library placement, reduced-motion handling, and tracker-binary resolution from either `PATH` or a repo build.
- Added black-box verification for viewer replay, dataset ingest/analyze, traced demos, first-run CLI, and trace-your-app customer journeys.
- Hardened customer UX checks with explicit `SKIP` semantics, strict-prerequisite enforcement, and external analyze-endpoint support for constrained environments.

## v0.1.0 - 2026-04-04

### Added

- Added the `ebpf-tracker-viewer` workspace crate to own the dashboard and replay viewer.
- Added the `ebpf-tracker-dataset` workspace crate to turn JSONL streams and replay logs into per-run dataset bundles.
- Added dataset analysis support for local or remote OpenAI-compatible backends, including LM Studio defaults.
- Added a `cargo viewer` workspace alias for launching the viewer locally.
- Added a `cargo dataset` workspace alias for launching the dataset tool locally.
- Added a typed `session` stream record for demo branding metadata.
- Added demo manifest branding fields and propagated them into demo runtime environment variables.
- Added an `ebpf-tracker see` shortcut and matching `cargo see` alias for the default dashboard demo flow.
- Added root agent workflow guidance in `AGENT.md`.
- Added an initial `attach` CLI scaffold and backend adapter layer so customer-owned container and Kubernetes targets can sit beside the existing managed runtime path.
- Added a baseline GitHub Actions CI workflow for formatting, build, and test checks on pushes and pull requests.
- Added a tag-driven GitHub Actions release workflow that builds and attaches release archives for the main CLI.
- Added first-release repository scaffolding with `CONTRIBUTING.md`, `SECURITY.md`, `RELEASE.md`, and GitHub issue/PR templates.
- Added `scripts/release-check.sh` as a fast generic verification gate for local release prep and tagged builds.
- Added `scripts/runtime-smoke.sh` for a minimal real tracing smoke path on a maintainer machine with Docker support.

### Changed

- Moved the live trace matrix viewer asset out of `scripts/` into `crates/ebpf-tracker-viewer`.
- Wired dashboard mode to preserve replayable logs and documented replay via the viewer crate.
- Bundled small replay samples into the viewer crate and refreshed the README/docs wording around the current event schema.
- Moved session-trace construction into `ebpf-tracker-events` so multiple consumers can share the same trace summary model.
- Tightened viewer-side noise filtering for infra and toolchain file paths in the live matrix dashboard.
- Updated examples and docs to describe replay flow, manifest-driven demos, and branded demo artifacts.
- Updated docs to describe dataset capture, replay-log ingestion, local analysis, and the shorter `see` entrypoint.
- Capped dataset analysis prompt sections so LM Studio can accept runs on smaller `4096`-token local contexts.
- Added an `--intelligence-dataset` flow that supervises dataset capture and LM Studio analysis from the main tracer, with live dashboard status.
- Added optional live dataset-analysis tracing so LM Studio server logs and analyzer progress can be watched in real time and persisted per run.
- Documented AWS-first attach scoping around EKS on EC2 and captured the remaining backend/platform follow-up work in `TASKLOG.md`.
- Clarified the README vocabulary for `run` versus `attach` and made the attach direction explicitly depend on existing eBPF backends instead of a homegrown Kubernetes control plane.
- Switched the LM Studio dataset analyzer path to LM Studio's native chat API with reasoning disabled so local Qwen models return final analysis content reliably.
- Made dataset-analysis live logging truly opt-in instead of always echoing analyzer progress on `stderr`.
- Scoped the Docker cleanup helper to tracked `ebpf-tracker` Compose projects so it no longer removes generic cache volumes or prunes global Docker cache unless `--all` is requested.
- Made `cargo viewer --help` print deterministic usage instead of launching the browser, and corrected replay examples to use `cargo viewer --replay ...`.
- Marked the root CLI package and viewer crate as `publish = false` so the initial public release stays GitHub-release-first instead of implying a crates.io publish.
- Clarified the install and example docs around the GitHub-first release path, repo-local aliases, and generated demo artifacts.
- Tightened release verification around the checked-in lockfile, fixed the tagged-build target handling in the release workflow, and ignored repo-root release archives under `dist/`.
- Realigned the release/docs surface for a solo maintainer so GitHub-hosted automation stays generic while local release prep still exercises the real tracer path.
