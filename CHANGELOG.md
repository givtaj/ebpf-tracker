# Changelog

This file tracks notable repo changes in progress on this branch.

## Unreleased

### Fixed

- Switched the tag-driven release workflow to GitHub's current `macos-15-intel` hosted runner label so macOS release builds do not cancel before execution.

### Changed

- Refreshed the root onboarding copy, CLI help, and example docs so installed-binary tracing is separated cleanly from checkout-only `demo` and `see` flows.
- Reworked the live trace viewer layout and replay controls, including clearer status grouping, replay-library placement, reduced-motion handling, and tracker-binary resolution that can use either `ebpf-tracker` on `PATH` or a repo build.
- Added a black-box release smoke path for viewer replay, dataset ingest/analyze, and traced demo commands, plus CI and release workflow integration for the non-Docker checks.
- Fixed the repo-local `cargo demo` and `cargo see` aliases so they point at the current `ebpf-tracker` binary name again.

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
