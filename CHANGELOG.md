# Changelog

This file tracks notable repo changes in progress on this branch.

## Unreleased

### Added

- Added the `ebpf-tracker-viewer` workspace crate to own the dashboard and replay viewer.
- Added the `ebpf-tracker-dataset` workspace crate to turn JSONL streams and replay logs into per-run dataset bundles.
- Added dataset analysis support for local or remote OpenAI-compatible backends, including LM Studio defaults.
- Added a `cargo viewer` workspace alias for launching the viewer locally.
- Added a `cargo dataset` workspace alias for launching the dataset tool locally.
- Added a typed `session` stream record for demo branding metadata.
- Added demo manifest branding fields and propagated them into demo runtime environment variables.
- Added an `eBPF_tracker see` shortcut and matching `cargo see` alias for the default dashboard demo flow.
- Added root agent workflow guidance in `AGENT.md`.

### Changed

- Moved the live trace matrix viewer asset out of `scripts/` into `crates/ebpf-tracker-viewer`.
- Wired dashboard mode to preserve replayable logs and documented replay via the viewer crate.
- Bundled small replay samples into the viewer crate and refreshed the README/docs wording around the current event schema.
- Moved session-trace construction into `ebpf-tracker-events` so multiple consumers can share the same trace summary model.
- Tightened viewer-side noise filtering for infra and toolchain file paths in the live matrix dashboard.
- Updated examples and docs to describe replay flow, manifest-driven demos, and branded demo artifacts.
- Updated docs to describe dataset capture, replay-log ingestion, local analysis, and the shorter `see` entrypoint.
