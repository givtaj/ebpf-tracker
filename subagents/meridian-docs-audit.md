# Meridian Docs Audit

- Agent: `Meridian`
- Scope: README and documentation refresh
- Status: completed

## What Changed

- Normalized syscall naming in the docs to `openat` where the current event schema uses that form.
- Tightened example wording around replay logs, dashboard runs, and helper crates.
- Kept the scope to documentation-only paths and left source code untouched.

## Files Updated

- `README.md`
- `docs/trace-payment-engine.md`
- `examples/README.md`
- `examples/session-io-demo/README.md`
- `crates/ebpf-tracker-viewer/README.md`
- `crates/ebpf-tracker-dataset/README.md`

## Intentionally Left Alone

- Source files in `src/`, `crates/**/src/`, and `examples/**/src/`
- The existing dirty worktree outside the documentation surface
