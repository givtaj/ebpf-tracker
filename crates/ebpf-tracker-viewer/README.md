# ebpf-tracker-viewer

Browser-based live trace dashboard and replay viewer for `ebpf-tracker`.

This crate ships the UI in [`assets/live-trace-matrix.js`](./assets/live-trace-matrix.js)
and the bundled demo replays in [`demo-library/`](./demo-library/). The Rust
binary is a small launcher: it resolves or materializes the Node script, starts
`node`, forwards stdio, and opens the browser when the server announces its
URL.

## Commands

Viewer help:

```bash
cargo viewer --help
```

Live trace with the default repo-local demo target:

```bash
cargo viewer
```

Replay a stored log:

```bash
cargo viewer --replay logs/ebpf-tracker-YYYYMMDD-HHMMSS.log
```

Replay with an explicit port:

```bash
cargo viewer --port 43118 --replay datasets/synthetic-jsonl-demo/events.jsonl
```

Bind to another host or tune replay playback:

```bash
cargo viewer --host 0.0.0.0 --speed 2 --interval-ms 50 --focus-comm node --replay logs/ebpf-tracker-YYYYMMDD-HHMMSS.log
```

Pass `--help` through to the traced command instead of the viewer:

```bash
cargo viewer -- cargo run --help
```

Run the binary directly:

```bash
cargo run -p ebpf-tracker-viewer -- --replay logs/ebpf-tracker-YYYYMMDD-HHMMSS.log
```

## Behavior

Without `--replay`, the wrapper traces a command session through
`ebpf-tracker`. If no command is supplied, it defaults to:

```bash
./target/debug/ebpf-tracker demo session-io-demo
```

If the command starts with `ebpf-tracker` or `./target/debug/ebpf-tracker`,
the wrapper preserves that command and injects JSONL logging defaults when they
are missing. The `demo` shorthand is also rewritten to the repo-local tracker
binary.

The injected defaults are:

- `--log-enable`
- `--emit jsonl`
- `--transport bpftrace` unless you already supplied a transport

Replay mode is enabled by `--replay`. In replay mode the viewer can:

- restart
- pause and resume
- step forward or backward
- fast-forward
- adjust replay speed
- adjust jump size

`--speed` and `--interval-ms` only apply in replay mode. `--focus-comm`
filters replay records to a single `comm` value before the viewer processes the
log.

`--host` controls the bind address used by the local viewer server.

The browser opens automatically on macOS, Linux, and Windows when the server
announces `live trace viewer on ...`. If the configured port is busy, the
viewer retries the next port up to 16 times.

## Assets

The launcher prefers the checked-in script at
[`assets/live-trace-matrix.js`](./assets/live-trace-matrix.js). You can point
`EBPF_TRACKER_VIEWER_SCRIPT` at a different file if you want to override it.

If the script is not available at runtime, the crate materializes the embedded
viewer assets into the cache root, in this order:

- `EBPF_TRACKER_CACHE_DIR`
- `XDG_CACHE_HOME/ebpf-tracker`
- `~/.cache/ebpf-tracker`
- the system temp directory

The generated viewer tree includes the script plus the bundled demo replays:

- `session-io-demo`
- `postcard-generator-rust`
- `postcard-generator-node`

The live viewer also discovers recorded `.log` files under the repository
`logs/` directory and under `examples/*/logs/` when those exist.

## Current Limits

- This crate is browser-first; it does not expose a separate native TUI.
- Replay controls are disabled in live-stream mode.
- The default live target is the repo-local tracker demo command, not a generic
  shell command.
- The bundled replays are fixed fixtures, not an exhaustive archive of all
  possible sessions.
