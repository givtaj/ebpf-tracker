# `ebpf-tracker-viewer`

> Experimental workspace crate. It is `publish = false`, and the UI is a local
> development viewer rather than an authenticated production service.

`ebpf-tracker-viewer` provides a browser dashboard for live normalized streams
and stored replay logs. The Rust binary resolves/materializes the bundled Node
script, launches it, forwards stdio, and opens the announced URL when possible.

## Prefer Replay For Safe UI Work

Replay does not start a new privileged trace:

```bash
cargo viewer --replay crates/ebpf-tracker-viewer/demo-library/session-io-demo.jsonl
cargo viewer --port 43118 --replay datasets/synthetic-jsonl-demo/events.jsonl
```

Replay controls include restart, pause/resume, step forward/backward,
fast-forward, speed, interval, and jump size. `--focus-comm` filters records to
one command before processing:

```bash
cargo viewer --speed 2 --interval-ms 50 --focus-comm node \
  --replay logs/ebpf-tracker-YYYYMMDD-HHMMSS.log
```

The bundled fixtures use the shared JSON contract, including `open_at` for the
JSON event kind (`openat` remains the raw/aggregate spelling).

## Live Mode

```bash
cargo viewer
cargo viewer -- cargo run --help
cargo run -p ebpf-tracker-viewer -- --replay logs/ebpf-tracker-YYYYMMDD-HHMMSS.log
```

Without `--replay`, the launcher traces a command through `ebpf-tracker`. With
no command, it defaults to:

```bash
ebpf-tracker demo session-io-demo
```

If `ebpf-tracker` is not on `PATH`, clone-local mode falls back to
`./target/debug/ebpf-tracker`. It preserves explicit tracker commands and
injects these defaults when missing:

- `--log-enable`
- `--emit jsonl`
- `--transport bpftrace`

Live mode therefore inherits the root CLI's privileged-container, host-PID, and
read-write-mount security boundary. Use it only for trusted code on an isolated
development host. Replay mode is the appropriate choice when collector behavior
is not under test.

## Bind And Browser Behavior

The server binds to `127.0.0.1` by default. `--host` selects another address:

```bash
cargo viewer --host 0.0.0.0 --replay logs/ebpf-tracker-YYYYMMDD-HHMMSS.log
```

Binding beyond loopback exposes an unauthenticated development UI and trace
data. Do so only on a controlled network with external access controls. If the
port is occupied, the viewer tries up to 16 subsequent ports. Browser opening
is attempted on macOS, Linux, and Windows after the server announces its URL.

`--speed` and `--interval-ms` apply only to replay. Replay controls are disabled
for a live stream.

## Assets And Cache

The source asset is
[`assets/live-trace-matrix.js`](./assets/live-trace-matrix.js). Override it with
`EBPF_TRACKER_VIEWER_SCRIPT` for development. If checked-in assets are not
available, the launcher materializes embedded files in this order:

1. `EBPF_TRACKER_CACHE_DIR`
2. `XDG_CACHE_HOME/ebpf-tracker`
3. `~/.cache/ebpf-tracker`
4. the system temp directory

The embedded demo library includes `session-io-demo`,
`postcard-generator-rust`, and `postcard-generator-node`. Clone-local mode also
discovers `.log` files under root `logs/` and `examples/*/logs/`.

## Limits

- The UI is browser-first and has no native TUI.
- The default live target is the bundled demo, not a generic shell.
- Fixtures are curated examples, not compatibility or performance evidence.
- Trace records can expose process names, PIDs, file paths, and command
  metadata; inspect captures before sharing.
- The viewer consumes whatever normalized stream it receives and cannot enforce
  upstream probe scope.
