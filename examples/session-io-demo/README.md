# Session IO Demo

This example shows the main benefit of `eBPF_tracker`: one wrapped `cargo run`
surfaces both build-time and runtime activity without adding instrumentation to
the Rust code.

What the demo does:

- `build.rs` reads `input/message.txt` and writes generated Rust into `target`
- the app reads the same file again at runtime
- the app opens a loopback TCP connection and exchanges one message
- the app writes a summary file into `logs/session-summary.txt`

Run it from the repo root:

```bash
cargo demo session-io-demo
```

Stream the same demo as JSON Lines:

```bash
cargo demo --emit jsonl session-io-demo
```

That keeps `stdout` machine-readable so another program can consume the event
stream directly.

Without `--emit`, the default mode is `raw`.

Look for trace lines that show the benefit:

- `openat` against `input/message.txt`
- `write` calls during code generation and runtime output
- `connect` from the demo binary to `127.0.0.1`
- `execve` from the overall Cargo session

Why this is a good first example:

- it is self-contained
- it uses only the Rust standard library
- it demonstrates hidden build-script side effects and app behavior in one run
