# Session IO Demo

This example shows the main benefit of `ebpf-tracker`: one wrapped `cargo run`
surfaces both build-time and runtime activity without adding instrumentation to
the Rust code.

It is meant to be run from a local clone of `ebpf-tracker`.

Manifest for this example:

```toml
runtime = "rust"
command = ["cargo", "run"]
clean = ["cargo", "clean", "--quiet", "--target-dir", "target"]
product_name = "ebpf-tracker"
product_tagline = "Trace the full command session, then replay it."
sponsor_name = "ebpf-tracker"
sponsor_message = "Replayable syscall demos for Rust and Node."
sponsor_url = "https://github.com/givtaj/ebpf-tracker"
```

What the demo does:

- `build.rs` reads `input/message.txt` and writes generated Rust into Cargo's `OUT_DIR`
- the app reads the same file again at runtime
- the app opens a loopback TCP connection and exchanges one message
- the app writes a summary file into `logs/session-summary.txt`
- the app prints the generated message, the server reply, and a final `wrote logs/session-summary.txt` line

Run it from the repo root:

```bash
cargo demo session-io-demo
```

Run the same manifest from anywhere with a repo-built binary:

```bash
/path/to/ebpf-tracker/target/debug/ebpf-tracker demo session-io-demo
```

Open the live dashboard for the same example:

```bash
/path/to/ebpf-tracker/target/debug/ebpf-tracker demo --dashboard session-io-demo
```

That dashboard run still uses the same `ebpf-demo.toml` manifest and keeps a
replayable trace log under the example's `logs/` directory, so from the repo
root you can reopen the session later with
`cargo viewer --replay examples/session-io-demo/logs/ebpf-tracker-YYYYMMDD-HHMMSS.log`.
The stored `session` record carries the same product/sponsor metadata into
replay.

Stream the same demo as JSON Lines:

```bash
cargo demo --emit jsonl session-io-demo
```

That keeps `stdout` machine-readable so another program can consume the event
stream directly.

Without `--emit`, the default mode is `raw`.

Run the same demo with the `perf` transport:

```bash
cargo demo --transport perf --emit jsonl session-io-demo
```

That keeps the JSONL contract stable while switching the runtime collector from
`bpftrace` to Linux `perf trace`. In `perf` mode, the `connect` and `write`
events stay useful, while `openat` file paths are best-effort and may be
omitted when `perf trace` cannot decode userspace string arguments.

Send the same stream into Jaeger:

```bash
cargo jaeger up
cargo demo --emit jsonl session-io-demo | cargo otel --target jaeger --service-name session-io-demo
```

Look for trace lines that show the benefit:

- `openat` against `input/message.txt`
- `write` calls during code generation and runtime output
- `connect` from the demo binary to `127.0.0.1`
- `execve` from the overall Cargo session

In the raw JSONL stream you will also see expected session noise from `cargo`,
the exec wrapper, and sometimes container-runtime processes. The clean
app-level sequence is:

- `openat` on `input/message.txt`
- `connect` from `session-io-demo`
- `openat` on `logs/session-summary.txt`
- `write` from `session-io-demo`

Why this is a good first example:

- it is self-contained
- it uses only the Rust standard library
- it demonstrates hidden build-script side effects and app behavior in one run
- it exercises the same session/replay metadata that the dashboard and viewer use
