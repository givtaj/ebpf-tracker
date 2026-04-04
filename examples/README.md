# Examples

This directory contains runnable demo projects for `ebpf-tracker`.

These examples are for people working from a local clone of
`ebpf-tracker`. They are not installed by `cargo install`.

Generated example outputs such as `logs/` and `dist/` appear only after you run
the demos locally. They are runtime artifacts, not committed release assets.

## How To Run An Example

Recommended from the repo root:

```bash
cargo demo
```

That launches the default example, `session-io-demo`.

To run a specific example:

```bash
cargo demo session-io-demo
```

To run the same example with the `perf` transport:

```bash
cargo demo --transport perf session-io-demo
```

To see the list of available examples:

```bash
cargo demo --list
```

Under the hood, `cargo demo` is a Cargo alias that runs the Rust CLI's `demo`
subcommand. Each example is declared by an `ebpf-demo.toml` manifest inside its
directory:

- `runtime` selects the Rust or Node tracing image
- `command` is the traced command to run inside that example
- `clean` is optional and runs before launch
- `product_*` and `sponsor_*` fields are optional demo-branding metadata that
  the viewer and replay logs preserve

From a repo-built binary, the same manifests can also be launched outside the
repository root:

```bash
/path/to/ebpf-tracker/target/debug/ebpf-tracker demo session-io-demo
/path/to/ebpf-tracker/target/debug/ebpf-tracker demo --dashboard session-io-demo
```

Dashboard runs still execute the example's `ebpf-demo.toml` manifest, but they
also preserve a replayable session log in that example's `logs/` directory.
From the repo root, use
`cargo viewer --replay examples/session-io-demo/logs/ebpf-tracker-YYYYMMDD-HHMMSS.log`
to walk backward or forward through a stored run.
That stored log now includes the manifest's product/sponsor metadata as a
typed `session` record, so replay keeps the same demo branding as the live run.

For a tool-friendly event stream instead of human-oriented terminal output:

```bash
cargo demo --emit jsonl session-io-demo
```

In that mode, `stdout` is reserved for JSON Lines events, so another app can
pipe, store, or render the trace stream while `stderr` still shows normal app
and runtime output.

You can also turn the same run into a reusable dataset bundle:

```bash
cargo demo --emit jsonl session-io-demo | cargo dataset --test-name session-io-demo
```

Then analyze the captured run with a local LM Studio model:

```bash
cargo dataset analyze --run datasets/<run-id> --provider lm-studio --model qwen/qwen3.5-9b
```

Or let the main tool supervise that flow for you:

```bash
cargo see --intelligence-dataset session-io-demo
```

That keeps the dashboard live while a background dataset worker buffers the
trace, writes a dataset bundle, schedules the LM Studio analysis, and reports
its phase plus any final summary in the UI.

Without `--emit`, the default mode is `raw`.
Without `--transport`, the default transport is `bpftrace`.

The `perf` transport is available too:

```bash
cargo demo --transport perf --emit jsonl session-io-demo
```

That keeps the same JSONL contract while swapping the runtime collector from
`bpftrace` to Linux `perf trace`. In `perf` mode, file-path fields are
best-effort and may be omitted when `perf trace` cannot decode userspace string
arguments.

To view the same example in Jaeger:

```bash
cargo jaeger up
cargo demo --emit jsonl session-io-demo | cargo otel --target jaeger --service-name session-io-demo
```

## What To Expect

- the first run may build the Docker image
- trace output will include the whole wrapped command session, not only your app
- raw JSONL may include Cargo, wrapper, and container-runtime noise around the app
- files written by the example stay inside that example directory, usually under
  `logs/` or `dist/`

For `session-io-demo`, the app-level signal to look for is usually:

- `openat` on `input/message.txt`
- `connect` from `session-io-demo`
- `openat` on `logs/session-summary.txt`
- `write` from `session-io-demo`

## Available Examples

- [session-io-demo](./session-io-demo/README.md): demonstrates build-time file
  generation plus runtime file, network, and output activity in one trace
- [postcard-generator-rust](./postcard-generator-rust/README.md): generates a
  visible postcard with Rust and writes HTML, SVG, and JSON artifacts
- [postcard-generator-node](./postcard-generator-node/README.md): mirrors the
  same visible postcard workflow in Node.js
