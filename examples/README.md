# Examples

This directory contains runnable demo projects for `eBPF_tracker`.

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
subcommand. The examples are designed to be launched from the repository root.

For a tool-friendly event stream instead of human-oriented terminal output:

```bash
cargo demo --emit jsonl session-io-demo
```

In that mode, `stdout` is reserved for JSON Lines events, so another app can
pipe, store, or render the trace stream while `stderr` still shows normal app
and runtime output.

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
- files written by the example stay inside that example directory, usually under
  `logs/`

## Available Examples

- [session-io-demo](./session-io-demo/README.md): demonstrates build-time file
  generation plus runtime file, network, and output activity in one trace
