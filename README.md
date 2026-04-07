# ebpf-tracker

`ebpf-tracker` is the installable CLI in this workspace. It wraps commands such
as `cargo run` or `npm run`, runs them inside a Linux Docker runtime, and
attaches tracing for the lifetime of that session.

## Choose Your Path

If you want to trace your own project, start with the installable CLI and run a
real smoke test:

```bash
ebpf-tracker /bin/true
ebpf-tracker cargo run
```

Expect the full wrapped session, including build tooling such as `cargo`,
`rustc`, and linkers before your app starts.

If you want the product experience first, use one of the demo/dashboard entry
points:

```bash
ebpf-tracker demo --dashboard session-io-demo
ebpf-tracker see
```

Run either command, not both at once. Each command opens the browser dashboard,
preserves replay logs, and is a supported first-run path for bundled demos. The
`cargo demo`, `cargo see`, and `cargo viewer` aliases are clone-only
conveniences for people working from this repository.

The customer UX suite is documented in [`docs/customer-ux-e2e.md`](./docs/customer-ux-e2e.md).
Its scripts may return `SKIP` on hosts that lack Docker or loopback support;
maintainers can force those capability gaps to fail with `--strict-prereqs`.

This README stays intentionally high level. The root should explain the product
and the workspace shape. Detailed CLI behavior, install steps, and run modes
belong in [`docs/cli.md`](./docs/cli.md).

## What It Does

- runs Rust and Node commands inside a managed Linux tracing runtime
- traces the full wrapped session, not only the final app process
- supports `bpftrace` by default and `perf trace` as an alternate transport
- can emit raw terminal output or JSONL event streams
- can launch a repo-local dashboard and replay stored sessions

If you run `ebpf-tracker cargo run`, you should expect to see the whole session:
`cargo`, `rustc`, linkers, and then your app. The same idea applies to Node
commands such as `npm run <script>`.

The install, run, dashboard, config, and attach flows are documented in
[`docs/cli.md`](./docs/cli.md). That page is the canonical source for command
examples and operational behavior.

## Workspace Map

- **Root CLI (`ebpf-tracker`)**: installable command-line entry point, runtime orchestration, config loading, `demo`, `see`, and experimental `attach` support (live `inspektor-gadget` on `k8s`/`aws-eks`, scaffold for other targets). Source lives under [`src/`](./src).
- **`crates/ebpf-tracker-events`**: shared event schema, line parsers, and session aggregation helpers used across the workspace. [README](./crates/ebpf-tracker-events/README.md)
- **`crates/ebpf-tracker-dataset`**: dataset bundle writer and analyzer for JSONL streams and replay logs. [README](./crates/ebpf-tracker-dataset/README.md)
- **`crates/ebpf-tracker-otel`**: OTLP exporter plus local Jaeger helper commands. [README](./crates/ebpf-tracker-otel/README.md)
- **`crates/ebpf-tracker-perf`**: `perf trace` normalizer and transport boundary for the non-default collector path. [README](./crates/ebpf-tracker-perf/README.md)
- **`crates/ebpf-tracker-viewer`**: browser dashboard and replay viewer. [README](./crates/ebpf-tracker-viewer/README.md)

These crates do separate jobs. The root README should not duplicate their full
behavior contracts.

## Examples

Runnable examples live under [`examples/`](./examples/README.md):

- [`examples/session-io-demo`](./examples/session-io-demo/README.md): build-time plus runtime file, network, and output activity in one trace
- [`examples/postcard-generator-rust`](./examples/postcard-generator-rust/README.md): visible postcard-generation flow in Rust
- [`examples/postcard-generator-node`](./examples/postcard-generator-node/README.md): the same visible workflow in Node.js

Useful repo-local entry points:

```bash
cargo demo
cargo demo --emit jsonl session-io-demo
cargo demo --transport perf --emit jsonl session-io-demo
cargo viewer --replay examples/session-io-demo/logs/ebpf-tracker-YYYYMMDD-HHMMSS.log
bash scripts/dashboard-smoke.sh
```

## More Docs

- [`docs/cli.md`](./docs/cli.md)
- [`docs/customer-ux-e2e.md`](./docs/customer-ux-e2e.md)
- [`examples/README.md`](./examples/README.md)
- [`docs/trace-payment-engine.md`](./docs/trace-payment-engine.md)
- [`CONTRIBUTING.md`](./CONTRIBUTING.md)
- [`SECURITY.md`](./SECURITY.md)
- [`RELEASE.md`](./RELEASE.md)
