# Halley Repo Onboarding Summary

- Agent: `Halley`
- Agent ID: `019d240c-4e5f-74c2-a7a7-f8f178c5b5b7`
- Scope: repo exploration and onboarding summary
- Status: completed

## Structure

- The root package is the installable CLI `eBPF_tracker`; the workspace members are the root crate, four helper crates, and two Rust examples. The Node example is supported, but it is not a Cargo workspace member. See `Cargo.toml:1`.
- The main product logic lives in `src/lib.rs:316`: it parses CLI args, supports normal tracing mode and `demo` mode, and dispatches into Docker-backed execution. `src/main.rs:1` is just a thin wrapper.
- Runtime selection and embedded asset materialization live in `src/runtime.rs:40`. This crate auto-detects Rust vs Node commands, picks the matching compose file, and can write embedded compose, Docker, and probe assets into a cache dir.
- The clean abstraction boundary is:
  - JSONL schema and trace-line parsing: `crates/ebpf-tracker-events/src/lib.rs:42`
  - `perf trace` normalization and aggregate synthesis: `crates/ebpf-tracker-perf/src/lib.rs:45`
  - Viewer launcher and embedded Node dashboard asset: `crates/ebpf-tracker-viewer/src/lib.rs:10`
  - OTLP/Jaeger export from JSONL stdin: `crates/ebpf-tracker-otel/src/main.rs:16`

## Primary Entry Points

- Normal CLI flow: `cargo run --bin eBPF_tracker -- <wrapped command>`. The key execution path builds `docker compose run --build --rm ...` in `src/lib.rs:976`.
- Demo flow: `eBPF_tracker demo [example]`, implemented in `src/lib.rs:1542`. Example manifests live under `examples/*/ebpf-demo.toml`, for example `examples/session-io-demo/ebpf-demo.toml:1`.
- Dashboard flow: `--dashboard` launches a Node viewer and opens the browser; see `src/lib.rs:914` and `crates/ebpf-tracker-viewer/src/main.rs:16`.
- Repo-local helper commands are Cargo aliases in `.cargo/config.toml:1`: `cargo demo`, `cargo viewer`, `cargo otel`, `cargo jaeger`.
- The best first example is `session-io-demo`, which intentionally exercises file IO, loopback networking, and writes a log artifact; see `examples/session-io-demo/src/main.rs:8`. The Node postcard example mirrors the same idea for Node in `examples/postcard-generator-node/src/generate.js:5`.

## How To Build, Test, And Run

- Build and install:
  - `cargo build`
  - `cargo install --path .`
- Test:
  - `cargo test --all`
  - The repo appears unit-test heavy inside crate sources rather than integration-test heavy; tests are embedded in root, runtime, events, perf, and otel crates, for example `src/lib.rs:1677` and `crates/ebpf-tracker-events/src/lib.rs:173`.
- Common local runs:
  - `cargo run --bin eBPF_tracker -- cargo run`
  - `cargo demo --list`
  - `cargo demo session-io-demo`
  - `cargo demo --transport perf --emit jsonl session-io-demo`
  - `cargo viewer -- --replay logs/ebpf-tracker-YYYYMMDD-HHMMSS.log`
  - `cargo jaeger up`
  - `cargo demo --emit jsonl session-io-demo | cargo otel --target jaeger --service-name session-io-demo`
- Config is file-based via `ebpf-tracker.toml`; the example config is `ebpf-tracker.toml.example:1`. README onboarding and command examples are in `README.md:59`.

## Notable Patterns And Risks

- This is containerized tracing, not host-native tracing. Docker with privileged Linux containers is a hard requirement. The README is explicit about that in `README.md:59`.
- The tool traces the full wrapped session by design, so raw output will include Cargo, npm, and container noise, not just the target app. That is called out in `README.md:19`.
- Embedded runtime and viewer assets are materialized to cache automatically, which is convenient for installed binaries but slightly non-obvious when debugging which compose, script, or probe file is actually running; see `src/runtime.rs:161` and `crates/ebpf-tracker-viewer/src/lib.rs:31`.
- `perf` mode is a compatibility path, but file-path decoding is best-effort; that limitation is documented in `README.md:187` and reflected in `crates/ebpf-tracker-perf/src/lib.rs:189`.
- The repo already contains generated example artifacts and logs under `examples/*/dist` and `examples/session-io-demo/logs`, so a dirty tree is normal during onboarding.
