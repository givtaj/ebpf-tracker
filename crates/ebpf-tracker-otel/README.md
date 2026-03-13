# ebpf-tracker-otel

OTLP exporter for `ebpf-tracker` JSONL streams.

This crate currently ships as a workspace helper for people running from a
local clone of `cargo-ebpf-tracker`. The `cargo otel` and `cargo jaeger`
commands below come from repo-local Cargo aliases.

Current purpose:

- read newline-delimited `StreamRecord` values from `stdin`
- group the raw stream into a session span plus per-process spans
- export those spans over OTLP to Jaeger or another collector
- manage a local Jaeger collector with Cargo-native commands
- validate OTLP endpoint, timeout, and custom header inputs before export

Current example:

```bash
cargo jaeger up
eBPF_tracker --emit jsonl cargo run | cargo otel --target jaeger --service-name session-io-demo
```

Optional hardened controls:

```bash
eBPF_tracker --emit jsonl cargo run | cargo otel --target otlp --endpoint http://127.0.0.1:4318 --timeout-seconds 15 --header authorization=Bearer-token
```

Useful commands:

```bash
cargo jaeger status
cargo jaeger down
```

The raw JSONL stream remains the source of truth. This crate builds a trace view on top of it.
