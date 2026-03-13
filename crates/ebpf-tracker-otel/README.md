# ebpf-tracker-otel

OTLP exporter for `ebpf-tracker` JSONL streams.

Current purpose:

- read newline-delimited `StreamRecord` values from `stdin`
- group the raw stream into a session span plus per-process spans
- export those spans over OTLP to Jaeger or another collector
- manage a local Jaeger collector with Cargo-native commands

Current example:

```bash
cargo jaeger up
eBPF_tracker --emit jsonl cargo run | cargo otel --target jaeger --service-name session-io-demo
```

Useful commands:

```bash
cargo jaeger status
cargo jaeger down
```

The raw JSONL stream remains the source of truth. This crate builds a trace view on top of it.
