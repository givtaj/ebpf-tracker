# ebpf-tracker-otel

Scaffold consumer for `ebpf-tracker` JSONL streams.

Current purpose:

- read newline-delimited `StreamRecord` values from `stdin`
- validate the stream contract shared by `crates/ebpf-tracker-events`
- prepare the boundary for future OTLP and Jaeger export work

Current example:

```bash
eBPF_tracker --emit jsonl cargo run | cargo run -p ebpf-tracker-otel -- --target jaeger --service-name session-io-demo
```

Today this prints a scaffold summary to `stderr`. It does not send live traces yet.
