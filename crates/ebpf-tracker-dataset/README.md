# ebpf-tracker-dataset

Dataset writer and analyzer for `ebpf-tracker` JSONL streams and replay logs.

Examples:

```bash
eBPF_tracker --emit jsonl cargo run | cargo dataset --test-name cargo-run-smoke
cargo dataset --replay logs/ebpf-tracker-YYYYMMDD-HHMMSS.log
cargo dataset analyze --run datasets/<run-id> --provider lm-studio --model qwen/qwen3.5-9b
```

Each run writes a bundle under `./datasets/<run-id>/`:

- `run.json`: run metadata and dataset pointers
- `events.jsonl`: normalized typed stream records
- `processes.json`: per-process rollup
- `aggregates.json`: aggregate metrics from the stream
- `features.json`: derived focus process, top files, top writes, and kind counts

Model analysis writes into `./datasets/<run-id>/analysis/`.
The first adapter is LM Studio over its local OpenAI-compatible API, but the
CLI also supports a generic `openai-compatible` provider so the same analysis
flow can move to stronger models later without changing the dataset format.
