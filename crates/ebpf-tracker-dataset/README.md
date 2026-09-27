# `ebpf-tracker-dataset`

> Experimental workspace crate. It is `publish = false`, and its bundle/API
> format may change before a stable release.

`ebpf-tracker-dataset` ingests normalized `ebpf-tracker` JSONL or replay logs,
writes one local dataset bundle per run, and can optionally send a bounded
summary to LM Studio or another OpenAI-compatible chat endpoint.

The root CLI can supervise this crate through `--intelligence-dataset`.

## Ingest

Ingest mode is the default:

```bash
cargo dataset [--output <dir>] [--replay <path>] [--run-id <id>] [--source <live|replay>] [--command <text>] [--test-name <name>] [--git-sha <sha>] [--transport <bpftrace|perf>] [--runtime <auto|rust|node>] [--exit-code <n>] [--exit-signal <name>] [--log-path <path>]
```

Without `--replay`, newline-delimited `StreamRecord` JSON is read from `stdin`.
`--source` defaults to `replay` with `--replay` and `live` otherwise. A
successful ingest prints this status shape to `stderr`:

```text
dataset written run_id=... source=... dir=... records=... ignored_lines=...
```

Example:

```bash
ebpf-tracker --emit jsonl cargo run | cargo dataset --test-name cargo-run-smoke
cargo dataset --replay crates/ebpf-tracker-viewer/demo-library/session-io-demo.jsonl
```

Input must use the shared JSON contract. In particular, an open syscall has
`"kind":"open_at"`; `openat` is the raw/aggregate spelling. Non-empty lines
that do not deserialize as a `StreamRecord` are ignored and counted in
`ignored_lines`.

## Bundle Layout

Each run is written under `./datasets/<run-id>/` by default:

- `run.json`: metadata, input pointers, counts, and session metadata
- `events.jsonl`: normalized `StreamRecord` values
- `processes.json`: per-process session rollups
- `aggregates.json`: aggregate metrics
- `features.json`: focus process, total bytes written, noise ratio, unique
  processes/files, kind counts, top processes/files, and top writes

`features.json` uses `open_at` in its event-kind counts because it follows the
JSON enum spelling.

## Analyze

Analyze an existing bundle with:

```bash
cargo dataset analyze --run <dataset-dir> [--provider <lm-studio|openai-compatible>] [--endpoint <url>] [--model <name>] [--api-key <token>] [--temperature <n>] [--max-tokens <n>] [--instructions-file <path>] [--live-logs]
```

`lm-studio` is the default provider. It defaults to
`http://127.0.0.1:1234` and model `qwen/qwen3.5-9b`. The parser accepts
`openai` as an alias, but the documented provider name is
`openai-compatible`; that provider requires both `--endpoint` and `--model`.

Analysis output is written under `analysis/` in the run directory. Successful
analysis prints this status shape to `stderr`:

```text
analysis written provider=... model=... markdown=... json=...
```

Output filenames combine a provider and sanitized model name, for example:

```text
analysis/lm-studio--qwen-qwen3.5-9b.md
analysis/lm-studio--qwen-qwen3.5-9b.json
```

`--live-logs` mirrors analyzer progress to `stderr` and an analysis `.live.log`
file. For LM Studio it also attempts to tail the newest server log below
`$LM_STUDIO_LOG_ROOT` or `~/.lmstudio/server-logs`; failure to find/read one is
reported and does not abort analysis.

## Data And Credential Boundary

Dataset bundles can contain process names, PIDs, file paths, command metadata,
and derived behavior summaries. Keep them local by default, inspect them before
sharing, and do not commit captures from sensitive workloads.

Ingest itself does not upload data. Analyze mode sends a bounded derivative of
the bundle to the configured endpoint. Confirm that the endpoint and model are
approved for the data. Supplying `--api-key` can expose a token through shell
history or process inspection; follow the endpoint operator's credential
handling guidance and never commit credentials or live command transcripts.

## Current Limits

- Only newline-delimited shared `StreamRecord` JSON is accepted.
- Invalid/non-JSON input is counted and skipped rather than failing ingest.
- The feature rollup is syscall-session metadata, not a performance benchmark
  or semantic correctness analysis.
- Model output is untrusted interpretation and should be checked against the
  bundle.
- `--live-logs` tails LM Studio logs only for the `lm-studio` provider.
- Bundles are local artifacts; retention, redaction, and deletion are the
  operator's responsibility.
