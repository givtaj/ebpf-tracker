# ebpf-tracker-dataset

`ebpf-tracker-dataset` ingests `ebpf-tracker` JSONL streams or replay logs,
writes a per-run dataset bundle, and analyzes an existing bundle with LM Studio
or any OpenAI-compatible chat API.

The root `ebpf-tracker` CLI can also run this crate in supervised background
mode via `--intelligence-dataset`.

## Commands

Ingest mode is the default when no subcommand is provided.

```bash
cargo dataset [--output <dir>] [--replay <path>] [--run-id <id>] [--source <live|replay>] [--command <text>] [--test-name <name>] [--git-sha <sha>] [--transport <bpftrace|perf>] [--runtime <auto|rust|node>] [--exit-code <n>] [--exit-signal <name>] [--log-path <path>]
```

It reads newline-delimited `ebpf-tracker` JSONL from `stdin` unless
`--replay <path>` is provided. `--source` defaults to `replay` when `--replay`
is set and otherwise to `live`. `--log-path` defaults to the replay path when
`--replay` is used.

The ingester writes under `./datasets/<run-id>/` by default and prints a status
line to `stderr` in the form:

```text
dataset written run_id=... source=... dir=... records=... ignored_lines=...
```

Supported ingest flags are:

- `--output <dir>`: output root, default `datasets`
- `--replay <path>`: read records from a replay file instead of `stdin`
- `--run-id <id>`: override the generated run directory name
- `--source <live|replay>`: explicitly set the dataset source
- `--command <text>`: record the traced command in `run.json`
- `--test-name <name>`: record the test name in `run.json`
- `--git-sha <sha>`: record the git SHA in `run.json`
- `--transport <bpftrace|perf>`: record the transport name in `run.json`
- `--runtime <auto|rust|node>`: record the runtime selection in `run.json`
- `--exit-code <n>`: record the exit code in `run.json`
- `--exit-signal <name>`: record the exit signal in `run.json`
- `--log-path <path>`: record the replay or log path in `run.json`

Analyze mode is invoked with the `analyze` subcommand.

```bash
cargo dataset analyze --run <dataset-dir> [--provider <lm-studio|openai-compatible>] [--endpoint <url>] [--model <name>] [--api-key <token>] [--temperature <n>] [--max-tokens <n>] [--instructions-file <path>] [--live-logs]
```

`lm-studio` is the default provider. It resolves to
`http://127.0.0.1:1234` by default and uses `qwen/qwen3.5-9b` unless a model is
passed explicitly. The parser also accepts `openai` as an alias for
`openai-compatible`, but the documented provider name is `openai-compatible`.
That provider requires both `--endpoint` and `--model`.

The analyzer writes to `./datasets/<run-id>/analysis/` and prints a status line
to `stderr` in the form:

```text
analysis written provider=... model=... markdown=... json=...
```

The output files are named from the provider and a sanitized model string, for
example `analysis/lm-studio--qwen-qwen3.5-9b.md` and
`analysis/lm-studio--qwen-qwen3.5-9b.json`.

`--live-logs` writes analyzer progress to `stderr` and persists the same lines
under `analysis/<provider>--<model>.live.log`. When the provider is
`lm-studio`, it also tails the newest LM Studio server log if one exists under
`$LM_STUDIO_LOG_ROOT` or `~/.lmstudio/server-logs`. If no log file is found, or
the file cannot be opened or read, the analyzer skips log tailing and records
that fact in the live log stream.

## Dataset Bundle

Each ingest run writes these files under `./datasets/<run-id>/`:

- `run.json`: dataset metadata, input pointers, record counts, and session metadata
- `events.jsonl`: normalized typed `StreamRecord` values
- `processes.json`: per-process rollup from the session trace
- `aggregates.json`: aggregate metrics from the session trace
- `features.json`: `focus_process`, `total_bytes_written`, `noise_syscall_ratio`, `unique_processes`, `unique_files`, `kind_counts`, `top_processes`, `top_files`, and `top_writes`

The ingester ignores non-empty lines that are not valid JSON `StreamRecord`
values and counts them in `ignored_lines`.

## Examples

```bash
ebpf-tracker --emit jsonl cargo run | cargo dataset --test-name cargo-run-smoke
cargo dataset --replay logs/ebpf-tracker-YYYYMMDD-HHMMSS.log
cargo dataset analyze --run datasets/<run-id> --provider lm-studio --model qwen/qwen3.5-9b
cargo dataset analyze --run datasets/<run-id> --provider lm-studio --model qwen/qwen3.5-9b --live-logs
```

## Limitations

- The crate only processes newline-delimited JSON `StreamRecord` values.
- Invalid or non-JSON lines are ignored rather than failing the ingest.
- `openai-compatible` mode requires both `--endpoint` and `--model`.
- `--live-logs` tails LM Studio logs only for the `lm-studio` provider.
- The crate writes local dataset bundles only; it does not upload them anywhere.
