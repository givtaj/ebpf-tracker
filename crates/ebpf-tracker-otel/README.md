# ebpf-tracker-otel

`ebpf-tracker-otel` turns `ebpf-tracker` JSONL streams into OTLP traces and can
launch a local Jaeger stack for inspection.

This crate is exposed in a local clone through the repo Cargo aliases
`cargo otel` and `cargo jaeger`.

## CLI Surface

Export mode reads newline-delimited `StreamRecord` values from `stdin`:

```bash
cargo otel [--target otlp|jaeger] [--endpoint URL] [--service-name NAME] [--timeout-seconds N] [--header NAME=VALUE]
```

Jaeger helper mode manages the local collector stack:

```bash
cargo jaeger <up|down|status>
```

## Export Behavior

- Empty input succeeds without contacting a collector.
- The input stream is grouped into one session span plus one span per process.
- Session spans carry aggregate events, and process spans carry syscall events.
- `--service-name` is trimmed and must not be empty.
- `--timeout-seconds` must be greater than zero.
- `--header` accepts `NAME=VALUE`, trims both sides, and may be repeated.
- `--endpoint` must be a valid `http` or `https` URL with a host.
- If `--endpoint` omits a concrete traces path, the code normalizes it to `/v1/traces`.
- `--target` accepts `otlp` or `jaeger` and changes the exported resource target label.
- Partial collector warnings are surfaced on `stderr`.
- Partial collector rejections fail the export.

Example:

```bash
ebpf-tracker --emit jsonl cargo run | cargo otel --target jaeger --service-name session-io-demo
```

Hardened OTLP example:

```bash
ebpf-tracker --emit jsonl cargo run | cargo otel --target otlp --endpoint http://127.0.0.1:4318 --timeout-seconds 15 --header authorization=Bearer-token
```

On success, the command prints a summary to `stderr` that includes the target,
endpoint, service name, record counts, span counts, and warning count.

## Jaeger Helper

`cargo jaeger up` materializes the bundled `docker-compose.jaeger.yml` into the
cache directory for this crate version, then runs `docker compose` against that
file. The same cache-root rules as the exporter apply: `EBPF_TRACKER_CACHE_DIR`
takes priority, then `XDG_CACHE_HOME`, then `HOME`, then the system temp dir.

The helper maps to:

- `up` -> `docker compose ... up -d`
- `status` -> `docker compose ... ps`
- `down` -> `docker compose ... down`

When `up` or `status` succeeds, the CLI prints the Jaeger UI URL
(`http://127.0.0.1:16686`) on `stderr`.

Example:

```bash
cargo jaeger up
cargo jaeger status
cargo jaeger down
```

## Notes

- The embedded Jaeger compose file exposes ports `16686`, `4317`, and `4318`.
- The exporter uses OTLP/HTTP protobuf requests.
- The raw JSONL stream remains the source of truth; this crate builds a trace
  view on top of it.
