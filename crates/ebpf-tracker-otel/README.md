# `ebpf-tracker-otel`

> Experimental workspace crate. It is `publish = false`; use it from a reviewed
> source checkout and expect the CLI/export mapping to evolve.

`ebpf-tracker-otel` converts normalized `ebpf-tracker` JSONL into OTLP/HTTP
protobuf traces. It also provides a clone-local helper for a Dockerized Jaeger
stack.

## Export

The clone-local `cargo otel` alias reads newline-delimited `StreamRecord` JSON
from `stdin`:

```bash
cargo otel [--target otlp|jaeger] [--endpoint URL] [--service-name NAME] [--timeout-seconds N] [--header NAME=VALUE]
```

Example:

```bash
ebpf-tracker --emit jsonl cargo run \
  | cargo otel --target jaeger --service-name session-io-demo
```

Explicit collector example:

```bash
ebpf-tracker --emit jsonl cargo run \
  | cargo otel --target otlp \
      --endpoint http://127.0.0.1:4318 \
      --timeout-seconds 15
```

Behavior:

- empty input succeeds without contacting a collector;
- one session span and one span per process are generated;
- aggregate records become session-span events and syscalls become
  process-span events;
- `--service-name` must be non-empty after trimming;
- `--timeout-seconds` must be greater than zero;
- repeatable `--header NAME=VALUE` values are trimmed on both sides;
- endpoints must use `http` or `https` and include a host;
- an endpoint without a concrete traces path is normalized to `/v1/traces`;
- partial collector warnings are printed to `stderr`; and
- partial collector rejection fails the export.

On success, the command reports its target, endpoint, service name, input/span
counts, and warning count on `stderr`.

## Jaeger Helper

Manage the bundled local stack with:

```bash
cargo jaeger up
cargo jaeger status
cargo jaeger down
```

The helper materializes `docker-compose.jaeger.yml` into the crate-version
cache, then invokes Docker Compose. Cache resolution is
`EBPF_TRACKER_CACHE_DIR`, `XDG_CACHE_HOME`, `HOME`, then the system temp
directory. Successful `up`/`status` commands print the Jaeger UI URL
`http://127.0.0.1:16686`.

The current Compose file publishes host ports `16686`, `4317`, `4318`, `5778`,
and `9411`. Docker's default port publishing may expose them beyond loopback.
Use the helper only on a trusted development host with appropriate firewall
rules; it is not a hardened or authenticated shared service.

## Data And Credential Boundary

Export transmits process names, PIDs, file paths, event metadata, and derived
session structure to the configured collector. The raw JSONL stream remains the
local source of truth, but the collector receives a transformed copy. Review
trace sensitivity and collector retention/access controls before exporting.

Headers supplied on the command line may be visible in shell history or process
inspection. Do not commit credentials, copy them into examples, or use the
bundled Jaeger stack for sensitive production data.

## Limits

- Only the normalized shared `StreamRecord` schema is accepted.
- OTLP spans are a view of syscall-session events, not full distributed tracing
  instrumentation.
- Export does not make an unscoped trace safe; collection scope is determined
  upstream.
- The Jaeger helper depends on Docker and is intended for disposable local
  inspection.
