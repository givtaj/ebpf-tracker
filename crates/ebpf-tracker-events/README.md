# `ebpf-tracker-events`

> Experimental workspace crate. It is `publish = false`, and its API/schema may
> change before a stable release.

`ebpf-tracker-events` owns the normalized event contract shared by the root CLI,
viewer, dataset, perf, attach, and OTel paths. It is a library, not a standalone
binary.

## Input Parsing

`parse_event_line` recognizes the line-oriented collector format:

```text
execve comm=<name> pid=<pid>
openat comm=<name> pid=<pid> file=<path>
write comm=<name> pid=<pid> bytes=<count>
connect comm=<name> pid=<pid> fd=<fd>
```

`parse_aggregate_line` recognizes bpftrace aggregates such as:

```text
@openat: 42
@writes: 5268
```

Everything else is `ParsedLine::Text` and is ignored by JSONL stream helpers.
Parsing is deliberately small and best-effort; this is not a lossless parser
for arbitrary bpftrace or perf output.

## JSONL Contract

`StreamRecord` is a tagged enum using the `type` field:

- `session`
- `syscall`
- `aggregate`

The critical naming distinction is:

| Layer | Open syscall spelling |
| --- | --- |
| Raw collector line | `openat` |
| Rust variant | `EventKind::OpenAt` |
| `EventKind::as_str()` | `openat` |
| Serde JSON `kind` | `open_at` |
| Aggregate metric | `openat` |

Serde applies `snake_case` to the Rust enum variant, so JSON consumers must
expect the JSON value `"kind":"open_at"` and preserve its underscore.

Example syscall record:

```json
{
  "type": "syscall",
  "timestamp_unix_ms": 123,
  "kind": "open_at",
  "comm": "session-io-demo",
  "pid": 723,
  "file": "input/message.txt"
}
```

Example session record:

```json
{
  "type": "session",
  "timestamp_unix_ms": 789,
  "demo_name": "postcard-generator-rust",
  "product_name": "ebpf-tracker"
}
```

A session can also carry optional `product_tagline`, `sponsor_name`,
`sponsor_message`, and `sponsor_url` fields.

## Session Aggregation

`build_session_trace` converts a `StreamRecord` slice into a replay/dashboard
summary:

- records are grouped by `(pid, comm)`;
- process traces are sorted by start time, then PID;
- write-byte totals use saturating arithmetic;
- session bounds come from the minimum and maximum record timestamps; and
- aggregate records preserve input order.

`SessionTrace` contains top-level counts, per-process summaries, and aggregate
metrics. Each `ProcessTrace` retains its syscall event list so consumers can
rebuild a timeline.

## Public API

The primary exported types and functions are:

- `EventKind`, `ParsedEvent`, and `ParsedLine`
- `StreamRecord`, `SessionTrace`, `ProcessTrace`, and `SyscallEvent`
- `AggregateMetric`
- `parse_event_line`, `parse_aggregate_line`, and `parse_trace_line`
- `stream_record_for_line` and `stream_record_for_line_at`
- `build_session_trace`

Example:

```rust
use ebpf_tracker_events::{stream_record_for_line, StreamRecord};

if let Some(record) = stream_record_for_line("write comm=demo pid=7 bytes=64") {
    assert!(matches!(record, StreamRecord::Syscall { .. }));
}
```

## Limits And Trust

- Fields are whitespace-delimited `key=value` pairs and are not shell-quoted or
  escaped. Paths containing whitespace are therefore not represented losslessly.
- Unknown/malformed lines are ignored instead of producing structured errors.
- Grouping uses PID plus command name; PID reuse remains possible within a long
  session.
- The schema carries process names, PIDs, paths, file descriptors, and byte
  counts. Treat stored or exported records as potentially sensitive.
- Workload isolation is a collector/orchestration concern, not something this
  parsing crate can enforce. It will normalize any supported line it receives.
