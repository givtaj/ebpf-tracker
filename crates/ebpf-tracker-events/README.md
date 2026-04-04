# `ebpf-tracker-events`

`ebpf-tracker-events` owns the shared event contract used by `ebpf-tracker` and
the downstream workspace crates. It is a library crate, not a standalone
binary.

The crate provides three things:

- parsing for the line-oriented trace output emitted by the CLI
- the JSONL record schema used by `--emit jsonl`
- session aggregation helpers for replay and dashboard consumers

## What It Parses

`parse_event_line` recognizes the current syscall event formats:

- `execve comm=<name> pid=<pid>`
- `openat comm=<name> pid=<pid> file=<path>`
- `write comm=<name> pid=<pid> bytes=<count>`
- `connect comm=<name> pid=<pid> fd=<fd>`

`parse_aggregate_line` recognizes aggregate metrics in the form:

```text
@writes: 5268
```

Everything else is treated as plain text and is ignored by the JSONL stream
helpers.

## JSONL Contract

`StreamRecord` is the shared JSONL payload type. It uses a tagged enum with the
`type` field and snake_case variant names:

- `session`
- `syscall`
- `aggregate`

`EventKind` is serialized as snake_case as well, so `OpenAt` becomes
`"openat"` and `Execve` becomes `"execve"`.

Example syscall record:

```json
{
  "type": "syscall",
  "timestamp_unix_ms": 123,
  "kind": "write",
  "comm": "session-io-demo",
  "pid": 723,
  "bytes": 239
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

The session variant can also carry optional branding fields:

- `product_tagline`
- `sponsor_name`
- `sponsor_message`
- `sponsor_url`

## Session Aggregation

`build_session_trace` turns a slice of `StreamRecord` values into a summary
trace suitable for replay and dashboard consumers.

The current behavior is:

- records are grouped by `(pid, comm)`
- process traces are sorted by start timestamp, then pid
- write byte totals are accumulated with saturating arithmetic
- session start and finish timestamps come from the min and max record time
- aggregate records are preserved in input order

`SessionTrace` stores top-level counts, per-process summaries, and aggregate
metrics. Each `ProcessTrace` keeps the original syscall event list so consumers
can reconstruct the session timeline.

## Limitations

- Parsing is whitespace-delimited and expects `key=value` fields.
- Event fields are not shell-quoted or escaped.
- Unknown event lines are ignored instead of producing errors.
- `build_session_trace` groups by pid plus command name, so pid reuse across a
  session would produce separate process entries only if the command name also
  changes.

## Public API

The main exported items are:

- `EventKind`
- `ParsedEvent`
- `ParsedLine`
- `StreamRecord`
- `SessionTrace`
- `ProcessTrace`
- `SyscallEvent`
- `AggregateMetric`
- `parse_event_line`
- `parse_aggregate_line`
- `parse_trace_line`
- `stream_record_for_line`
- `stream_record_for_line_at`
- `build_session_trace`

## Usage

This crate is consumed internally by the workspace, but it can also be used as a
normal Rust library:

```rust
use ebpf_tracker_events::{stream_record_for_line, StreamRecord};

if let Some(record) = stream_record_for_line("write comm=demo pid=7 bytes=64") {
    assert!(matches!(record, StreamRecord::Syscall { .. }));
}
```
