# Alpha.4 file-open outcomes

Implemented the in-container agent's completed `openat` observations. The agent
copies the filename at entry, keys pending state by thread ID, and emits one
record at exit with `return_value` and `errno`. It removes pending state on
completion, thread exit, and collector shutdown. The existing process-tree
filter applies to both entry and exit; generic host CLI probes remain unchanged.
Startup now requires the `sys_exit_openat` tracepoint.

The shared event schema retains these optional fields in parsed events, JSONL,
and per-process session events. Missing fields in legacy captures mean unknown
outcome. The raw parser rejects partial, invalid, duplicate, and inconsistent
outcomes. A final pathname is separated from metadata so text such as `errno=0`
inside a filename cannot overwrite a failure. Collector string truncation and
embedded newlines remain limitations; syscall outcomes do not imply HTTP
request attribution or successful file reads.

Minimal perf/attach/OTel Rust construction updates leave their outcome fields
absent. No platform/transport expansion, Roots changes, database access, Docker
calls, or commits were performed by this agent.

Validation:

- PASS: `cargo test -p ebpf-tracker-events -p ebpf-tracker-perf -p ebpf-tracker-otel --locked`
  (12 events, 14 perf, 11 OTel tests; doc tests pass).
- Covers ENOENT, EACCES, file descriptor zero and positive success, JSON/session
  retention, legacy reads, malformed metadata rejection, pathname metadata
  collision, and independent interleaved process events.
- Linux-only tests added for the exit-tracepoint prerequisite and collector
  result serialization. Parent owns native package and live Docker execution,
  including actual concurrent worker correlation and isolation verification.
- PASS: owned Rust files formatted and `git diff --check`.

## Integrated result

Implementation commit: `3d7359fd7bc400fde442bcccf19c179e1fffeffa`. Parent verified
138 workspace tests, 14 Linux agent tests, the native ARM64 installed-package
fixture, actual-capture and legacy offline replay with Docker blocked, and the
final browser display. Four HTTP500/ENOENT reproductions matched four captured
failures; five control opens succeeded. Explicit worker naming fixed the first
validator failure; journey wording and failure-row layout were corrected.
The tests establish concurrent requests, not distinct overlapping thread IDs
or request attribution. Native amd64 CI and publication remain pending. No
Roots source, services or database were accessed. See `docs/alpha-validation.md`.
