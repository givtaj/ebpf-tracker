# Trace `givtaj/payment-engine`

This guide applies the current experimental `ebpf-tracker` workflow to a real
external Rust project:

- repository: <https://github.com/givtaj/payment-engine>
- application shape: a Rust CLI that reads `transactions.csv` and writes
  account balances to standard output

This is a compatibility example, not an endorsement or a promise that every
revision of the external repository will keep working. Review the checkout and
its dependencies before executing it. The tracer runs the target in a
privileged container with the Docker host PID namespace and a read-write bind
mount; use an isolated development host and never trace untrusted code.

## Prerequisites

- an installed `ebpf-tracker` binary from this repository;
- Git and a Rust toolchain;
- a Docker engine that permits privileged containers and exposes Linux eBPF
  facilities; and
- a trusted `payment-engine` checkout with a suitable `transactions.csv`.

## 1. Clone And Review The Target

```bash
git clone https://github.com/givtaj/payment-engine.git
cd payment-engine
```

Inspect the revision and its dependencies before continuing. Pin a commit if
you need a repeatable result.

## 2. Enable File And Output Events

Create `ebpf-tracker.toml` in the target repository:

```toml
[probe]
exec = true
write = true
open = true
connect = false
```

This config produces a generated bpftrace probe scoped to the wrapped process
tree. That reduces unrelated trace data, but does not reduce the container's
privilege or turn the command into a sandbox.

## 3. Capture A JSONL Trace

```bash
ebpf-tracker --config ebpf-tracker.toml --emit jsonl \
  cargo run -- transactions.csv > trace.jsonl
```

In JSONL mode, normalized trace records use `stdout`; Cargo and application
output remain readable on `stderr`. The underlying command's exit status is
preserved.

Look for records shaped like these; timestamps and PIDs will differ:

```json
{"type":"syscall","timestamp_unix_ms":1774500000100,"kind":"execve","comm":"payments_engine","pid":2100}
{"type":"syscall","timestamp_unix_ms":1774500000200,"kind":"open_at","comm":"payments_engine","pid":2100,"file":"transactions.csv"}
{"type":"syscall","timestamp_unix_ms":1774500000300,"kind":"write","comm":"payments_engine","pid":2100,"bytes":18}
```

The naming layers are intentionally different:

- bpftrace/raw event name: `openat`
- normalized JSON `kind`: `open_at`
- aggregate metric name: `openat`

JSON consumers must preserve the underscore in the `open_at` kind.

The application's own output should still appear during the run, for example:

```text
Processed 9 records, skipped 0 invalid lines.
client,available,held,total,locked
2,2.0,0,2.0,false
1,-0.5,0.0,-0.5,true
```

Exact business output depends on the input file and target revision.

## 4. Focus On The Application

The trace intentionally includes the complete wrapped Cargo process tree:
`cargo`, `rustc`, linkers, and the application. Filter the stored stream for
the target command and input path:

```bash
rg '"comm":"payments_engine"|"comm":"payments_engin"|"file":"transactions.csv"' trace.jsonl
```

Linux `comm` is limited to 15 characters, so `payments_engine` may appear as
`payments_engin`. Filtering is a presentation step; the built-in generated
probe already excludes processes outside the wrapped workload tree.

## 5. Understand Historical Counts

One earlier 10,000-record experiment used:

```bash
ebpf-tracker --config ebpf-tracker.toml --transport perf --emit jsonl \
  cargo run --release -- transactions-10000.csv
```

That run observed 41,739 JSONL records: 158 `execve`, 13,097 `openat`, 28,472
`write`, and 8 `connect` aggregate events, with 54 records attributed to the
truncated `payments_engin` command. These are historical observations from one
host, input, target revision, cache state, and collector. They are not a
benchmark or an expected assertion for a new run.

The counts describe syscall event volume. They do not measure CPU time, memory,
instructions retired, request latency, or business correctness. With the
`perf` transport, file paths are best-effort and may be absent when `perf trace`
cannot decode userspace string pointers.

## 6. Trace Tests

The same pattern can cover test fixtures:

```bash
ebpf-tracker --config ebpf-tracker.toml --emit jsonl cargo test > test-trace.jsonl
rg '"comm":"payments_engine"|"comm":"payments_engin"|tests/data' test-trace.jsonl
```

This combines build, test harness, fixture access, and child-process activity
in one session. It is still syscall metadata, not a semantic test-coverage
tool.

## Next Steps And Limits

- Keep `trace.jsonl` or `test-trace.jsonl` only if their process/path metadata
  is safe to retain and share.
- From an `ebpf-tracker` source checkout, replay a trace with
  `cargo viewer --replay /path/to/trace.jsonl`.
- Run the payment engine without tracing when you need unmodified business
  output only.
- Host-installed native libraries are not automatically available inside the
  bundled Rust Bookworm runtime.
- An arbitrary custom `--probe` is not automatically workload-scoped and
  requires the explicit host-wide acknowledgement documented in the
  [CLI guide](./cli.md#custom-bpftrace-probes).
