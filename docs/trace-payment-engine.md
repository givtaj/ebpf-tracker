# Trace `givtaj/payment-engine`

This guide shows how to use an installed `eBPF_tracker` binary against a real
public Rust project:

- repo: <https://github.com/givtaj/payment-engine>
- app shape: Rust CLI that reads `transactions.csv` and writes account balances
  to `stdout`

Why this is a good customer-facing example:

- it is not part of this repository
- it builds with plain Cargo
- it opens CSV inputs, writes CSV outputs, and has a useful `cargo test` flow
- it shows why `--emit jsonl` matters when the wrapped app already uses
  `stdout`

## 1. Clone The Target Repo

```bash
git clone https://github.com/givtaj/payment-engine.git
cd payment-engine
```

## 2. Add A Trace Config

Create `ebpf-tracker.toml` in the `payment-engine` repo:

```toml
[probe]
exec = true
write = true
open = true
connect = false
```

This is a file-heavy CLI, so `open` and `write` are the useful defaults. It
does not need network tracing for the main demo flow.

## 3. Trace A Real Run

Use JSONL mode so the trace stays on `stdout` and the payment engine's normal
CSV output remains human-readable on `stderr`:

```bash
eBPF_tracker --config ebpf-tracker.toml --emit jsonl cargo run -- transactions.csv | tee trace.jsonl
```

What you should see:

- JSON Lines records on `stdout`
- the payment engine still prints its final CSV result
- one important line in the trace is:

```json
{"type":"syscall","kind":"openat","comm":"payments_engine","file":"transactions.csv",...}
```

You should also see `write` events from `payments_engine` when it emits the
account CSV.

## 3.1 Sample Observed Events

From a real traced run of `payment-engine`, the useful app-level signal looked
like this:

```json
{"type":"syscall","kind":"execve","comm":"payments_engine",...}
{"type":"syscall","kind":"openat","comm":"payments_engine","file":"transactions.csv",...}
{"type":"syscall","kind":"write","comm":"payments_engine","bytes":10,...}
{"type":"syscall","kind":"write","comm":"payments_engine","bytes":18,...}
{"type":"syscall","kind":"write","comm":"payments_engine","bytes":16,...}
```

The app's own output still appeared during the same traced run:

```text
Processed 9 records, skipped 0 invalid lines.
client,available,held,total,locked
2,2.0,0,2.0,false
1,-0.5,0.0,-0.5,true
```

The raw session also included a lot of expected build/runtime noise from
`cargo`, `rustc`, `ld`, and the container runtime. That is why the next step is
usually to filter the JSONL stream down to `payments_engine`.

## 4. Filter The Stream

Because `eBPF_tracker` traces the full wrapped Cargo session, the raw stream
includes `cargo`, `rustc`, linker, and container setup noise. The clean way to
inspect the app itself is to filter the JSONL stream:

```bash
eBPF_tracker --config ebpf-tracker.toml --emit jsonl cargo run -- transactions.csv \
  | rg '"comm":"payments_engine"|"file":"transactions.csv"'
```

That gives you a tighter app-focused view without changing the underlying
trace.

## 5. What `eBPF_tracker` Measured

For a larger project-shaped run, I generated a synthetic
`transactions-10000.csv` with 10,000 records and traced this command:

```bash
eBPF_tracker --config ebpf-tracker.toml --transport perf --emit jsonl cargo run --release -- transactions-10000.csv
```

This is what came from `eBPF_tracker` itself:

- full traced run produced `41,739` JSONL records
- aggregate counts at the end of the run:
  - `execve = 158`
  - `openat = 13097`
  - `writes = 28472`
  - `connects = 8`
- app-specific records with `comm="payments_engin"`: `54`
- app-specific `write` records: `5`

Notes:

- Linux truncates `comm` to 15 characters, so `payments_engine` appears as
  `payments_engin` in the stream.
- These counts describe syscall behavior and event volume for the wrapped Cargo
  session.
- They do not describe CPU time, memory usage, instructions retired, or other
  hardware-performance metrics.
- The tracing workflow now isolates Cargo build outputs inside the container,
  so running `eBPF_tracker` against `cargo run` should not leave Linux
  artifacts in the host repo's `target/` tree.

## 6. Trace The Test Suite

The same repo is also a good `cargo test` example because it opens multiple CSV
fixtures under `tests/data`:

```bash
eBPF_tracker --config ebpf-tracker.toml --emit jsonl cargo test \
  | rg '"comm":"payments_engine"|"file":"tests/data'
```

This is a strong example of build-time plus runtime plus test-fixture activity
in one trace session.

## Notes

- If you want a full machine-readable trace, keep `trace.jsonl`.
- You can replay that stored trace with the viewer crate via
  `cargo viewer -- --replay trace.jsonl`.
- If you want the business output only, run the payment engine once without
  tracing.
- The current product still traces the whole command session, so filtering is
  part of the intended Unix workflow today.
- If a repo was already traced with an older version and now has Linux binaries
  under `target/` on macOS, rebuild it natively or run `cargo clean` once.
