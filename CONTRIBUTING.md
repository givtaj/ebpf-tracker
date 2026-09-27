# Contributing

`ebpf-tracker` is an experimental alpha with one primary goal: make a trusted
Rust or Node.js command session observable and replayable without pretending
the project is already a production agent. Contributions should improve that
narrow workflow or make its limits more explicit.

## Safety Before Setup

The real tracer uses a privileged container, the Docker host PID namespace,
and a read-write project bind mount. Do not run runtime tests against untrusted
repositories, pull requests, dependencies, commands, probe programs, or test
fixtures. Use a disposable Linux VM/droplet when possible and keep credentials
and unrelated sensitive workloads off that host.

Standard Rust build and unit-test commands do not by themselves authorize a
privileged runtime smoke test. Call out privileged test requirements in a pull
request so reviewers can choose an appropriate host. Read
[`SECURITY.md`](./SECURITY.md) before changing runtime or probe behavior.

## Local Setup

1. Install the Rust toolchain.
2. Clone the repository and work from its root.
3. Build the workspace:

```bash
cargo build --workspace --locked
```

Node.js is needed for viewer/frontend work. A Docker engine that supports
privileged containers and exposes Linux eBPF facilities is needed only for the
real tracing path. The shipped workload images are Debian Bookworm images for
Rust 1 and Node.js 22; host-installed tools are not automatically present in
them.

## Verify Changes

Start with the non-privileged checks:

```bash
cargo fmt --all --check
cargo test --all --locked
cargo build --workspace --locked
cargo run --bin ebpf-tracker -- --help
cargo demo --list
```

Use the generic release gate for release-readiness work:

```bash
bash scripts/release-check.sh
```

If a change affects CLI orchestration, generated probes, Docker runtimes, or
demos, run the real tracer smoke path on an isolated, trusted Docker host:

```bash
bash scripts/runtime-smoke.sh
```

For viewer work, use the deterministic replay path when live tracing is not
required:

```bash
bash scripts/dashboard-smoke.sh --no-open
```

Run the smallest additional focused check that exercises the changed behavior.
Record skips separately from passes; a missing Docker, loopback, kernel, or
browser capability is not evidence that the customer workflow passed.

## Preserve The Public Contracts

Keep code, tests, examples, and documentation aligned. In particular:

- the executable and product name is exactly `ebpf-tracker`;
- raw probe lines use `openat`, JSONL syscall records use `"kind":"open_at"`,
  and aggregate metrics use `openat`;
- built-in/default probe scoping and arbitrary custom `--probe` behavior must
  remain visibly distinct;
- live attach support and scaffold-only plans must not be described as the
  same behavior; and
- a scaffold command that exits successfully must never be reported as a live
  trace success.

If you change a command, flag, event field, runtime assumption, privilege,
mount, filtering rule, or attach backend, update the relevant user-facing docs
in the same pull request.

## Commit And Pull Request Expectations

- Keep each change focused on one user-visible behavior or documentation topic.
- Explain the customer outcome, the trust/security impact, and the exact checks
  performed.
- Include tests when behavior changes, or explain why a test is not practical.
- Avoid mixing unrelated refactors with feature work.
- Do not commit generated logs, trace captures, dataset bundles, credentials,
  or sensitive host paths unless sanitized fixtures are the explicit subject
  of the change.
- Treat JSONL fixtures and screenshots as potentially sensitive and review them
  before committing.

## Documentation Map

- [`README.md`](./README.md): status, safety boundary, and golden workflow
- [`docs/cli.md`](./docs/cli.md): detailed command behavior and support matrix
- [`SECURITY.md`](./SECURITY.md): trust, privilege, and disclosure policy
- [`examples/README.md`](./examples/README.md): runnable clone-local demos
- crate READMEs: package-specific contracts and limitations
- [`architecture.md`](./architecture.md): data flow and trust boundaries

Examples must remain runnable from a local clone. When changing a demo
manifest, inputs, or generated outputs, update its README and the linked smoke
expectations. Keep `CHANGELOG.md` in sync with user-visible changes according
to the repository workflow.

Report suspected vulnerabilities through the private process described in
[`SECURITY.md`](./SECURITY.md), not in a public issue or pull request.
