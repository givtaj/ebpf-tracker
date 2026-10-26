**Draft: not ready for publication.** This candidate is being focused on a
Linux Docker Axum API, with Roots as the reference application. Docker
attachment is still a scaffold and Axum/container acceptance has not run.
The generic commands below describe the implemented foundation, not completed
Roots compatibility. Resolve the integration choice and pass the acceptance
contract in `docs/alpha-scope.md` before replacing this draft and publishing.

The implemented foundation can **trace a trusted development command,
save its activity, and replay the capture locally.**

```bash
ebpf-tracker --version
ebpf-tracker demo --emit jsonl session-io-demo > trace.jsonl
ebpf-tracker replay trace.jsonl
```

For existing command-mode experiments, use the sample `ebpf-tracker.toml` config
to enable process, file-open, write, and connection probes. Without a config,
the default records process execution only.

Live tracing requires Docker with privileged containers and a Linux kernel
that exposes the needed eBPF features. Use trusted workloads on an isolated
development machine. Bundled Rust demos require host Cargo for cleanup;
dashboard and replay require host Node.js. Replay does not start Docker.

Planned downloads are Linux x86_64 and Intel macOS CLI archives plus `SHA256SUMS`.
The macOS launcher still requires a compatible Linux Docker VM for tracing.
Source builds remain available; this release is not published to crates.io.

Events describe syscall attempts, not successful I/O, remote connection
addresses, throughput, or precise application timing. The privileged runtime
is not a security sandbox or a production monitoring agent. APIs and event
formats may change during alpha.

Cloud attachment, host monitoring, perf, AI analysis, datasets, and OTLP remain
experimental extras. New feature work in those areas is deferred while the
capture-and-replay workflow matures.

See the [alpha scope](https://github.com/givtaj/ebpf-tracker/blob/v0.2.0-alpha.1/docs/alpha-scope.md),
[CLI guide](https://github.com/givtaj/ebpf-tracker/blob/v0.2.0-alpha.1/docs/cli.md),
and [security policy](https://github.com/givtaj/ebpf-tracker/blob/v0.2.0-alpha.1/SECURITY.md).
