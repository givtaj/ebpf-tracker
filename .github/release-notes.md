This alpha focuses on one workflow: **trace a trusted development command,
save its activity, and replay the capture locally.**

```bash
ebpf-tracker --version
ebpf-tracker demo --emit jsonl session-io-demo > trace.jsonl
ebpf-tracker replay trace.jsonl
```

For your own Rust or Node.js project, use the sample `ebpf-tracker.toml` config
to enable process, file-open, write, and connection probes. Without a config,
the default records process execution only.

Live tracing requires Docker with privileged containers and a Linux kernel
that exposes the needed eBPF features. Use trusted workloads on an isolated
development machine. Bundled Rust demos require host Cargo for cleanup;
dashboard and replay require host Node.js. Replay does not start Docker.

Downloads include Linux x86_64 and Intel macOS CLI archives plus `SHA256SUMS`.
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
