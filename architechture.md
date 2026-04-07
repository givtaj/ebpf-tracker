# Architecture

```mermaid
flowchart TB
    user["Developer / Operator"]

    subgraph host["Host Machine / Workspace"]
        cli["ebpf-tracker CLI<br/>run, demo, see, attach"]
        config["Project Inputs<br/>ebpf-tracker.toml, --probe, demo manifests"]
        assets["Runtime Assets<br/>compose files, Dockerfiles, probe files<br/>checked-in or materialized from cache"]
        dashboard["Dashboard Wrapper<br/>src/dashboard.rs"]
        viewer["ebpf-tracker-viewer<br/>Rust launcher + Node web UI"]
        browser["Browser"]
        attach["Attach Mode<br/>inspektor-gadget on k8s or aws-eks<br/>other targets scaffolded"]
        runtime_lines["Runtime Trace Output<br/>stdout and stderr lines"]
        events["ebpf-tracker-events<br/>shared parser, StreamRecord schema,<br/>session aggregation"]
        perfcrate["ebpf-tracker-perf<br/>perf trace expression + normalizer"]
        stream["Normalized Event Stream<br/>raw passthrough or JSONL"]
        logs["Replay Logs<br/>logs/ebpf-tracker-*.log"]
        intelligence["Intelligence Supervisor<br/>optional live dataset + analysis"]
        dataset["ebpf-tracker-dataset"]
        analysis["Dataset Bundle + Analysis<br/>datasets/run-id/*"]
        otel["ebpf-tracker-otel"]
        collector["OTLP / Jaeger"]
    end

    subgraph runtime["Linux Docker Tracing Runtime"]
        compose["docker compose run --build --rm"]
        entry["run-bpftrace-wrap.sh"]
        tracer["bpftrace probe<br/>or perf trace"]
        exec_helper["exec-target-from-env"]
        workload["Wrapped workload + child processes<br/>cargo, rustc, npm, node, app"]
    end

    user --> cli
    user -->|"--dashboard / see / demo --dashboard"| dashboard
    user -->|"attach"| attach

    config --> cli
    assets --> cli

    dashboard --> viewer
    viewer -->|"re-invokes tracker with<br/>--emit jsonl + --log-enable"| cli
    viewer --> browser

    cli -->|"resolve runtime and build command"| compose
    compose --> entry
    entry --> tracer
    entry --> exec_helper
    exec_helper --> workload
    workload -->|"syscalls"| tracer
    tracer --> runtime_lines

    runtime_lines -->|"bpftrace path"| events
    runtime_lines -->|"perf path"| perfcrate
    perfcrate --> events
    attach -->|"normalize backend output"| events

    events --> stream

    stream -->|"stdout / stderr"| user
    stream --> logs
    stream --> viewer
    stream --> dataset
    stream --> otel
    stream --> intelligence

    intelligence --> dataset
    dataset --> analysis
    analysis --> viewer
    otel --> collector

    events -. shared contract .-> dataset
    events -. shared contract .-> viewer
    events -. shared contract .-> otel
```

## Notes

- `ebpf-tracker` is the orchestration entry point. It resolves runtime, config, transport, logging, demo assets, and dashboard mode before launching the traced session.
- The default collection path is `bpftrace` inside a privileged Docker runtime. The alternate transport is `perf trace`, normalized through `ebpf-tracker-perf`.
- `ebpf-tracker-events` is the shared contract across the workspace. It defines the `StreamRecord` JSONL schema and the session aggregation model consumed by the viewer, dataset, and OTel crates.
- `ebpf-tracker-viewer`, `ebpf-tracker-dataset`, and `ebpf-tracker-otel` are downstream consumers of the same normalized event stream.
- `attach` is a parallel entry path for live targets like `k8s` and `aws-eks`; it bypasses the Docker runtime and normalizes backend output into the same event model.
