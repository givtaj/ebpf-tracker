use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

use ebpf_tracker_events::{EventKind, StreamRecord};
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::common::v1::any_value::Value;
use opentelemetry_proto::tonic::common::v1::{AnyValue, InstrumentationScope, KeyValue};
use opentelemetry_proto::tonic::resource::v1::Resource;
use opentelemetry_proto::tonic::trace::v1::span::{self, Event};
use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};
use prost::Message;
use rand::random;
use reqwest::blocking::Client;

const JAEGER_COMPOSE_FILE_NAME: &str = "docker-compose.jaeger.yml";
const EMBEDDED_JAEGER_COMPOSE: &str = include_str!("../docker-compose.jaeger.yml");

pub const DEFAULT_SERVICE_NAME: &str = "ebpf-tracker";
pub const DEFAULT_JAEGER_OTLP_HTTP_ENDPOINT: &str = "http://127.0.0.1:4318/v1/traces";
pub const DEFAULT_OTLP_HTTP_ENDPOINT: &str = "http://127.0.0.1:4318/v1/traces";
pub const DEFAULT_JAEGER_UI_URL: &str = "http://127.0.0.1:16686";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CollectorTarget {
    Otlp,
    Jaeger,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JaegerCommand {
    Up,
    Down,
    Status,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportConfig {
    pub target: CollectorTarget,
    pub endpoint: String,
    pub service_name: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StreamSummary {
    pub total_records: usize,
    pub syscall_records: usize,
    pub aggregate_records: usize,
    pub process_spans: usize,
    pub exported_spans: usize,
    pub span_events: usize,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SessionTrace {
    pub started_unix_ms: u64,
    pub finished_unix_ms: u64,
    pub total_records: usize,
    pub syscall_records: usize,
    pub aggregate_records: usize,
    pub processes: Vec<ProcessTrace>,
    pub aggregates: Vec<AggregateMetric>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessTrace {
    pub comm: String,
    pub pid: u32,
    pub started_unix_ms: u64,
    pub finished_unix_ms: u64,
    pub syscall_count: usize,
    pub writes: usize,
    pub opens: usize,
    pub connects: usize,
    pub execs: usize,
    pub bytes_written: u64,
    pub events: Vec<SyscallEvent>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyscallEvent {
    pub timestamp_unix_ms: u64,
    pub kind: EventKind,
    pub file: Option<String>,
    pub bytes: Option<u64>,
    pub fd: Option<i32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregateMetric {
    pub timestamp_unix_ms: u64,
    pub metric: String,
    pub value: u64,
}

#[derive(Debug)]
struct ProcessAccumulator {
    comm: String,
    pid: u32,
    started_unix_ms: u64,
    finished_unix_ms: u64,
    writes: usize,
    opens: usize,
    connects: usize,
    execs: usize,
    bytes_written: u64,
    events: Vec<SyscallEvent>,
}

impl CollectorTarget {
    pub fn as_str(self) -> &'static str {
        match self {
            CollectorTarget::Otlp => "otlp",
            CollectorTarget::Jaeger => "jaeger",
        }
    }

    pub fn default_endpoint(self) -> &'static str {
        match self {
            CollectorTarget::Otlp => DEFAULT_OTLP_HTTP_ENDPOINT,
            CollectorTarget::Jaeger => DEFAULT_JAEGER_OTLP_HTTP_ENDPOINT,
        }
    }
}

impl Default for ExportConfig {
    fn default() -> Self {
        Self {
            target: CollectorTarget::Otlp,
            endpoint: DEFAULT_OTLP_HTTP_ENDPOINT.to_string(),
            service_name: DEFAULT_SERVICE_NAME.to_string(),
        }
    }
}

impl SessionTrace {
    pub fn summary(&self) -> StreamSummary {
        let session_span = usize::from(self.total_records > 0);
        StreamSummary {
            total_records: self.total_records,
            syscall_records: self.syscall_records,
            aggregate_records: self.aggregate_records,
            process_spans: self.processes.len(),
            exported_spans: self.processes.len() + session_span,
            span_events: self.syscall_records + self.aggregate_records,
        }
    }
}

pub fn parse_target(raw: &str) -> Result<CollectorTarget, String> {
    match raw {
        "otlp" => Ok(CollectorTarget::Otlp),
        "jaeger" => Ok(CollectorTarget::Jaeger),
        _ => Err(format!("unsupported export target: {raw}")),
    }
}

pub fn read_stream_records<R: BufRead>(reader: R) -> Result<Vec<StreamRecord>, String> {
    let mut records = Vec::new();

    for line in reader.lines() {
        let line = line.map_err(|err| format!("failed to read stdin: {err}"))?;
        if line.trim().is_empty() {
            continue;
        }

        let record: StreamRecord =
            serde_json::from_str(&line).map_err(|err| format!("invalid stream record: {err}"))?;
        records.push(record);
    }

    Ok(records)
}

pub fn build_session_trace(records: &[StreamRecord]) -> SessionTrace {
    if records.is_empty() {
        return SessionTrace::default();
    }

    let mut started_unix_ms = u64::MAX;
    let mut finished_unix_ms = 0u64;
    let mut syscall_records = 0usize;
    let mut aggregate_records = 0usize;
    let mut processes: BTreeMap<(u32, String), ProcessAccumulator> = BTreeMap::new();
    let mut aggregates = Vec::new();

    for record in records {
        match record {
            StreamRecord::Syscall {
                timestamp_unix_ms,
                kind,
                comm,
                pid,
                file,
                bytes,
                fd,
            } => {
                started_unix_ms = started_unix_ms.min(*timestamp_unix_ms);
                finished_unix_ms = finished_unix_ms.max(*timestamp_unix_ms);
                syscall_records += 1;

                let key = (*pid, comm.clone());
                let entry = processes.entry(key).or_insert_with(|| ProcessAccumulator {
                    comm: comm.clone(),
                    pid: *pid,
                    started_unix_ms: *timestamp_unix_ms,
                    finished_unix_ms: *timestamp_unix_ms,
                    writes: 0,
                    opens: 0,
                    connects: 0,
                    execs: 0,
                    bytes_written: 0,
                    events: Vec::new(),
                });

                entry.started_unix_ms = entry.started_unix_ms.min(*timestamp_unix_ms);
                entry.finished_unix_ms = entry.finished_unix_ms.max(*timestamp_unix_ms);

                match kind {
                    EventKind::Execve => entry.execs += 1,
                    EventKind::OpenAt => entry.opens += 1,
                    EventKind::Write => {
                        entry.writes += 1;
                        entry.bytes_written = entry
                            .bytes_written
                            .saturating_add(bytes.unwrap_or_default());
                    }
                    EventKind::Connect => entry.connects += 1,
                }

                entry.events.push(SyscallEvent {
                    timestamp_unix_ms: *timestamp_unix_ms,
                    kind: *kind,
                    file: file.clone(),
                    bytes: *bytes,
                    fd: *fd,
                });
            }
            StreamRecord::Aggregate {
                timestamp_unix_ms,
                metric,
                value,
            } => {
                started_unix_ms = started_unix_ms.min(*timestamp_unix_ms);
                finished_unix_ms = finished_unix_ms.max(*timestamp_unix_ms);
                aggregate_records += 1;
                aggregates.push(AggregateMetric {
                    timestamp_unix_ms: *timestamp_unix_ms,
                    metric: metric.clone(),
                    value: *value,
                });
            }
        }
    }

    let mut process_traces: Vec<ProcessTrace> = processes
        .into_values()
        .map(|process| ProcessTrace {
            comm: process.comm,
            pid: process.pid,
            started_unix_ms: process.started_unix_ms,
            finished_unix_ms: process.finished_unix_ms,
            syscall_count: process.events.len(),
            writes: process.writes,
            opens: process.opens,
            connects: process.connects,
            execs: process.execs,
            bytes_written: process.bytes_written,
            events: process.events,
        })
        .collect();
    process_traces.sort_by_key(|process| (process.started_unix_ms, process.pid));

    SessionTrace {
        started_unix_ms,
        finished_unix_ms,
        total_records: records.len(),
        syscall_records,
        aggregate_records,
        processes: process_traces,
        aggregates,
    }
}

pub fn export_jsonl<R: BufRead>(reader: R, config: &ExportConfig) -> Result<StreamSummary, String> {
    let records = read_stream_records(reader)?;
    export_records(&records, config)
}

pub fn export_records(
    records: &[StreamRecord],
    config: &ExportConfig,
) -> Result<StreamSummary, String> {
    let trace = build_session_trace(records);
    let summary = trace.summary();

    if trace.total_records == 0 {
        return Ok(summary);
    }

    let request = build_export_request(&trace, config);
    post_export_request(&request, &config.endpoint)?;
    Ok(summary)
}

pub fn format_export_message(config: &ExportConfig, summary: &StreamSummary) -> String {
    format!(
        "exported target={} endpoint={} service={} records={} syscalls={} aggregates={} spans={} process_spans={} events={}",
        config.target.as_str(),
        config.endpoint,
        config.service_name,
        summary.total_records,
        summary.syscall_records,
        summary.aggregate_records,
        summary.exported_spans,
        summary.process_spans,
        summary.span_events
    )
}

pub fn run_jaeger(command: JaegerCommand) -> Result<i32, String> {
    let compose_file = ensure_jaeger_compose_file()?;
    let mut docker = Command::new("docker");
    docker.arg("compose").arg("-f").arg(&compose_file);

    match command {
        JaegerCommand::Up => {
            docker.arg("up").arg("-d");
        }
        JaegerCommand::Down => {
            docker.arg("down");
        }
        JaegerCommand::Status => {
            docker.arg("ps");
        }
    }

    let status = docker
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|err| format!("failed to run docker compose for Jaeger: {err}"))?;

    Ok(exit_code(status))
}

fn cache_root_candidates() -> Vec<PathBuf> {
    let mut roots = Vec::new();

    if let Ok(path) = env::var("EBPF_TRACKER_CACHE_DIR") {
        roots.push(PathBuf::from(path));
        return roots;
    }

    if let Ok(path) = env::var("XDG_CACHE_HOME") {
        roots.push(PathBuf::from(path).join("ebpf-tracker"));
    }

    if let Ok(path) = env::var("HOME") {
        roots.push(PathBuf::from(path).join(".cache").join("ebpf-tracker"));
    }

    roots.push(env::temp_dir().join("ebpf-tracker"));
    roots
}

fn write_if_changed(path: &Path, content: &str) -> Result<(), String> {
    if path.exists() {
        let existing = fs::read_to_string(path)
            .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
        if existing == content {
            return Ok(());
        }
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
    }

    fs::write(path, content).map_err(|err| format!("failed to write {}: {err}", path.display()))?;
    Ok(())
}

fn ensure_jaeger_compose_file() -> Result<PathBuf, String> {
    let mut errors = Vec::new();

    for root in cache_root_candidates() {
        let runtime_dir = root.join(format!("otel-runtime-v{}", env!("CARGO_PKG_VERSION")));
        let result = (|| -> Result<PathBuf, String> {
            let compose_file = runtime_dir.join(JAEGER_COMPOSE_FILE_NAME);
            write_if_changed(&compose_file, EMBEDDED_JAEGER_COMPOSE)?;
            Ok(compose_file)
        })();

        match result {
            Ok(compose_file) => return Ok(compose_file),
            Err(err) => errors.push(err),
        }
    }

    Err(format!(
        "failed to materialize Jaeger runtime assets: {}",
        errors.join("; ")
    ))
}

fn build_export_request(trace: &SessionTrace, config: &ExportConfig) -> ExportTraceServiceRequest {
    let trace_id = random_trace_id();
    let session_span_id = random_span_id();
    let session_span = build_session_span(trace, &session_span_id, &trace_id);

    let mut spans = Vec::with_capacity(trace.processes.len() + 1);
    spans.push(session_span);
    for process in &trace.processes {
        spans.push(build_process_span(process, &trace_id, &session_span_id));
    }

    ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            resource: Some(Resource {
                attributes: vec![
                    string_key_value("service.name", config.service_name.clone()),
                    string_key_value("service.namespace", "ebpf-tracker"),
                    string_key_value("ebpf.export.target", config.target.as_str()),
                ],
                dropped_attributes_count: 0,
                entity_refs: Vec::new(),
            }),
            scope_spans: vec![ScopeSpans {
                scope: Some(InstrumentationScope {
                    name: "ebpf-tracker-otel".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    attributes: Vec::new(),
                    dropped_attributes_count: 0,
                }),
                spans,
                schema_url: String::new(),
            }],
            schema_url: String::new(),
        }],
    }
}

fn build_session_span(trace: &SessionTrace, session_span_id: &[u8], trace_id: &[u8]) -> Span {
    Span {
        trace_id: trace_id.to_vec(),
        span_id: session_span_id.to_vec(),
        trace_state: String::new(),
        parent_span_id: Vec::new(),
        flags: 1,
        name: "ebpf.session".to_string(),
        kind: span::SpanKind::Internal as i32,
        start_time_unix_nano: to_unix_nanos(trace.started_unix_ms),
        end_time_unix_nano: to_unix_nanos(trace.finished_unix_ms.saturating_add(1)),
        attributes: vec![
            int_key_value("ebpf.record.total", trace.total_records as i64),
            int_key_value("ebpf.record.syscalls", trace.syscall_records as i64),
            int_key_value("ebpf.record.aggregates", trace.aggregate_records as i64),
            int_key_value("ebpf.process.count", trace.processes.len() as i64),
        ],
        dropped_attributes_count: 0,
        events: trace
            .aggregates
            .iter()
            .map(|aggregate| Event {
                time_unix_nano: to_unix_nanos(aggregate.timestamp_unix_ms),
                name: format!("aggregate.{}", aggregate.metric),
                attributes: vec![
                    string_key_value("ebpf.metric.name", aggregate.metric.clone()),
                    int_key_value("ebpf.metric.value", aggregate.value as i64),
                ],
                dropped_attributes_count: 0,
            })
            .collect(),
        dropped_events_count: 0,
        links: Vec::new(),
        dropped_links_count: 0,
        status: None,
    }
}

fn build_process_span(process: &ProcessTrace, trace_id: &[u8], parent_span_id: &[u8]) -> Span {
    let span_id = random_span_id();
    Span {
        trace_id: trace_id.to_vec(),
        span_id,
        trace_state: String::new(),
        parent_span_id: parent_span_id.to_vec(),
        flags: 1,
        name: format!("process {} ({})", process.comm, process.pid),
        kind: span::SpanKind::Internal as i32,
        start_time_unix_nano: to_unix_nanos(process.started_unix_ms),
        end_time_unix_nano: to_unix_nanos(process.finished_unix_ms.saturating_add(1)),
        attributes: vec![
            int_key_value("process.pid", process.pid as i64),
            string_key_value("process.command", process.comm.clone()),
            int_key_value("ebpf.process.syscalls", process.syscall_count as i64),
            int_key_value("ebpf.process.execs", process.execs as i64),
            int_key_value("ebpf.process.opens", process.opens as i64),
            int_key_value("ebpf.process.connects", process.connects as i64),
            int_key_value("ebpf.process.writes", process.writes as i64),
            int_key_value("ebpf.process.bytes_written", process.bytes_written as i64),
        ],
        dropped_attributes_count: 0,
        events: process
            .events
            .iter()
            .map(|event| build_process_event(event))
            .collect(),
        dropped_events_count: 0,
        links: Vec::new(),
        dropped_links_count: 0,
        status: None,
    }
}

fn build_process_event(event: &SyscallEvent) -> Event {
    let mut attributes = vec![string_key_value("ebpf.syscall.kind", event.kind.as_str())];
    if let Some(file) = &event.file {
        attributes.push(string_key_value("file.path", file.clone()));
    }
    if let Some(bytes) = event.bytes {
        attributes.push(int_key_value("ebpf.write.bytes", bytes as i64));
    }
    if let Some(fd) = event.fd {
        attributes.push(int_key_value("ebpf.fd", fd as i64));
    }

    Event {
        time_unix_nano: to_unix_nanos(event.timestamp_unix_ms),
        name: event.kind.as_str().to_string(),
        attributes,
        dropped_attributes_count: 0,
    }
}

fn post_export_request(request: &ExportTraceServiceRequest, endpoint: &str) -> Result<(), String> {
    let client = Client::builder()
        .build()
        .map_err(|err| format!("failed to build HTTP client: {err}"))?;
    let body = request.encode_to_vec();
    let response = client
        .post(endpoint)
        .header("content-type", "application/x-protobuf")
        .header("accept", "application/x-protobuf")
        .body(body)
        .send()
        .map_err(|err| format!("failed to export OTLP traces to {endpoint}: {err:?}"))?;

    if !response.status().is_success() {
        let status = response.status();
        let details = response
            .text()
            .unwrap_or_else(|_| "collector returned a non-success response".to_string());
        return Err(format!(
            "collector rejected OTLP trace export at {endpoint} with {status}: {details}"
        ));
    }

    Ok(())
}

fn random_trace_id() -> Vec<u8> {
    loop {
        let candidate = random::<[u8; 16]>();
        if candidate.iter().any(|byte| *byte != 0) {
            return candidate.to_vec();
        }
    }
}

fn random_span_id() -> Vec<u8> {
    loop {
        let candidate = random::<[u8; 8]>();
        if candidate.iter().any(|byte| *byte != 0) {
            return candidate.to_vec();
        }
    }
}

fn to_unix_nanos(timestamp_unix_ms: u64) -> u64 {
    timestamp_unix_ms.saturating_mul(1_000_000)
}

fn string_key_value(key: impl Into<String>, value: impl Into<String>) -> KeyValue {
    KeyValue {
        key: key.into(),
        value: Some(AnyValue {
            value: Some(Value::StringValue(value.into())),
        }),
    }
}

fn int_key_value(key: impl Into<String>, value: i64) -> KeyValue {
    KeyValue {
        key: key.into(),
        value: Some(AnyValue {
            value: Some(Value::IntValue(value)),
        }),
    }
}

fn exit_code(status: ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }

    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return 128 + signal;
        }
    }

    1
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use ebpf_tracker_events::{EventKind, StreamRecord};
    use opentelemetry_proto::tonic::common::v1::any_value::Value;

    use super::{
        build_export_request, build_session_trace, format_export_message, parse_target,
        read_stream_records, CollectorTarget, ExportConfig, SessionTrace, StreamSummary,
    };

    #[test]
    fn parses_known_targets() {
        assert_eq!(parse_target("otlp"), Ok(CollectorTarget::Otlp));
        assert_eq!(parse_target("jaeger"), Ok(CollectorTarget::Jaeger));
    }

    #[test]
    fn reads_jsonl_records() {
        let input = Cursor::new(
            "{\"type\":\"syscall\",\"timestamp_unix_ms\":1,\"kind\":\"write\",\"comm\":\"cargo\",\"pid\":7,\"bytes\":10}\n{\"type\":\"aggregate\",\"timestamp_unix_ms\":2,\"metric\":\"writes\",\"value\":1}\n",
        );
        let records = read_stream_records(input).expect("jsonl should parse");

        assert_eq!(records.len(), 2);
    }

    #[test]
    fn groups_records_into_session_and_process_traces() {
        let records = vec![
            StreamRecord::Syscall {
                timestamp_unix_ms: 10,
                kind: EventKind::Execve,
                comm: "cargo".to_string(),
                pid: 100,
                file: None,
                bytes: None,
                fd: None,
            },
            StreamRecord::Syscall {
                timestamp_unix_ms: 12,
                kind: EventKind::Write,
                comm: "cargo".to_string(),
                pid: 100,
                file: None,
                bytes: Some(16),
                fd: None,
            },
            StreamRecord::Syscall {
                timestamp_unix_ms: 15,
                kind: EventKind::OpenAt,
                comm: "session-io-demo".to_string(),
                pid: 200,
                file: Some("input/message.txt".to_string()),
                bytes: None,
                fd: None,
            },
            StreamRecord::Aggregate {
                timestamp_unix_ms: 20,
                metric: "writes".to_string(),
                value: 2,
            },
        ];

        let trace = build_session_trace(&records);

        assert_eq!(
            trace,
            SessionTrace {
                started_unix_ms: 10,
                finished_unix_ms: 20,
                total_records: 4,
                syscall_records: 3,
                aggregate_records: 1,
                processes: vec![
                    super::ProcessTrace {
                        comm: "cargo".to_string(),
                        pid: 100,
                        started_unix_ms: 10,
                        finished_unix_ms: 12,
                        syscall_count: 2,
                        writes: 1,
                        opens: 0,
                        connects: 0,
                        execs: 1,
                        bytes_written: 16,
                        events: vec![
                            super::SyscallEvent {
                                timestamp_unix_ms: 10,
                                kind: EventKind::Execve,
                                file: None,
                                bytes: None,
                                fd: None,
                            },
                            super::SyscallEvent {
                                timestamp_unix_ms: 12,
                                kind: EventKind::Write,
                                file: None,
                                bytes: Some(16),
                                fd: None,
                            },
                        ],
                    },
                    super::ProcessTrace {
                        comm: "session-io-demo".to_string(),
                        pid: 200,
                        started_unix_ms: 15,
                        finished_unix_ms: 15,
                        syscall_count: 1,
                        writes: 0,
                        opens: 1,
                        connects: 0,
                        execs: 0,
                        bytes_written: 0,
                        events: vec![super::SyscallEvent {
                            timestamp_unix_ms: 15,
                            kind: EventKind::OpenAt,
                            file: Some("input/message.txt".to_string()),
                            bytes: None,
                            fd: None,
                        }],
                    },
                ],
                aggregates: vec![super::AggregateMetric {
                    timestamp_unix_ms: 20,
                    metric: "writes".to_string(),
                    value: 2,
                }],
            }
        );
    }

    #[test]
    fn export_request_contains_service_name_and_process_spans() {
        let trace = SessionTrace {
            started_unix_ms: 10,
            finished_unix_ms: 12,
            total_records: 2,
            syscall_records: 2,
            aggregate_records: 0,
            processes: vec![super::ProcessTrace {
                comm: "cargo".to_string(),
                pid: 100,
                started_unix_ms: 10,
                finished_unix_ms: 12,
                syscall_count: 2,
                writes: 1,
                opens: 0,
                connects: 0,
                execs: 1,
                bytes_written: 16,
                events: vec![
                    super::SyscallEvent {
                        timestamp_unix_ms: 10,
                        kind: EventKind::Execve,
                        file: None,
                        bytes: None,
                        fd: None,
                    },
                    super::SyscallEvent {
                        timestamp_unix_ms: 12,
                        kind: EventKind::Write,
                        file: None,
                        bytes: Some(16),
                        fd: None,
                    },
                ],
            }],
            aggregates: Vec::new(),
        };

        let request = build_export_request(
            &trace,
            &ExportConfig {
                target: CollectorTarget::Jaeger,
                endpoint: "http://127.0.0.1:4318/v1/traces".to_string(),
                service_name: "session-io-demo".to_string(),
            },
        );
        let resource_spans = request.resource_spans.first().expect("resource spans");
        let service_name = resource_spans
            .resource
            .as_ref()
            .expect("resource")
            .attributes[0]
            .value
            .as_ref()
            .expect("service name value")
            .value
            .as_ref()
            .expect("service name");

        assert_eq!(resource_spans.scope_spans[0].spans.len(), 2);
        assert!(matches!(service_name, Value::StringValue(value) if value == "session-io-demo"));
    }

    #[test]
    fn export_message_names_the_target() {
        let message = format_export_message(
            &ExportConfig {
                target: CollectorTarget::Jaeger,
                endpoint: "http://127.0.0.1:4318/v1/traces".to_string(),
                service_name: "session-io-demo".to_string(),
            },
            &StreamSummary {
                total_records: 4,
                syscall_records: 3,
                aggregate_records: 1,
                process_spans: 2,
                exported_spans: 3,
                span_events: 4,
            },
        );

        assert!(message.contains("target=jaeger"));
        assert!(message.contains("service=session-io-demo"));
        assert!(message.contains("spans=3"));
    }
}
