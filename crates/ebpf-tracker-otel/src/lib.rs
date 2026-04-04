use std::env;
use std::fs;
use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::Duration;

use ebpf_tracker_events::{SessionTrace, StreamRecord};
use opentelemetry_proto::tonic::collector::trace::v1::{
    ExportTracePartialSuccess, ExportTraceServiceRequest, ExportTraceServiceResponse,
};
use opentelemetry_proto::tonic::common::v1::any_value::Value;
use opentelemetry_proto::tonic::common::v1::{AnyValue, InstrumentationScope, KeyValue};
use opentelemetry_proto::tonic::resource::v1::Resource;
use opentelemetry_proto::tonic::trace::v1::span::{self, Event};
use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};
use prost::Message;
use rand::random;
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, ACCEPT, CONTENT_TYPE};
use reqwest::{StatusCode, Url};

const JAEGER_COMPOSE_FILE_NAME: &str = "docker-compose.jaeger.yml";
const EMBEDDED_JAEGER_COMPOSE: &str = include_str!("../docker-compose.jaeger.yml");
const OTLP_TRACES_PATH: &str = "/v1/traces";
const DEFAULT_EXPORT_TIMEOUT_SECONDS: u64 = 10;
const DEFAULT_USER_AGENT: &str = concat!("ebpf-tracker-otel/", env!("CARGO_PKG_VERSION"));

pub const DEFAULT_SERVICE_NAME: &str = "ebpf-tracker";
pub const DEFAULT_JAEGER_OTLP_HTTP_ENDPOINT: &str = "http://127.0.0.1:4318/v1/traces";
pub const DEFAULT_OTLP_HTTP_ENDPOINT: &str = "http://127.0.0.1:4318/v1/traces";
pub const DEFAULT_JAEGER_UI_URL: &str = "http://127.0.0.1:16686";

pub use ebpf_tracker_events::{build_session_trace, AggregateMetric, ProcessTrace, SyscallEvent};

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
    pub timeout_seconds: u64,
    pub headers: Vec<ExportHeader>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportHeader {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StreamSummary {
    pub total_records: usize,
    pub syscall_records: usize,
    pub aggregate_records: usize,
    pub process_spans: usize,
    pub exported_spans: usize,
    pub span_events: usize,
    pub collector_warnings: Vec<String>,
}

#[derive(Clone, Debug)]
struct ValidatedExportConfig {
    target: CollectorTarget,
    endpoint: Url,
    service_name: String,
    timeout: Duration,
    headers: HeaderMap,
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
            timeout_seconds: DEFAULT_EXPORT_TIMEOUT_SECONDS,
            headers: Vec::new(),
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

pub fn summarize_trace(trace: &SessionTrace) -> StreamSummary {
    let session_span = usize::from(trace.total_records > 0);
    StreamSummary {
        total_records: trace.total_records,
        syscall_records: trace.syscall_records,
        aggregate_records: trace.aggregate_records,
        process_spans: trace.processes.len(),
        exported_spans: trace.processes.len() + session_span,
        span_events: trace.syscall_records + trace.aggregate_records,
        collector_warnings: Vec::new(),
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
    let validated = validate_export_config(config)?;
    let trace = build_session_trace(records);
    let mut summary = summarize_trace(&trace);

    if trace.total_records == 0 {
        return Ok(summary);
    }

    let request = build_export_request(&trace, &validated);
    if let Some(warning) = post_export_request(&request, &validated)? {
        summary.collector_warnings.push(warning);
    }

    Ok(summary)
}

pub fn format_export_message(config: &ExportConfig, summary: &StreamSummary) -> String {
    format!(
        "exported target={} endpoint={} service={} records={} syscalls={} aggregates={} spans={} process_spans={} events={} warnings={}",
        config.target.as_str(),
        config.endpoint,
        config.service_name,
        summary.total_records,
        summary.syscall_records,
        summary.aggregate_records,
        summary.exported_spans,
        summary.process_spans,
        summary.span_events,
        summary.collector_warnings.len()
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

fn validate_export_config(config: &ExportConfig) -> Result<ValidatedExportConfig, String> {
    let service_name = config.service_name.trim();
    if service_name.is_empty() {
        return Err("service name must not be empty".to_string());
    }

    if config.timeout_seconds == 0 {
        return Err("timeout seconds must be greater than zero".to_string());
    }

    let endpoint = normalize_endpoint(&config.endpoint)?;
    let headers = build_header_map(&config.headers)?;

    Ok(ValidatedExportConfig {
        target: config.target,
        endpoint,
        service_name: service_name.to_string(),
        timeout: Duration::from_secs(config.timeout_seconds),
        headers,
    })
}

fn normalize_endpoint(raw_endpoint: &str) -> Result<Url, String> {
    let trimmed = raw_endpoint.trim();
    if trimmed.is_empty() {
        return Err("endpoint must not be empty".to_string());
    }

    let mut endpoint =
        Url::parse(trimmed).map_err(|err| format!("invalid OTLP endpoint {trimmed:?}: {err}"))?;
    match endpoint.scheme() {
        "http" | "https" => {}
        scheme => {
            return Err(format!(
                "unsupported OTLP endpoint scheme {scheme:?}; expected http or https"
            ));
        }
    }

    if endpoint.host_str().is_none() {
        return Err(format!(
            "OTLP endpoint must include a host: {}",
            endpoint.as_str()
        ));
    }

    if endpoint.path().is_empty() || endpoint.path() == "/" {
        endpoint.set_path(OTLP_TRACES_PATH);
    }

    Ok(endpoint)
}

fn build_header_map(headers: &[ExportHeader]) -> Result<HeaderMap, String> {
    let mut header_map = HeaderMap::new();

    for header in headers {
        let name = header.name.trim();
        if name.is_empty() {
            return Err("header name must not be empty".to_string());
        }

        let header_name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|err| format!("invalid header name {name:?}: {err}"))?;
        let header_value = HeaderValue::from_str(header.value.trim())
            .map_err(|err| format!("invalid header value for {name:?}: {err}"))?;
        header_map.insert(header_name, header_value);
    }

    Ok(header_map)
}

fn build_export_request(
    trace: &SessionTrace,
    config: &ValidatedExportConfig,
) -> ExportTraceServiceRequest {
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
        events: process.events.iter().map(build_process_event).collect(),
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

fn post_export_request(
    request: &ExportTraceServiceRequest,
    config: &ValidatedExportConfig,
) -> Result<Option<String>, String> {
    let client = Client::builder()
        .connect_timeout(config.timeout)
        .timeout(config.timeout)
        .user_agent(DEFAULT_USER_AGENT)
        .build()
        .map_err(|err| format!("failed to build HTTP client: {err}"))?;
    let body = request.encode_to_vec();
    let response = client
        .post(config.endpoint.clone())
        .headers(config.headers.clone())
        .header(CONTENT_TYPE, "application/x-protobuf")
        .header(ACCEPT, "application/x-protobuf")
        .body(body)
        .send()
        .map_err(|err| {
            format!(
                "failed to export OTLP traces to {} within {:?}: {err:?}",
                config.endpoint, config.timeout
            )
        })?;

    let status = response.status();
    let response_body = response.bytes().map_err(|err| {
        format!(
            "failed to read OTLP collector response from {}: {err:?}",
            config.endpoint
        )
    })?;

    parse_export_response(status, response_body.as_ref(), config.endpoint.as_str())
}

fn parse_export_response(
    status: StatusCode,
    response_body: &[u8],
    endpoint: &str,
) -> Result<Option<String>, String> {
    if !status.is_success() {
        let details = summarize_response_body(response_body);
        return Err(format!(
            "collector rejected OTLP trace export at {endpoint} with {status}: {details}"
        ));
    }

    if response_body.is_empty() {
        return Ok(None);
    }

    let response = ExportTraceServiceResponse::decode(response_body).map_err(|err| {
        format!("collector returned an unreadable OTLP response from {endpoint}: {err}")
    })?;

    match response.partial_success {
        Some(partial_success) => interpret_partial_success(partial_success, endpoint),
        None => Ok(None),
    }
}

fn interpret_partial_success(
    partial_success: ExportTracePartialSuccess,
    endpoint: &str,
) -> Result<Option<String>, String> {
    let message = partial_success.error_message.trim();
    if partial_success.rejected_spans > 0 {
        let detail = if message.is_empty() {
            "collector did not provide a rejection reason".to_string()
        } else {
            message.to_string()
        };
        return Err(format!(
            "collector partially rejected OTLP trace export at {endpoint}: rejected_spans={} message={detail}",
            partial_success.rejected_spans
        ));
    }

    if message.is_empty() {
        Ok(None)
    } else {
        Ok(Some(message.to_string()))
    }
}

fn summarize_response_body(body: &[u8]) -> String {
    if body.is_empty() {
        return "collector returned an empty response body".to_string();
    }

    match std::str::from_utf8(body) {
        Ok(text) => {
            let trimmed = text.trim();
            if trimmed.is_empty() {
                "collector returned an empty response body".to_string()
            } else if trimmed.len() > 240 {
                format!("{}...", &trimmed[..240])
            } else {
                trimmed.to_string()
            }
        }
        Err(_) => format!(
            "collector returned {} bytes of binary response data",
            body.len()
        ),
    }
}

pub fn parse_header(raw_header: &str) -> Result<ExportHeader, String> {
    let (name, value) = raw_header
        .split_once('=')
        .ok_or_else(|| "header must use NAME=VALUE format".to_string())?;

    let name = name.trim();
    if name.is_empty() {
        return Err("header name must not be empty".to_string());
    }

    Ok(ExportHeader {
        name: name.to_string(),
        value: value.trim().to_string(),
    })
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
    use prost::Message;
    use reqwest::StatusCode;

    use super::{
        build_export_request, build_session_trace, export_records, format_export_message,
        parse_export_response, parse_header, parse_target, read_stream_records,
        validate_export_config, CollectorTarget, ExportConfig, ExportHeader, SessionTrace,
        StreamSummary,
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
    fn parse_header_requires_name_value_pairs() {
        assert_eq!(
            parse_header("authorization=Bearer token").expect("header should parse"),
            ExportHeader {
                name: "authorization".to_string(),
                value: "Bearer token".to_string(),
            }
        );
        assert!(parse_header("broken-header").is_err());
    }

    #[test]
    fn validates_export_config_and_normalizes_endpoint() {
        let validated = validate_export_config(&ExportConfig {
            target: CollectorTarget::Jaeger,
            endpoint: "http://127.0.0.1:4318".to_string(),
            service_name: " session-io-demo ".to_string(),
            timeout_seconds: 15,
            headers: vec![ExportHeader {
                name: "authorization".to_string(),
                value: "Bearer token".to_string(),
            }],
        })
        .expect("config should validate");

        assert_eq!(
            validated.endpoint.as_str(),
            "http://127.0.0.1:4318/v1/traces"
        );
        assert_eq!(validated.service_name, "session-io-demo");
        assert_eq!(
            validated
                .headers
                .get("authorization")
                .expect("authorization header")
                .to_str()
                .expect("header value"),
            "Bearer token"
        );
    }

    #[test]
    fn rejects_invalid_export_config() {
        assert!(validate_export_config(&ExportConfig {
            target: CollectorTarget::Otlp,
            endpoint: "not-a-url".to_string(),
            service_name: "demo".to_string(),
            timeout_seconds: 10,
            headers: Vec::new(),
        })
        .is_err());

        assert!(validate_export_config(&ExportConfig {
            target: CollectorTarget::Otlp,
            endpoint: "http://127.0.0.1:4318/v1/traces".to_string(),
            service_name: "   ".to_string(),
            timeout_seconds: 10,
            headers: Vec::new(),
        })
        .is_err());

        assert!(validate_export_config(&ExportConfig {
            target: CollectorTarget::Otlp,
            endpoint: "http://127.0.0.1:4318/v1/traces".to_string(),
            service_name: "demo".to_string(),
            timeout_seconds: 0,
            headers: Vec::new(),
        })
        .is_err());
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
        let trace = sample_trace();
        let validated = validate_export_config(&ExportConfig {
            target: CollectorTarget::Jaeger,
            endpoint: "http://127.0.0.1:4318/v1/traces".to_string(),
            service_name: "session-io-demo".to_string(),
            timeout_seconds: 10,
            headers: Vec::new(),
        })
        .expect("config should validate");
        let request = build_export_request(&trace, &validated);
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
    fn export_records_returns_empty_summary_without_network_when_input_is_empty() {
        let summary = export_records(
            &[],
            &ExportConfig {
                target: CollectorTarget::Jaeger,
                endpoint: "http://127.0.0.1:4318".to_string(),
                service_name: "session-io-demo".to_string(),
                timeout_seconds: 10,
                headers: vec![ExportHeader {
                    name: "authorization".to_string(),
                    value: "Bearer token".to_string(),
                }],
            },
        )
        .expect("empty export should not require a live collector");

        assert_eq!(summary.total_records, 0);
        assert_eq!(summary.exported_spans, 0);
    }

    #[test]
    fn parse_export_response_surfaces_collector_warning() {
        let response_body =
            opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceResponse {
                partial_success: Some(
                    opentelemetry_proto::tonic::collector::trace::v1::ExportTracePartialSuccess {
                        rejected_spans: 0,
                        error_message: "collector warning".to_string(),
                    },
                ),
            }
            .encode_to_vec();
        let warning = parse_export_response(
            StatusCode::OK,
            &response_body,
            "http://127.0.0.1:4318/v1/traces",
        )
        .expect("warning response should parse");

        assert_eq!(warning, Some("collector warning".to_string()));
    }

    #[test]
    fn partial_success_rejections_fail_export() {
        let response =
            opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceResponse {
                partial_success: Some(
                    opentelemetry_proto::tonic::collector::trace::v1::ExportTracePartialSuccess {
                        rejected_spans: 2,
                        error_message: "bad spans".to_string(),
                    },
                ),
            }
            .encode_to_vec();
        let error =
            parse_export_response(StatusCode::OK, &response, "http://127.0.0.1:4318/v1/traces")
                .expect_err("partial rejection should fail");

        assert!(error.contains("rejected_spans=2"));
        assert!(error.contains("bad spans"));
    }

    #[test]
    fn export_message_names_the_target_and_warning_count() {
        let message = format_export_message(
            &ExportConfig {
                target: CollectorTarget::Jaeger,
                endpoint: "http://127.0.0.1:4318/v1/traces".to_string(),
                service_name: "session-io-demo".to_string(),
                timeout_seconds: 10,
                headers: Vec::new(),
            },
            &StreamSummary {
                total_records: 4,
                syscall_records: 3,
                aggregate_records: 1,
                process_spans: 2,
                exported_spans: 3,
                span_events: 4,
                collector_warnings: vec!["collector warning".to_string()],
            },
        );

        assert!(message.contains("target=jaeger"));
        assert!(message.contains("service=session-io-demo"));
        assert!(message.contains("spans=3"));
        assert!(message.contains("warnings=1"));
    }

    fn sample_trace() -> SessionTrace {
        SessionTrace {
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
        }
    }
}
