use std::io::BufRead;

use ebpf_tracker_events::StreamRecord;

pub const DEFAULT_SERVICE_NAME: &str = "ebpf-tracker";
pub const DEFAULT_JAEGER_OTLP_HTTP_ENDPOINT: &str = "http://127.0.0.1:4318/v1/traces";
pub const DEFAULT_OTLP_HTTP_ENDPOINT: &str = "http://127.0.0.1:4318/v1/traces";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CollectorTarget {
    Otlp,
    Jaeger,
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
}

impl CollectorTarget {
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

pub fn parse_target(raw: &str) -> Result<CollectorTarget, String> {
    match raw {
        "otlp" => Ok(CollectorTarget::Otlp),
        "jaeger" => Ok(CollectorTarget::Jaeger),
        _ => Err(format!("unsupported export target: {raw}")),
    }
}

pub fn consume_jsonl<R: BufRead>(reader: R) -> Result<StreamSummary, String> {
    let mut summary = StreamSummary::default();

    for line in reader.lines() {
        let line = line.map_err(|err| format!("failed to read stdin: {err}"))?;
        if line.trim().is_empty() {
            continue;
        }

        let record: StreamRecord =
            serde_json::from_str(&line).map_err(|err| format!("invalid stream record: {err}"))?;
        summary.total_records += 1;

        match record {
            StreamRecord::Syscall { .. } => summary.syscall_records += 1,
            StreamRecord::Aggregate { .. } => summary.aggregate_records += 1,
        }
    }

    Ok(summary)
}

pub fn scaffold_message(config: &ExportConfig, summary: &StreamSummary) -> String {
    format!(
        "scaffold exporter target={} endpoint={} service={} records={} syscalls={} aggregates={}",
        match config.target {
            CollectorTarget::Otlp => "otlp",
            CollectorTarget::Jaeger => "jaeger",
        },
        config.endpoint,
        config.service_name,
        summary.total_records,
        summary.syscall_records,
        summary.aggregate_records
    )
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::{
        consume_jsonl, parse_target, scaffold_message, CollectorTarget, ExportConfig, StreamSummary,
    };

    #[test]
    fn parses_known_targets() {
        assert_eq!(parse_target("otlp"), Ok(CollectorTarget::Otlp));
        assert_eq!(parse_target("jaeger"), Ok(CollectorTarget::Jaeger));
    }

    #[test]
    fn consumes_syscall_and_aggregate_records() {
        let input = Cursor::new(
            "{\"type\":\"syscall\",\"timestamp_unix_ms\":1,\"kind\":\"write\",\"comm\":\"cargo\",\"pid\":7,\"bytes\":10}\n{\"type\":\"aggregate\",\"timestamp_unix_ms\":2,\"metric\":\"writes\",\"value\":1}\n",
        );
        let summary = consume_jsonl(input).expect("jsonl should parse");

        assert_eq!(
            summary,
            StreamSummary {
                total_records: 2,
                syscall_records: 1,
                aggregate_records: 1,
            }
        );
    }

    #[test]
    fn scaffold_message_names_the_target() {
        let message = scaffold_message(
            &ExportConfig {
                target: CollectorTarget::Jaeger,
                endpoint: "http://127.0.0.1:4318/v1/traces".to_string(),
                service_name: "session-io-demo".to_string(),
            },
            &StreamSummary {
                total_records: 4,
                syscall_records: 3,
                aggregate_records: 1,
            },
        );

        assert!(message.contains("target=jaeger"));
        assert!(message.contains("service=session-io-demo"));
        assert!(message.contains("records=4"));
    }
}
