use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    Execve,
    OpenAt,
    Write,
    Connect,
}

impl EventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            EventKind::Execve => "execve",
            EventKind::OpenAt => "openat",
            EventKind::Write => "write",
            EventKind::Connect => "connect",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedEvent {
    pub kind: EventKind,
    pub comm: String,
    pub pid: u32,
    pub file: Option<String>,
    pub bytes: Option<u64>,
    pub fd: Option<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedLine {
    Event(ParsedEvent),
    Aggregate { name: String, value: u64 },
    Text,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StreamRecord {
    Session {
        timestamp_unix_ms: u64,
        demo_name: String,
        product_name: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        product_tagline: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        sponsor_name: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        sponsor_message: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        sponsor_url: Option<String>,
    },
    Syscall {
        timestamp_unix_ms: u64,
        kind: EventKind,
        comm: String,
        pid: u32,
        #[serde(skip_serializing_if = "Option::is_none")]
        file: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        bytes: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        fd: Option<i32>,
    },
    Aggregate {
        timestamp_unix_ms: u64,
        metric: String,
        value: u64,
    },
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionTrace {
    pub started_unix_ms: u64,
    pub finished_unix_ms: u64,
    pub total_records: usize,
    pub syscall_records: usize,
    pub aggregate_records: usize,
    pub processes: Vec<ProcessTrace>,
    pub aggregates: Vec<AggregateMetric>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyscallEvent {
    pub timestamp_unix_ms: u64,
    pub kind: EventKind,
    pub file: Option<String>,
    pub bytes: Option<u64>,
    pub fd: Option<i32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

pub fn parse_trace_line(line: &str) -> ParsedLine {
    if let Some((name, value)) = parse_aggregate_line(line) {
        return ParsedLine::Aggregate { name, value };
    }

    if let Some(event) = parse_event_line(line) {
        return ParsedLine::Event(event);
    }

    ParsedLine::Text
}

pub fn parse_aggregate_line(line: &str) -> Option<(String, u64)> {
    let trimmed = line.trim();
    if !trimmed.starts_with('@') {
        return None;
    }

    let (name, value) = trimmed[1..].split_once(':')?;
    let value = value.trim().parse().ok()?;
    Some((name.trim().to_string(), value))
}

pub fn parse_event_line(line: &str) -> Option<ParsedEvent> {
    let mut parts = line.split_whitespace();
    let kind = match parts.next()? {
        "execve" => EventKind::Execve,
        "openat" => EventKind::OpenAt,
        "write" => EventKind::Write,
        "connect" => EventKind::Connect,
        _ => return None,
    };

    let mut comm = None;
    let mut pid = None;
    let mut file = None;
    let mut bytes = None;
    let mut fd = None;

    for part in parts {
        let (key, value) = match part.split_once('=') {
            Some(pair) => pair,
            None => continue,
        };

        match key {
            "comm" => comm = Some(value.to_string()),
            "pid" => pid = value.parse().ok(),
            "file" => file = Some(value.to_string()),
            "bytes" => bytes = value.parse().ok(),
            "fd" => fd = value.parse().ok(),
            _ => {}
        }
    }

    Some(ParsedEvent {
        kind,
        comm: comm?,
        pid: pid?,
        file,
        bytes,
        fd,
    })
}

pub fn stream_record_for_line(line: &str) -> Option<StreamRecord> {
    stream_record_for_line_at(line, current_timestamp_millis())
}

pub fn stream_record_for_line_at(line: &str, timestamp_unix_ms: u64) -> Option<StreamRecord> {
    match parse_trace_line(line) {
        ParsedLine::Event(event) => Some(StreamRecord::Syscall {
            timestamp_unix_ms,
            kind: event.kind,
            comm: event.comm,
            pid: event.pid,
            file: event.file,
            bytes: event.bytes,
            fd: event.fd,
        }),
        ParsedLine::Aggregate { name, value } => Some(StreamRecord::Aggregate {
            timestamp_unix_ms,
            metric: name,
            value,
        }),
        ParsedLine::Text => None,
    }
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
            StreamRecord::Session {
                timestamp_unix_ms, ..
            } => {
                started_unix_ms = started_unix_ms.min(*timestamp_unix_ms);
                finished_unix_ms = finished_unix_ms.max(*timestamp_unix_ms);
            }
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

fn current_timestamp_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::{
        build_session_trace, parse_event_line, stream_record_for_line, stream_record_for_line_at,
        EventKind, StreamRecord,
    };

    #[test]
    fn parses_open_event_line() {
        let parsed = parse_event_line("openat comm=session-io-demo pid=723 file=input/message.txt")
            .expect("event line should parse");
        assert_eq!(parsed.comm, "session-io-demo");
        assert_eq!(parsed.pid, 723);
        assert_eq!(parsed.file.as_deref(), Some("input/message.txt"));
    }

    #[test]
    fn stream_record_serializes_syscall_fields() {
        let record = stream_record_for_line_at("write comm=session-io-demo pid=723 bytes=239", 123)
            .expect("syscall should produce stream record");

        match record {
            StreamRecord::Syscall {
                timestamp_unix_ms,
                kind,
                comm,
                pid,
                bytes,
                file,
                fd,
            } => {
                assert_eq!(timestamp_unix_ms, 123);
                assert_eq!(kind, EventKind::Write);
                assert_eq!(comm, "session-io-demo");
                assert_eq!(pid, 723);
                assert_eq!(bytes, Some(239));
                assert_eq!(file, None);
                assert_eq!(fd, None);
            }
            _ => panic!("expected syscall record"),
        }
    }

    #[test]
    fn stream_record_keeps_json_kind_names_stable() {
        let record = stream_record_for_line_at("connect comm=app pid=7 fd=4", 55)
            .expect("syscall should produce stream record");
        let json = serde_json::to_value(&record).expect("record should serialize");

        assert_eq!(json["type"], "syscall");
        assert_eq!(json["kind"], "connect");
        assert_eq!(json["timestamp_unix_ms"], 55);
    }

    #[test]
    fn stream_record_serializes_aggregate_fields() {
        let record = stream_record_for_line_at("@writes: 5268", 456)
            .expect("aggregate should produce stream record");

        match record {
            StreamRecord::Aggregate {
                timestamp_unix_ms,
                metric,
                value,
            } => {
                assert_eq!(timestamp_unix_ms, 456);
                assert_eq!(metric, "writes");
                assert_eq!(value, 5268);
            }
            _ => panic!("expected aggregate record"),
        }
    }

    #[test]
    fn session_record_serializes_branding_fields() {
        let record = StreamRecord::Session {
            timestamp_unix_ms: 789,
            demo_name: "postcard-generator-rust".to_string(),
            product_name: "ebpf-tracker".to_string(),
            product_tagline: Some("Trace the full command session".to_string()),
            sponsor_name: Some("ebpf-tracker".to_string()),
            sponsor_message: Some("Replayable syscall demos for Rust and Node".to_string()),
            sponsor_url: Some("https://github.com/givtaj/ebpf-tracker".to_string()),
        };

        let json = serde_json::to_value(&record).expect("record should serialize");

        assert_eq!(json["type"], "session");
        assert_eq!(json["demo_name"], "postcard-generator-rust");
        assert_eq!(json["product_name"], "ebpf-tracker");
        assert_eq!(json["product_tagline"], "Trace the full command session");
        assert_eq!(json["sponsor_name"], "ebpf-tracker");
    }

    #[test]
    fn plain_text_does_not_enter_jsonl_stream() {
        assert!(stream_record_for_line(
            "Finished `dev` profile [unoptimized + debuginfo] target(s) in 1.04s"
        )
        .is_none());
    }

    #[test]
    fn build_session_trace_groups_records_by_process() {
        let records = vec![
            StreamRecord::Session {
                timestamp_unix_ms: 100,
                demo_name: "session-io-demo".to_string(),
                product_name: "ebpf-tracker".to_string(),
                product_tagline: None,
                sponsor_name: None,
                sponsor_message: None,
                sponsor_url: None,
            },
            StreamRecord::Syscall {
                timestamp_unix_ms: 110,
                kind: EventKind::Execve,
                comm: "cargo".to_string(),
                pid: 7,
                file: None,
                bytes: None,
                fd: None,
            },
            StreamRecord::Syscall {
                timestamp_unix_ms: 120,
                kind: EventKind::Write,
                comm: "session-io-demo".to_string(),
                pid: 9,
                file: None,
                bytes: Some(64),
                fd: Some(1),
            },
            StreamRecord::Aggregate {
                timestamp_unix_ms: 130,
                metric: "writes".to_string(),
                value: 1,
            },
        ];

        let trace = build_session_trace(&records);

        assert_eq!(trace.started_unix_ms, 100);
        assert_eq!(trace.finished_unix_ms, 130);
        assert_eq!(trace.total_records, 4);
        assert_eq!(trace.syscall_records, 2);
        assert_eq!(trace.aggregate_records, 1);
        assert_eq!(trace.processes.len(), 2);
        assert_eq!(trace.processes[1].comm, "session-io-demo");
        assert_eq!(trace.processes[1].bytes_written, 64);
        assert_eq!(trace.aggregates.len(), 1);
        assert_eq!(trace.aggregates[0].metric, "writes");
    }
}
