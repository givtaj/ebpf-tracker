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
    pub return_value: Option<i64>,
    pub errno: Option<u32>,
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
        #[serde(skip_serializing_if = "Option::is_none")]
        return_value: Option<i64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        errno: Option<u32>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_value: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errno: Option<u32>,
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
    let line = line.trim_end_matches(['\r', '\n']);
    // The collector writes the pathname last. Keep it separate from header
    // fields so spaces or text such as `errno=0` in a pathname cannot rewrite
    // the syscall result. Newlines and collector string truncation remain
    // limitations of the raw line format.
    let (header, path) = match line.split_once(" file=") {
        Some((header, path)) => (header, Some(path.to_string())),
        None => (line, None),
    };
    let mut parts = header.split_whitespace();
    let kind = match parts.next()? {
        "execve" => EventKind::Execve,
        "openat" => EventKind::OpenAt,
        "write" => EventKind::Write,
        "connect" => EventKind::Connect,
        _ => return None,
    };

    let mut comm = None;
    let mut pid = None;
    let mut file = path;
    let mut bytes = None;
    let mut fd = None;
    let mut return_value = None;
    let mut errno = None;

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
            "return_value" => {
                if return_value.is_some() {
                    return None;
                }
                return_value = Some(value.parse::<i64>().ok()?);
            }
            "errno" => {
                if errno.is_some() {
                    return None;
                }
                errno = Some(value.parse::<u32>().ok()?);
            }
            _ => {}
        }
    }

    // Legacy entry-only records have neither field. A partial or inconsistent
    // result is invalid, not evidence of success or a legacy observation.
    match (return_value, errno) {
        (None, None) => {}
        (Some(result), Some(error)) if kind == EventKind::OpenAt => {
            let expected = if result < 0 {
                u32::try_from(result.checked_neg()?).ok()?
            } else {
                0
            };
            if error != expected {
                return None;
            }
        }
        _ => return None,
    }

    Some(ParsedEvent {
        kind,
        comm: comm?,
        pid: pid?,
        file,
        bytes,
        fd,
        return_value,
        errno,
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
            return_value: event.return_value,
            errno: event.errno,
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
                return_value,
                errno,
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
                    return_value: *return_value,
                    errno: *errno,
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
        assert_eq!((parsed.return_value, parsed.errno), (None, None));
    }

    #[test]
    fn completed_file_opens_preserve_result_through_json_and_session() {
        for (result, errno) in [(-2, 2), (-13, 13), (0, 0), (17, 0)] {
            let line = format!(
                "openat comm=api pid=723 return_value={result} errno={errno} file=/data/input.txt"
            );
            let record =
                stream_record_for_line_at(&line, 123).expect("completed open should parse");
            let json = serde_json::to_value(&record).unwrap();
            assert_eq!(json["return_value"], result);
            assert_eq!(json["errno"], errno);
            assert_eq!(json["kind"], "open_at");
            assert_eq!(json["file"], "/data/input.txt");
            let decoded: StreamRecord = serde_json::from_value(json).unwrap();
            assert_eq!(decoded, record);
            let trace = build_session_trace(&[decoded]);
            assert_eq!(trace.syscall_records, 1);
            let event = &trace.processes[0].events[0];
            assert_eq!(event.return_value, Some(result));
            assert_eq!(event.errno, Some(errno as u32));
        }
    }

    #[test]
    fn legacy_captures_keep_unknown_outcomes() {
        let json = r#"{"type":"syscall","timestamp_unix_ms":123,"kind":"open_at","comm":"api","pid":7,"file":"/data/input.txt"}"#;
        let record: StreamRecord = serde_json::from_str(json).unwrap();
        let trace = build_session_trace(&[record.clone()]);
        let event = &trace.processes[0].events[0];
        assert_eq!((event.return_value, event.errno), (None, None));
        let encoded = serde_json::to_value(record).unwrap();
        assert!(encoded.get("return_value").is_none());
        assert!(encoded.get("errno").is_none());
        let legacy_event = r#"{"timestamp_unix_ms":123,"kind":"open_at","file":"/data/input.txt","bytes":null,"fd":null}"#;
        let event: super::SyscallEvent = serde_json::from_str(legacy_event).unwrap();
        assert_eq!((event.return_value, event.errno), (None, None));
    }

    #[test]
    fn malformed_outcomes_are_not_accepted_as_success_or_legacy() {
        for fields in [
            "return_value=0",
            "errno=0",
            "return_value=nope errno=0",
            "return_value=0 errno=nope",
            "return_value=0 errno=-1",
            "return_value=-2 errno=0",
            "return_value=5 errno=2",
            "return_value=-2 errno=13",
            "return_value=-9223372036854775808 errno=0",
            "return_value=0 errno=0 errno=0",
            "return_value=0 return_value=0 errno=0",
        ] {
            assert!(
                parse_event_line(&format!(
                    "openat comm=api pid=7 {fields} file=/data/input.txt"
                ))
                .is_none(),
                "accepted invalid outcome: {fields}"
            );
        }
        assert!(parse_event_line("write comm=api pid=7 return_value=0 errno=0").is_none());
    }

    #[test]
    fn filename_cannot_overwrite_outcome_fields() {
        let line = "openat comm=api pid=7 return_value=-2 errno=2 file=/data/missing file errno=0 return_value=0\n";
        let event = parse_event_line(line).unwrap();
        assert_eq!(event.return_value, Some(-2));
        assert_eq!(event.errno, Some(2));
        assert_eq!(
            event.file.as_deref(),
            Some("/data/missing file errno=0 return_value=0")
        );
    }

    #[test]
    fn interleaved_worker_results_remain_independent() {
        let inputs = [
            "openat comm=worker pid=7 return_value=-2 errno=2 file=/data/missing.txt",
            "openat comm=child pid=8 return_value=0 errno=0 file=/data/control.txt",
            "openat comm=worker pid=7 return_value=-13 errno=13 file=/data/private.txt",
            "openat comm=worker pid=7 file=/data/legacy.txt",
        ];
        let records: Vec<_> = inputs
            .iter()
            .enumerate()
            .map(|(n, input)| stream_record_for_line_at(input, n as u64).unwrap())
            .collect();
        let trace = build_session_trace(&records);
        let events = &trace.processes.iter().find(|p| p.pid == 7).unwrap().events;
        assert_eq!(
            events.iter().map(|e| e.errno).collect::<Vec<_>>(),
            vec![Some(2), Some(13), None]
        );
        let child = &trace.processes.iter().find(|p| p.pid == 8).unwrap().events[0];
        assert_eq!((child.return_value, child.errno), (Some(0), Some(0)));
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
                ..
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
                return_value: None,
                errno: None,
            },
            StreamRecord::Syscall {
                timestamp_unix_ms: 120,
                kind: EventKind::Write,
                comm: "session-io-demo".to_string(),
                pid: 9,
                file: None,
                bytes: Some(64),
                fd: Some(1),
                return_value: None,
                errno: None,
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
