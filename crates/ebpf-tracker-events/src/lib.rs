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

fn current_timestamp_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::{
        parse_event_line, stream_record_for_line, stream_record_for_line_at, EventKind,
        StreamRecord,
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
    fn plain_text_does_not_enter_jsonl_stream() {
        assert!(stream_record_for_line(
            "Finished `dev` profile [unoptimized + debuginfo] target(s) in 1.04s"
        )
        .is_none());
    }
}
