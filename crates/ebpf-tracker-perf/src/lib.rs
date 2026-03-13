use std::time::{SystemTime, UNIX_EPOCH};

use ebpf_tracker_events::{EventKind, StreamRecord};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportKind {
    BpftraceStdout,
    PerfTraceCli,
    PerfEventArray,
    RingBuf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImplementationStatus {
    Available,
    Scaffold,
    Planned,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportPlan {
    pub kind: TransportKind,
    pub status: ImplementationStatus,
    pub notes: &'static str,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PerfTraceSession {
    execs: u64,
    opens: u64,
    writes: u64,
    connects: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedPerfTraceEvent {
    pub kind: EventKind,
    pub comm: String,
    pub pid: u32,
    pub file: Option<String>,
    pub bytes: Option<u64>,
    pub fd: Option<i32>,
}

pub fn default_transport_plan() -> Vec<TransportPlan> {
    vec![
        TransportPlan {
            kind: TransportKind::BpftraceStdout,
            status: ImplementationStatus::Available,
            notes: "Current release path: bpftrace prints trace lines that the CLI turns into events.",
        },
        TransportPlan {
            kind: TransportKind::PerfTraceCli,
            status: ImplementationStatus::Available,
            notes: "First native-adjacent transport: Linux perf trace streams syscall lines that this crate normalizes into StreamRecord values.",
        },
        TransportPlan {
            kind: TransportKind::PerfEventArray,
            status: ImplementationStatus::Scaffold,
            notes: "Reserved for direct BPF perf-event-array delivery when the perf CLI path is no longer sufficient.",
        },
        TransportPlan {
            kind: TransportKind::RingBuf,
            status: ImplementationStatus::Planned,
            notes: "Preferred future path when strict cross-CPU ordering matters for streamed events.",
        },
    ]
}

pub fn default_perf_event_kinds() -> Vec<EventKind> {
    vec![EventKind::Execve]
}

pub fn perf_trace_expression(event_kinds: &[EventKind]) -> String {
    event_kinds
        .iter()
        .map(|kind| kind.as_str())
        .collect::<Vec<_>>()
        .join(",")
}

pub fn parse_perf_trace_line(line: &str) -> Option<ParsedPerfTraceEvent> {
    let trimmed = line.trim();
    let (_, remainder) = trimmed.split_once(": ")?;
    let (process, syscall) = remainder.split_once(' ')?;
    let (comm, pid) = parse_process(process)?;
    let open_paren = syscall.find('(')?;
    let close_paren = syscall.rfind(')')?;
    if close_paren <= open_paren {
        return None;
    }

    let kind = parse_event_kind(&syscall[..open_paren])?;
    let args = &syscall[open_paren + 1..close_paren];

    Some(ParsedPerfTraceEvent {
        kind,
        comm,
        pid,
        file: parse_file_arg(kind, args),
        bytes: parse_bytes_arg(kind, args),
        fd: parse_fd_arg(kind, args),
    })
}

pub fn stream_record_for_perf_trace_line(line: &str) -> Option<StreamRecord> {
    stream_record_for_perf_trace_line_at(line, current_timestamp_millis())
}

pub fn stream_record_for_perf_trace_line_at(
    line: &str,
    timestamp_unix_ms: u64,
) -> Option<StreamRecord> {
    let parsed = parse_perf_trace_line(line)?;
    Some(StreamRecord::Syscall {
        timestamp_unix_ms,
        kind: parsed.kind,
        comm: parsed.comm,
        pid: parsed.pid,
        file: parsed.file,
        bytes: parsed.bytes,
        fd: parsed.fd,
    })
}

impl PerfTraceSession {
    pub fn observe(&mut self, record: &StreamRecord) {
        let StreamRecord::Syscall { kind, .. } = record else {
            return;
        };

        match kind {
            EventKind::Execve => self.execs += 1,
            EventKind::OpenAt => self.opens += 1,
            EventKind::Write => self.writes += 1,
            EventKind::Connect => self.connects += 1,
        }
    }

    pub fn merge(&mut self, other: &Self) {
        self.execs += other.execs;
        self.opens += other.opens;
        self.writes += other.writes;
        self.connects += other.connects;
    }

    pub fn aggregate_records_now(&self) -> Vec<StreamRecord> {
        self.aggregate_records_at(current_timestamp_millis())
    }

    pub fn aggregate_records_at(&self, timestamp_unix_ms: u64) -> Vec<StreamRecord> {
        [
            ("execve", self.execs),
            ("openat", self.opens),
            ("writes", self.writes),
            ("connects", self.connects),
        ]
        .into_iter()
        .filter(|(_, value)| *value > 0)
        .map(|(metric, value)| StreamRecord::Aggregate {
            timestamp_unix_ms,
            metric: metric.to_string(),
            value,
        })
        .collect()
    }

    pub fn is_empty(&self) -> bool {
        self.execs == 0 && self.opens == 0 && self.writes == 0 && self.connects == 0
    }
}

fn parse_process(process: &str) -> Option<(String, u32)> {
    let (comm, pid) = process.rsplit_once('/')?;
    let pid = pid.parse().ok()?;
    Some((comm.to_string(), pid))
}

fn parse_event_kind(raw_kind: &str) -> Option<EventKind> {
    match raw_kind.trim() {
        "execve" => Some(EventKind::Execve),
        "openat" => Some(EventKind::OpenAt),
        "write" => Some(EventKind::Write),
        "connect" => Some(EventKind::Connect),
        _ => None,
    }
}

fn parse_file_arg(kind: EventKind, args: &str) -> Option<String> {
    match kind {
        EventKind::Execve => find_named_arg(args, &["filename:", "pathname:"])
            .or_else(|| first_positional_arg(args))
            .map(clean_perf_value)
            .and_then(sanitize_file_value),
        EventKind::OpenAt => find_named_arg(args, &["filename:", "pathname:"])
            .map(clean_perf_value)
            .and_then(sanitize_file_value),
        EventKind::Write | EventKind::Connect => None,
    }
}

fn parse_bytes_arg(kind: EventKind, args: &str) -> Option<u64> {
    match kind {
        EventKind::Write => find_named_arg(args, &["count:", "len:"])
            .map(clean_perf_value)
            .and_then(|value| value.parse().ok()),
        EventKind::Execve | EventKind::OpenAt | EventKind::Connect => None,
    }
}

fn parse_fd_arg(kind: EventKind, args: &str) -> Option<i32> {
    match kind {
        EventKind::Write | EventKind::Connect => find_named_arg(args, &["fd:", "sockfd:"])
            .map(clean_perf_value)
            .and_then(|value| value.parse().ok()),
        EventKind::Execve | EventKind::OpenAt => None,
    }
}

fn first_positional_arg(args: &str) -> Option<&str> {
    let end = args.find(',').unwrap_or(args.len());
    let value = args[..end].trim();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn find_named_arg<'a>(args: &'a str, labels: &[&str]) -> Option<&'a str> {
    for label in labels {
        if let Some(value) = capture_after_label(args, label) {
            return Some(value);
        }
    }

    None
}

fn capture_after_label<'a>(args: &'a str, label: &str) -> Option<&'a str> {
    let start = args.find(label)? + label.len();
    let mut value = &args[start..];
    value = value.trim_start();

    let terminators = [", ", ",\t", ",\n"];
    let mut end = value.len();
    for terminator in terminators {
        if let Some(index) = value.find(terminator) {
            end = end.min(index);
        }
    }

    Some(value[..end].trim())
}

fn clean_perf_value(raw_value: &str) -> String {
    let trimmed = raw_value.trim();
    let unquoted = trimmed
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(trimmed);
    unquoted.to_string()
}

fn sanitize_file_value(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || looks_like_pointer(trimmed) {
        return None;
    }

    Some(trimmed.to_string())
}

fn looks_like_pointer(value: &str) -> bool {
    value.starts_with("0x")
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
        default_perf_event_kinds, default_transport_plan, parse_perf_trace_line,
        perf_trace_expression, stream_record_for_perf_trace_line_at, ImplementationStatus,
        PerfTraceSession, TransportKind,
    };
    use ebpf_tracker_events::{EventKind, StreamRecord};

    #[test]
    fn transport_plan_lists_current_and_future_paths() {
        let plan = default_transport_plan();

        assert_eq!(plan.len(), 4);
        assert_eq!(plan[0].kind, TransportKind::BpftraceStdout);
        assert_eq!(plan[0].status, ImplementationStatus::Available);
        assert_eq!(plan[1].kind, TransportKind::PerfTraceCli);
        assert_eq!(plan[1].status, ImplementationStatus::Available);
        assert_eq!(plan[2].kind, TransportKind::PerfEventArray);
        assert_eq!(plan[2].status, ImplementationStatus::Scaffold);
        assert_eq!(plan[3].kind, TransportKind::RingBuf);
        assert_eq!(plan[3].status, ImplementationStatus::Planned);
    }

    #[test]
    fn default_perf_events_match_current_default_probe() {
        assert_eq!(default_perf_event_kinds(), vec![EventKind::Execve]);
    }

    #[test]
    fn perf_expression_uses_syscall_names() {
        let expression =
            perf_trace_expression(&[EventKind::Execve, EventKind::OpenAt, EventKind::Write]);

        assert_eq!(expression, "execve,openat,write");
    }

    #[test]
    fn parses_perf_openat_line() {
        let parsed = parse_perf_trace_line(
            "2272.992 ( 0.037 ms): gnome-shell/1370 openat(dfd: CWD, filename: /proc/self/stat, flags: CLOEXEC) = 31",
        )
        .expect("perf trace line should parse");

        assert_eq!(parsed.kind, EventKind::OpenAt);
        assert_eq!(parsed.comm, "gnome-shell");
        assert_eq!(parsed.pid, 1370);
        assert_eq!(parsed.file.as_deref(), Some("/proc/self/stat"));
    }

    #[test]
    fn parses_perf_write_line() {
        let parsed = parse_perf_trace_line(
            "991.447 ( 0.021 ms): cargo/723 write(fd: 1, buf: 0xffff8f6f, count: 85) = 85",
        )
        .expect("write line should parse");

        assert_eq!(parsed.kind, EventKind::Write);
        assert_eq!(parsed.fd, Some(1));
        assert_eq!(parsed.bytes, Some(85));
    }

    #[test]
    fn parses_perf_connect_line() {
        let parsed = parse_perf_trace_line(
            "991.448 ( 0.031 ms): session-io-demo/723 connect(fd: 4, usrvaddr: 0xffff8f7c, addrlen: 16) = 0",
        )
        .expect("connect line should parse");

        assert_eq!(parsed.kind, EventKind::Connect);
        assert_eq!(parsed.fd, Some(4));
    }

    #[test]
    fn parses_perf_execve_line_with_positional_path() {
        let record = stream_record_for_perf_trace_line_at(
            "991.450 ( 0.052 ms): cargo/723 execve(\"target/debug/session-io-demo\", argv: 0xffffefc0, envp: 0xffffefe0) = 0",
            777,
        )
        .expect("execve line should become a stream record");

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
                assert_eq!(timestamp_unix_ms, 777);
                assert_eq!(kind, EventKind::Execve);
                assert_eq!(comm, "cargo");
                assert_eq!(pid, 723);
                assert_eq!(file.as_deref(), Some("target/debug/session-io-demo"));
                assert_eq!(bytes, None);
                assert_eq!(fd, None);
            }
            StreamRecord::Aggregate { .. } => panic!("expected syscall record"),
        }
    }

    #[test]
    fn drops_pointer_like_file_arguments() {
        let record = stream_record_for_perf_trace_line_at(
            "991.450 ( 0.052 ms): cargo/723 openat(dfd: CWD, filename: 0x16601ab0) = -1 ENOENT (No such file or directory)",
            777,
        )
        .expect("openat line should still parse");

        match record {
            StreamRecord::Syscall { file, .. } => assert_eq!(file, None),
            StreamRecord::Aggregate { .. } => panic!("expected syscall record"),
        }
    }

    #[test]
    fn aggregates_perf_records_in_userspace() {
        let mut session = PerfTraceSession::default();
        session.observe(
            &stream_record_for_perf_trace_line_at(
                "1.0 ( 0.01 ms): cargo/7 execve(\"cargo\", argv: 0x1, envp: 0x2) = 0",
                1,
            )
            .expect("execve line should parse"),
        );
        session.observe(
            &stream_record_for_perf_trace_line_at(
                "1.1 ( 0.01 ms): cargo/7 write(fd: 1, buf: 0x2, count: 10) = 10",
                2,
            )
            .expect("write line should parse"),
        );
        session.observe(
            &stream_record_for_perf_trace_line_at(
                "1.2 ( 0.01 ms): cargo/7 connect(fd: 4, usrvaddr: 0x3, addrlen: 16) = 0",
                3,
            )
            .expect("connect line should parse"),
        );

        let aggregates = session.aggregate_records_at(9);

        assert_eq!(
            aggregates,
            vec![
                StreamRecord::Aggregate {
                    timestamp_unix_ms: 9,
                    metric: "execve".to_string(),
                    value: 1,
                },
                StreamRecord::Aggregate {
                    timestamp_unix_ms: 9,
                    metric: "writes".to_string(),
                    value: 1,
                },
                StreamRecord::Aggregate {
                    timestamp_unix_ms: 9,
                    metric: "connects".to_string(),
                    value: 1,
                },
            ]
        );
    }
}
