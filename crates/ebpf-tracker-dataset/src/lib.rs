use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{BufRead, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ebpf_tracker_events::{build_session_trace, EventKind, SessionTrace, StreamRecord};
use serde::Serialize;

mod analysis;

pub use analysis::{analyze_run, AnalyzeConfig, AnalyzeSummary, ModelProvider};

const DATASET_VERSION: u32 = 1;
const KNOWN_TOOLING_COMMS: &[&str] = &[
    "cargo",
    "rustc",
    "cc",
    "ld",
    "clang",
    "as",
    "collect2",
    "exec-target-fro",
    "containerd",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DatasetSource {
    Live,
    Replay,
}

impl DatasetSource {
    pub fn as_str(self) -> &'static str {
        match self {
            DatasetSource::Live => "live",
            DatasetSource::Replay => "replay",
        }
    }

    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw {
            "live" => Ok(Self::Live),
            "replay" => Ok(Self::Replay),
            _ => Err(format!("unsupported dataset source: {raw}")),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DatasetConfig {
    pub output_root: PathBuf,
    pub replay_path: Option<PathBuf>,
    pub run_id: Option<String>,
    pub source: Option<DatasetSource>,
    pub command: Option<String>,
    pub test_name: Option<String>,
    pub git_sha: Option<String>,
    pub transport: Option<String>,
    pub runtime: Option<String>,
    pub exit_code: Option<i32>,
    pub exit_signal: Option<String>,
    pub log_path: Option<PathBuf>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DatasetSummary {
    pub run_id: String,
    pub output_dir: PathBuf,
    pub total_records: usize,
    pub ignored_lines: usize,
    pub source: DatasetSource,
}

#[derive(Default)]
struct ParsedStream {
    records: Vec<StreamRecord>,
    ignored_lines: usize,
    non_empty_lines: usize,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct SessionMetadata {
    demo_name: Option<String>,
    product_name: Option<String>,
    product_tagline: Option<String>,
    sponsor_name: Option<String>,
    sponsor_message: Option<String>,
    sponsor_url: Option<String>,
}

#[derive(Serialize)]
struct RunDataset {
    dataset_version: u32,
    run_id: String,
    source: DatasetSource,
    created_unix_ms: u64,
    started_unix_ms: Option<u64>,
    finished_unix_ms: Option<u64>,
    total_records: usize,
    syscall_records: usize,
    aggregate_records: usize,
    process_count: usize,
    ignored_lines: usize,
    non_empty_lines: usize,
    command: Option<String>,
    test_name: Option<String>,
    git_sha: Option<String>,
    transport: Option<String>,
    runtime: Option<String>,
    exit_code: Option<i32>,
    exit_signal: Option<String>,
    log_path: Option<String>,
    replay_path: Option<String>,
    demo_name: Option<String>,
    product_name: Option<String>,
    product_tagline: Option<String>,
    sponsor_name: Option<String>,
    sponsor_message: Option<String>,
    sponsor_url: Option<String>,
    files: DatasetFiles,
}

#[derive(Serialize)]
struct DatasetFiles {
    events: String,
    processes: String,
    aggregates: String,
    features: String,
}

#[derive(Serialize)]
struct DatasetFeatures {
    focus_process: Option<String>,
    total_bytes_written: u64,
    noise_syscall_ratio: f64,
    unique_processes: usize,
    unique_files: usize,
    kind_counts: KindCounts,
    top_processes: Vec<NamedCount>,
    top_files: Vec<NamedCount>,
    top_writes: Vec<WriteEntry>,
}

#[derive(Serialize, Default)]
struct KindCounts {
    open_at: usize,
    execve: usize,
    connect: usize,
    write: usize,
    other: usize,
}

#[derive(Serialize)]
struct NamedCount {
    name: String,
    count: usize,
}

#[derive(Serialize)]
struct WriteEntry {
    comm: String,
    bytes: u64,
    timestamp_unix_ms: u64,
}

pub fn default_output_root() -> PathBuf {
    PathBuf::from("datasets")
}

pub fn ingest_reader<R: BufRead>(
    reader: R,
    config: &DatasetConfig,
) -> Result<DatasetSummary, String> {
    let parsed = read_dataset_input(reader)?;
    write_dataset(parsed, config)
}

pub fn ingest_records(
    records: &[StreamRecord],
    config: &DatasetConfig,
) -> Result<DatasetSummary, String> {
    write_dataset(
        ParsedStream {
            records: records.to_vec(),
            ignored_lines: 0,
            non_empty_lines: records.len(),
        },
        config,
    )
}

pub fn ingest_path(path: &Path, config: &DatasetConfig) -> Result<DatasetSummary, String> {
    let file = File::open(path)
        .map_err(|err| format!("failed to open replay file {}: {err}", path.display()))?;
    ingest_reader(std::io::BufReader::new(file), config)
}

fn read_dataset_input<R: BufRead>(reader: R) -> Result<ParsedStream, String> {
    let mut parsed = ParsedStream::default();

    for line in reader.lines() {
        let line = line.map_err(|err| format!("failed to read dataset input: {err}"))?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        parsed.non_empty_lines += 1;

        match serde_json::from_str::<StreamRecord>(trimmed) {
            Ok(record) => parsed.records.push(record),
            Err(_) => parsed.ignored_lines += 1,
        }
    }

    Ok(parsed)
}

fn write_dataset(parsed: ParsedStream, config: &DatasetConfig) -> Result<DatasetSummary, String> {
    let source = config.source.unwrap_or(if config.replay_path.is_some() {
        DatasetSource::Replay
    } else {
        DatasetSource::Live
    });

    let run_id = config
        .run_id
        .clone()
        .unwrap_or_else(|| generate_run_id(source));
    let output_dir = config.output_root.join(&run_id);
    fs::create_dir_all(&output_dir).map_err(|err| {
        format!(
            "failed to create dataset dir {}: {err}",
            output_dir.display()
        )
    })?;

    let trace = build_session_trace(&parsed.records);
    let metadata = session_metadata(&parsed.records);
    let features = build_features(&parsed.records);

    write_events_jsonl(&output_dir.join("events.jsonl"), &parsed.records)?;
    write_json_pretty(&output_dir.join("processes.json"), &trace.processes)?;
    write_json_pretty(&output_dir.join("aggregates.json"), &trace.aggregates)?;
    write_json_pretty(&output_dir.join("features.json"), &features)?;

    let run = RunDataset {
        dataset_version: DATASET_VERSION,
        run_id: run_id.clone(),
        source,
        created_unix_ms: current_timestamp_millis(),
        started_unix_ms: trace_started(&trace),
        finished_unix_ms: trace_finished(&trace),
        total_records: trace.total_records,
        syscall_records: trace.syscall_records,
        aggregate_records: trace.aggregate_records,
        process_count: trace.processes.len(),
        ignored_lines: parsed.ignored_lines,
        non_empty_lines: parsed.non_empty_lines,
        command: normalize_optional_string(config.command.as_deref()),
        test_name: normalize_optional_string(config.test_name.as_deref()),
        git_sha: normalize_optional_string(config.git_sha.as_deref()),
        transport: normalize_optional_string(config.transport.as_deref()),
        runtime: normalize_optional_string(config.runtime.as_deref()),
        exit_code: config.exit_code,
        exit_signal: normalize_optional_string(config.exit_signal.as_deref()),
        log_path: normalize_optional_path(config.log_path.as_deref()),
        replay_path: normalize_optional_path(config.replay_path.as_deref()),
        demo_name: metadata.demo_name,
        product_name: metadata.product_name,
        product_tagline: metadata.product_tagline,
        sponsor_name: metadata.sponsor_name,
        sponsor_message: metadata.sponsor_message,
        sponsor_url: metadata.sponsor_url,
        files: DatasetFiles {
            events: "events.jsonl".to_string(),
            processes: "processes.json".to_string(),
            aggregates: "aggregates.json".to_string(),
            features: "features.json".to_string(),
        },
    };
    write_json_pretty(&output_dir.join("run.json"), &run)?;

    Ok(DatasetSummary {
        run_id,
        output_dir,
        total_records: trace.total_records,
        ignored_lines: parsed.ignored_lines,
        source,
    })
}

fn build_features(records: &[StreamRecord]) -> DatasetFeatures {
    let mut kind_counts = KindCounts::default();
    let mut process_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut file_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut unique_processes = BTreeSet::new();
    let mut unique_files = BTreeSet::new();
    let mut total_bytes_written = 0u64;
    let mut noise_syscalls = 0usize;
    let mut total_syscalls = 0usize;
    let mut top_writes = Vec::new();

    for record in records {
        let StreamRecord::Syscall {
            timestamp_unix_ms,
            kind,
            comm,
            file,
            bytes,
            ..
        } = record
        else {
            continue;
        };

        total_syscalls += 1;
        unique_processes.insert(comm.clone());
        *process_counts.entry(comm.clone()).or_insert(0) += 1;

        if KNOWN_TOOLING_COMMS.contains(&comm.as_str()) {
            noise_syscalls += 1;
        }

        match kind {
            EventKind::OpenAt => {
                kind_counts.open_at += 1;
                if let Some(file) = file {
                    unique_files.insert(file.clone());
                    *file_counts.entry(file.clone()).or_insert(0) += 1;
                }
            }
            EventKind::Execve => kind_counts.execve += 1,
            EventKind::Connect => kind_counts.connect += 1,
            EventKind::Write => {
                kind_counts.write += 1;
                let bytes = bytes.unwrap_or_default();
                total_bytes_written = total_bytes_written.saturating_add(bytes);
                top_writes.push(WriteEntry {
                    comm: comm.clone(),
                    bytes,
                    timestamp_unix_ms: *timestamp_unix_ms,
                });
            }
        }
    }

    top_writes.sort_by(|left, right| {
        right
            .bytes
            .cmp(&left.bytes)
            .then_with(|| left.timestamp_unix_ms.cmp(&right.timestamp_unix_ms))
    });
    top_writes.truncate(8);

    DatasetFeatures {
        focus_process: infer_focus_process(records),
        total_bytes_written,
        noise_syscall_ratio: if total_syscalls == 0 {
            0.0
        } else {
            noise_syscalls as f64 / total_syscalls as f64
        },
        unique_processes: unique_processes.len(),
        unique_files: unique_files.len(),
        kind_counts,
        top_processes: top_named_counts(process_counts),
        top_files: top_named_counts(file_counts),
        top_writes,
    }
}

fn top_named_counts(counts: BTreeMap<String, usize>) -> Vec<NamedCount> {
    let mut entries: Vec<NamedCount> = counts
        .into_iter()
        .map(|(name, count)| NamedCount { name, count })
        .collect();
    entries.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.name.cmp(&right.name))
    });
    entries.truncate(8);
    entries
}

fn infer_focus_process(records: &[StreamRecord]) -> Option<String> {
    let mut scores: BTreeMap<String, f64> = BTreeMap::new();

    for record in records {
        let StreamRecord::Syscall {
            kind, comm, bytes, ..
        } = record
        else {
            continue;
        };

        let mut score = match kind {
            EventKind::Connect => 120.0,
            EventKind::Write => 12.0 + (bytes.unwrap_or_default() as f64 / 64.0).min(10.0),
            EventKind::Execve => 40.0,
            EventKind::OpenAt => 2.0,
        };

        if KNOWN_TOOLING_COMMS.contains(&comm.as_str()) {
            score *= 0.15;
        }

        *scores.entry(comm.clone()).or_insert(0.0) += score;
    }

    scores
        .into_iter()
        .max_by(|left, right| {
            left.1
                .partial_cmp(&right.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| right.0.cmp(&left.0))
        })
        .map(|(comm, _)| comm)
}

fn session_metadata(records: &[StreamRecord]) -> SessionMetadata {
    for record in records {
        if let StreamRecord::Session {
            demo_name,
            product_name,
            product_tagline,
            sponsor_name,
            sponsor_message,
            sponsor_url,
            ..
        } = record
        {
            return SessionMetadata {
                demo_name: Some(demo_name.clone()),
                product_name: Some(product_name.clone()),
                product_tagline: product_tagline.clone(),
                sponsor_name: sponsor_name.clone(),
                sponsor_message: sponsor_message.clone(),
                sponsor_url: sponsor_url.clone(),
            };
        }
    }

    SessionMetadata::default()
}

fn write_events_jsonl(path: &Path, records: &[StreamRecord]) -> Result<(), String> {
    let file = File::create(path)
        .map_err(|err| format!("failed to create dataset events {}: {err}", path.display()))?;
    let mut writer = BufWriter::new(file);

    for record in records {
        serde_json::to_writer(&mut writer, record)
            .map_err(|err| format!("failed to serialize dataset event: {err}"))?;
        writer
            .write_all(b"\n")
            .map_err(|err| format!("failed to write dataset events {}: {err}", path.display()))?;
    }

    writer
        .flush()
        .map_err(|err| format!("failed to flush dataset events {}: {err}", path.display()))?;
    Ok(())
}

fn write_json_pretty<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let file = File::create(path)
        .map_err(|err| format!("failed to create dataset file {}: {err}", path.display()))?;
    let mut writer = BufWriter::new(file);
    serde_json::to_writer_pretty(&mut writer, value)
        .map_err(|err| format!("failed to serialize dataset file {}: {err}", path.display()))?;
    writer
        .write_all(b"\n")
        .map_err(|err| format!("failed to finalize dataset file {}: {err}", path.display()))?;
    writer
        .flush()
        .map_err(|err| format!("failed to flush dataset file {}: {err}", path.display()))?;
    Ok(())
}

fn trace_started(trace: &SessionTrace) -> Option<u64> {
    (trace.total_records > 0).then_some(trace.started_unix_ms)
}

fn trace_finished(trace: &SessionTrace) -> Option<u64> {
    (trace.total_records > 0).then_some(trace.finished_unix_ms)
}

fn normalize_optional_string(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn normalize_optional_path(path: Option<&Path>) -> Option<String> {
    path.map(|path| path.display().to_string())
}

fn current_timestamp_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn generate_run_id(source: DatasetSource) -> String {
    format!("run-{}-{}", current_timestamp_millis(), source.as_str())
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::fs;
    use std::io::Cursor;
    use std::path::PathBuf;

    use ebpf_tracker_events::StreamRecord;

    use super::{
        default_output_root, ingest_reader, ingest_records, read_dataset_input, DatasetConfig,
        DatasetSource,
    };

    fn temp_dir(name: &str) -> PathBuf {
        let path = env::temp_dir().join(format!(
            "ebpf-tracker-dataset-{name}-{}",
            super::current_timestamp_millis()
        ));
        if path.exists() {
            fs::remove_dir_all(&path).expect("temp dir cleanup should work");
        }
        fs::create_dir_all(&path).expect("temp dir should be created");
        path
    }

    #[test]
    fn default_output_root_points_to_datasets_dir() {
        assert_eq!(default_output_root(), PathBuf::from("datasets"));
    }

    #[test]
    fn read_dataset_input_ignores_non_json_lines() {
        let input = Cursor::new(
            "build noise\n{\"type\":\"syscall\",\"timestamp_unix_ms\":1,\"kind\":\"write\",\"comm\":\"app\",\"pid\":7,\"bytes\":9}\n",
        );

        let parsed = read_dataset_input(input).expect("dataset input should parse");

        assert_eq!(parsed.records.len(), 1);
        assert_eq!(parsed.ignored_lines, 1);
        assert_eq!(parsed.non_empty_lines, 2);
    }

    #[test]
    fn ingest_reader_writes_dataset_bundle() {
        let input = Cursor::new(
            concat!(
                "{\"type\":\"session\",\"timestamp_unix_ms\":10,\"demo_name\":\"session-io-demo\",\"product_name\":\"ebpf-tracker\"}\n",
                "{\"type\":\"syscall\",\"timestamp_unix_ms\":11,\"kind\":\"execve\",\"comm\":\"cargo\",\"pid\":7}\n",
                "{\"type\":\"syscall\",\"timestamp_unix_ms\":12,\"kind\":\"connect\",\"comm\":\"session-io-demo\",\"pid\":9,\"fd\":4}\n",
                "{\"type\":\"syscall\",\"timestamp_unix_ms\":13,\"kind\":\"write\",\"comm\":\"session-io-demo\",\"pid\":9,\"bytes\":42}\n",
                "{\"type\":\"aggregate\",\"timestamp_unix_ms\":14,\"metric\":\"writes\",\"value\":1}\n"
            ),
        );
        let output_root = temp_dir("bundle");
        let config = DatasetConfig {
            output_root: output_root.clone(),
            run_id: Some("sample-run".to_string()),
            source: Some(DatasetSource::Live),
            command: Some("cargo demo --emit jsonl session-io-demo".to_string()),
            test_name: Some("session-io-demo".to_string()),
            transport: Some("bpftrace".to_string()),
            ..DatasetConfig::default()
        };

        let summary = ingest_reader(input, &config).expect("dataset bundle should be written");

        assert_eq!(summary.run_id, "sample-run");
        assert_eq!(summary.total_records, 5);
        assert!(summary.output_dir.join("run.json").is_file());
        assert!(summary.output_dir.join("events.jsonl").is_file());
        assert!(summary.output_dir.join("processes.json").is_file());
        assert!(summary.output_dir.join("aggregates.json").is_file());
        assert!(summary.output_dir.join("features.json").is_file());

        let run = fs::read_to_string(summary.output_dir.join("run.json"))
            .expect("run metadata should be readable");
        assert!(run.contains("\"run_id\": \"sample-run\""));
        assert!(run.contains("\"demo_name\": \"session-io-demo\""));

        let features = fs::read_to_string(summary.output_dir.join("features.json"))
            .expect("features should be readable");
        assert!(features.contains("\"focus_process\": \"session-io-demo\""));

        fs::remove_dir_all(output_root).expect("temp output should be removed");
    }

    #[test]
    fn ingest_records_writes_dataset_bundle() {
        let output_root = temp_dir("records-bundle");
        let records = vec![
            serde_json::from_str::<StreamRecord>(
                "{\"type\":\"session\",\"timestamp_unix_ms\":10,\"demo_name\":\"session-io-demo\",\"product_name\":\"ebpf-tracker\"}",
            )
            .expect("session record should parse"),
            serde_json::from_str::<StreamRecord>(
                "{\"type\":\"syscall\",\"timestamp_unix_ms\":12,\"kind\":\"connect\",\"comm\":\"session-io-demo\",\"pid\":9,\"fd\":4}",
            )
            .expect("syscall record should parse"),
            serde_json::from_str::<StreamRecord>(
                "{\"type\":\"aggregate\",\"timestamp_unix_ms\":14,\"metric\":\"writes\",\"value\":1}",
            )
            .expect("aggregate record should parse"),
        ];
        let config = DatasetConfig {
            output_root: output_root.clone(),
            run_id: Some("records-run".to_string()),
            source: Some(DatasetSource::Live),
            ..DatasetConfig::default()
        };

        let summary = ingest_records(&records, &config).expect("dataset bundle should be written");

        assert_eq!(summary.run_id, "records-run");
        assert_eq!(summary.total_records, 3);
        assert!(summary.output_dir.join("run.json").is_file());
        assert!(summary.output_dir.join("features.json").is_file());

        fs::remove_dir_all(output_root).expect("temp output should be removed");
    }
}
