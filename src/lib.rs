use std::env;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use ebpf_tracker_events::{stream_record_for_line, EventKind, StreamRecord};
use ebpf_tracker_perf::{
    default_perf_event_kinds, perf_trace_expression, stream_record_for_perf_trace_line,
    PerfTraceSession,
};
use serde::Deserialize;

const DEFAULT_PROBE: &str = "/probes/execve.bt";
const COMPOSE_FILE_NAME: &str = "docker-compose.bpftrace.yml";
const DEFAULT_CONFIG_FILE_NAME: &str = "ebpf-tracker.toml";
const GENERATED_CONFIG_PROBE_FILE_NAME: &str = "generated-config.bt";
const GENERATED_RUNTIME_OVERRIDE_FILE_NAME: &str = "generated-runtime.override.yml";
const DEFAULT_EXAMPLE_NAME: &str = "session-io-demo";
const EXAMPLES_DIR_NAME: &str = "examples";
const EMBEDDED_COMPOSE: &str = include_str!("../docker-compose.bpftrace.yml");
const EMBEDDED_DOCKERFILE: &str = include_str!("../docker/bpftrace-rust.Dockerfile");
const EMBEDDED_RUN_SCRIPT: &str = include_str!("../scripts/run-bpftrace-wrap.sh");
const EMBEDDED_PROBE_EXECVE: &str = include_str!("../probes/execve.bt");
const GENERATED_EXEC_PROBE: &str = r#"tracepoint:syscalls:sys_enter_execve
/comm != "bpftrace"/
{
  printf("execve comm=%s pid=%d\n", comm, pid);
}
"#;
const GENERATED_WRITE_PROBE: &str = r#"tracepoint:syscalls:sys_enter_write
/comm != "bpftrace" && comm != "dockerd" && comm != "containerd-shim" && comm != "initd"/
{
  printf("write comm=%s pid=%d bytes=%d\n", comm, pid, args->count);
  @writes = count();
}
"#;
const GENERATED_OPEN_PROBE: &str = r#"tracepoint:syscalls:sys_enter_openat
/comm != "bpftrace" && comm != "dockerd" && comm != "containerd-shim" && comm != "initd"/
{
  printf("openat comm=%s pid=%d file=%s\n", comm, pid, str(args->filename));
  @openat = count();
}
"#;
const GENERATED_CONNECT_PROBE: &str = r#"tracepoint:syscalls:sys_enter_connect
/comm != "bpftrace" && comm != "dockerd" && comm != "containerd-shim" && comm != "initd"/
{
  printf("connect comm=%s pid=%d fd=%d\n", comm, pid, args->fd);
  @connects = count();
}
"#;

#[derive(Debug)]
struct CliArgs {
    probe_file: Option<String>,
    config_path: Option<PathBuf>,
    log_enable: bool,
    emit_mode: EmitMode,
    transport_mode: TransportMode,
    command: Vec<String>,
}

#[derive(Debug)]
struct DemoArgs {
    example_name: Option<String>,
    list_examples: bool,
    emit_mode: EmitMode,
    transport_mode: TransportMode,
}

enum ParseOutcome {
    Help,
    Demo(DemoArgs),
    Run(CliArgs),
}

#[derive(Debug, Default, Deserialize)]
struct TrackerConfig {
    #[serde(default)]
    probe: ProbeConfig,
    #[serde(default)]
    runtime: RuntimeConfig,
}

#[derive(Debug, Default, Deserialize)]
struct ProbeConfig {
    exec: Option<bool>,
    write: Option<bool>,
    open: Option<bool>,
    connect: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
struct RuntimeConfig {
    cpus: Option<f64>,
    memory: Option<String>,
    cpuset: Option<String>,
    pids_limit: Option<i64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EmitMode {
    Raw,
    Jsonl,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TransportMode {
    Bpftrace,
    Perf,
}

impl TransportMode {
    fn as_str(self) -> &'static str {
        match self {
            TransportMode::Bpftrace => "bpftrace",
            TransportMode::Perf => "perf",
        }
    }
}

fn print_usage() {
    eprintln!(
        "Usage: eBPF_tracker [--probe <file-or-name>] [--config <path>] [--log-enable] [--emit <raw|jsonl>] [--transport <bpftrace|perf>] <command> [args...]"
    );
    eprintln!("Usage: eBPF_tracker demo [--list] [--emit <raw|jsonl>] [--transport <bpftrace|perf>] [example-name]");
    eprintln!("Default emit mode: raw");
    eprintln!("Default transport: bpftrace");
    eprintln!("Example: eBPF_tracker cargo run");
    eprintln!("Example: eBPF_tracker --config ebpf-tracker.toml cargo run");
    eprintln!("Example: eBPF_tracker --probe execve.bt cargo run");
    eprintln!("Example: eBPF_tracker --probe ./probes/custom.bt cargo run");
    eprintln!("Example: eBPF_tracker --log-enable cargo test");
    eprintln!("Example: eBPF_tracker --emit jsonl cargo run");
    eprintln!("Example: eBPF_tracker --transport perf --emit jsonl cargo run");
    eprintln!("Example: cargo demo");
    eprintln!("Example: cargo demo session-io-demo");
    eprintln!("Example: cargo demo --list");
    eprintln!("Example: cargo demo --transport perf --emit jsonl session-io-demo");
    eprintln!("Example: cargo demo --emit jsonl session-io-demo");
}

fn resolve_probe_path(raw_probe: &str) -> String {
    if raw_probe.starts_with('/') {
        raw_probe.to_string()
    } else if raw_probe.contains('/') {
        format!("/workspace/{raw_probe}")
    } else {
        format!("/probes/{raw_probe}")
    }
}

fn parse_emit_mode(raw_mode: &str) -> Result<EmitMode, String> {
    match raw_mode {
        "raw" => Ok(EmitMode::Raw),
        "jsonl" => Ok(EmitMode::Jsonl),
        _ => Err(format!("unsupported emit mode: {raw_mode}")),
    }
}

fn parse_transport_mode(raw_mode: &str) -> Result<TransportMode, String> {
    match raw_mode {
        "bpftrace" => Ok(TransportMode::Bpftrace),
        "perf" => Ok(TransportMode::Perf),
        _ => Err(format!("unsupported transport: {raw_mode}")),
    }
}

fn parse_args(args: Vec<String>) -> Result<ParseOutcome, String> {
    if matches!(args.first().map(String::as_str), Some("demo")) {
        return parse_demo_args(&args[1..]);
    }

    let mut probe_file = None;
    let mut config_path = None;
    let mut log_enable = false;
    let mut emit_mode = EmitMode::Raw;
    let mut transport_mode = TransportMode::Bpftrace;
    let mut index = 0usize;

    while index < args.len() {
        let arg = &args[index];
        match arg.as_str() {
            "--probe" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "missing value for --probe".to_string())?;
                probe_file = Some(resolve_probe_path(value));
                index += 2;
            }
            "--config" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "missing value for --config".to_string())?;
                config_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--log-enable" => {
                log_enable = true;
                index += 1;
            }
            "--emit" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "missing value for --emit".to_string())?;
                emit_mode = parse_emit_mode(value)?;
                index += 2;
            }
            "--transport" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "missing value for --transport".to_string())?;
                transport_mode = parse_transport_mode(value)?;
                index += 2;
            }
            "-h" | "--help" => return Ok(ParseOutcome::Help),
            "--" => {
                index += 1;
                break;
            }
            _ if arg.starts_with("--probe=") => {
                let value = arg.trim_start_matches("--probe=");
                if value.is_empty() {
                    return Err("missing value for --probe".to_string());
                }
                probe_file = Some(resolve_probe_path(value));
                index += 1;
            }
            _ if arg.starts_with("--config=") => {
                let value = arg.trim_start_matches("--config=");
                if value.is_empty() {
                    return Err("missing value for --config".to_string());
                }
                config_path = Some(PathBuf::from(value));
                index += 1;
            }
            _ if arg.starts_with("--emit=") => {
                let value = arg.trim_start_matches("--emit=");
                if value.is_empty() {
                    return Err("missing value for --emit".to_string());
                }
                emit_mode = parse_emit_mode(value)?;
                index += 1;
            }
            _ if arg.starts_with("--transport=") => {
                let value = arg.trim_start_matches("--transport=");
                if value.is_empty() {
                    return Err("missing value for --transport".to_string());
                }
                transport_mode = parse_transport_mode(value)?;
                index += 1;
            }
            _ => break,
        }
    }

    let command = args[index..].to_vec();
    if command.is_empty() {
        return Err("missing command to run".to_string());
    }

    Ok(ParseOutcome::Run(CliArgs {
        probe_file,
        config_path,
        log_enable,
        emit_mode,
        transport_mode,
        command,
    }))
}

fn parse_demo_args(args: &[String]) -> Result<ParseOutcome, String> {
    let mut example_name = None;
    let mut list_examples = false;
    let mut emit_mode = EmitMode::Raw;
    let mut transport_mode = TransportMode::Bpftrace;
    let mut index = 0usize;

    while index < args.len() {
        let arg = &args[index];
        match arg.as_str() {
            "-h" | "--help" => return Ok(ParseOutcome::Help),
            "--list" => {
                list_examples = true;
                index += 1;
            }
            "--emit" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "missing value for --emit".to_string())?;
                emit_mode = parse_emit_mode(value)?;
                index += 2;
            }
            "--transport" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "missing value for --transport".to_string())?;
                transport_mode = parse_transport_mode(value)?;
                index += 2;
            }
            _ if arg.starts_with("--emit=") => {
                let value = arg.trim_start_matches("--emit=");
                if value.is_empty() {
                    return Err("missing value for --emit".to_string());
                }
                emit_mode = parse_emit_mode(value)?;
                index += 1;
            }
            _ if arg.starts_with("--transport=") => {
                let value = arg.trim_start_matches("--transport=");
                if value.is_empty() {
                    return Err("missing value for --transport".to_string());
                }
                transport_mode = parse_transport_mode(value)?;
                index += 1;
            }
            _ if arg.starts_with('-') => return Err(format!("unknown demo flag: {arg}")),
            _ if example_name.is_none() => {
                example_name = Some(arg.clone());
                index += 1;
            }
            _ => return Err("demo accepts at most one example name".to_string()),
        }
    }

    Ok(ParseOutcome::Demo(DemoArgs {
        example_name,
        list_examples,
        emit_mode,
        transport_mode,
    }))
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

fn ensure_embedded_runtime() -> Result<PathBuf, String> {
    let mut errors = Vec::new();

    for root in cache_root_candidates() {
        let runtime_dir = root.join(format!("runtime-v{}", env!("CARGO_PKG_VERSION")));
        let result = (|| -> Result<PathBuf, String> {
            write_if_changed(
                &runtime_dir.join("docker-compose.bpftrace.yml"),
                EMBEDDED_COMPOSE,
            )?;
            write_if_changed(
                &runtime_dir.join("docker/bpftrace-rust.Dockerfile"),
                EMBEDDED_DOCKERFILE,
            )?;
            write_if_changed(
                &runtime_dir.join("scripts/run-bpftrace-wrap.sh"),
                EMBEDDED_RUN_SCRIPT,
            )?;
            write_if_changed(&runtime_dir.join("probes/execve.bt"), EMBEDDED_PROBE_EXECVE)?;
            Ok(runtime_dir.join(COMPOSE_FILE_NAME))
        })();

        match result {
            Ok(compose_file) => return Ok(compose_file),
            Err(err) => errors.push(err),
        }
    }

    Err(format!(
        "failed to materialize runtime assets: {}",
        errors.join("; ")
    ))
}

fn resolve_compose_file() -> Result<PathBuf, String> {
    if let Ok(path) = env::var("EBPF_TRACKER_COMPOSE_FILE") {
        let compose = PathBuf::from(path);
        if compose.is_file() {
            return Ok(compose);
        }
        return Err(format!(
            "compose file from EBPF_TRACKER_COMPOSE_FILE not found: {}",
            compose.display()
        ));
    }

    let current_dir =
        env::current_dir().map_err(|err| format!("failed to read current dir: {err}"))?;
    let cwd_candidate = current_dir.join(COMPOSE_FILE_NAME);
    if cwd_candidate.is_file() {
        return Ok(cwd_candidate);
    }

    let exe =
        env::current_exe().map_err(|err| format!("failed to resolve executable path: {err}"))?;
    for ancestor in exe.ancestors() {
        let candidate = ancestor.join(COMPOSE_FILE_NAME);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }

    ensure_embedded_runtime()
}

fn resolve_config_path(
    explicit_config_path: Option<&Path>,
    project_dir: &Path,
) -> Result<Option<PathBuf>, String> {
    if let Some(config_path) = explicit_config_path {
        let resolved = if config_path.is_absolute() {
            config_path.to_path_buf()
        } else {
            project_dir.join(config_path)
        };

        if resolved.is_file() {
            return Ok(Some(resolved));
        }

        return Err(format!("config file not found: {}", resolved.display()));
    }

    let default_config = project_dir.join(DEFAULT_CONFIG_FILE_NAME);
    if default_config.is_file() {
        Ok(Some(default_config))
    } else {
        Ok(None)
    }
}

fn load_config(config_path: &Path) -> Result<TrackerConfig, String> {
    let content = fs::read_to_string(config_path)
        .map_err(|err| format!("failed to read config {}: {err}", config_path.display()))?;
    toml::from_str(&content)
        .map_err(|err| format!("failed to parse config {}: {err}", config_path.display()))
}

fn config_enabled(value: Option<bool>) -> bool {
    value.unwrap_or(false)
}

fn trace_event_kinds_from_config(config: Option<&TrackerConfig>) -> Result<Vec<EventKind>, String> {
    let Some(config) = config else {
        return Ok(default_perf_event_kinds());
    };

    let mut event_kinds = Vec::new();
    if config_enabled(config.probe.exec) {
        event_kinds.push(EventKind::Execve);
    }
    if config_enabled(config.probe.write) {
        event_kinds.push(EventKind::Write);
    }
    if config_enabled(config.probe.open) {
        event_kinds.push(EventKind::OpenAt);
    }
    if config_enabled(config.probe.connect) {
        event_kinds.push(EventKind::Connect);
    }

    if event_kinds.is_empty() {
        return Err(
            "config did not enable any probe features; set one of probe.exec/probe.write/probe.open/probe.connect"
                .to_string(),
        );
    }

    Ok(event_kinds)
}

fn build_generated_probe(config: &ProbeConfig) -> Result<String, String> {
    let mut sections = Vec::new();

    if config_enabled(config.exec) {
        sections.push(GENERATED_EXEC_PROBE);
    }
    if config_enabled(config.write) {
        sections.push(GENERATED_WRITE_PROBE);
    }
    if config_enabled(config.open) {
        sections.push(GENERATED_OPEN_PROBE);
    }
    if config_enabled(config.connect) {
        sections.push(GENERATED_CONNECT_PROBE);
    }

    if sections.is_empty() {
        return Err(
            "config did not enable any probe features; set one of probe.exec/probe.write/probe.open/probe.connect"
                .to_string(),
        );
    }

    Ok(sections.join("\n"))
}

fn generated_probe_path(compose_file: &Path) -> Result<PathBuf, String> {
    let runtime_root = compose_file.parent().ok_or_else(|| {
        format!(
            "failed to determine runtime root from compose file {}",
            compose_file.display()
        )
    })?;
    Ok(runtime_root
        .join("probes")
        .join(GENERATED_CONFIG_PROBE_FILE_NAME))
}

fn generated_runtime_override_path(compose_file: &Path) -> Result<PathBuf, String> {
    let runtime_root = compose_file.parent().ok_or_else(|| {
        format!(
            "failed to determine runtime root from compose file {}",
            compose_file.display()
        )
    })?;
    Ok(runtime_root.join(GENERATED_RUNTIME_OVERRIDE_FILE_NAME))
}

fn resolve_tracker_config(
    explicit_config_path: Option<&Path>,
    project_dir: &Path,
) -> Result<Option<TrackerConfig>, String> {
    let config_path = resolve_config_path(explicit_config_path, project_dir)?;
    config_path.as_deref().map(load_config).transpose()
}

fn resolve_probe_file(
    cli_args: &CliArgs,
    config: Option<&TrackerConfig>,
    compose_file: &Path,
) -> Result<String, String> {
    if let Some(probe_file) = &cli_args.probe_file {
        return Ok(probe_file.clone());
    }

    if let Some(config) = config {
        let generated_probe = build_generated_probe(&config.probe)?;
        let output_path = generated_probe_path(compose_file)?;
        write_if_changed(&output_path, &generated_probe)?;
        return Ok(format!("/probes/{GENERATED_CONFIG_PROBE_FILE_NAME}"));
    }

    Ok(DEFAULT_PROBE.to_string())
}

fn resolve_runtime_override(
    config: Option<&TrackerConfig>,
    compose_file: &Path,
) -> Result<Option<PathBuf>, String> {
    let Some(config) = config else {
        return Ok(None);
    };

    let Some(override_content) = build_runtime_override(&config.runtime)? else {
        return Ok(None);
    };

    let output_path = generated_runtime_override_path(compose_file)?;
    write_if_changed(&output_path, &override_content)?;
    Ok(Some(output_path))
}

fn build_runtime_override(config: &RuntimeConfig) -> Result<Option<String>, String> {
    let mut lines = Vec::new();

    if let Some(cpus) = config.cpus {
        if !cpus.is_finite() || cpus <= 0.0 {
            return Err("runtime.cpus must be greater than zero".to_string());
        }
        lines.push(format!("    cpus: {cpus}"));
    }

    if let Some(memory) = config.memory.as_deref() {
        let memory = memory.trim();
        if memory.is_empty() {
            return Err("runtime.memory must not be empty".to_string());
        }
        lines.push(format!("    mem_limit: {}", yaml_string(memory)));
    }

    if let Some(cpuset) = config.cpuset.as_deref() {
        let cpuset = cpuset.trim();
        if cpuset.is_empty() {
            return Err("runtime.cpuset must not be empty".to_string());
        }
        if !cpuset
            .chars()
            .all(|ch| ch.is_ascii_digit() || ch == ',' || ch == '-')
        {
            return Err(
                "runtime.cpuset must use only digits, commas, and hyphens like \"0-3\" or \"0,1\""
                    .to_string(),
            );
        }
        lines.push(format!("    cpuset: {}", yaml_string(cpuset)));
    }

    if let Some(pids_limit) = config.pids_limit {
        if pids_limit == 0 || pids_limit < -1 {
            return Err("runtime.pids_limit must be greater than zero or -1".to_string());
        }
        lines.push(format!("    pids_limit: {pids_limit}"));
    }

    if lines.is_empty() {
        return Ok(None);
    }

    let mut content = String::from("services:\n  bpftrace:\n");
    for line in lines {
        content.push_str(&line);
        content.push('\n');
    }

    Ok(Some(content))
}

fn yaml_string(value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

fn resolve_perf_events(
    cli_args: &CliArgs,
    config: Option<&TrackerConfig>,
) -> Result<String, String> {
    if cli_args.probe_file.is_some() {
        return Err("--probe is only supported with --transport bpftrace".to_string());
    }

    let event_kinds = trace_event_kinds_from_config(config)?;
    Ok(perf_trace_expression(&event_kinds))
}

fn build_compose_command(
    compose_file: &Path,
    runtime_override_file: Option<&Path>,
    project_dir: &Path,
    cli_args: &CliArgs,
    probe_file: Option<&str>,
    perf_events: Option<&str>,
    wrapped_command: &[String],
) -> Command {
    let mut command = Command::new("docker");
    command.arg("compose").arg("-f").arg(compose_file);

    if let Some(runtime_override_file) = runtime_override_file {
        command.arg("-f").arg(runtime_override_file);
    }

    command.arg("run").arg("--build").arg("--rm");

    command.arg("-e").arg(format!(
        "EBPF_TRACKER_TRANSPORT={}",
        cli_args.transport_mode.as_str()
    ));

    if let Some(probe_file) = probe_file {
        command
            .arg("-e")
            .arg(format!("EBPF_TRACKER_PROBE={probe_file}"));
    }

    if let Some(perf_events) = perf_events {
        command
            .arg("-e")
            .arg(format!("EBPF_TRACKER_PERF_EVENTS={perf_events}"));
    }

    command
        .arg("bpftrace")
        .args(wrapped_command)
        .env("PROJECT_DIR", project_dir);

    command
}

fn timestamp_for_filename() -> String {
    if let Ok(output) = Command::new("date").arg("+%Y%m%d-%H%M%S").output() {
        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !text.is_empty() {
                return text;
            }
        }
    }

    let fallback = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    fallback.to_string()
}

fn copy_stream<R, W>(mut reader: R, mut terminal: W, log_file: Arc<Mutex<File>>) -> io::Result<()>
where
    R: Read,
    W: Write,
{
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let read_bytes = reader.read(&mut buffer)?;
        if read_bytes == 0 {
            break;
        }

        terminal.write_all(&buffer[..read_bytes])?;
        terminal.flush()?;

        let mut file = log_file
            .lock()
            .map_err(|_| io::Error::other("log file lock poisoned"))?;
        file.write_all(&buffer[..read_bytes])?;
        file.flush()?;
    }
    Ok(())
}

fn append_log_line(log_file: &Arc<Mutex<File>>, line: &str) -> io::Result<()> {
    let mut file = log_file
        .lock()
        .map_err(|_| io::Error::other("log file lock poisoned"))?;
    file.write_all(line.as_bytes())?;
    file.flush()?;
    Ok(())
}

#[derive(Default)]
struct JsonlCopySummary {
    perf_session: PerfTraceSession,
}

fn emit_stream_record(record: &StreamRecord, terminal_lock: &Arc<Mutex<()>>) -> io::Result<()> {
    let serialized =
        serde_json::to_string(record).map_err(|err| io::Error::other(err.to_string()))?;

    let _terminal = terminal_lock
        .lock()
        .map_err(|_| io::Error::other("terminal lock poisoned"))?;
    let mut stdout = io::stdout();
    stdout.write_all(serialized.as_bytes())?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    Ok(())
}

fn create_log_file(project_dir: &Path) -> Result<(Arc<Mutex<File>>, PathBuf), String> {
    let logs_dir = project_dir.join("logs");
    fs::create_dir_all(&logs_dir)
        .map_err(|err| format!("failed to create logs dir {}: {err}", logs_dir.display()))?;

    let timestamp = timestamp_for_filename();
    let log_file_path = logs_dir.join(format!("ebpf-tracker-{timestamp}.log"));
    let log_file = File::create(&log_file_path).map_err(|err| {
        format!(
            "failed to create log file {}: {err}",
            log_file_path.display()
        )
    })?;

    Ok((Arc::new(Mutex::new(log_file)), log_file_path))
}

fn copy_stream_jsonl<R: Read>(
    reader: R,
    log_file: Option<Arc<Mutex<File>>>,
    terminal_lock: Arc<Mutex<()>>,
    transport_mode: TransportMode,
) -> io::Result<JsonlCopySummary> {
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    let mut summary = JsonlCopySummary::default();

    loop {
        line.clear();
        let read = reader.read_line(&mut line)?;
        if read == 0 {
            break;
        }

        if let Some(log_file) = &log_file {
            append_log_line(log_file, &line)?;
        }

        let trimmed = line.trim_end_matches(['\n', '\r']);
        let record = match transport_mode {
            TransportMode::Bpftrace => stream_record_for_line(trimmed),
            TransportMode::Perf => stream_record_for_perf_trace_line(trimmed),
        };

        if let Some(record) = record {
            if transport_mode == TransportMode::Perf {
                summary.perf_session.observe(&record);
            }
            emit_stream_record(&record, &terminal_lock)?;
        } else {
            let _terminal = terminal_lock
                .lock()
                .map_err(|_| io::Error::other("terminal lock poisoned"))?;
            let mut stderr = io::stderr();
            stderr.write_all(line.as_bytes())?;
            stderr.flush()?;
        }
    }

    Ok(summary)
}

fn run_with_jsonl(
    mut command: Command,
    project_dir: &Path,
    log_enable: bool,
    transport_mode: TransportMode,
) -> Result<i32, String> {
    let mut child = command
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("failed to run docker compose: {err}"))?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "failed to capture child stdout".to_string())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "failed to capture child stderr".to_string())?;

    let log_file = if log_enable {
        let (log_file, log_file_path) = create_log_file(project_dir)?;
        eprintln!("logging enabled: {}", log_file_path.display());
        Some(log_file)
    } else {
        None
    };

    let terminal_lock = Arc::new(Mutex::new(()));

    let out_log = log_file.as_ref().map(Arc::clone);
    let out_terminal = Arc::clone(&terminal_lock);
    let out_handle =
        thread::spawn(move || copy_stream_jsonl(stdout, out_log, out_terminal, transport_mode));

    let err_log = log_file.as_ref().map(Arc::clone);
    let err_terminal = Arc::clone(&terminal_lock);
    let err_handle =
        thread::spawn(move || copy_stream_jsonl(stderr, err_log, err_terminal, transport_mode));

    let status = child
        .wait()
        .map_err(|err| format!("failed waiting for docker compose: {err}"))?;

    let out_result = out_handle
        .join()
        .map_err(|_| "stdout capture thread panicked".to_string())?;
    let out_summary = out_result.map_err(|err| format!("stdout capture failed: {err}"))?;

    let err_result = err_handle
        .join()
        .map_err(|_| "stderr jsonl thread panicked".to_string())?;
    let err_summary = err_result.map_err(|err| format!("stderr jsonl forwarding failed: {err}"))?;

    if transport_mode == TransportMode::Perf {
        let mut summary = out_summary.perf_session;
        summary.merge(&err_summary.perf_session);
        if !summary.is_empty() {
            for record in summary.aggregate_records_now() {
                emit_stream_record(&record, &terminal_lock).map_err(|err| {
                    format!("failed to emit perf aggregate records as jsonl: {err}")
                })?;
            }
        }
    }

    Ok(exit_code(status))
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

fn run_without_log(mut command: Command) -> Result<i32, String> {
    let status = command
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|err| format!("failed to run docker compose: {err}"))?;
    Ok(exit_code(status))
}

fn run_with_log(mut command: Command, project_dir: &Path) -> Result<i32, String> {
    let logs_dir = project_dir.join("logs");
    fs::create_dir_all(&logs_dir)
        .map_err(|err| format!("failed to create logs dir {}: {err}", logs_dir.display()))?;

    let timestamp = timestamp_for_filename();
    let log_file_path = logs_dir.join(format!("ebpf-tracker-{timestamp}.log"));
    eprintln!("logging enabled: {}", log_file_path.display());

    let log_file = File::create(&log_file_path).map_err(|err| {
        format!(
            "failed to create log file {}: {err}",
            log_file_path.display()
        )
    })?;
    let log_file = Arc::new(Mutex::new(log_file));

    let mut child = command
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("failed to run docker compose: {err}"))?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "failed to capture child stdout".to_string())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "failed to capture child stderr".to_string())?;

    let log_stdout = Arc::clone(&log_file);
    let out_handle = thread::spawn(move || copy_stream(stdout, io::stdout(), log_stdout));

    let log_stderr = Arc::clone(&log_file);
    let err_handle = thread::spawn(move || copy_stream(stderr, io::stderr(), log_stderr));

    let status = child
        .wait()
        .map_err(|err| format!("failed waiting for docker compose: {err}"))?;

    let out_result = out_handle
        .join()
        .map_err(|_| "stdout forwarding thread panicked".to_string())?;
    out_result.map_err(|err| format!("stdout forwarding failed: {err}"))?;

    let err_result = err_handle
        .join()
        .map_err(|_| "stderr forwarding thread panicked".to_string())?;
    err_result.map_err(|err| format!("stderr forwarding failed: {err}"))?;

    Ok(exit_code(status))
}

fn repo_root_from(start_dir: &Path) -> Result<PathBuf, String> {
    for ancestor in start_dir.ancestors() {
        let manifest = ancestor.join("Cargo.toml");
        let main_rs = ancestor.join("src").join("main.rs");
        let examples = ancestor.join(EXAMPLES_DIR_NAME);
        if manifest.is_file() && main_rs.is_file() && examples.is_dir() {
            return Ok(ancestor.to_path_buf());
        }
    }

    Err("demo mode must be run from the repository root or one of its subdirectories".to_string())
}

fn available_examples(repo_root: &Path) -> Result<Vec<String>, String> {
    let mut examples = Vec::new();
    let examples_dir = repo_root.join(EXAMPLES_DIR_NAME);

    for entry in fs::read_dir(&examples_dir)
        .map_err(|err| format!("failed to read {}: {err}", examples_dir.display()))?
    {
        let entry =
            entry.map_err(|err| format!("failed to read {}: {err}", examples_dir.display()))?;
        let path = entry.path();
        if path.is_dir() && path.join("Cargo.toml").is_file() {
            examples.push(entry.file_name().to_string_lossy().to_string());
        }
    }

    examples.sort();
    Ok(examples)
}

fn resolve_example_dir(repo_root: &Path, example_name: &str) -> Result<PathBuf, String> {
    let example_dir = repo_root.join(EXAMPLES_DIR_NAME).join(example_name);
    if example_dir.join("Cargo.toml").is_file() {
        Ok(example_dir)
    } else {
        let examples = available_examples(repo_root)?;
        let available = if examples.is_empty() {
            "none".to_string()
        } else {
            examples.join(", ")
        };
        Err(format!(
            "unknown example: {example_name}. available examples: {available}"
        ))
    }
}

fn clean_example(example_dir: &Path) -> Result<(), String> {
    let status = Command::new("cargo")
        .arg("clean")
        .arg("--quiet")
        .arg("--target-dir")
        .arg("target")
        .current_dir(example_dir)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|err| {
            format!(
                "failed to run cargo clean in {}: {err}",
                example_dir.display()
            )
        })?;

    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "cargo clean failed in {} with exit code {}",
            example_dir.display(),
            exit_code(status)
        ))
    }
}

fn run_demo(demo_args: DemoArgs) -> Result<i32, String> {
    let current_dir =
        env::current_dir().map_err(|err| format!("failed to read current dir: {err}"))?;
    let repo_root = repo_root_from(&current_dir)?;

    if demo_args.list_examples {
        for example in available_examples(&repo_root)? {
            println!("{example}");
        }
        return Ok(0);
    }

    let example_name = demo_args
        .example_name
        .unwrap_or_else(|| DEFAULT_EXAMPLE_NAME.to_string());
    let example_dir = resolve_example_dir(&repo_root, &example_name)?;

    eprintln!("Running example: {example_name}");
    clean_example(&example_dir)?;

    run_cli(
        CliArgs {
            probe_file: None,
            config_path: Some(PathBuf::from(DEFAULT_CONFIG_FILE_NAME)),
            log_enable: false,
            emit_mode: demo_args.emit_mode,
            transport_mode: demo_args.transport_mode,
            command: vec!["cargo".to_string(), "run".to_string()],
        },
        example_dir,
    )
}

fn run_cli(cli_args: CliArgs, project_dir: PathBuf) -> Result<i32, String> {
    let config = resolve_tracker_config(cli_args.config_path.as_deref(), &project_dir)?;
    let compose_file = resolve_compose_file()?;
    let runtime_override = resolve_runtime_override(config.as_ref(), &compose_file)?;
    let (probe_file, perf_events) = match cli_args.transport_mode {
        TransportMode::Bpftrace => (
            Some(resolve_probe_file(
                &cli_args,
                config.as_ref(),
                &compose_file,
            )?),
            None,
        ),
        TransportMode::Perf => (None, Some(resolve_perf_events(&cli_args, config.as_ref())?)),
    };
    let command = build_compose_command(
        &compose_file,
        runtime_override.as_deref(),
        &project_dir,
        &cli_args,
        probe_file.as_deref(),
        perf_events.as_deref(),
        &cli_args.command,
    );

    if cli_args.emit_mode == EmitMode::Jsonl {
        run_with_jsonl(
            command,
            &project_dir,
            cli_args.log_enable,
            cli_args.transport_mode,
        )
    } else if cli_args.log_enable {
        run_with_log(command, &project_dir)
    } else {
        run_without_log(command)
    }
}

fn run() -> Result<i32, String> {
    let args: Vec<String> = env::args().skip(1).collect();
    match parse_args(args)? {
        ParseOutcome::Help => {
            print_usage();
            Ok(0)
        }
        ParseOutcome::Demo(demo_args) => run_demo(demo_args),
        ParseOutcome::Run(cli_args) => {
            let project_dir =
                env::current_dir().map_err(|err| format!("failed to read current dir: {err}"))?;
            run_cli(cli_args, project_dir)
        }
    }
}

pub fn main_entry() -> i32 {
    match run() {
        Ok(code) => code,
        Err(message) => {
            eprintln!("{message}");
            print_usage();
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{build_generated_probe, build_runtime_override, load_config, RuntimeConfig};
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn generated_probe_includes_enabled_sections_only() {
        let config = super::ProbeConfig {
            exec: Some(true),
            write: Some(true),
            open: Some(false),
            connect: Some(false),
        };

        let probe = build_generated_probe(&config).expect("probe should be generated");
        assert!(probe.contains("sys_enter_execve"));
        assert!(probe.contains("sys_enter_write"));
        assert!(!probe.contains("sys_enter_openat"));
        assert!(!probe.contains("sys_enter_connect"));
    }

    #[test]
    fn config_parses_probe_flags() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("ebpf-tracker-config-{unique}.toml"));
        fs::write(
            &path,
            "[probe]\nexec = true\nwrite = true\nopen = false\nconnect = true\n",
        )
        .expect("config file should be written");

        let config = load_config(&path).expect("config should parse");
        assert_eq!(config.probe.exec, Some(true));
        assert_eq!(config.probe.write, Some(true));
        assert_eq!(config.probe.open, Some(false));
        assert_eq!(config.probe.connect, Some(true));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn config_parses_runtime_controls() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("ebpf-tracker-runtime-config-{unique}.toml"));
        fs::write(
            &path,
            "[probe]\nexec = true\n\n[runtime]\ncpus = 2.0\nmemory = \"512m\"\ncpuset = \"0-1\"\npids_limit = 256\n",
        )
        .expect("config file should be written");

        let config = load_config(&path).expect("config should parse");
        assert_eq!(config.runtime.cpus, Some(2.0));
        assert_eq!(config.runtime.memory.as_deref(), Some("512m"));
        assert_eq!(config.runtime.cpuset.as_deref(), Some("0-1"));
        assert_eq!(config.runtime.pids_limit, Some(256));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn runtime_override_contains_requested_docker_controls() {
        let override_content = build_runtime_override(&RuntimeConfig {
            cpus: Some(1.5),
            memory: Some("2g".to_string()),
            cpuset: Some("0-3".to_string()),
            pids_limit: Some(512),
        })
        .expect("runtime override should build")
        .expect("runtime override should not be empty");

        assert!(override_content.contains("services:"));
        assert!(override_content.contains("  bpftrace:"));
        assert!(override_content.contains("    cpus: 1.5"));
        assert!(override_content.contains("    mem_limit: \"2g\""));
        assert!(override_content.contains("    cpuset: \"0-3\""));
        assert!(override_content.contains("    pids_limit: 512"));
    }

    #[test]
    fn runtime_override_rejects_invalid_values() {
        assert!(build_runtime_override(&RuntimeConfig {
            cpus: Some(0.0),
            memory: None,
            cpuset: None,
            pids_limit: None,
        })
        .is_err());

        assert!(build_runtime_override(&RuntimeConfig {
            cpus: None,
            memory: Some("   ".to_string()),
            cpuset: None,
            pids_limit: None,
        })
        .is_err());

        assert!(build_runtime_override(&RuntimeConfig {
            cpus: None,
            memory: None,
            cpuset: Some("0,1,a".to_string()),
            pids_limit: None,
        })
        .is_err());

        assert!(build_runtime_override(&RuntimeConfig {
            cpus: None,
            memory: None,
            cpuset: None,
            pids_limit: Some(0),
        })
        .is_err());
    }
}
