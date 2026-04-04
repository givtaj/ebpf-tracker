use std::env;
use std::fs::{self, File};
use std::io::{self, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use attach::{parse_attach_args, run_attach, AttachArgs, AttachParseOutcome};
use compose::{build_compose_command, ComposeRunConfig};
use dashboard::{
    build_demo_args_for_dashboard, build_tracker_args_for_dashboard, run_with_dashboard,
};
use ebpf_tracker_events::{stream_record_for_line, EventKind, StreamRecord};
use ebpf_tracker_perf::{
    default_perf_event_kinds, perf_trace_expression, stream_record_for_perf_trace_line,
    PerfTraceSession,
};
use intelligence::{
    parse_intelligence_arg, IntelligenceOptions, IntelligenceReporter, IntelligenceSupervisor,
};
use runtime::{
    parse_runtime_selection, resolve_compose_file_with_source, resolve_runtime_profile,
    write_if_changed, RuntimeAssetResolution, RuntimeAssetSource, RuntimeProfile, RuntimeSelection,
};
use serde::Deserialize;

mod attach;
mod compose;
mod dashboard;
mod intelligence;
mod runtime;

const DEFAULT_PROBE: &str = "/probes/execve.bt";
const DEFAULT_CONFIG_FILE_NAME: &str = "ebpf-tracker.toml";
const GENERATED_CONFIG_PROBE_FILE_NAME: &str = "generated-config.bt";
const GENERATED_RUNTIME_OVERRIDE_FILE_NAME: &str = "generated-runtime.override.yml";
const DEFAULT_EXAMPLE_NAME: &str = "session-io-demo";
const EXAMPLES_DIR_NAME: &str = "examples";
const DEMO_MANIFEST_FILE_NAME: &str = "ebpf-demo.toml";
const DEFAULT_DASHBOARD_PORT: u16 = 43115;
const INTERACTIVE_PTY_ENV_NAME: &str = "EBPF_TRACKER_INTERACTIVE_PTY";
const DEMO_ENV_NAME: &str = "EBPF_TRACKER_DEMO_NAME";
const DEMO_ENV_PRODUCT_NAME: &str = "EBPF_TRACKER_DEMO_PRODUCT_NAME";
const DEMO_ENV_PRODUCT_TAGLINE: &str = "EBPF_TRACKER_DEMO_PRODUCT_TAGLINE";
const DEMO_ENV_SPONSOR_NAME: &str = "EBPF_TRACKER_DEMO_SPONSOR_NAME";
const DEMO_ENV_SPONSOR_MESSAGE: &str = "EBPF_TRACKER_DEMO_SPONSOR_MESSAGE";
const DEMO_ENV_SPONSOR_URL: &str = "EBPF_TRACKER_DEMO_SPONSOR_URL";
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
    runtime_selection: RuntimeSelection,
    dashboard: DashboardOptions,
    intelligence: IntelligenceOptions,
    command: Vec<String>,
    session_record: Option<StreamRecord>,
    extra_env: Vec<(String, String)>,
}

#[derive(Debug)]
struct DemoArgs {
    example_name: Option<String>,
    list_examples: bool,
    log_enable: bool,
    emit_mode: EmitMode,
    transport_mode: TransportMode,
    dashboard: DashboardOptions,
    intelligence: IntelligenceOptions,
}

#[derive(Debug)]
struct DemoManifest {
    runtime_selection: RuntimeSelection,
    command: Vec<String>,
    clean_command: Option<Vec<String>>,
    branding: DemoBranding,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct DemoBranding {
    product_name: Option<String>,
    product_tagline: Option<String>,
    sponsor_name: Option<String>,
    sponsor_message: Option<String>,
    sponsor_url: Option<String>,
}

impl DemoBranding {
    fn is_empty(&self) -> bool {
        self.product_name.is_none()
            && self.product_tagline.is_none()
            && self.sponsor_name.is_none()
            && self.sponsor_message.is_none()
            && self.sponsor_url.is_none()
    }

    fn session_record(&self, example_name: &str) -> Option<StreamRecord> {
        if self.is_empty() {
            return None;
        }

        let product_name = self
            .product_name
            .clone()
            .unwrap_or_else(|| "ebpf-tracker".to_string());
        Some(StreamRecord::Session {
            timestamp_unix_ms: current_timestamp_millis(),
            demo_name: example_name.to_string(),
            product_name,
            product_tagline: self.product_tagline.clone(),
            sponsor_name: self.sponsor_name.clone(),
            sponsor_message: self.sponsor_message.clone(),
            sponsor_url: self.sponsor_url.clone(),
        })
    }

    fn extra_env(&self, example_name: &str) -> Vec<(String, String)> {
        let mut env = vec![(DEMO_ENV_NAME.to_string(), example_name.to_string())];

        if let Some(value) = &self.product_name {
            env.push((DEMO_ENV_PRODUCT_NAME.to_string(), value.clone()));
        }
        if let Some(value) = &self.product_tagline {
            env.push((DEMO_ENV_PRODUCT_TAGLINE.to_string(), value.clone()));
        }
        if let Some(value) = &self.sponsor_name {
            env.push((DEMO_ENV_SPONSOR_NAME.to_string(), value.clone()));
        }
        if let Some(value) = &self.sponsor_message {
            env.push((DEMO_ENV_SPONSOR_MESSAGE.to_string(), value.clone()));
        }
        if let Some(value) = &self.sponsor_url {
            env.push((DEMO_ENV_SPONSOR_URL.to_string(), value.clone()));
        }

        env
    }
}

enum ParseOutcome {
    Help,
    Attach(AttachArgs),
    Demo(DemoArgs),
    Run(CliArgs),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DashboardOptions {
    enabled: bool,
    port: u16,
}

impl Default for DashboardOptions {
    fn default() -> Self {
        Self {
            enabled: false,
            port: DEFAULT_DASHBOARD_PORT,
        }
    }
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

#[derive(Debug, Deserialize)]
struct DemoManifestFile {
    runtime: String,
    command: Vec<String>,
    clean: Option<Vec<String>>,
    product_name: Option<String>,
    product_tagline: Option<String>,
    sponsor_name: Option<String>,
    sponsor_message: Option<String>,
    sponsor_url: Option<String>,
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

impl EmitMode {
    fn as_str(self) -> &'static str {
        match self {
            EmitMode::Raw => "raw",
            EmitMode::Jsonl => "jsonl",
        }
    }
}

impl RuntimeSelection {
    fn as_str(self) -> &'static str {
        match self {
            RuntimeSelection::Auto => "auto",
            RuntimeSelection::Rust => "rust",
            RuntimeSelection::Node => "node",
        }
    }
}

fn print_usage() {
    eprintln!(
        "Usage: ebpf-tracker [--probe <file-or-name>] [--config <path>] [--log-enable] [--emit <raw|jsonl>] [--transport <bpftrace|perf>] [--runtime <auto|rust|node>] [--dashboard] [--dashboard-port <port>] [--intelligence-dataset] [--intelligence-provider <lm-studio|openai-compatible>] [--intelligence-model <name>] [--intelligence-endpoint <url>] <command> [args...]"
    );
    eprintln!("Usage: ebpf-tracker attach <docker|k8s|aws-eks|aws-ecs> [--backend <inspektor-gadget|tetragon>] [--namespace <ns>] [--selector <label-selector>] [--pod <name>] [--cluster <name>] [--region <aws-region>] [--service <name>] [--task <id>] [--container <name>] [experimental scaffold]");
    eprintln!("Usage: ebpf-tracker demo [--list] [--emit <raw|jsonl>] [--transport <bpftrace|perf>] [--dashboard] [--dashboard-port <port>] [--intelligence-dataset] [--intelligence-provider <lm-studio|openai-compatible>] [--intelligence-model <name>] [example-name]");
    eprintln!("Usage: ebpf-tracker see [--port <port>] [--intelligence-dataset] [--intelligence-provider <lm-studio|openai-compatible>] [--intelligence-model <name>] [example-name]");
    eprintln!("Default emit mode: raw");
    eprintln!("Default transport: bpftrace");
    eprintln!("Default runtime: auto");
    eprintln!("Default dashboard port: {DEFAULT_DASHBOARD_PORT}");
    eprintln!("Example: ebpf-tracker cargo run");
    eprintln!("Example: ebpf-tracker npm test");
    eprintln!("Example: ebpf-tracker --config ebpf-tracker.toml cargo run");
    eprintln!("Example: ebpf-tracker --probe execve.bt cargo run");
    eprintln!("Example: ebpf-tracker --probe ./probes/custom.bt cargo run");
    eprintln!("Example: ebpf-tracker --log-enable cargo test");
    eprintln!("Example: ebpf-tracker --emit jsonl cargo run");
    eprintln!("Example: ebpf-tracker --transport perf --emit jsonl cargo run");
    eprintln!("Example: ebpf-tracker --runtime node /bin/sh -lc \"npm run dev\"");
    eprintln!("Example: ebpf-tracker attach k8s --selector app=payments");
    eprintln!("Example: ebpf-tracker attach aws-eks --cluster prod --region us-east-1 --selector app=payments");
    eprintln!("Example: ebpf-tracker --dashboard cargo run");
    eprintln!("Example: ebpf-tracker see --intelligence-dataset session-io-demo");
    eprintln!("Example: ebpf-tracker --dashboard --intelligence-dataset cargo run");
    eprintln!("Example: ebpf-tracker demo --dashboard session-io-demo");
    eprintln!("Example: ebpf-tracker see");
    eprintln!("Example: ebpf-tracker see postcard-generator-rust");
    eprintln!("Repository demo mode: ebpf-tracker demo --list");
    eprintln!("Repository demo example: ebpf-tracker demo --emit jsonl session-io-demo");
    eprintln!("The see subcommand is a shortcut for the dashboard demo experience.");
    eprintln!("The demo subcommand expects a local clone of ebpf-tracker.");
    eprintln!(
        "The attach subcommand is experimental scaffold/plan mode and does not start tracing yet."
    );
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

fn parse_dashboard_port(raw_port: &str) -> Result<u16, String> {
    let port = raw_port
        .parse::<u16>()
        .map_err(|_| format!("invalid dashboard port: {raw_port}"))?;
    if port == 0 {
        return Err("dashboard port must be greater than zero".to_string());
    }
    Ok(port)
}

fn parse_args(args: Vec<String>) -> Result<ParseOutcome, String> {
    if matches!(args.first().map(String::as_str), Some("attach")) {
        return match parse_attach_args(&args[1..])? {
            AttachParseOutcome::Help => Ok(ParseOutcome::Help),
            AttachParseOutcome::Run(attach_args) => Ok(ParseOutcome::Attach(attach_args)),
        };
    }
    if matches!(args.first().map(String::as_str), Some("demo")) {
        return parse_demo_args(&args[1..]);
    }
    if matches!(args.first().map(String::as_str), Some("see")) {
        return parse_see_args(&args[1..]);
    }

    let mut probe_file = None;
    let mut config_path = None;
    let mut log_enable = false;
    let mut emit_mode = EmitMode::Raw;
    let mut transport_mode = TransportMode::Bpftrace;
    let mut runtime_selection = RuntimeSelection::Auto;
    let mut dashboard = DashboardOptions::default();
    let mut intelligence = IntelligenceOptions::default();
    let mut index = 0usize;

    while index < args.len() {
        if parse_intelligence_arg(&args, &mut index, &mut intelligence)? {
            continue;
        }

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
            "--runtime" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "missing value for --runtime".to_string())?;
                runtime_selection = parse_runtime_selection(value)?;
                index += 2;
            }
            "--dashboard" => {
                dashboard.enabled = true;
                index += 1;
            }
            "--dashboard-port" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "missing value for --dashboard-port".to_string())?;
                dashboard.port = parse_dashboard_port(value)?;
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
            _ if arg.starts_with("--runtime=") => {
                let value = arg.trim_start_matches("--runtime=");
                if value.is_empty() {
                    return Err("missing value for --runtime".to_string());
                }
                runtime_selection = parse_runtime_selection(value)?;
                index += 1;
            }
            _ if arg.starts_with("--dashboard-port=") => {
                let value = arg.trim_start_matches("--dashboard-port=");
                if value.is_empty() {
                    return Err("missing value for --dashboard-port".to_string());
                }
                dashboard.port = parse_dashboard_port(value)?;
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
        runtime_selection,
        dashboard,
        intelligence,
        command,
        session_record: None,
        extra_env: Vec::new(),
    }))
}

fn parse_demo_args(args: &[String]) -> Result<ParseOutcome, String> {
    let mut example_name = None;
    let mut list_examples = false;
    let mut log_enable = false;
    let mut emit_mode = EmitMode::Raw;
    let mut transport_mode = TransportMode::Bpftrace;
    let mut dashboard = DashboardOptions::default();
    let mut intelligence = IntelligenceOptions::default();
    let mut index = 0usize;

    while index < args.len() {
        if parse_intelligence_arg(args, &mut index, &mut intelligence)? {
            continue;
        }

        let arg = &args[index];
        match arg.as_str() {
            "-h" | "--help" => return Ok(ParseOutcome::Help),
            "--list" => {
                list_examples = true;
                index += 1;
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
            "--dashboard" => {
                dashboard.enabled = true;
                index += 1;
            }
            "--dashboard-port" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "missing value for --dashboard-port".to_string())?;
                dashboard.port = parse_dashboard_port(value)?;
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
            _ if arg.starts_with("--dashboard-port=") => {
                let value = arg.trim_start_matches("--dashboard-port=");
                if value.is_empty() {
                    return Err("missing value for --dashboard-port".to_string());
                }
                dashboard.port = parse_dashboard_port(value)?;
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
        log_enable,
        emit_mode,
        transport_mode,
        dashboard,
        intelligence,
    }))
}

fn parse_see_args(args: &[String]) -> Result<ParseOutcome, String> {
    let mut example_name = None;
    let mut dashboard = DashboardOptions {
        enabled: true,
        port: DEFAULT_DASHBOARD_PORT,
    };
    let mut intelligence = IntelligenceOptions::default();
    let mut index = 0usize;

    while index < args.len() {
        if parse_intelligence_arg(args, &mut index, &mut intelligence)? {
            continue;
        }

        let arg = &args[index];
        match arg.as_str() {
            "-h" | "--help" => return Ok(ParseOutcome::Help),
            "--port" | "--dashboard-port" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| format!("missing value for {arg}"))?;
                dashboard.port = parse_dashboard_port(value)?;
                index += 2;
            }
            _ if arg.starts_with("--port=") => {
                let value = arg.trim_start_matches("--port=");
                if value.is_empty() {
                    return Err("missing value for --port".to_string());
                }
                dashboard.port = parse_dashboard_port(value)?;
                index += 1;
            }
            _ if arg.starts_with("--dashboard-port=") => {
                let value = arg.trim_start_matches("--dashboard-port=");
                if value.is_empty() {
                    return Err("missing value for --dashboard-port".to_string());
                }
                dashboard.port = parse_dashboard_port(value)?;
                index += 1;
            }
            _ if arg.starts_with('-') => return Err(format!("unknown see flag: {arg}")),
            _ if example_name.is_none() => {
                example_name = Some(arg.clone());
                index += 1;
            }
            _ => return Err("see accepts at most one example name".to_string()),
        }
    }

    Ok(ParseOutcome::Demo(DemoArgs {
        example_name,
        list_examples: false,
        log_enable: true,
        emit_mode: EmitMode::Jsonl,
        transport_mode: TransportMode::Bpftrace,
        dashboard,
        intelligence,
    }))
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

struct ResolvedRunPlan {
    runtime_profile: RuntimeProfile,
    runtime_resolution: RuntimeAssetResolution,
    runtime_override: Option<PathBuf>,
    probe_file: Option<String>,
    perf_events: Option<String>,
}

impl ResolvedRunPlan {
    fn resolve(cli_args: &CliArgs, project_dir: &Path) -> Result<Self, String> {
        let runtime_profile =
            resolve_runtime_profile(cli_args.runtime_selection, &cli_args.command);
        let config = resolve_tracker_config(cli_args.config_path.as_deref(), project_dir)?;
        let runtime_resolution = resolve_compose_file_with_source(runtime_profile)?;
        let runtime_override =
            resolve_runtime_override(config.as_ref(), &runtime_resolution.compose_file)?;
        let (probe_file, perf_events) = match cli_args.transport_mode {
            TransportMode::Bpftrace => (
                Some(resolve_probe_file(
                    cli_args,
                    config.as_ref(),
                    &runtime_resolution.compose_file,
                )?),
                None,
            ),
            TransportMode::Perf => (None, Some(resolve_perf_events(cli_args, config.as_ref())?)),
        };

        Ok(Self {
            runtime_profile,
            runtime_resolution,
            runtime_override,
            probe_file,
            perf_events,
        })
    }

    fn build_command(&self, cli_args: &CliArgs, project_dir: &Path) -> Command {
        build_compose_command(ComposeRunConfig {
            compose_file: &self.runtime_resolution.compose_file,
            runtime_override_file: self.runtime_override.as_deref(),
            project_dir,
            runtime_profile: self.runtime_profile,
            transport_mode: cli_args.transport_mode,
            extra_env: &cli_args.extra_env,
            probe_file: self.probe_file.as_deref(),
            perf_events: self.perf_events.as_deref(),
            wrapped_command: &cli_args.command,
        })
    }

    fn maybe_report_runtime_assets(&self) {
        if should_report_runtime_resolution(&self.runtime_resolution.source) {
            eprintln!("runtime assets: {}", self.runtime_resolution.description());
        }
    }
}

fn should_report_runtime_resolution(source: &RuntimeAssetSource) -> bool {
    matches!(
        source,
        RuntimeAssetSource::EnvironmentOverride(_) | RuntimeAssetSource::EmbeddedRuntime { .. }
    )
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

fn current_timestamp_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn append_log_bytes(log_file: &Arc<Mutex<File>>, bytes: &[u8]) -> io::Result<()> {
    let mut file = log_file
        .lock()
        .map_err(|_| io::Error::other("log file lock poisoned"))?;
    file.write_all(bytes)?;
    file.flush()?;
    Ok(())
}

fn append_stream_record(log_file: &Arc<Mutex<File>>, record: &StreamRecord) -> io::Result<()> {
    let serialized =
        serde_json::to_string(record).map_err(|err| io::Error::other(err.to_string()))?;
    append_log_bytes(log_file, serialized.as_bytes())?;
    append_log_bytes(log_file, b"\n")?;
    Ok(())
}

fn trim_line_endings(bytes: &[u8]) -> &[u8] {
    let mut end = bytes.len();
    while end > 0 && matches!(bytes[end - 1], b'\n' | b'\r') {
        end -= 1;
    }
    &bytes[..end]
}

fn stream_record_for_bytes(
    line_bytes: &[u8],
    transport_mode: TransportMode,
) -> Option<StreamRecord> {
    let trimmed = trim_line_endings(line_bytes);
    let text = String::from_utf8_lossy(trimmed);

    match transport_mode {
        TransportMode::Bpftrace => stream_record_for_line(&text),
        TransportMode::Perf => stream_record_for_perf_trace_line(&text),
    }
}

fn forward_passthrough_bytes(bytes: &[u8], terminal_lock: &Arc<Mutex<()>>) -> io::Result<()> {
    let _terminal = terminal_lock
        .lock()
        .map_err(|_| io::Error::other("terminal lock poisoned"))?;
    let mut stderr = io::stderr();
    stderr.write_all(bytes)?;
    stderr.flush()?;
    Ok(())
}

fn process_jsonl_line_bytes(
    line_bytes: &[u8],
    log_file: Option<&Arc<Mutex<File>>>,
    terminal_lock: &Arc<Mutex<()>>,
    transport_mode: TransportMode,
    intelligence: Option<&IntelligenceReporter>,
    summary: &mut JsonlCopySummary,
) -> io::Result<()> {
    if let Some(record) = stream_record_for_bytes(line_bytes, transport_mode) {
        if let Some(log_file) = log_file {
            append_stream_record(log_file, &record)?;
        }
        if transport_mode == TransportMode::Perf {
            summary.perf_session.observe(&record);
        }
        if let Some(intelligence) = intelligence {
            intelligence.observe(&record);
        }
        emit_stream_record(&record, terminal_lock)?;
    } else {
        if let Some(log_file) = log_file {
            append_log_bytes(log_file, line_bytes)?;
        }
        forward_passthrough_bytes(line_bytes, terminal_lock)?;
    }

    Ok(())
}

#[derive(Default)]
struct JsonlCopySummary {
    perf_session: PerfTraceSession,
}

#[derive(Clone, Copy)]
enum TerminalTarget {
    Stdout,
    Stderr,
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

fn emit_initial_stream_record(
    record: &StreamRecord,
    log_file: Option<&Arc<Mutex<File>>>,
    terminal_lock: &Arc<Mutex<()>>,
) -> io::Result<()> {
    emit_stream_record(record, terminal_lock)?;

    if let Some(log_file) = log_file {
        let serialized =
            serde_json::to_string(record).map_err(|err| io::Error::other(err.to_string()))?;
        append_log_bytes(log_file, serialized.as_bytes())?;
        append_log_bytes(log_file, b"\n")?;
    }

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
    intelligence: Option<IntelligenceReporter>,
) -> io::Result<JsonlCopySummary> {
    let mut reader = BufReader::new(reader);
    let mut buffer = [0u8; 16 * 1024];
    let mut pending = Vec::new();
    let mut summary = JsonlCopySummary::default();

    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }

        pending.extend_from_slice(&buffer[..read]);

        while let Some(newline_index) = pending.iter().position(|byte| *byte == b'\n') {
            let line: Vec<u8> = pending.drain(..=newline_index).collect();
            process_jsonl_line_bytes(
                &line,
                log_file.as_ref(),
                &terminal_lock,
                transport_mode,
                intelligence.as_ref(),
                &mut summary,
            )?;
        }
    }

    if !pending.is_empty() {
        process_jsonl_line_bytes(
            &pending,
            log_file.as_ref(),
            &terminal_lock,
            transport_mode,
            intelligence.as_ref(),
            &mut summary,
        )?;
    }

    Ok(summary)
}

fn forward_terminal_bytes(
    bytes: &[u8],
    terminal_lock: &Arc<Mutex<()>>,
    target: TerminalTarget,
) -> io::Result<()> {
    let _terminal = terminal_lock
        .lock()
        .map_err(|_| io::Error::other("terminal lock poisoned"))?;

    match target {
        TerminalTarget::Stdout => {
            let mut stdout = io::stdout();
            stdout.write_all(bytes)?;
            stdout.flush()?;
        }
        TerminalTarget::Stderr => {
            let mut stderr = io::stderr();
            stderr.write_all(bytes)?;
            stderr.flush()?;
        }
    }

    Ok(())
}

fn copy_stream_passthrough<R: Read>(
    reader: R,
    log_file: Option<Arc<Mutex<File>>>,
    terminal_lock: Arc<Mutex<()>>,
    terminal_target: TerminalTarget,
    transport_mode: TransportMode,
    intelligence: Option<IntelligenceReporter>,
) -> io::Result<()> {
    let mut reader = BufReader::new(reader);
    let mut buffer = [0u8; 16 * 1024];
    let mut pending = Vec::new();

    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }

        let chunk = &buffer[..read];
        forward_terminal_bytes(chunk, &terminal_lock, terminal_target)?;
        if let Some(log_file) = log_file.as_ref() {
            append_log_bytes(log_file, chunk)?;
        }

        pending.extend_from_slice(chunk);
        while let Some(newline_index) = pending.iter().position(|byte| *byte == b'\n') {
            let line: Vec<u8> = pending.drain(..=newline_index).collect();
            if let Some(record) = stream_record_for_bytes(&line, transport_mode) {
                if let Some(intelligence) = intelligence.as_ref() {
                    intelligence.observe(&record);
                }
            }
        }
    }

    if !pending.is_empty() {
        if let Some(record) = stream_record_for_bytes(&pending, transport_mode) {
            if let Some(intelligence) = intelligence.as_ref() {
                intelligence.observe(&record);
            }
        }
    }

    Ok(())
}

fn run_with_jsonl(
    mut command: Command,
    project_dir: &Path,
    log_enable: bool,
    transport_mode: TransportMode,
    initial_record: Option<&StreamRecord>,
    cli_args: &CliArgs,
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
    let intelligence = match IntelligenceSupervisor::start(&cli_args.intelligence, cli_args) {
        Ok(supervisor) => supervisor,
        Err(err) => {
            eprintln!("intelligence disabled: {err}");
            None
        }
    };

    if let Some(record) = initial_record {
        emit_initial_stream_record(record, log_file.as_ref(), &terminal_lock)
            .map_err(|err| format!("failed to emit session metadata: {err}"))?;
        if let Some(reporter) = intelligence.as_ref().map(IntelligenceSupervisor::reporter) {
            reporter.observe(record);
        }
    }

    let out_log = log_file.as_ref().map(Arc::clone);
    let out_terminal = Arc::clone(&terminal_lock);
    let out_intelligence = intelligence.as_ref().map(IntelligenceSupervisor::reporter);
    let out_handle = thread::spawn(move || {
        copy_stream_jsonl(
            stdout,
            out_log,
            out_terminal,
            transport_mode,
            out_intelligence,
        )
    });

    let err_log = log_file.as_ref().map(Arc::clone);
    let err_terminal = Arc::clone(&terminal_lock);
    let err_handle = if interactive_pty_enabled() {
        thread::spawn(move || {
            copy_stream_passthrough(
                stderr,
                err_log,
                err_terminal,
                TerminalTarget::Stderr,
                transport_mode,
                None,
            )
            .map(|_| JsonlCopySummary::default())
        })
    } else {
        let err_intelligence = intelligence.as_ref().map(IntelligenceSupervisor::reporter);
        thread::spawn(move || {
            copy_stream_jsonl(
                stderr,
                err_log,
                err_terminal,
                transport_mode,
                err_intelligence,
            )
        })
    };

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
                if let Some(reporter) = intelligence.as_ref().map(IntelligenceSupervisor::reporter)
                {
                    reporter.observe(&record);
                }
            }
        }
    }

    if let Some(intelligence) = intelligence {
        if let Err(err) = intelligence.finish(exit_code(&status), exit_signal_label(&status)) {
            eprintln!("intelligence job failed: {err}");
        }
    }

    Ok(exit_code(&status))
}

fn run_with_raw_capture(
    mut command: Command,
    project_dir: &Path,
    log_enable: bool,
    transport_mode: TransportMode,
    initial_record: Option<&StreamRecord>,
    cli_args: &CliArgs,
) -> Result<i32, String> {
    let log_file = if log_enable {
        let (log_file, log_file_path) = create_log_file(project_dir)?;
        eprintln!("logging enabled: {}", log_file_path.display());
        Some(log_file)
    } else {
        None
    };

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

    let terminal_lock = Arc::new(Mutex::new(()));
    let intelligence = match IntelligenceSupervisor::start(&cli_args.intelligence, cli_args) {
        Ok(supervisor) => supervisor,
        Err(err) => {
            eprintln!("intelligence disabled: {err}");
            None
        }
    };

    if let Some(record) = initial_record {
        if let Some(reporter) = intelligence.as_ref().map(IntelligenceSupervisor::reporter) {
            reporter.observe(record);
        }
    }

    let out_log = log_file.as_ref().map(Arc::clone);
    let out_terminal = Arc::clone(&terminal_lock);
    let out_intelligence = intelligence.as_ref().map(IntelligenceSupervisor::reporter);
    let out_handle = thread::spawn(move || {
        copy_stream_passthrough(
            stdout,
            out_log,
            out_terminal,
            TerminalTarget::Stdout,
            transport_mode,
            out_intelligence,
        )
    });

    let err_log = log_file.as_ref().map(Arc::clone);
    let err_terminal = Arc::clone(&terminal_lock);
    let err_intelligence = intelligence.as_ref().map(IntelligenceSupervisor::reporter);
    let err_handle = thread::spawn(move || {
        copy_stream_passthrough(
            stderr,
            err_log,
            err_terminal,
            TerminalTarget::Stderr,
            transport_mode,
            err_intelligence,
        )
    });

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

    if let Some(intelligence) = intelligence {
        if let Err(err) = intelligence.finish(exit_code(&status), exit_signal_label(&status)) {
            eprintln!("intelligence job failed: {err}");
        }
    }

    Ok(exit_code(&status))
}

fn exit_signal_label(status: &ExitStatus) -> Option<String> {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        return status.signal().map(|signal| format!("signal-{signal}"));
    }

    #[allow(unreachable_code)]
    None
}

fn exit_code(status: &ExitStatus) -> i32 {
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
    Ok(exit_code(&status))
}

fn interactive_pty_enabled() -> bool {
    matches!(std::env::var(INTERACTIVE_PTY_ENV_NAME).as_deref(), Ok("1"))
}

fn is_repo_root(candidate: &Path) -> bool {
    let manifest = candidate.join("Cargo.toml");
    let main_rs = candidate.join("src").join("main.rs");
    let examples = candidate.join(EXAMPLES_DIR_NAME);
    manifest.is_file() && main_rs.is_file() && examples.is_dir()
}

fn find_repo_root(start_dir: &Path) -> Option<PathBuf> {
    for ancestor in start_dir.ancestors() {
        if is_repo_root(ancestor) {
            return Some(ancestor.to_path_buf());
        }
    }
    None
}

fn repo_root_from(start_dir: &Path) -> Result<PathBuf, String> {
    if let Some(repo_root) = find_repo_root(start_dir) {
        return Ok(repo_root);
    }

    if let Ok(exe) = env::current_exe() {
        if let Some(repo_root) = find_repo_root(&exe) {
            return Ok(repo_root);
        }
    }

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    if is_repo_root(&manifest_dir) {
        return Ok(manifest_dir);
    }

    Err(
        "demo mode requires a local ebpf-tracker checkout or a repo-built ebpf-tracker binary"
            .to_string(),
    )
}

fn demo_manifest_path(example_dir: &Path) -> PathBuf {
    example_dir.join(DEMO_MANIFEST_FILE_NAME)
}

fn load_demo_manifest(example_dir: &Path) -> Result<DemoManifest, String> {
    let manifest_path = demo_manifest_path(example_dir);
    let content = fs::read_to_string(&manifest_path)
        .map_err(|err| format!("failed to read {}: {err}", manifest_path.display()))?;
    let parsed: DemoManifestFile = toml::from_str(&content)
        .map_err(|err| format!("failed to parse {}: {err}", manifest_path.display()))?;

    if parsed.command.is_empty() {
        return Err(format!(
            "{} must define a non-empty command",
            manifest_path.display()
        ));
    }

    if parsed
        .clean
        .as_ref()
        .is_some_and(|command| command.is_empty())
    {
        return Err(format!(
            "{} must not define an empty clean command",
            manifest_path.display()
        ));
    }

    Ok(DemoManifest {
        runtime_selection: parse_runtime_selection(&parsed.runtime)?,
        command: parsed.command,
        clean_command: parsed.clean,
        branding: DemoBranding {
            product_name: parsed.product_name,
            product_tagline: parsed.product_tagline,
            sponsor_name: parsed.sponsor_name,
            sponsor_message: parsed.sponsor_message,
            sponsor_url: parsed.sponsor_url,
        },
    })
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
        if path.is_dir() && demo_manifest_path(&path).is_file() {
            examples.push(entry.file_name().to_string_lossy().to_string());
        }
    }

    examples.sort();
    Ok(examples)
}

fn resolve_example_dir(repo_root: &Path, example_name: &str) -> Result<PathBuf, String> {
    let example_dir = repo_root.join(EXAMPLES_DIR_NAME).join(example_name);
    if demo_manifest_path(&example_dir).is_file() {
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

fn clean_example(example_dir: &Path, clean_command: Option<&[String]>) -> Result<(), String> {
    let Some(clean_command) = clean_command else {
        return Ok(());
    };
    let Some(program) = clean_command.first() else {
        return Ok(());
    };

    let status = Command::new(program)
        .args(&clean_command[1..])
        .current_dir(example_dir)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|err| {
            format!(
                "failed to run clean command in {}: {err}",
                example_dir.display()
            )
        })?;

    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "clean command failed in {} with exit code {}",
            example_dir.display(),
            exit_code(&status)
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
    let manifest = load_demo_manifest(&example_dir)?;
    let session_record = manifest.branding.session_record(&example_name);
    let extra_env = manifest.branding.extra_env(&example_name);

    eprintln!("Running example: {example_name}");
    clean_example(&example_dir, manifest.clean_command.as_deref())?;

    run_cli(
        CliArgs {
            probe_file: None,
            config_path: Some(PathBuf::from(DEFAULT_CONFIG_FILE_NAME)),
            log_enable: demo_args.log_enable,
            emit_mode: demo_args.emit_mode,
            transport_mode: demo_args.transport_mode,
            runtime_selection: manifest.runtime_selection,
            dashboard: DashboardOptions::default(),
            intelligence: demo_args.intelligence,
            command: manifest.command,
            session_record,
            extra_env,
        },
        example_dir,
    )
}

fn run_cli(cli_args: CliArgs, project_dir: PathBuf) -> Result<i32, String> {
    let run_plan = ResolvedRunPlan::resolve(&cli_args, &project_dir)?;
    run_plan.maybe_report_runtime_assets();
    let command = run_plan.build_command(&cli_args, &project_dir);

    if cli_args.emit_mode == EmitMode::Jsonl {
        run_with_jsonl(
            command,
            &project_dir,
            cli_args.log_enable,
            cli_args.transport_mode,
            cli_args.session_record.as_ref(),
            &cli_args,
        )
    } else if cli_args.log_enable || cli_args.intelligence.enabled {
        run_with_raw_capture(
            command,
            &project_dir,
            cli_args.log_enable,
            cli_args.transport_mode,
            cli_args.session_record.as_ref(),
            &cli_args,
        )
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
        ParseOutcome::Attach(attach_args) => run_attach(attach_args),
        ParseOutcome::Demo(demo_args) => {
            if demo_args.dashboard.enabled {
                if demo_args.list_examples {
                    return Err("--dashboard is not supported with demo --list".to_string());
                }
                let current_dir = env::current_dir()
                    .map_err(|err| format!("failed to read current dir: {err}"))?;
                run_with_dashboard(
                    demo_args.dashboard,
                    build_demo_args_for_dashboard(&demo_args),
                    &current_dir,
                    demo_args.emit_mode,
                )
            } else {
                run_demo(demo_args)
            }
        }
        ParseOutcome::Run(cli_args) => {
            let project_dir =
                env::current_dir().map_err(|err| format!("failed to read current dir: {err}"))?;
            if cli_args.dashboard.enabled {
                run_with_dashboard(
                    cli_args.dashboard,
                    build_tracker_args_for_dashboard(&cli_args),
                    &project_dir,
                    cli_args.emit_mode,
                )
            } else {
                run_cli(cli_args, project_dir)
            }
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
    use super::{
        build_demo_args_for_dashboard, build_generated_probe, build_runtime_override,
        build_tracker_args_for_dashboard, load_config, load_demo_manifest, parse_args,
        repo_root_from, should_report_runtime_resolution, stream_record_for_bytes, CliArgs,
        DashboardOptions, EmitMode, IntelligenceOptions, ParseOutcome, ResolvedRunPlan,
        RuntimeConfig, TransportMode, DEFAULT_DASHBOARD_PORT,
    };
    use crate::attach::{AttachBackend, AttachPlatform};
    use crate::dashboard::parse_dashboard_url;
    use crate::runtime::{RuntimeAssetSource, RuntimeSelection};
    use ebpf_tracker_events::StreamRecord;
    use std::fs;
    use std::path::{Path, PathBuf};
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

    #[test]
    fn demo_manifest_parses_runtime_and_command() {
        let temp_dir = unique_temp_dir("ebpf-demo-manifest");
        fs::create_dir_all(&temp_dir).expect("temp dir should be created");
        fs::write(
            temp_dir.join("ebpf-demo.toml"),
            "runtime = \"node\"\ncommand = [\"npm\", \"run\", \"generate\"]\n",
        )
        .expect("manifest should be written");

        let manifest = load_demo_manifest(&temp_dir).expect("manifest should load");
        assert_eq!(manifest.runtime_selection, RuntimeSelection::Node);
        assert_eq!(
            manifest.command,
            vec!["npm".to_string(), "run".to_string(), "generate".to_string()]
        );
        assert!(manifest.clean_command.is_none());
        assert!(manifest.branding.is_empty());

        let _ = fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn demo_manifest_parses_branding_metadata() {
        let temp_dir = unique_temp_dir("ebpf-demo-branding");
        fs::create_dir_all(&temp_dir).expect("temp dir should be created");
        fs::write(
            temp_dir.join("ebpf-demo.toml"),
            concat!(
                "runtime = \"rust\"\n",
                "command = [\"cargo\", \"run\"]\n",
                "product_name = \"ebpf-tracker\"\n",
                "product_tagline = \"Trace the full command session\"\n",
                "sponsor_name = \"ebpf-tracker\"\n",
                "sponsor_message = \"Replayable syscall demos\"\n",
                "sponsor_url = \"https://github.com/givtaj/ebpf-tracker\"\n"
            ),
        )
        .expect("manifest should be written");

        let manifest = load_demo_manifest(&temp_dir).expect("manifest should load");
        assert_eq!(
            manifest.branding.product_name.as_deref(),
            Some("ebpf-tracker")
        );
        assert_eq!(
            manifest.branding.product_tagline.as_deref(),
            Some("Trace the full command session")
        );
        assert_eq!(
            manifest.branding.sponsor_name.as_deref(),
            Some("ebpf-tracker")
        );

        let _ = fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn demo_manifest_rejects_empty_command() {
        let temp_dir = unique_temp_dir("ebpf-demo-empty-command");
        fs::create_dir_all(&temp_dir).expect("temp dir should be created");
        fs::write(
            temp_dir.join("ebpf-demo.toml"),
            "runtime = \"rust\"\ncommand = []\n",
        )
        .expect("manifest should be written");

        let error = load_demo_manifest(&temp_dir).expect_err("manifest should fail");
        assert!(error.contains("non-empty command"));

        let _ = fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn cli_args_parse_runtime_selection_before_command() {
        let parsed = parse_args(vec![
            "--runtime".to_string(),
            "node".to_string(),
            "npm".to_string(),
            "test".to_string(),
        ])
        .expect("args should parse");

        match parsed {
            ParseOutcome::Run(cli_args) => {
                assert_eq!(cli_args.runtime_selection, RuntimeSelection::Node);
                assert_eq!(
                    cli_args.command,
                    vec!["npm".to_string(), "test".to_string()]
                );
            }
            _ => panic!("expected run outcome"),
        }
    }

    #[test]
    fn cli_args_parse_runtime_selection_equals_form() {
        let parsed = parse_args(vec![
            "--runtime=node".to_string(),
            "node".to_string(),
            "script.js".to_string(),
        ])
        .expect("args should parse");

        match parsed {
            ParseOutcome::Run(cli_args) => {
                assert_eq!(cli_args.runtime_selection, RuntimeSelection::Node);
                assert_eq!(
                    cli_args.command,
                    vec!["node".to_string(), "script.js".to_string()]
                );
            }
            _ => panic!("expected run outcome"),
        }
    }

    #[test]
    fn cli_args_parse_dashboard_options() {
        let parsed = parse_args(vec![
            "--dashboard".to_string(),
            "--dashboard-port=44000".to_string(),
            "cargo".to_string(),
            "run".to_string(),
        ])
        .expect("args should parse");

        match parsed {
            ParseOutcome::Run(cli_args) => {
                assert_eq!(
                    cli_args.dashboard,
                    DashboardOptions {
                        enabled: true,
                        port: 44000
                    }
                );
            }
            _ => panic!("expected run outcome"),
        }
    }

    #[test]
    fn attach_args_parse_platform_and_backend() {
        let parsed = parse_args(vec![
            "attach".to_string(),
            "aws-eks".to_string(),
            "--backend=tetragon".to_string(),
            "--cluster=prod-cluster".to_string(),
            "--selector=app=payments".to_string(),
        ])
        .expect("args should parse");

        match parsed {
            ParseOutcome::Attach(attach_args) => {
                assert_eq!(attach_args.platform, AttachPlatform::AwsEks);
                assert_eq!(attach_args.backend, AttachBackend::Tetragon);
                assert_eq!(attach_args.cluster.as_deref(), Some("prod-cluster"));
                assert_eq!(attach_args.selector.as_deref(), Some("app=payments"));
            }
            _ => panic!("expected attach outcome"),
        }
    }

    #[test]
    fn cli_args_parse_intelligence_options() {
        let parsed = parse_args(vec![
            "--intelligence-dataset".to_string(),
            "--intelligence-model".to_string(),
            "qwen/qwen3.5-9b".to_string(),
            "cargo".to_string(),
            "run".to_string(),
        ])
        .expect("args should parse");

        match parsed {
            ParseOutcome::Run(cli_args) => {
                assert!(cli_args.intelligence.enabled);
                assert_eq!(
                    cli_args.intelligence.model.as_deref(),
                    Some("qwen/qwen3.5-9b")
                );
            }
            _ => panic!("expected run outcome"),
        }
    }

    #[test]
    fn demo_args_parse_dashboard_options() {
        let parsed = parse_args(vec![
            "demo".to_string(),
            "--log-enable".to_string(),
            "--dashboard".to_string(),
            "--dashboard-port".to_string(),
            "44001".to_string(),
            "session-io-demo".to_string(),
        ])
        .expect("args should parse");

        match parsed {
            ParseOutcome::Demo(demo_args) => {
                assert!(demo_args.log_enable);
                assert_eq!(
                    demo_args.dashboard,
                    DashboardOptions {
                        enabled: true,
                        port: 44001
                    }
                );
            }
            _ => panic!("expected demo outcome"),
        }
    }

    #[test]
    fn see_args_use_dashboard_demo_defaults() {
        let parsed = parse_args(vec!["see".to_string()]).expect("args should parse");

        match parsed {
            ParseOutcome::Demo(demo_args) => {
                assert_eq!(demo_args.example_name, None);
                assert!(demo_args.log_enable);
                assert_eq!(demo_args.emit_mode, EmitMode::Jsonl);
                assert_eq!(demo_args.transport_mode, TransportMode::Bpftrace);
                assert_eq!(
                    demo_args.dashboard,
                    DashboardOptions {
                        enabled: true,
                        port: DEFAULT_DASHBOARD_PORT
                    }
                );
            }
            _ => panic!("expected demo outcome"),
        }
    }

    #[test]
    fn see_args_accept_example_name_and_port_alias() {
        let parsed = parse_args(vec![
            "see".to_string(),
            "--port=44002".to_string(),
            "postcard-generator-rust".to_string(),
        ])
        .expect("args should parse");

        match parsed {
            ParseOutcome::Demo(demo_args) => {
                assert_eq!(
                    demo_args.example_name,
                    Some("postcard-generator-rust".to_string())
                );
                assert_eq!(
                    demo_args.dashboard,
                    DashboardOptions {
                        enabled: true,
                        port: 44002
                    }
                );
            }
            _ => panic!("expected demo outcome"),
        }
    }

    #[test]
    fn dashboard_tracker_args_force_jsonl_and_preserve_command() {
        let args = build_tracker_args_for_dashboard(&super::CliArgs {
            probe_file: Some("/probes/custom.bt".to_string()),
            config_path: Some(Path::new("ebpf-tracker.toml").to_path_buf()),
            log_enable: true,
            emit_mode: EmitMode::Raw,
            transport_mode: TransportMode::Perf,
            runtime_selection: RuntimeSelection::Node,
            dashboard: DashboardOptions {
                enabled: true,
                port: DEFAULT_DASHBOARD_PORT,
            },
            intelligence: IntelligenceOptions::default(),
            command: vec!["npm".to_string(), "test".to_string()],
            session_record: None,
            extra_env: Vec::new(),
        });

        assert_eq!(
            args,
            vec![
                "--probe",
                "/probes/custom.bt",
                "--config",
                "ebpf-tracker.toml",
                "--log-enable",
                "--emit",
                "jsonl",
                "--transport",
                "perf",
                "--runtime",
                "node",
                "--",
                "npm",
                "test",
            ]
        );
    }

    #[test]
    fn dashboard_demo_args_force_jsonl_after_demo_subcommand() {
        let args = build_demo_args_for_dashboard(&super::DemoArgs {
            example_name: Some("session-io-demo".to_string()),
            list_examples: false,
            log_enable: false,
            emit_mode: EmitMode::Raw,
            transport_mode: TransportMode::Perf,
            dashboard: DashboardOptions {
                enabled: true,
                port: DEFAULT_DASHBOARD_PORT,
            },
            intelligence: IntelligenceOptions::default(),
        });

        assert_eq!(
            args,
            vec![
                "demo",
                "--log-enable",
                "--emit",
                "jsonl",
                "--transport",
                "perf",
                "session-io-demo",
            ]
        );
    }

    #[test]
    fn dashboard_demo_args_append_intelligence_flags() {
        let args = build_demo_args_for_dashboard(&super::DemoArgs {
            example_name: Some("session-io-demo".to_string()),
            list_examples: false,
            log_enable: false,
            emit_mode: EmitMode::Raw,
            transport_mode: TransportMode::Bpftrace,
            dashboard: DashboardOptions {
                enabled: true,
                port: DEFAULT_DASHBOARD_PORT,
            },
            intelligence: IntelligenceOptions {
                enabled: true,
                model: Some("qwen/qwen3.5-9b".to_string()),
                ..IntelligenceOptions::default()
            },
        });

        assert!(args.contains(&"--intelligence-dataset".to_string()));
        assert!(args.contains(&"--intelligence-model".to_string()));
        assert!(args.contains(&"qwen/qwen3.5-9b".to_string()));
    }

    #[test]
    fn dashboard_url_parser_extracts_viewer_address() {
        assert_eq!(
            parse_dashboard_url("live trace viewer on http://127.0.0.1:43115\n"),
            Some("http://127.0.0.1:43115")
        );
    }

    #[test]
    fn repo_root_can_be_resolved_from_outside_repo_for_repo_built_binary() {
        let temp_dir = unique_temp_dir("ebpf-demo-outside-repo");
        fs::create_dir_all(&temp_dir).expect("temp dir should be created");

        let repo_root =
            repo_root_from(&temp_dir).expect("repo-built binaries should resolve the repo root");
        assert_eq!(repo_root, PathBuf::from(env!("CARGO_MANIFEST_DIR")));

        let _ = fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn invalid_utf8_stream_bytes_do_not_abort_jsonl_parsing() {
        let record = stream_record_for_bytes(b"\xff\xfe\xfd\n", TransportMode::Perf);
        assert!(record.is_none());
    }

    #[test]
    fn ascii_stream_bytes_still_parse_into_records() {
        let record = stream_record_for_bytes(
            b"write comm=payments_engine pid=42 bytes=512\n",
            TransportMode::Bpftrace,
        )
        .expect("ascii event line should parse");

        match record {
            StreamRecord::Syscall {
                comm, bytes, pid, ..
            } => {
                assert_eq!(comm, "payments_engine");
                assert_eq!(pid, 42);
                assert_eq!(bytes, Some(512));
            }
            _ => panic!("expected syscall record"),
        }
    }

    #[test]
    fn runtime_resolution_reporting_is_limited_to_non_default_sources() {
        assert!(should_report_runtime_resolution(
            &RuntimeAssetSource::EnvironmentOverride(PathBuf::from("/tmp/custom.yml"))
        ));
        assert!(should_report_runtime_resolution(
            &RuntimeAssetSource::EmbeddedRuntime {
                cache_root: PathBuf::from("/tmp/cache")
            }
        ));
        assert!(!should_report_runtime_resolution(
            &RuntimeAssetSource::CurrentDir(PathBuf::from("/tmp/project/docker-compose.yml"))
        ));
        assert!(!should_report_runtime_resolution(
            &RuntimeAssetSource::ExecutableAncestor(PathBuf::from("/tmp/bin/docker-compose.yml"))
        ));
    }

    #[test]
    fn resolved_run_plan_uses_environment_override_source() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic")
            .as_nanos();
        let temp_dir = Path::new("/tmp").join(format!("ebpf-run-plan-{unique}"));
        fs::create_dir_all(&temp_dir).expect("temp dir should be created");
        let compose_file = temp_dir.join("docker-compose.bpftrace.yml");
        fs::write(
            &compose_file,
            "services:\n  bpftrace:\n    image: example\n",
        )
        .expect("compose file should be written");

        let original_compose = std::env::var_os("EBPF_TRACKER_COMPOSE_FILE");
        std::env::set_var("EBPF_TRACKER_COMPOSE_FILE", &compose_file);

        let run_plan = ResolvedRunPlan::resolve(
            &CliArgs {
                probe_file: None,
                config_path: None,
                log_enable: false,
                emit_mode: EmitMode::Raw,
                transport_mode: TransportMode::Bpftrace,
                runtime_selection: RuntimeSelection::Rust,
                dashboard: DashboardOptions::default(),
                intelligence: IntelligenceOptions::default(),
                command: vec!["cargo".to_string(), "run".to_string()],
                session_record: None,
                extra_env: Vec::new(),
            },
            &temp_dir,
        )
        .expect("run plan should resolve");

        assert_eq!(
            run_plan.runtime_resolution.source,
            RuntimeAssetSource::EnvironmentOverride(compose_file.clone())
        );
        assert_eq!(run_plan.runtime_resolution.compose_file, compose_file);

        if let Some(original_compose) = original_compose {
            std::env::set_var("EBPF_TRACKER_COMPOSE_FILE", original_compose);
        } else {
            std::env::remove_var("EBPF_TRACKER_COMPOSE_FILE");
        }
        let _ = fs::remove_dir_all(temp_dir);
    }

    fn unique_temp_dir(prefix: &str) -> std::path::PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic")
            .as_nanos();
        Path::new("/tmp").join(format!("{prefix}-{unique}"))
    }
}
