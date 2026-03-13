use std::env;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{self, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;

const DEFAULT_PROBE: &str = "/probes/execve.bt";
const COMPOSE_FILE_NAME: &str = "docker-compose.bpftrace.yml";
const DEFAULT_CONFIG_FILE_NAME: &str = "ebpf-tracker.toml";
const GENERATED_CONFIG_PROBE_FILE_NAME: &str = "generated-config.bt";
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
    command: Vec<String>,
}

enum ParseOutcome {
    Help,
    Run(CliArgs),
}

#[derive(Debug, Default, Deserialize)]
struct TrackerConfig {
    #[serde(default)]
    probe: ProbeConfig,
}

#[derive(Debug, Default, Deserialize)]
struct ProbeConfig {
    exec: Option<bool>,
    write: Option<bool>,
    open: Option<bool>,
    connect: Option<bool>,
}

fn print_usage() {
    eprintln!(
        "Usage: eBPF_tracker [--probe <file-or-name>] [--config <path>] [--log-enable] <command> [args...]"
    );
    eprintln!("Example: eBPF_tracker cargo run");
    eprintln!("Example: eBPF_tracker --config ebpf-tracker.toml cargo run");
    eprintln!("Example: eBPF_tracker --probe execve.bt cargo run");
    eprintln!("Example: eBPF_tracker --probe ./probes/custom.bt cargo run");
    eprintln!("Example: eBPF_tracker --log-enable cargo test");
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

fn parse_args(args: Vec<String>) -> Result<ParseOutcome, String> {
    let mut probe_file = None;
    let mut config_path = None;
    let mut log_enable = false;
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
        command,
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

fn resolve_probe_file(cli_args: &CliArgs, project_dir: &Path) -> Result<(PathBuf, String), String> {
    if let Some(probe_file) = &cli_args.probe_file {
        return Ok((resolve_compose_file()?, probe_file.clone()));
    }

    let config_path = resolve_config_path(cli_args.config_path.as_deref(), project_dir)?;
    if let Some(config_path) = config_path {
        let config = load_config(&config_path)?;
        let generated_probe = build_generated_probe(&config.probe)?;
        let compose_file = resolve_compose_file()?;
        let output_path = generated_probe_path(&compose_file)?;
        write_if_changed(&output_path, &generated_probe)?;
        return Ok((
            compose_file,
            format!("/probes/{GENERATED_CONFIG_PROBE_FILE_NAME}"),
        ));
    }

    Ok((resolve_compose_file()?, DEFAULT_PROBE.to_string()))
}

fn build_compose_command(
    compose_file: &Path,
    project_dir: &Path,
    probe_file: &str,
    wrapped_command: &[String],
) -> Command {
    let mut command = Command::new("docker");
    command
        .arg("compose")
        .arg("-f")
        .arg(compose_file)
        .arg("run")
        .arg("--rm")
        .arg("-e")
        .arg(format!("EBPF_TRACKER_PROBE={probe_file}"))
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

fn run() -> Result<i32, String> {
    let args: Vec<String> = env::args().skip(1).collect();
    let parsed = parse_args(args)?;
    let cli_args = match parsed {
        ParseOutcome::Help => {
            print_usage();
            return Ok(0);
        }
        ParseOutcome::Run(cli_args) => cli_args,
    };

    let project_dir =
        env::current_dir().map_err(|err| format!("failed to read current dir: {err}"))?;
    let (compose_file, probe_file) = resolve_probe_file(&cli_args, &project_dir)?;
    let command =
        build_compose_command(&compose_file, &project_dir, &probe_file, &cli_args.command);

    if cli_args.log_enable {
        run_with_log(command, &project_dir)
    } else {
        run_without_log(command)
    }
}

fn main() {
    match run() {
        Ok(code) => process::exit(code),
        Err(message) => {
            eprintln!("{message}");
            print_usage();
            process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{build_generated_probe, load_config};
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
}
