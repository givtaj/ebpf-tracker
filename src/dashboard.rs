use std::env;
use std::io::{self, BufReader, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;

use crate::intelligence::append_intelligence_args;
use crate::{exit_code, CliArgs, DashboardOptions, DemoArgs, EmitMode, INTERACTIVE_PTY_ENV_NAME};

pub(crate) fn build_tracker_args_for_dashboard(cli_args: &CliArgs) -> Vec<String> {
    let mut args = Vec::new();

    if let Some(probe_file) = &cli_args.probe_file {
        args.push("--probe".to_string());
        args.push(probe_file.clone());
    }

    if cli_args.allow_host_wide_probe {
        args.push("--allow-host-wide-probe".to_string());
    }

    if let Some(config_path) = &cli_args.config_path {
        args.push("--config".to_string());
        args.push(config_path.display().to_string());
    }

    args.push("--log-enable".to_string());

    args.push("--emit".to_string());
    args.push(EmitMode::Jsonl.as_str().to_string());
    args.push("--transport".to_string());
    args.push(cli_args.transport_mode.as_str().to_string());
    args.push("--runtime".to_string());
    args.push(cli_args.runtime_selection.as_str().to_string());
    append_intelligence_args(&mut args, &cli_args.intelligence);
    args.push("--".to_string());
    args.extend(cli_args.command.iter().cloned());

    args
}

pub(crate) fn build_demo_args_for_dashboard(demo_args: &DemoArgs) -> Vec<String> {
    let mut args = vec![
        "demo".to_string(),
        "--log-enable".to_string(),
        "--emit".to_string(),
        EmitMode::Jsonl.as_str().to_string(),
        "--transport".to_string(),
        demo_args.transport_mode.as_str().to_string(),
    ];

    if demo_args.list_examples {
        args.push("--list".to_string());
    }

    if let Some(example_name) = &demo_args.example_name {
        args.push(example_name.clone());
    }

    append_intelligence_args(&mut args, &demo_args.intelligence);

    args
}

pub(crate) fn parse_dashboard_url(line: &str) -> Option<&str> {
    line.trim()
        .strip_prefix("live trace viewer on ")
        .map(str::trim)
}

pub(crate) fn run_with_dashboard(
    dashboard: DashboardOptions,
    tracker_args: Vec<String>,
    project_dir: &Path,
    forced_from_emit: EmitMode,
) -> Result<i32, String> {
    let dashboard_script = resolve_dashboard_script()?;
    let current_exe =
        env::current_exe().map_err(|err| format!("failed to resolve executable path: {err}"))?;

    if forced_from_emit != EmitMode::Jsonl {
        eprintln!("dashboard mode forces --emit jsonl for the viewer stream");
    }

    let mut command = Command::new("node");
    command
        .arg(&dashboard_script)
        .arg("--port")
        .arg(dashboard.port.to_string())
        .arg("--")
        .arg(&current_exe)
        .args(tracker_args)
        .current_dir(project_dir)
        .envs(
            io::stdin()
                .is_terminal()
                .then_some([(INTERACTIVE_PTY_ENV_NAME, "1")])
                .into_iter()
                .flatten(),
        );
    run_viewer_command(command)
}

pub(crate) fn run_viewer_command(mut command: Command) -> Result<i32, String> {
    let mut child = command
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| {
            format!(
                "failed to start viewer via node (Node.js must be installed on the host): {err}"
            )
        })?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "failed to capture dashboard stdout".to_string())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "failed to capture dashboard stderr".to_string())?;

    let out_handle = thread::spawn(move || forward_dashboard_stdout(stdout));
    let err_handle = thread::spawn(move || forward_dashboard_stderr(stderr));

    let status = child
        .wait()
        .map_err(|err| format!("failed waiting for dashboard viewer: {err}"))?;

    let out_result = out_handle
        .join()
        .map_err(|_| "dashboard stdout forwarding thread panicked".to_string())?;
    out_result.map_err(|err| format!("dashboard stdout forwarding failed: {err}"))?;

    let err_result = err_handle
        .join()
        .map_err(|_| "dashboard stderr forwarding thread panicked".to_string())?;
    err_result.map_err(|err| format!("dashboard stderr forwarding failed: {err}"))?;

    Ok(exit_code(&status))
}

fn resolve_dashboard_script() -> Result<PathBuf, String> {
    ebpf_tracker_viewer::viewer_script_path()
}

fn try_open_browser(url: &str) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    let mut command = {
        let mut command = Command::new("open");
        command.arg(url);
        command
    };

    #[cfg(target_os = "linux")]
    let mut command = {
        let mut command = Command::new("xdg-open");
        command.arg(url);
        command
    };

    #[cfg(target_os = "windows")]
    let mut command = {
        let mut command = Command::new("cmd");
        command.arg("/C").arg("start").arg("").arg(url);
        command
    };

    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|err| format!("failed to launch browser for {url}: {err}"))?;

    Ok(())
}

fn forward_dashboard_stdout<R: Read>(mut reader: R) -> io::Result<()> {
    let mut stdout = io::stdout();
    let mut buffer = [0u8; 16 * 1024];

    loop {
        let read_bytes = reader.read(&mut buffer)?;
        if read_bytes == 0 {
            break;
        }
        stdout.write_all(&buffer[..read_bytes])?;
        stdout.flush()?;
    }

    Ok(())
}

fn forward_dashboard_stderr<R: Read>(reader: R) -> io::Result<()> {
    let mut reader = BufReader::new(reader);
    let mut stderr = io::stderr();
    let mut opened = false;
    let mut buffer = [0u8; 16 * 1024];
    let mut pending = Vec::new();

    loop {
        let read_bytes = reader.read(&mut buffer)?;
        if read_bytes == 0 {
            break;
        }

        let chunk = &buffer[..read_bytes];
        stderr.write_all(chunk)?;
        stderr.flush()?;

        pending.extend_from_slice(chunk);
        while let Some(newline_index) = pending.iter().position(|byte| *byte == b'\n') {
            let line: Vec<u8> = pending.drain(..=newline_index).collect();
            if !opened {
                let text = String::from_utf8_lossy(&line);
                if let Some(url) = parse_dashboard_url(&text) {
                    if let Err(err) = try_open_browser(url) {
                        writeln!(stderr, "dashboard ready at {url} ({err})")?;
                    }
                    opened = true;
                }
            }
        }
    }

    if !opened && !pending.is_empty() {
        let text = String::from_utf8_lossy(&pending);
        if let Some(url) = parse_dashboard_url(&text) {
            if let Err(err) = try_open_browser(url) {
                writeln!(stderr, "dashboard ready at {url} ({err})")?;
            }
        }
    }

    Ok(())
}
