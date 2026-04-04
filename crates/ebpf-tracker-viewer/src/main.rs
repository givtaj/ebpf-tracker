use std::env;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;

fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<i32, String> {
    let args: Vec<String> = env::args().skip(1).collect();
    if viewer_help_requested(&args) {
        print_usage();
        return Ok(0);
    }

    let mut command = ebpf_tracker_viewer::build_node_command(&args)?;
    let mut child = command
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("failed to run viewer: {err}"))?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "failed to capture viewer stdout".to_string())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "failed to capture viewer stderr".to_string())?;

    let out_handle = thread::spawn(move || forward_stdout(stdout));
    let err_handle = thread::spawn(move || forward_stderr(stderr));

    let status = child
        .wait()
        .map_err(|err| format!("failed waiting for viewer: {err}"))?;

    let out_result = out_handle
        .join()
        .map_err(|_| "viewer stdout forwarding thread panicked".to_string())?;
    out_result.map_err(|err| format!("viewer stdout forwarding failed: {err}"))?;

    let err_result = err_handle
        .join()
        .map_err(|_| "viewer stderr forwarding thread panicked".to_string())?;
    err_result.map_err(|err| format!("viewer stderr forwarding failed: {err}"))?;

    Ok(exit_code(status))
}

fn print_usage() {
    eprintln!(
        "Usage: ebpf-tracker-viewer [--port <port>] [--host <host>] [--replay <path>] [--speed <x>] [--interval-ms <ms>] [--focus-comm <comm>] [command...]"
    );
    eprintln!("Usage: ebpf-tracker-viewer [--port <port>] [--host <host>] -- <command> [args...]");
    eprintln!("Starts the live trace viewer and opens the browser automatically.");
    eprintln!("Without --replay, remaining args are traced through ebpf-tracker.");
    eprintln!("Repository alias: cargo viewer --help");
    eprintln!("Example: cargo viewer --replay logs/ebpf-tracker-YYYYMMDD-HHMMSS.log");
    eprintln!(
        "Example: cargo viewer --port 43118 --replay datasets/synthetic-jsonl-demo/events.jsonl"
    );
    eprintln!("Example: cargo viewer cargo run");
    eprintln!("Example: cargo viewer -- cargo run --help");
}

fn viewer_help_requested(args: &[String]) -> bool {
    let mut index = 0usize;

    while index < args.len() {
        match args[index].as_str() {
            "-h" | "--help" | "help" => return true,
            "--" => return false,
            "--port" | "--host" | "--replay" | "--speed" | "--interval-ms" | "--focus-comm" => {
                if index + 1 >= args.len() {
                    return false;
                }
                index += 2;
            }
            _ => return false,
        }
    }

    false
}

fn forward_stdout<R: Read>(mut reader: R) -> io::Result<()> {
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

fn forward_stderr<R: Read>(reader: R) -> io::Result<()> {
    let mut reader = BufReader::new(reader);
    let mut stderr = io::stderr();
    let mut opened = false;
    let mut line = Vec::new();

    loop {
        line.clear();
        let read_bytes = reader.read_until(b'\n', &mut line)?;
        if read_bytes == 0 {
            break;
        }

        let text = String::from_utf8_lossy(&line);
        if !opened {
            if let Some(url) = parse_dashboard_url(&text) {
                if let Err(err) = try_open_browser(url) {
                    writeln!(stderr, "viewer ready at {url} ({err})")?;
                }
                opened = true;
            }
        }

        stderr.write_all(&line)?;
        stderr.flush()?;
    }

    Ok(())
}

fn parse_dashboard_url(line: &str) -> Option<&str> {
    line.trim()
        .strip_prefix("live trace viewer on ")
        .map(str::trim)
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

#[cfg(test)]
mod tests {
    use super::{parse_dashboard_url, viewer_help_requested};

    fn owned(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|part| part.to_string()).collect()
    }

    #[test]
    fn help_flag_prints_viewer_usage() {
        assert!(viewer_help_requested(&owned(&["--help"])));
        assert!(viewer_help_requested(&owned(&["help"])));
        assert!(viewer_help_requested(&owned(&[
            "--port", "43115", "--help"
        ])));
        assert!(viewer_help_requested(&owned(&[
            "--replay",
            "logs/run.log",
            "--help"
        ])));
    }

    #[test]
    fn command_help_can_be_passed_through_with_separator() {
        assert!(!viewer_help_requested(&owned(&[
            "--", "cargo", "run", "--help"
        ])));
        assert!(!viewer_help_requested(&owned(&["cargo", "run", "--help"])));
    }

    #[test]
    fn parse_dashboard_url_extracts_browser_target() {
        assert_eq!(
            parse_dashboard_url("live trace viewer on http://127.0.0.1:43115"),
            Some("http://127.0.0.1:43115")
        );
        assert_eq!(parse_dashboard_url("replaying: trace.jsonl"), None);
    }
}
