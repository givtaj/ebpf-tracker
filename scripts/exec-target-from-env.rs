use std::env;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::ExitStatusExt;
use std::process::{self, Command};

const INTERACTIVE_PTY_ENV_NAME: &str = "EBPF_TRACKER_INTERACTIVE_PTY";
const STATUS_FILE_ENV_NAME: &str = "EBPF_TRACKER_STATUS_FILE";

fn main() {
    let Some(status_path) = env::var_os(STATUS_FILE_ENV_NAME) else {
        eprintln!("missing environment variable: {STATUS_FILE_ENV_NAME}");
        process::exit(125);
    };
    let status = run_workload();
    // The wrapper owns the private directory. Refuse to overwrite an existing
    // handoff, and write only after the supervised workload has finished.
    let result = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(status_path)
        .and_then(|mut file| writeln!(file, "{status}"));
    if let Err(error) = result {
        eprintln!("failed to record workload exit status: {error}");
        process::exit(125);
    }
    process::exit(status);
}

fn run_workload() -> i32 {
    let arg_count = env::var("EBPF_TRACKER_ARG_COUNT")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .unwrap_or(0);

    if arg_count == 0 {
        return 0;
    }

    let mut args = Vec::with_capacity(arg_count);
    for index in 1..=arg_count {
        let var_name = format!("EBPF_TRACKER_ARG_{index}");
        match env::var(&var_name) {
            Ok(value) => args.push(value),
            Err(_) => {
                eprintln!("missing environment variable: {var_name}");
                return 127;
            }
        }
    }

    let program = args[0].clone();
    let mut command = if interactive_pty_enabled() {
        let quoted_command = shell_quote_command(&args);
        let wrapper = format!(
            "exec script -qefc {} /dev/null >&2",
            shell_quote(&quoted_command)
        );
        let mut command = Command::new("/bin/sh");
        command.arg("-lc").arg(wrapper);
        command
    } else {
        let mut command = Command::new(&program);
        command.args(&args[1..]);
        command
    };

    // Keep the helper alive as bpftrace's root child. The workload and its
    // descendants are still covered by the fork-tracking probes. Do not expose
    // the status handoff variable to the workload (including nested trackers).
    command.env_remove(STATUS_FILE_ENV_NAME);
    match command.status() {
        Ok(status) => status
            .code()
            .unwrap_or_else(|| 128 + status.signal().unwrap_or(1)),
        Err(error) => {
            eprintln!("failed to start {program}: {error}");
            match error.kind() {
                std::io::ErrorKind::NotFound => 127,
                _ => 126,
            }
        }
    }
}

fn interactive_pty_enabled() -> bool {
    matches!(env::var(INTERACTIVE_PTY_ENV_NAME).as_deref(), Ok("1"))
}

fn shell_quote_command(args: &[String]) -> String {
    args.iter()
        .map(|arg| shell_quote(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

fn shell_quote(value: &str) -> String {
    if value.is_empty() {
        return "''".to_string();
    }

    format!("'{}'", value.replace('\'', r#"'"'"'"#))
}

#[cfg(test)]
mod tests {
    use super::shell_quote_command;
    use std::process::Command;

    #[test]
    fn pty_command_quoting_preserves_arguments() {
        let args = ["", "two words", "single'quote", "$(exit 77)", "line\nbreak"];
        let command = shell_quote_command(&args.map(String::from));
        let output = Command::new("/bin/sh")
            .arg("-c")
            .arg(format!("set -- {command}; printf '%s\\0' \"$@\""))
            .output()
            .unwrap();
        assert!(output.status.success());
        let expected = args.join("\0") + "\0";
        assert_eq!(output.stdout, expected.as_bytes());
    }
}
