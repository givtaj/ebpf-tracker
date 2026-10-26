use std::fs::{self, File};
use std::path::{Path, PathBuf};

use crate::dashboard::run_viewer_command;

#[derive(Debug)]
pub(crate) struct ReplayArgs {
    file: PathBuf,
    viewer_options: Vec<String>,
}

#[derive(Debug)]
pub(crate) enum ReplayParseOutcome {
    Help,
    Run(ReplayArgs),
}

pub(crate) fn print_replay_usage() {
    eprintln!("Usage: ebpf-tracker replay <path> [--port <port>] [--speed <x>] [--interval-ms <ms>] [--focus-comm <comm>]");
    eprintln!("Open a saved JSONL or trace log in the local browser viewer.");
    eprintln!("Requires Node.js on the host. Does not start Docker or rerun the recorded command.");
    eprintln!("The viewer binds to 127.0.0.1 and opens the browser automatically. Press Ctrl-C to close it.");
    eprintln!("Example: ebpf-tracker replay trace.jsonl --focus-comm session-io-demo");
    eprintln!("Example: ebpf-tracker replay --port 43118 --speed 2 logs/run.log");
    eprintln!("Use -- before a filename beginning with '-'.");
}

pub(crate) fn parse_replay_args(args: &[String]) -> Result<ReplayParseOutcome, String> {
    let mut file = None;
    let mut viewer_options = Vec::new();
    let mut index = 0;

    while index < args.len() {
        let arg = &args[index];
        match arg.as_str() {
            "-h" | "--help" => return Ok(ReplayParseOutcome::Help),
            "--" => {
                let remaining = &args[index + 1..];
                if file.is_some() || remaining.len() != 1 {
                    return Err("replay requires exactly one trace file".to_string());
                }
                file = Some(PathBuf::from(&remaining[0]));
                break;
            }
            "--port" | "--speed" | "--interval-ms" | "--focus-comm" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| format!("missing value for replay {arg}"))?;
                validate_viewer_option(arg, value)?;
                viewer_options.extend([arg.clone(), value.clone()]);
                index += 2;
            }
            _ if arg.starts_with('-') => {
                return Err(format!("unsupported replay option: {arg}"));
            }
            _ => {
                if file.replace(PathBuf::from(arg)).is_some() {
                    return Err("replay accepts one trace file, not a command".to_string());
                }
                index += 1;
            }
        }
    }

    let file = file.ok_or_else(|| {
        "missing replay file; use ebpf-tracker replay <path> or replay --help".to_string()
    })?;
    Ok(ReplayParseOutcome::Run(ReplayArgs {
        file,
        viewer_options,
    }))
}

fn validate_viewer_option(option: &str, value: &str) -> Result<(), String> {
    let valid = match option {
        "--port" => value.parse::<u16>().is_ok_and(|port| port > 0),
        "--speed" => value
            .parse::<f64>()
            .is_ok_and(|speed| speed.is_finite() && speed > 0.0),
        "--interval-ms" => value
            .parse::<u32>()
            .is_ok_and(|ms| ms > 0 && ms <= i32::MAX as u32),
        "--focus-comm" => !value.is_empty(),
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(format!("invalid replay {option} value: {value}"))
    }
}

fn readable_replay_path(path: &Path) -> Result<PathBuf, String> {
    let metadata = fs::metadata(path)
        .map_err(|err| format!("cannot read replay file {}: {err}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!("replay path is not a file: {}", path.display()));
    }
    File::open(path).map_err(|err| format!("cannot read replay file {}: {err}", path.display()))?;
    path.canonicalize()
        .map_err(|err| format!("cannot resolve replay file {}: {err}", path.display()))
}

pub(crate) fn run_replay(args: ReplayArgs) -> Result<i32, String> {
    // Validate before materializing assets or launching Node. Always provide
    // --replay so the viewer cannot fall back to its live tracing default.
    let path = readable_replay_path(&args.file)?;
    let mut viewer_args = vec!["--replay".to_string(), path.display().to_string()];
    viewer_args.extend(args.viewer_options);
    let command = ebpf_tracker_viewer::build_node_command(&viewer_args)?;
    run_viewer_command(command)
}

#[cfg(test)]
mod tests {
    use super::{parse_replay_args, readable_replay_path, ReplayParseOutcome};

    fn args(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|part| part.to_string()).collect()
    }

    #[test]
    fn replay_requires_a_file_and_rejects_commands_and_live_options() {
        for input in [
            vec![],
            args(&["trace.jsonl", "cargo", "run"]),
            args(&["trace.jsonl", "--host", "0.0.0.0"]),
            args(&["trace.jsonl", "--dashboard"]),
        ] {
            assert!(parse_replay_args(&input).is_err());
        }
    }

    #[test]
    fn replay_accepts_options_before_and_after_filename() {
        let ReplayParseOutcome::Run(parsed) = parse_replay_args(&args(&[
            "--port",
            "43118",
            "trace with spaces.jsonl",
            "--speed",
            "2",
            "--focus-comm",
            "node",
        ]))
        .expect("replay arguments should parse") else {
            panic!("expected replay arguments");
        };
        assert_eq!(parsed.file.to_str(), Some("trace with spaces.jsonl"));
        assert_eq!(
            parsed.viewer_options,
            args(&["--port", "43118", "--speed", "2", "--focus-comm", "node"])
        );
    }

    #[test]
    fn replay_rejects_invalid_option_values() {
        for (option, value) in [
            ("--port", "0"),
            ("--port", "65536"),
            ("--speed", "NaN"),
            ("--speed", "inf"),
            ("--speed", "-1"),
            ("--interval-ms", "0"),
            ("--interval-ms", "2147483648"),
            ("--focus-comm", ""),
        ] {
            assert!(parse_replay_args(&args(&["trace.jsonl", option, value])).is_err());
        }
        assert!(parse_replay_args(&args(&["trace.jsonl", "--port"])).is_err());
    }

    #[test]
    fn replay_help_does_not_require_an_existing_file() {
        assert!(matches!(
            parse_replay_args(&args(&["missing.jsonl", "--help"])),
            Ok(ReplayParseOutcome::Help)
        ));
        let ReplayParseOutcome::Run(parsed) = parse_replay_args(&args(&["--", "--help"]))
            .expect("separator permits filenames beginning with a dash")
        else {
            panic!("expected replay arguments");
        };
        assert_eq!(parsed.file.to_str(), Some("--help"));
    }

    #[test]
    fn replay_path_reports_missing_files_and_directories() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let missing = root.join("this-replay-fixture-does-not-exist.jsonl");
        assert!(readable_replay_path(&missing)
            .unwrap_err()
            .contains("cannot read replay file"));
        assert!(readable_replay_path(root).is_err());
        let fixture = root.join("crates/ebpf-tracker-viewer/demo-library/session-io-demo.jsonl");
        assert!(readable_replay_path(&fixture)
            .expect("fixture exists")
            .is_absolute());
    }
}
