use std::env;
use std::io::{self, BufReader};
use std::path::PathBuf;
use std::process;

use ebpf_tracker_dataset::{
    analyze_run, default_output_root, ingest_path, ingest_reader, AnalyzeConfig, DatasetConfig,
    DatasetSource, ModelProvider,
};

enum CliCommand {
    Analyze(AnalyzeConfig),
    Ingest(DatasetConfig),
    Help,
}

fn print_usage() {
    eprintln!(
        "Usage: ebpf-tracker-dataset [--output <dir>] [--replay <path>] [--run-id <id>] [--source <live|replay>] [--command <text>] [--test-name <name>] [--git-sha <sha>] [--transport <bpftrace|perf>] [--runtime <auto|rust|node>] [--exit-code <n>] [--exit-signal <name>] [--log-path <path>]"
    );
    eprintln!(
        "Usage: ebpf-tracker-dataset analyze --run <dataset-dir> [--provider <lm-studio|openai-compatible>] [--endpoint <url>] [--model <name>] [--api-key <token>] [--temperature <n>] [--max-tokens <n>] [--instructions-file <path>] [--live-logs]"
    );
    eprintln!("Reads ebpf-tracker JSONL from stdin unless --replay <path> is provided.");
    eprintln!("Writes a per-run dataset bundle under ./datasets by default.");
    eprintln!("Cargo alias: cargo dataset --replay logs/ebpf-tracker-YYYYMMDD-HHMMSS.log");
    eprintln!(
        "Example: ebpf-tracker --emit jsonl cargo run | cargo dataset --test-name cargo-run-smoke"
    );
    eprintln!(
        "Example: cargo dataset analyze --run datasets/run-123 --provider lm-studio --model qwen/qwen3.5-9b"
    );
    eprintln!(
        "Example: cargo dataset analyze --run datasets/run-123 --provider lm-studio --model qwen/qwen3.5-9b --live-logs"
    );
}

fn parse_ingest_args(args: &[String]) -> Result<DatasetConfig, String> {
    if args
        .first()
        .is_some_and(|value| matches!(value.as_str(), "-h" | "--help" | "help"))
    {
        return Err(String::new());
    }

    let mut config = DatasetConfig {
        output_root: default_output_root(),
        ..DatasetConfig::default()
    };
    let mut index = 0usize;

    while index < args.len() {
        let arg = &args[index];
        match arg.as_str() {
            "-h" | "--help" | "help" => return Err(String::new()),
            "--output" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "missing value for --output".to_string())?;
                config.output_root = PathBuf::from(value);
                index += 2;
            }
            "--replay" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "missing value for --replay".to_string())?;
                config.replay_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--run-id" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "missing value for --run-id".to_string())?;
                config.run_id = Some(value.clone());
                index += 2;
            }
            "--source" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "missing value for --source".to_string())?;
                config.source = Some(DatasetSource::parse(value)?);
                index += 2;
            }
            "--command" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "missing value for --command".to_string())?;
                config.command = Some(value.clone());
                index += 2;
            }
            "--test-name" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "missing value for --test-name".to_string())?;
                config.test_name = Some(value.clone());
                index += 2;
            }
            "--git-sha" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "missing value for --git-sha".to_string())?;
                config.git_sha = Some(value.clone());
                index += 2;
            }
            "--transport" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "missing value for --transport".to_string())?;
                config.transport = Some(value.clone());
                index += 2;
            }
            "--runtime" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "missing value for --runtime".to_string())?;
                config.runtime = Some(value.clone());
                index += 2;
            }
            "--exit-code" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "missing value for --exit-code".to_string())?;
                config.exit_code = Some(
                    value
                        .parse()
                        .map_err(|_| format!("invalid exit code: {value}"))?,
                );
                index += 2;
            }
            "--exit-signal" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "missing value for --exit-signal".to_string())?;
                config.exit_signal = Some(value.clone());
                index += 2;
            }
            "--log-path" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "missing value for --log-path".to_string())?;
                config.log_path = Some(PathBuf::from(value));
                index += 2;
            }
            _ if arg.starts_with("--output=") => {
                config.output_root = PathBuf::from(arg.trim_start_matches("--output="));
                index += 1;
            }
            _ if arg.starts_with("--replay=") => {
                config.replay_path = Some(PathBuf::from(arg.trim_start_matches("--replay=")));
                index += 1;
            }
            _ if arg.starts_with("--run-id=") => {
                config.run_id = Some(arg.trim_start_matches("--run-id=").to_string());
                index += 1;
            }
            _ if arg.starts_with("--source=") => {
                config.source = Some(DatasetSource::parse(arg.trim_start_matches("--source="))?);
                index += 1;
            }
            _ if arg.starts_with("--command=") => {
                config.command = Some(arg.trim_start_matches("--command=").to_string());
                index += 1;
            }
            _ if arg.starts_with("--test-name=") => {
                config.test_name = Some(arg.trim_start_matches("--test-name=").to_string());
                index += 1;
            }
            _ if arg.starts_with("--git-sha=") => {
                config.git_sha = Some(arg.trim_start_matches("--git-sha=").to_string());
                index += 1;
            }
            _ if arg.starts_with("--transport=") => {
                config.transport = Some(arg.trim_start_matches("--transport=").to_string());
                index += 1;
            }
            _ if arg.starts_with("--runtime=") => {
                config.runtime = Some(arg.trim_start_matches("--runtime=").to_string());
                index += 1;
            }
            _ if arg.starts_with("--exit-code=") => {
                let value = arg.trim_start_matches("--exit-code=");
                config.exit_code = Some(
                    value
                        .parse()
                        .map_err(|_| format!("invalid exit code: {value}"))?,
                );
                index += 1;
            }
            _ if arg.starts_with("--exit-signal=") => {
                config.exit_signal = Some(arg.trim_start_matches("--exit-signal=").to_string());
                index += 1;
            }
            _ if arg.starts_with("--log-path=") => {
                config.log_path = Some(PathBuf::from(arg.trim_start_matches("--log-path=")));
                index += 1;
            }
            _ => return Err(format!("unknown flag: {arg}")),
        }
    }

    if config.log_path.is_none() {
        config.log_path = config.replay_path.clone();
    }

    Ok(config)
}

fn parse_analyze_args(args: &[String]) -> Result<AnalyzeConfig, String> {
    if args
        .first()
        .is_some_and(|value| matches!(value.as_str(), "-h" | "--help" | "help"))
    {
        return Err(String::new());
    }

    let mut config = AnalyzeConfig::default();
    let mut index = 0usize;

    while index < args.len() {
        let arg = &args[index];
        match arg.as_str() {
            "-h" | "--help" | "help" => return Err(String::new()),
            "--run" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "missing value for --run".to_string())?;
                config.run_dir = PathBuf::from(value);
                index += 2;
            }
            "--provider" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "missing value for --provider".to_string())?;
                config.provider = ModelProvider::parse(value)?;
                index += 2;
            }
            "--endpoint" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "missing value for --endpoint".to_string())?;
                config.endpoint = Some(value.clone());
                index += 2;
            }
            "--model" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "missing value for --model".to_string())?;
                config.model = Some(value.clone());
                index += 2;
            }
            "--api-key" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "missing value for --api-key".to_string())?;
                config.api_key = Some(value.clone());
                index += 2;
            }
            "--temperature" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "missing value for --temperature".to_string())?;
                config.temperature = value
                    .parse()
                    .map_err(|_| format!("invalid temperature: {value}"))?;
                index += 2;
            }
            "--max-tokens" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "missing value for --max-tokens".to_string())?;
                config.max_tokens = Some(
                    value
                        .parse()
                        .map_err(|_| format!("invalid max tokens: {value}"))?,
                );
                index += 2;
            }
            "--instructions-file" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "missing value for --instructions-file".to_string())?;
                config.instructions_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--live-logs" => {
                config.live_logs = true;
                index += 1;
            }
            _ if arg.starts_with("--run=") => {
                config.run_dir = PathBuf::from(arg.trim_start_matches("--run="));
                index += 1;
            }
            _ if arg.starts_with("--provider=") => {
                config.provider = ModelProvider::parse(arg.trim_start_matches("--provider="))?;
                index += 1;
            }
            _ if arg.starts_with("--endpoint=") => {
                config.endpoint = Some(arg.trim_start_matches("--endpoint=").to_string());
                index += 1;
            }
            _ if arg.starts_with("--model=") => {
                config.model = Some(arg.trim_start_matches("--model=").to_string());
                index += 1;
            }
            _ if arg.starts_with("--api-key=") => {
                config.api_key = Some(arg.trim_start_matches("--api-key=").to_string());
                index += 1;
            }
            _ if arg.starts_with("--temperature=") => {
                let value = arg.trim_start_matches("--temperature=");
                config.temperature = value
                    .parse()
                    .map_err(|_| format!("invalid temperature: {value}"))?;
                index += 1;
            }
            _ if arg.starts_with("--max-tokens=") => {
                let value = arg.trim_start_matches("--max-tokens=");
                config.max_tokens = Some(
                    value
                        .parse()
                        .map_err(|_| format!("invalid max tokens: {value}"))?,
                );
                index += 1;
            }
            _ if arg.starts_with("--instructions-file=") => {
                config.instructions_path = Some(PathBuf::from(
                    arg.trim_start_matches("--instructions-file="),
                ));
                index += 1;
            }
            _ => return Err(format!("unknown flag: {arg}")),
        }
    }

    if config.run_dir.as_os_str().is_empty() {
        return Err("missing required --run <dataset-dir>".to_string());
    }

    Ok(config)
}

fn parse_args(args: &[String]) -> Result<CliCommand, String> {
    match args {
        [] => Ok(CliCommand::Ingest(parse_ingest_args(args)?)),
        [single] if matches!(single.as_str(), "-h" | "--help" | "help") => Ok(CliCommand::Help),
        [subcommand, rest @ ..] if subcommand == "analyze" => {
            if rest
                .first()
                .is_some_and(|value| matches!(value.as_str(), "-h" | "--help" | "help"))
            {
                Ok(CliCommand::Help)
            } else {
                Ok(CliCommand::Analyze(parse_analyze_args(rest)?))
            }
        }
        _ => Ok(CliCommand::Ingest(parse_ingest_args(args)?)),
    }
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let command = match parse_args(&args) {
        Ok(command) => command,
        Err(message) => {
            eprintln!("{message}");
            print_usage();
            process::exit(1);
        }
    };

    match command {
        CliCommand::Help => {
            print_usage();
            process::exit(0);
        }
        CliCommand::Analyze(config) => match analyze_run(&config) {
            Ok(summary) => {
                eprintln!(
                    "analysis written provider={} model={} markdown={} json={}",
                    summary.provider.as_str(),
                    summary.model,
                    summary.output_markdown.display(),
                    summary.output_json.display()
                );
            }
            Err(message) => {
                eprintln!("{message}");
                process::exit(1);
            }
        },
        CliCommand::Ingest(config) => {
            let summary = match &config.replay_path {
                Some(path) => ingest_path(path, &config),
                None => {
                    let stdin = io::stdin();
                    ingest_reader(BufReader::new(stdin.lock()), &config)
                }
            };

            match summary {
                Ok(summary) => {
                    eprintln!(
                        "dataset written run_id={} source={} dir={} records={} ignored_lines={}",
                        summary.run_id,
                        summary.source.as_str(),
                        summary.output_dir.display(),
                        summary.total_records,
                        summary.ignored_lines
                    );
                }
                Err(message) => {
                    eprintln!("{message}");
                    process::exit(1);
                }
            }
        }
    }
}
