use std::env;
use std::io::{self, BufReader};
use std::process;

use ebpf_tracker_otel::{
    export_jsonl, format_export_message, parse_header, parse_target, run_jaeger, ExportConfig,
    JaegerCommand, DEFAULT_JAEGER_UI_URL,
};

enum CliCommand {
    Export(ExportConfig),
    Jaeger(JaegerCommand),
    Help,
}

fn print_usage() {
    eprintln!(
        "Usage: ebpf-tracker-otel [--target <otlp|jaeger>] [--endpoint <url>] [--service-name <name>] [--timeout-seconds <n>] [--header <name=value>]"
    );
    eprintln!("Usage: ebpf-tracker-otel jaeger <up|down|status>");
    eprintln!("Reads ebpf-tracker JSONL records from stdin and exports them as OTLP traces.");
    eprintln!("Cargo alias: cargo otel --target jaeger --service-name session-io-demo");
    eprintln!("Cargo alias: cargo jaeger up");
    eprintln!("Example: cargo otel --target otlp --endpoint http://127.0.0.1:4318/v1/traces --timeout-seconds 15");
    eprintln!("Example: cargo otel --header authorization=Bearer-token");
}

fn parse_export_args(args: &[String]) -> Result<ExportConfig, String> {
    let mut config = ExportConfig::default();
    let mut index = 0usize;

    while index < args.len() {
        let arg = &args[index];
        match arg.as_str() {
            "-h" | "--help" => return Err(String::new()),
            "--target" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "missing value for --target".to_string())?;
                config.target = parse_target(value)?;
                config.endpoint = config.target.default_endpoint().to_string();
                index += 2;
            }
            "--endpoint" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "missing value for --endpoint".to_string())?;
                config.endpoint = value.clone();
                index += 2;
            }
            "--service-name" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "missing value for --service-name".to_string())?;
                config.service_name = value.clone();
                index += 2;
            }
            "--timeout-seconds" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "missing value for --timeout-seconds".to_string())?;
                config.timeout_seconds = value
                    .parse()
                    .map_err(|_| format!("invalid timeout seconds: {value}"))?;
                index += 2;
            }
            "--header" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "missing value for --header".to_string())?;
                config.headers.push(parse_header(value)?);
                index += 2;
            }
            _ if arg.starts_with("--target=") => {
                let value = arg.trim_start_matches("--target=");
                if value.is_empty() {
                    return Err("missing value for --target".to_string());
                }
                config.target = parse_target(value)?;
                config.endpoint = config.target.default_endpoint().to_string();
                index += 1;
            }
            _ if arg.starts_with("--endpoint=") => {
                let value = arg.trim_start_matches("--endpoint=");
                if value.is_empty() {
                    return Err("missing value for --endpoint".to_string());
                }
                config.endpoint = value.to_string();
                index += 1;
            }
            _ if arg.starts_with("--service-name=") => {
                let value = arg.trim_start_matches("--service-name=");
                if value.is_empty() {
                    return Err("missing value for --service-name".to_string());
                }
                config.service_name = value.to_string();
                index += 1;
            }
            _ if arg.starts_with("--timeout-seconds=") => {
                let value = arg.trim_start_matches("--timeout-seconds=");
                if value.is_empty() {
                    return Err("missing value for --timeout-seconds".to_string());
                }
                config.timeout_seconds = value
                    .parse()
                    .map_err(|_| format!("invalid timeout seconds: {value}"))?;
                index += 1;
            }
            _ if arg.starts_with("--header=") => {
                let value = arg.trim_start_matches("--header=");
                if value.is_empty() {
                    return Err("missing value for --header".to_string());
                }
                config.headers.push(parse_header(value)?);
                index += 1;
            }
            _ => return Err(format!("unknown flag: {arg}")),
        }
    }

    Ok(config)
}

fn parse_jaeger_args(args: &[String]) -> Result<JaegerCommand, String> {
    match args {
        [] => Err("missing Jaeger action".to_string()),
        [action] => match action.as_str() {
            "up" => Ok(JaegerCommand::Up),
            "down" => Ok(JaegerCommand::Down),
            "status" => Ok(JaegerCommand::Status),
            "-h" | "--help" | "help" => Err(String::new()),
            _ => Err(format!("unknown Jaeger action: {action}")),
        },
        _ => Err("jaeger accepts exactly one action: up, down, or status".to_string()),
    }
}

fn parse_args(args: &[String]) -> Result<CliCommand, String> {
    match args {
        [] => Ok(CliCommand::Export(ExportConfig::default())),
        [single] if matches!(single.as_str(), "-h" | "--help" | "help") => Ok(CliCommand::Help),
        [subcommand, rest @ ..] if subcommand == "jaeger" => {
            if rest
                .first()
                .is_some_and(|value| matches!(value.as_str(), "-h" | "--help" | "help"))
            {
                Ok(CliCommand::Help)
            } else {
                Ok(CliCommand::Jaeger(parse_jaeger_args(rest)?))
            }
        }
        _ => parse_export_args(args).map(CliCommand::Export),
    }
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let command = match parse_args(&args) {
        Ok(command) => command,
        Err(message) if message.is_empty() => {
            print_usage();
            process::exit(0);
        }
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
        CliCommand::Jaeger(action) => match run_jaeger(action) {
            Ok(code) => {
                if code == 0 && matches!(action, JaegerCommand::Up | JaegerCommand::Status) {
                    eprintln!("Jaeger UI: {DEFAULT_JAEGER_UI_URL}");
                }
                process::exit(code);
            }
            Err(message) => {
                eprintln!("{message}");
                process::exit(1);
            }
        },
        CliCommand::Export(config) => {
            let stdin = io::stdin();
            let summary = match export_jsonl(BufReader::new(stdin.lock()), &config) {
                Ok(summary) => summary,
                Err(message) => {
                    eprintln!("{message}");
                    process::exit(1);
                }
            };

            for warning in &summary.collector_warnings {
                eprintln!("collector warning: {warning}");
            }
            eprintln!("{}", format_export_message(&config, &summary));
        }
    }
}
