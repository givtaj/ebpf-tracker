use std::env;
use std::io::{self, BufReader};
use std::process;

use ebpf_tracker_otel::{consume_jsonl, parse_target, scaffold_message, ExportConfig};

fn print_usage() {
    eprintln!("Usage: ebpf-tracker-otel [--target <otlp|jaeger>] [--endpoint <url>] [--service-name <name>]");
    eprintln!(
        "Reads ebpf-tracker JSONL records from stdin and prepares them for future OTLP export."
    );
}

fn parse_args(args: &[String]) -> Result<ExportConfig, String> {
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
            _ => return Err(format!("unknown flag: {arg}")),
        }
    }

    Ok(config)
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let config = match parse_args(&args) {
        Ok(config) => config,
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

    let stdin = io::stdin();
    let summary = match consume_jsonl(BufReader::new(stdin.lock())) {
        Ok(summary) => summary,
        Err(message) => {
            eprintln!("{message}");
            process::exit(1);
        }
    };

    eprintln!("{}", scaffold_message(&config, &summary));
}
