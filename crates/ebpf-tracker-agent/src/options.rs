use std::path::PathBuf;

#[derive(Debug)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) struct Options {
    pub app_user: String,
    pub output: PathBuf,
    pub shutdown_timeout: u64,
    pub command: Vec<String>,
}

#[derive(Debug)]
pub(crate) enum Outcome {
    Help,
    Version,
    Run(Options),
}

pub(crate) fn parse(args: Vec<String>) -> Result<Outcome, String> {
    let mut app_user = None;
    let mut output = None;
    let mut shutdown_timeout = 10;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--help" | "-h" => return Ok(Outcome::Help),
            "--version" | "-V" => return Ok(Outcome::Version),
            "--" => {
                index += 1;
                break;
            }
            option @ ("--app-user" | "--output" | "--shutdown-timeout") => {
                let value = args
                    .get(index + 1)
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| format!("missing value for {option}"))?;
                match option {
                    "--app-user" => app_user = Some(value.clone()),
                    "--output" => output = Some(PathBuf::from(value)),
                    _ => {
                        shutdown_timeout = value
                            .parse::<u64>()
                            .ok()
                            .filter(|seconds| (1..=300).contains(seconds))
                            .ok_or("--shutdown-timeout must be between 1 and 300 seconds")?;
                    }
                }
                index += 2;
            }
            _ => {
                return Err("expected an agent option or -- before the application command".into())
            }
        }
    }
    let command = args[index..].to_vec();
    if command.is_empty() {
        return Err("missing application command after --".into());
    }
    Ok(Outcome::Run(Options {
        app_user: app_user.ok_or("--app-user is required")?,
        output: output.ok_or("--output is required")?,
        shutdown_timeout,
        command,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(value: &[&str]) -> Vec<String> {
        value.iter().map(|v| (*v).into()).collect()
    }
    #[test]
    fn explicit_boundary_preserves_every_application_argument() {
        let Outcome::Run(options) = parse(args(&[
            "--app-user",
            "roots",
            "--output",
            "/traces/run.jsonl",
            "--",
            "/app/api",
            "--version",
            "two words",
            "$(false)",
        ]))
        .unwrap() else {
            panic!()
        };
        assert_eq!(
            options.command,
            args(&["/app/api", "--version", "two words", "$(false)"])
        );
        assert_eq!(options.shutdown_timeout, 10);
    }
    #[test]
    fn missing_required_arguments_and_invalid_timeout_are_rejected() {
        for input in [
            vec![],
            args(&["--", "true"]),
            args(&["--app-user", "roots", "--output", "a", "true"]),
            args(&[
                "--app-user",
                "roots",
                "--output",
                "a",
                "--shutdown-timeout",
                "0",
                "--",
                "true",
            ]),
        ] {
            assert!(parse(input).is_err());
        }
    }
    #[test]
    fn discovery_does_not_require_a_workload() {
        assert!(matches!(parse(args(&["--help"])), Ok(Outcome::Help)));
        assert!(matches!(parse(args(&["-V"])), Ok(Outcome::Version)));
    }
}
