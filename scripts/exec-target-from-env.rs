use std::env;
use std::os::unix::process::CommandExt;
use std::process::{self, Command};

fn main() {
    let arg_count = env::var("EBPF_TRACKER_ARG_COUNT")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .unwrap_or(0);

    if arg_count == 0 {
        process::exit(0);
    }

    let mut args = Vec::with_capacity(arg_count);
    for index in 1..=arg_count {
        let var_name = format!("EBPF_TRACKER_ARG_{index}");
        match env::var(&var_name) {
            Ok(value) => args.push(value),
            Err(_) => {
                eprintln!("missing environment variable: {var_name}");
                process::exit(127);
            }
        }
    }

    let program = args[0].clone();
    let error = Command::new(&program).args(&args[1..]).exec();
    eprintln!("failed to exec {program}: {error}");
    process::exit(match error.kind() {
        std::io::ErrorKind::NotFound => 127,
        _ => 126,
    });
}
