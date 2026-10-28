#[cfg(target_os = "linux")]
mod linux;
mod options;

fn main() {
    #[cfg(target_os = "linux")]
    if linux::is_internal_helper() {
        std::process::exit(linux::helper_entry());
    }
    let code = match options::parse(std::env::args().skip(1).collect()) {
        Ok(options::Outcome::Help) => {
            println!("Usage: ebpf-tracker-agent --app-user <name-or-uid> --output <new-file> [--shutdown-timeout <seconds>] -- <command> [args...]");
            println!("Linux development/CI runtime. Requires root, bpftrace, host PID namespace and kernel tracing permissions.");
            println!("Runs the application as a non-root user with capabilities removed. App logs retain stdout/stderr; captures are JSONL.");
            println!("The output must be a new file in an existing directory; existing files and symlink paths are refused.");
            println!("Default shutdown timeout: 10 seconds. No Docker daemon or socket is used.");
            0
        }
        Ok(options::Outcome::Version) => {
            println!("ebpf-tracker-agent {}", env!("CARGO_PKG_VERSION"));
            0
        }
        Ok(options::Outcome::Run(options)) => {
            #[cfg(target_os = "linux")]
            {
                linux::run(options)
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = options;
                eprintln!("ebpf-tracker-agent: live capture requires Linux; use ebpf-tracker replay for saved captures");
                125
            }
        }
        Err(message) => {
            eprintln!("ebpf-tracker-agent: {message}");
            2
        }
    };
    std::process::exit(code);
}
