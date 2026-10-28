use super::{
    optional_number, permissions, write_number, HelperConfig, INTERNAL_CONFIG, POLL,
    STARTUP_TIMEOUT,
};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Instant;

pub(super) fn entry() -> i32 {
    match run() {
        Ok(status) => status,
        Err(error) => {
            eprintln!("ebpf-tracker-agent workload: {error}");
            125
        }
    }
}

fn private_config(path: &PathBuf) -> Result<HelperConfig, String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("internal workload helper requires root".into());
    }
    let parent = path.parent().ok_or("invalid private configuration path")?;
    for (path, directory) in [(parent, true), (path.as_path(), false)] {
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| format!("cannot inspect private configuration: {error}"))?;
        if metadata.uid() != 0
            || metadata.mode() & 0o077 != 0
            || (directory && !metadata.is_dir())
            || (!directory && !metadata.is_file())
        {
            return Err("internal configuration must be root-owned and private".into());
        }
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| error.to_string())?;
    let config: HelperConfig =
        serde_json::from_reader(file).map_err(|_| "invalid private workload configuration")?;
    if config.uid == 0
        || config.command.is_empty()
        || config.agent_pid < 1
        || config.stdout_fd <= 2
        || config.stderr_fd <= 2
    {
        return Err("invalid private workload launch contract".into());
    }
    Ok(config)
}

fn run() -> Result<i32, String> {
    let path = PathBuf::from(
        std::env::var_os(INTERNAL_CONFIG).ok_or("missing private workload configuration")?,
    );
    let config = private_config(&path)?;
    let directory = path.parent().ok_or("missing private runtime directory")?;
    write_number(&directory.join("helper-pid"), std::process::id() as i32)
        .map_err(|error| error.to_string())?;
    let started = Instant::now();
    loop {
        // An actual syscall provides a kernel-PID handshake before app execution.
        unsafe {
            libc::syscall(libc::SYS_getpid);
        }
        if let Some(signal) = optional_number(&directory.join("stop"))? {
            let code = 128 + signal;
            write_number(&directory.join("status"), code).map_err(|error| error.to_string())?;
            return Ok(code);
        }
        if directory.join("go").is_file() {
            break;
        }
        if started.elapsed() >= STARTUP_TIMEOUT || unsafe { libc::kill(config.agent_pid, 0) } < 0 {
            return Err("tracing supervisor did not release the workload".into());
        }
        std::thread::sleep(POLL);
    }
    let stdout = app_stdio(config.stdout_fd)
        .map_err(|error| format!("cannot restore application stdout: {error}"))?;
    let stderr = app_stdio(config.stderr_fd)
        .map_err(|error| format!("cannot restore application stderr: {error}"))?;
    let mut command = Command::new(&config.command[0]);
    command
        .args(&config.command[1..])
        .stdin(Stdio::inherit())
        .stdout(stdout)
        .stderr(stderr);
    // Internal controls never reach the workload. Its ordinary environment is retained.
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("EBPF_TRACKER_") {
            command.env_remove(name);
        }
    }
    let (setup_read, setup_write) = setup_error_pipe()
        .map_err(|error| format!("cannot prepare privilege-drop status: {error}"))?;
    let setup_fd = setup_write.as_raw_fd();
    unsafe {
        command.pre_exec(move || {
            let result = if libc::setpgid(0, 0) < 0 {
                Err(io::Error::last_os_error())
            } else {
                permissions::drop_privileges(config.uid, config.gid, config.last_capability)
            };
            if let Err(error) = &result {
                let code = error.raw_os_error().unwrap_or(libc::EPERM).to_ne_bytes();
                // Four bytes fit atomically in this private pipe. No allocation
                // or locks are used between fork and exec.
                libc::write(setup_fd, code.as_ptr().cast(), code.len());
            }
            result
        });
    }
    let spawned = command.spawn();
    drop(setup_write);
    let status = match spawned {
        Ok(mut child) => {
            drop(setup_read);
            if let Err(error) = write_number(&directory.join("app-pid"), child.id() as i32) {
                unsafe {
                    libc::kill(-(child.id() as i32), libc::SIGKILL);
                }
                let _ = child.wait();
                return Err(format!("cannot publish application PID: {error}"));
            }
            let status = child
                .wait()
                .map_err(|error| format!("cannot wait for application: {error}"))?;
            status
                .code()
                .unwrap_or_else(|| 128 + status.signal().unwrap_or(1))
        }
        Err(error) => {
            let mut setup_error = [0u8; 4];
            let setup_failed = File::from(setup_read).read_exact(&mut setup_error).is_ok();
            if setup_failed {
                eprintln!(
                    "ebpf-tracker-agent: application privilege/process setup failed: {}",
                    io::Error::from_raw_os_error(i32::from_ne_bytes(setup_error))
                );
                125
            } else {
                eprintln!("ebpf-tracker-agent: application could not start: {error}");
                match error.kind() {
                    io::ErrorKind::NotFound => 127,
                    _ => 126,
                }
            }
        }
    };
    write_number(&directory.join("status"), status)
        .map_err(|error| format!("cannot record workload exit status: {error}"))?;
    Ok(status)
}

fn setup_error_pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut descriptors = [-1; 2];
    if unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe {
        (
            OwnedFd::from_raw_fd(descriptors[0]),
            OwnedFd::from_raw_fd(descriptors[1]),
        )
    })
}

fn app_stdio(fd: i32) -> io::Result<Stdio> {
    // bpftrace inherited these descriptors from the supervisor. Close the spare
    // copies on application exec; only stdout/stderr themselves remain open.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(Stdio::from(unsafe { OwnedFd::from_raw_fd(duplicate) }))
}
