use std::ffi::CString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const REQUIRED_EVENTS: &[&str] = &[
    "sched/sched_process_fork",
    "sched/sched_process_exit",
    "syscalls/sys_enter_getpid",
    "syscalls/sys_enter_execve",
    "syscalls/sys_enter_openat",
    "syscalls/sys_enter_write",
    "syscalls/sys_enter_connect",
];

pub(super) struct TracingMounts {
    owned: Vec<PathBuf>,
}

impl Drop for TracingMounts {
    fn drop(&mut self) {
        for path in self.owned.iter().rev() {
            if let Ok(path) = CString::new(path.as_os_str().as_encoded_bytes()) {
                // Only detach mounts created by this invocation, after all
                // collector processes have exited. Existing mounts are retained.
                unsafe {
                    libc::umount2(path.as_ptr(), libc::MNT_DETACH);
                }
            }
        }
    }
}

fn available(root: &Path) -> bool {
    REQUIRED_EVENTS
        .iter()
        .all(|event| fs::read_to_string(root.join("events").join(event).join("id")).is_ok())
}

pub(super) fn prepare() -> Result<TracingMounts, String> {
    let mut mounts = TracingMounts { owned: Vec::new() };
    let direct = Path::new("/sys/kernel/tracing");
    let debug = Path::new("/sys/kernel/debug");
    if available(direct) || available(&debug.join("tracing")) {
        return Ok(mounts);
    }
    let mut errors = Vec::new();
    for (target, filesystem, events) in [
        (direct, "tracefs", direct.to_path_buf()),
        (debug, "debugfs", debug.join("tracing")),
    ] {
        let mount_result = (|| -> io::Result<()> {
            fs::create_dir_all(target)?;
            let target_c =
                CString::new(target.as_os_str().as_encoded_bytes()).map_err(io::Error::other)?;
            let fs_c = CString::new(filesystem).map_err(io::Error::other)?;
            let result = unsafe {
                libc::mount(
                    fs_c.as_ptr(),
                    target_c.as_ptr(),
                    fs_c.as_ptr(),
                    libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                    std::ptr::null(),
                )
            };
            if result < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        })();
        match mount_result {
            Ok(()) => {
                mounts.owned.push(target.to_path_buf());
                if available(&events) {
                    return Ok(mounts);
                }
                errors.push(format!("{filesystem} mounted but required syscall/scheduler tracepoints are unavailable"));
            }
            Err(error) => errors.push(format!("{filesystem}: {error}")),
        }
    }
    Err(format!("kernel tracing is unavailable; this alpha needs a privileged Linux development container with host PID namespace and tracefs/debugfs permissions ({})", errors.join("; ")))
}
