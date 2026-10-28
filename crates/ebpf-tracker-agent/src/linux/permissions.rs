use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path};

pub(super) fn resolve_user(name: &str) -> Result<(u32, u32), String> {
    let name_c = CString::new(name).map_err(|_| "invalid application user")?;
    let mut buffer = vec![0u8; 65536];
    let mut passwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result = std::ptr::null_mut();
    let rc = unsafe {
        if let Ok(uid) = name.parse::<u32>() {
            libc::getpwuid_r(
                uid,
                &mut passwd,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        } else {
            libc::getpwnam_r(
                name_c.as_ptr(),
                &mut passwd,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        }
    };
    if rc != 0 || result.is_null() {
        return Err("--app-user must identify an existing non-root passwd entry".into());
    }
    if passwd.pw_uid == 0 {
        return Err("--app-user must not be root (uid 0)".into());
    }
    Ok((passwd.pw_uid, passwd.pw_gid))
}

pub(super) fn capability_limit() -> io::Result<u32> {
    std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")?
        .trim()
        .parse()
        .map_err(io::Error::other)
}

// Called only from Command::pre_exec. Keep this path allocation- and lock-free.
pub(super) unsafe fn drop_privileges(uid: u32, gid: u32, last_cap: u32) -> io::Result<()> {
    if uid == 0 {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 {
        return Err(io::Error::last_os_error());
    }
    if libc::prctl(
        libc::PR_CAP_AMBIENT,
        libc::PR_CAP_AMBIENT_CLEAR_ALL,
        0,
        0,
        0,
    ) < 0
    {
        return Err(io::Error::last_os_error());
    }
    for capability in 0..=last_cap {
        if libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    if libc::setgroups(0, std::ptr::null()) < 0 {
        return Err(io::Error::last_os_error());
    }
    if libc::setresgid(gid, gid, gid) < 0 {
        return Err(io::Error::last_os_error());
    }
    if libc::setresuid(uid, uid, uid) < 0 {
        return Err(io::Error::last_os_error());
    }
    #[repr(C)]
    struct Header {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let header = Header {
        version: 0x2008_0522,
        pid: 0,
    };
    let data = [Data {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    if libc::syscall(libc::SYS_capset, &header as *const Header, data.as_ptr()) < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(super) fn create_capture(path: &Path) -> io::Result<File> {
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    let components: Vec<_> = absolute.components().collect();
    let Some(Component::Normal(filename)) = components.last() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "output must name a new regular file",
        ));
    };
    let root = unsafe { libc::open(c"/".as_ptr(), libc::O_DIRECTORY | libc::O_CLOEXEC) };
    if root < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut directory = unsafe { OwnedFd::from_raw_fd(root) };
    for component in &components[..components.len() - 1] {
        match component {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(name) => {
                let name = CString::new(name.as_bytes()).map_err(io::Error::other)?;
                let next = unsafe {
                    libc::openat(
                        directory.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if next < 0 {
                    return Err(io::Error::last_os_error());
                }
                directory = unsafe { OwnedFd::from_raw_fd(next) };
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "output parent traversal is not allowed",
                ))
            }
        }
    }
    let filename = CString::new(filename.as_bytes()).map_err(io::Error::other)?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            filename.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o644,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    #[test]
    fn root_and_missing_user_are_refused() {
        assert!(resolve_user("root").is_err());
        assert!(resolve_user("0").is_err());
        assert!(resolve_user("ebpf-tracker-user-that-does-not-exist").is_err());
    }
    #[test]
    fn capture_never_follows_symlinks_or_replaces_previous_output() {
        let dir = super::super::RunDirectory::new().unwrap();
        let capture = dir.path.join("events.jsonl");
        drop(create_capture(&capture).unwrap());
        assert!(create_capture(&capture).is_err());
        symlink(&capture, dir.path.join("link")).unwrap();
        assert!(create_capture(&dir.path.join("link")).is_err());
        symlink(&dir.path, dir.path.join("directory-link")).unwrap();
        assert!(create_capture(&dir.path.join("directory-link/other.jsonl")).is_err());
    }

    #[test]
    #[ignore = "requires root with CAP_SETUID, CAP_SETGID and CAP_SETPCAP; real runtime smoke also covers this"]
    fn application_has_no_capabilities_or_supplementary_groups() {
        use std::os::unix::process::CommandExt;
        let _lock = super::super::PROCESS_TESTS.lock().unwrap();
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let (uid, gid) = resolve_user("nobody").unwrap();
        let limit = capability_limit().unwrap();
        let mut command = std::process::Command::new("/bin/cat");
        command.arg("/proc/self/status");
        unsafe {
            command.pre_exec(move || drop_privileges(uid, gid, limit));
        }
        let output = command.output().unwrap();
        assert!(output.status.success());
        let status = String::from_utf8(output.stdout).unwrap();
        for key in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
            assert!(status
                .lines()
                .any(|line| line == format!("{key}:\t0000000000000000")));
        }
        assert!(status.lines().any(|line| line == "NoNewPrivs:\t1"));
        assert!(status
            .lines()
            .any(|line| line.starts_with("Groups:") && line[7..].trim().is_empty()));
        assert!(status
            .lines()
            .any(|line| line == format!("Uid:\t{uid}\t{uid}\t{uid}\t{uid}")));
        assert!(status
            .lines()
            .any(|line| line == format!("Gid:\t{gid}\t{gid}\t{gid}\t{gid}")));
    }
}
