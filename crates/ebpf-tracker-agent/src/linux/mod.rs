mod permissions;
mod tracefs;
mod workload;

use crate::options::Options;
use ebpf_tracker_events::{stream_record_for_line, StreamRecord};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{symlink, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const INTERNAL_CONFIG: &str = "EBPF_TRACKER_AGENT_INTERNAL_CONFIG";
const READY: &str = "__EBPF_TRACKER_AGENT_READY__";
const SCOPE: &str = "__EBPF_TRACKER_AGENT_SCOPE__";
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const POLL: Duration = Duration::from_millis(20);
static SIGNAL: AtomicI32 = AtomicI32::new(0);
#[cfg(test)]
static PROCESS_TESTS: Mutex<()> = Mutex::new(());

#[derive(Serialize, Deserialize)]
struct HelperConfig {
    agent_pid: i32,
    uid: u32,
    gid: u32,
    last_capability: u32,
    stdout_fd: i32,
    stderr_fd: i32,
    command: Vec<String>,
}

struct RunDirectory {
    path: PathBuf,
}
impl RunDirectory {
    fn new() -> io::Result<Self> {
        let mut template = b"/tmp/ebpf-tracker-agent.XXXXXX\0".to_vec();
        let result = unsafe { libc::mkdtemp(template.as_mut_ptr().cast()) };
        if result.is_null() {
            return Err(io::Error::last_os_error());
        }
        let path = unsafe { std::ffi::CStr::from_ptr(result) }
            .to_string_lossy()
            .into_owned();
        Ok(Self {
            path: PathBuf::from(path),
        })
    }
}
impl Drop for RunDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

pub(crate) fn is_internal_helper() -> bool {
    let mut args = std::env::args_os();
    let named_helper = args.next().is_some_and(|arg| {
        Path::new(&arg)
            .file_name()
            .is_some_and(|name| name == "workload-helper")
    });
    named_helper && args.next().is_none() && std::env::var_os(INTERNAL_CONFIG).is_some()
}

pub(crate) fn helper_entry() -> i32 {
    workload::entry()
}

pub(crate) fn run(options: Options) -> i32 {
    match run_inner(options) {
        Ok(status) => status,
        Err(error) => {
            eprintln!("ebpf-tracker-agent: {error}");
            125
        }
    }
}

fn run_inner(options: Options) -> Result<i32, String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("capture supervisor requires root and Linux tracing permissions; the application is launched separately as --app-user".into());
    }
    let (uid, gid) = permissions::resolve_user(&options.app_user)?;
    let last_capability = permissions::capability_limit()
        .map_err(|error| format!("cannot inspect Linux capabilities: {error}"))?;
    if last_capability > 63 {
        return Err("this kernel capability range is not supported by this alpha".into());
    }
    let _tracing_mounts = tracefs::prepare()?;
    let _signals = SignalGuard::install()
        .map_err(|error| format!("cannot install supervisor signal handlers: {error}"))?;
    if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } < 0 {
        return Err(format!(
            "cannot enable child reaping: {}",
            io::Error::last_os_error()
        ));
    }
    let output = permissions::create_capture(&options.output).map_err(|error| {
        format!(
            "cannot create new capture {} (existing files and symlinks are refused): {error}",
            options.output.display()
        )
    })?;
    let output = Arc::new(Mutex::new(output));
    let directory = RunDirectory::new()
        .map_err(|error| format!("cannot create private runtime directory: {error}"))?;
    let stdout = inherited_descriptor(libc::STDOUT_FILENO)
        .map_err(|error| format!("cannot preserve application stdout: {error}"))?;
    let stderr = inherited_descriptor(libc::STDERR_FILENO)
        .map_err(|error| format!("cannot preserve application stderr: {error}"))?;
    let config = HelperConfig {
        agent_pid: std::process::id() as i32,
        uid,
        gid,
        last_capability,
        stdout_fd: stdout.as_raw_fd(),
        stderr_fd: stderr.as_raw_fd(),
        command: options.command,
    };
    let config_path = directory.path.join("config.json");
    write_private(
        &config_path,
        &serde_json::to_vec(&config).map_err(|error| error.to_string())?,
    )
    .map_err(|error| format!("cannot prepare workload configuration: {error}"))?;
    let probe = directory.path.join("probe.bt");
    write_private(&probe, include_bytes!("../probe.bt"))
        .map_err(|error| format!("cannot prepare scoped probe: {error}"))?;
    let helper = directory.path.join("workload-helper");
    symlink(
        std::env::current_exe().map_err(|error| error.to_string())?,
        &helper,
    )
    .map_err(|error| format!("cannot prepare workload helper: {error}"))?;

    let mut command = Command::new("/usr/bin/bpftrace");
    command
        .args(["-q", "-B", "line"])
        .arg(&probe)
        .arg("-c")
        .arg(&helper)
        .env(INTERNAL_CONFIG, &config_path)
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut collector = command.spawn().map_err(|error| format!("cannot start /usr/bin/bpftrace: {error}; install the Bookworm runtime package and grant tracing permissions"))?;
    let collector_pid = collector.id() as i32;
    let collector_stdout = collector.stdout.take().expect("piped collector stdout");
    let collector_stderr = collector.stderr.take().expect("piped collector stderr");
    let (sender, receiver) = mpsc::channel();
    let event_sender = sender.clone();
    let capture = Arc::clone(&output);
    let out_thread = thread::spawn(move || read_collector(collector_stdout, capture, event_sender));
    let err_thread = thread::spawn(move || {
        for line in BufReader::new(collector_stderr).lines() {
            match line {
                Ok(line) => eprintln!("ebpf-tracker-agent collector: {line}"),
                Err(error) => {
                    let _ = sender.send(CollectorEvent::Error(format!(
                        "collector diagnostics failed: {error}"
                    )));
                    break;
                }
            }
        }
    });
    let result = supervise(
        collector_pid,
        &directory.path,
        &receiver,
        &output,
        Duration::from_secs(options.shutdown_timeout),
        STARTUP_TIMEOUT,
    );
    let out_result = out_thread.join();
    let err_result = err_thread.join();
    if out_result.is_err() || err_result.is_err() {
        return Err("collector output thread failed".into());
    }
    // The reader may report its final write error after waitpid observes the
    // collector exit. Joining closes that race before accepting the capture.
    for event in receiver.try_iter() {
        if let CollectorEvent::Error(error) = event {
            return Err(error);
        }
    }
    output
        .lock()
        .map_err(|_| "capture writer lock failed")?
        .sync_all()
        .map_err(|error| format!("cannot flush capture: {error}"))?;
    result
}

fn inherited_descriptor(fd: i32) -> io::Result<OwnedFd> {
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD, 3) };
    if duplicate < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(duplicate) })
}

fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn write_number(path: &Path, value: i32) -> io::Result<()> {
    let temporary = path.with_extension("tmp");
    write_private(&temporary, value.to_string().as_bytes())?;
    fs::rename(temporary, path)
}

fn optional_number(path: &Path) -> Result<Option<i32>, String> {
    match fs::read_to_string(path) {
        Ok(value) => value
            .parse::<i32>()
            .map(Some)
            .map_err(|_| "invalid private workload status".into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("cannot read private workload status: {error}")),
    }
}

enum CollectorEvent {
    Ready,
    Scope(i32),
    Error(String),
}

fn read_collector(
    reader: impl io::Read,
    output: Arc<Mutex<File>>,
    sender: mpsc::Sender<CollectorEvent>,
) {
    for line in BufReader::new(reader).lines() {
        let line = match line {
            Ok(line) => line,
            Err(error) => {
                let _ = sender.send(CollectorEvent::Error(format!(
                    "collector stream failed: {error}"
                )));
                return;
            }
        };
        if line == READY {
            let _ = sender.send(CollectorEvent::Ready);
            continue;
        }
        if let Some(pid) = line
            .strip_prefix(SCOPE)
            .and_then(|value| value.parse::<i32>().ok())
        {
            let _ = sender.send(CollectorEvent::Scope(pid));
            continue;
        }
        if let Some(record) = stream_record_for_line(&line) {
            if let Err(error) = write_record(&output, &record) {
                let _ = sender.send(CollectorEvent::Error(format!(
                    "cannot write capture: {error}"
                )));
                return;
            }
        } else if !line.trim().is_empty() {
            eprintln!("ebpf-tracker-agent collector: {line}");
        }
    }
}

fn write_record(output: &Mutex<File>, record: &StreamRecord) -> io::Result<()> {
    let mut file = output
        .lock()
        .map_err(|_| io::Error::other("capture writer lock failed"))?;
    serde_json::to_writer(&mut *file, record)?;
    file.write_all(b"\n")?;
    file.flush()
}

fn session_record() -> StreamRecord {
    StreamRecord::Session {
        timestamp_unix_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64,
        demo_name: "application".into(),
        product_name: "ebpf-tracker-agent".into(),
        product_tagline: Some("Scoped application syscall capture".into()),
        sponsor_name: None,
        sponsor_message: None,
        sponsor_url: None,
    }
}

fn signal_group(pid: Option<i32>, signal: i32) {
    if let Some(pid) = pid.filter(|pid| *pid > 1) {
        unsafe {
            libc::kill(-pid, signal);
        }
    }
}

fn signal_adopted_children(
    collector: i32,
    signal: i32,
    app_group: Option<i32>,
    sent: &mut HashSet<(i32, i32)>,
) {
    let children = format!("/proc/self/task/{}/children", std::process::id());
    if let Ok(children) = fs::read_to_string(children) {
        for pid in children
            .split_whitespace()
            .filter_map(|value| value.parse::<i32>().ok())
        {
            let covered_by_app_group = app_group.is_some_and(|group| {
                sent.contains(&(group, signal)) && unsafe { libc::getpgid(pid) } == group
            });
            if pid > 1 && pid != collector && !covered_by_app_group && sent.insert((pid, signal)) {
                unsafe {
                    libc::kill(pid, signal);
                }
            }
        }
    }
}

fn reap(collector: i32, collector_status: &mut Option<i32>) -> Result<bool, String> {
    loop {
        let mut status = 0;
        let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
        if pid > 0 {
            if pid == collector {
                *collector_status = Some(if libc::WIFEXITED(status) {
                    libc::WEXITSTATUS(status)
                } else {
                    128 + libc::WTERMSIG(status)
                });
            }
        } else if pid == 0 {
            return Ok(true);
        } else {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ECHILD) {
                return Ok(false);
            }
            if error.raw_os_error() != Some(libc::EINTR) {
                return Err(format!("cannot reap runtime children: {error}"));
            }
        }
    }
}

fn supervise(
    collector: i32,
    directory: &Path,
    receiver: &mpsc::Receiver<CollectorEvent>,
    output: &Mutex<File>,
    timeout: Duration,
    startup_timeout: Duration,
) -> Result<i32, String> {
    let started = Instant::now();
    let mut ready = false;
    let mut scope_pid = None;
    let mut released = false;
    let mut app_pid = None;
    let mut app_status = None;
    let mut collector_status = None;
    let mut failure = None;
    let mut stop_signal = None;
    let mut stopping = None;
    let mut collector_interrupt = None;
    let mut app_completion = None;
    let mut sent_signals = HashSet::new();
    loop {
        let now = Instant::now();
        for event in receiver.try_iter() {
            match event {
                CollectorEvent::Ready => ready = true,
                CollectorEvent::Scope(pid) => scope_pid = Some(pid),
                CollectorEvent::Error(error) => {
                    failure.get_or_insert(error);
                }
            }
        }
        let signal = SIGNAL.swap(0, Ordering::SeqCst);
        if signal != 0 && stop_signal.is_none() {
            stop_signal = Some(signal);
        }
        match optional_number(&directory.join("app-pid")) {
            Ok(pid) => app_pid = pid.or(app_pid),
            Err(error) => {
                failure.get_or_insert(error);
            }
        }
        let children_remain = match reap(collector, &mut collector_status) {
            Ok(remain) => remain,
            Err(error) => {
                failure.get_or_insert(error);
                true
            }
        };
        // Read the handoff after reaping: a fast workload can finish between a
        // prior read and waitpid, and its already-written status must win.
        match optional_number(&directory.join("status")) {
            Ok(status) => {
                if status.is_some_and(|code| !(0..=255).contains(&code)) {
                    failure.get_or_insert("invalid workload exit status".into());
                } else {
                    app_status = status.or(app_status);
                }
            }
            Err(error) => {
                failure.get_or_insert(error);
            }
        }
        if let Some(code) = collector_status {
            if code != 0 && collector_interrupt.is_none() && stop_signal.is_none() {
                failure.get_or_insert(format!("bpftrace failed with status {code}; check tracing permissions, tracefs, and host PID namespace"));
            }
            if app_status.is_none() && stop_signal.is_none() {
                failure.get_or_insert(
                    "collector exited without a workload status; the capture is incomplete".into(),
                );
            }
        }
        if !released && started.elapsed() >= startup_timeout && stop_signal.is_none() {
            failure.get_or_insert("tracing readiness/scope handshake timed out; the application was not released (requires the Linux host PID namespace)".into());
        }
        if !released
            && ready
            && failure.is_none()
            && stop_signal.is_none()
            && collector_status.is_none()
        {
            match optional_number(&directory.join("helper-pid")) {
                Ok(Some(pid)) if Some(pid) == scope_pid && pid > 1 => {
                    let result = write_record(output, &session_record())
                        .and_then(|_| write_private(&directory.join("go"), b"ready"));
                    match result {
                        Ok(()) => {
                            released = true;
                            eprintln!(
                                "ebpf-tracker-agent: tracing ready; starting non-root application"
                            );
                        }
                        Err(error) => {
                            failure
                                .get_or_insert(format!("cannot release traced workload: {error}"));
                        }
                    }
                }
                Ok(Some(_)) if scope_pid.is_some() => {
                    failure.get_or_insert(
                        "kernel/workload PID mismatch; this alpha requires host PID namespace"
                            .into(),
                    );
                }
                Err(error) => {
                    failure.get_or_insert(error);
                }
                _ => {}
            }
        }
        if (failure.is_some() || stop_signal.is_some()) && stopping.is_none() {
            stopping = Some(now);
            let signal = stop_signal.unwrap_or(libc::SIGTERM);
            let _ = write_number(&directory.join("stop"), signal);
        }
        if let Some(stop_started) = stopping {
            let signal = if now.duration_since(stop_started) >= timeout {
                libc::SIGKILL
            } else {
                stop_signal.unwrap_or(libc::SIGTERM)
            };
            if let Some(pid) = app_pid {
                if sent_signals.insert((pid, signal)) {
                    signal_group(Some(pid), signal);
                }
            }
            signal_adopted_children(collector, signal, app_pid, &mut sent_signals);
            // Keep the helper alive long enough to reap SIGKILL and record 137.
            // Interrupting bpftrace immediately could kill that handoff first.
            let handoff_expired =
                now.duration_since(stop_started) >= timeout + Duration::from_secs(2);
            if app_pid.is_none() || app_status.is_some() || handoff_expired {
                if handoff_expired && app_status.is_none() && app_pid.is_some() {
                    failure.get_or_insert(
                        "workload did not publish an exit status after forced shutdown".into(),
                    );
                }
                if collector_interrupt.is_none() {
                    signal_group(Some(collector), libc::SIGINT);
                    collector_interrupt = Some(now);
                }
            }
        }
        if app_status.is_some() {
            let completed = *app_completion.get_or_insert(now);
            let signal = if now.duration_since(completed) >= timeout {
                libc::SIGKILL
            } else {
                libc::SIGTERM
            };
            if let Some(pid) = app_pid {
                if sent_signals.insert((pid, signal)) {
                    signal_group(Some(pid), signal);
                }
            }
            signal_adopted_children(collector, signal, app_pid, &mut sent_signals);
            if collector_status.is_none()
                && now.duration_since(completed) >= Duration::from_secs(2)
                && collector_interrupt.is_none()
            {
                signal_group(Some(collector), libc::SIGINT);
                collector_interrupt = Some(now);
            }
        }
        if collector_interrupt.is_some_and(|at| now.duration_since(at) >= Duration::from_secs(3))
            && collector_status.is_none()
        {
            signal_group(Some(collector), libc::SIGKILL);
            failure.get_or_insert("collector did not stop and flush within its deadline".into());
        }
        if collector_status.is_some() && !children_remain {
            break;
        }
        thread::sleep(POLL);
    }
    if let Some(error) = failure {
        Err(error)
    } else {
        app_status
            .or_else(|| stop_signal.map(|signal| 128 + signal))
            .ok_or_else(|| "missing workload exit status".into())
    }
}

extern "C" fn receive_signal(signal: i32) {
    let _ = SIGNAL.compare_exchange(0, signal, Ordering::SeqCst, Ordering::SeqCst);
}
struct SignalGuard {
    previous: Vec<(i32, libc::sigaction)>,
}
impl SignalGuard {
    fn install() -> io::Result<Self> {
        SIGNAL.store(0, Ordering::SeqCst);
        let mut guard = Self {
            previous: Vec::new(),
        };
        for signal in [libc::SIGINT, libc::SIGTERM] {
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            action.sa_sigaction = receive_signal as usize;
            action.sa_flags = libc::SA_RESTART;
            unsafe {
                libc::sigemptyset(&mut action.sa_mask);
            }
            let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
            if unsafe { libc::sigaction(signal, &action, &mut old) } < 0 {
                return Err(io::Error::last_os_error());
            }
            guard.previous.push((signal, old));
        }
        Ok(guard)
    }
}
impl Drop for SignalGuard {
    fn drop(&mut self) {
        for (signal, old) in &self.previous {
            unsafe {
                libc::sigaction(*signal, old, std::ptr::null_mut());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_collector(script: &str, directory: &Path) -> i32 {
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", script, "mock-collector"])
            .arg(directory)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        command.spawn().unwrap().id() as i32
    }

    #[test]
    fn ready_gate_precedes_workload_and_fast_exit_status_is_preserved() {
        let _lock = PROCESS_TESTS.lock().unwrap();
        let _signals = SignalGuard::install().unwrap();
        let directory = RunDirectory::new().unwrap();
        let output =
            Mutex::new(permissions::create_capture(&directory.path.join("capture.jsonl")).unwrap());
        let collector = mock_collector("while [ ! -f \"$1/go\" ]; do sleep 0.01; done; printf 23 > \"$1/status.tmp\"; mv \"$1/status.tmp\" \"$1/status\"", &directory.path);
        write_number(&directory.path.join("helper-pid"), collector).unwrap();
        let (sender, receiver) = mpsc::channel();
        sender.send(CollectorEvent::Ready).unwrap();
        sender.send(CollectorEvent::Scope(collector)).unwrap();
        let status = supervise(
            collector,
            &directory.path,
            &receiver,
            &output,
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(status, 23);
        assert!(directory.path.join("go").exists());
        let capture = fs::read_to_string(directory.path.join("capture.jsonl")).unwrap();
        assert!(capture.contains("\"type\":\"session\""));
    }

    #[test]
    fn collector_exit_without_status_is_a_failure() {
        let _lock = PROCESS_TESTS.lock().unwrap();
        let _signals = SignalGuard::install().unwrap();
        let directory = RunDirectory::new().unwrap();
        let output =
            Mutex::new(permissions::create_capture(&directory.path.join("capture.jsonl")).unwrap());
        let collector = mock_collector("exit 0", &directory.path);
        let (_sender, receiver) = mpsc::channel();
        let error = supervise(
            collector,
            &directory.path,
            &receiver,
            &output,
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .unwrap_err();
        assert!(error.contains("without a workload status"));
        assert!(!directory.path.join("go").exists());
    }

    #[test]
    fn missing_or_mismatched_scope_never_releases_workload() {
        let _lock = PROCESS_TESTS.lock().unwrap();
        for wrong_scope in [false, true] {
            let _signals = SignalGuard::install().unwrap();
            let directory = RunDirectory::new().unwrap();
            let output = Mutex::new(
                permissions::create_capture(&directory.path.join("capture.jsonl")).unwrap(),
            );
            let collector = mock_collector("exec sleep 30", &directory.path);
            write_number(&directory.path.join("helper-pid"), collector).unwrap();
            let (sender, receiver) = mpsc::channel();
            sender.send(CollectorEvent::Ready).unwrap();
            if wrong_scope {
                sender.send(CollectorEvent::Scope(collector + 1)).unwrap();
            }
            assert!(supervise(
                collector,
                &directory.path,
                &receiver,
                &output,
                Duration::from_secs(1),
                Duration::from_millis(80)
            )
            .is_err());
            assert!(!directory.path.join("go").exists());
        }
    }

    #[test]
    fn collector_protocol_is_not_written_as_user_events() {
        let directory = RunDirectory::new().unwrap();
        let path = directory.path.join("capture.jsonl");
        let output = Arc::new(Mutex::new(permissions::create_capture(&path).unwrap()));
        let (sender, receiver) = mpsc::channel();
        read_collector(
            format!("{READY}\n{SCOPE}123\nopenat comm=api pid=124 file=/app/data\n").as_bytes(),
            output,
            sender,
        );
        assert!(matches!(receiver.recv().unwrap(), CollectorEvent::Ready));
        assert!(matches!(
            receiver.recv().unwrap(),
            CollectorEvent::Scope(123)
        ));
        let lines = fs::read_to_string(path).unwrap();
        let records: Vec<StreamRecord> = lines
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(records.len(), 1);
        assert!(matches!(records[0], StreamRecord::Syscall { .. }));
    }

    #[test]
    fn write_failures_are_reported_instead_of_silent_capture_success() {
        let output = Arc::new(Mutex::new(
            OpenOptions::new().write(true).open("/dev/full").unwrap(),
        ));
        let (sender, receiver) = mpsc::channel();
        read_collector(
            "write comm=api pid=124 bytes=1\n".as_bytes(),
            output,
            sender,
        );
        assert!(matches!(receiver.recv().unwrap(), CollectorEvent::Error(_)));
    }
}
