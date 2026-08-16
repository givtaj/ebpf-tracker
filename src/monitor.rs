use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const DEFAULT_INTERVAL_MS: u64 = 2_000;
const DEFAULT_TOP_LIMIT: usize = 6;
const DEFAULT_CONTAINER_LIMIT: usize = 5;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(2);
const ROOT_MOUNT: &str = "/";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MonitorArgs {
    pub(crate) interval_ms: u64,
    pub(crate) samples: Option<usize>,
    pub(crate) clear_screen: bool,
}

impl Default for MonitorArgs {
    fn default() -> Self {
        Self {
            interval_ms: DEFAULT_INTERVAL_MS,
            samples: None,
            clear_screen: true,
        }
    }
}

pub(crate) fn parse_monitor_args(args: &[String]) -> Result<MonitorArgs, String> {
    let has_once = args.iter().any(|arg| arg == "--once");
    let has_samples = args
        .iter()
        .any(|arg| arg == "--samples" || arg.starts_with("--samples="));
    if has_once && has_samples {
        return Err("--once and --samples cannot be combined".to_string());
    }

    let mut parsed = MonitorArgs::default();
    let mut index = 0usize;

    while index < args.len() {
        let arg = &args[index];
        match arg.as_str() {
            "--once" => {
                parsed.samples = Some(1);
                index += 1;
            }
            "--no-clear" => {
                parsed.clear_screen = false;
                index += 1;
            }
            "--interval-ms" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "missing value for --interval-ms".to_string())?;
                parsed.interval_ms = parse_positive_u64(value, "--interval-ms")?;
                index += 2;
            }
            "--samples" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "missing value for --samples".to_string())?;
                parsed.samples = Some(parse_positive_usize(value, "--samples")?);
                index += 2;
            }
            _ if arg.starts_with("--interval-ms=") => {
                let value = arg.trim_start_matches("--interval-ms=");
                parsed.interval_ms = parse_positive_u64(value, "--interval-ms")?;
                index += 1;
            }
            _ if arg.starts_with("--samples=") => {
                let value = arg.trim_start_matches("--samples=");
                parsed.samples = Some(parse_positive_usize(value, "--samples")?);
                index += 1;
            }
            _ if arg.starts_with('-') => return Err(format!("unknown monitor flag: {arg}")),
            _ => {
                return Err(format!(
                    "monitor does not accept positional arguments: {arg}"
                ))
            }
        }
    }

    Ok(parsed)
}

pub(crate) fn run_monitor(args: MonitorArgs) -> Result<i32, String> {
    let mut previous = Baseline::read();
    let interval = Duration::from_millis(args.interval_ms);
    let mut rendered = 0usize;

    loop {
        thread::sleep(interval);
        let snapshot = DropletSnapshot::read(previous.as_ref());
        previous = Some(snapshot.baseline.clone());
        let final_sample = args.samples.is_some_and(|limit| rendered + 1 >= limit);
        render_to_stdout(&snapshot, args.clear_screen, !final_sample)?;
        rendered += 1;

        if args.samples.is_some_and(|limit| rendered >= limit) {
            break;
        }
    }

    Ok(0)
}

fn parse_positive_u64(value: &str, flag: &str) -> Result<u64, String> {
    let parsed = value
        .parse::<u64>()
        .map_err(|_| format!("invalid value for {flag}: {value}"))?;
    if parsed == 0 {
        return Err(format!("{flag} must be greater than zero"));
    }
    Ok(parsed)
}

fn parse_positive_usize(value: &str, flag: &str) -> Result<usize, String> {
    let parsed = value
        .parse::<usize>()
        .map_err(|_| format!("invalid value for {flag}: {value}"))?;
    if parsed == 0 {
        return Err(format!("{flag} must be greater than zero"));
    }
    Ok(parsed)
}

#[derive(Clone, Debug)]
struct Baseline {
    cpu: Option<CpuTimes>,
    processes: HashMap<u32, ProcessSample>,
}

impl Baseline {
    fn read() -> Option<Self> {
        Some(Self {
            cpu: read_cpu_times(),
            processes: read_process_samples(),
        })
    }
}

#[derive(Clone, Debug)]
struct DropletSnapshot {
    baseline: Baseline,
    hostname: String,
    timestamp_unix_ms: u128,
    uptime_seconds: u64,
    load: LoadAverage,
    cpu_percent: Option<f64>,
    memory: Option<MemorySnapshot>,
    disk: Option<DiskSnapshot>,
    process_count: usize,
    top_cpu: Vec<ProcessView>,
    top_memory: Vec<ProcessView>,
    ebpf: EbpfSnapshot,
    containers: ContainerSnapshot,
}

impl DropletSnapshot {
    fn read(previous: Option<&Baseline>) -> Self {
        let current_cpu = read_cpu_times();
        let current_processes = read_process_samples();
        let process_count = count_processes();
        let cpu_percent = previous
            .and_then(|baseline| baseline.cpu.as_ref().zip(current_cpu.as_ref()))
            .and_then(|(before, after)| calculate_cpu_percent(before, after));
        let top_cpu = previous
            .map(|baseline| {
                top_cpu_processes(
                    &baseline.processes,
                    &current_processes,
                    cpu_delta(previous, current_cpu.as_ref()),
                )
            })
            .unwrap_or_default();
        let top_memory = top_memory_processes(&current_processes);

        Self {
            baseline: Baseline {
                cpu: current_cpu,
                processes: current_processes,
            },
            hostname: read_hostname(),
            timestamp_unix_ms: now_unix_ms(),
            uptime_seconds: read_uptime_seconds().unwrap_or_default(),
            load: read_load_average().unwrap_or_default(),
            cpu_percent,
            memory: read_memory_snapshot(),
            disk: read_disk_snapshot(ROOT_MOUNT),
            process_count,
            top_cpu,
            top_memory,
            ebpf: read_ebpf_snapshot(),
            containers: read_container_snapshot(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct CpuTimes {
    total: u64,
    idle: u64,
}

#[derive(Clone, Debug)]
struct ProcessSample {
    pid: u32,
    comm: String,
    state: String,
    cpu_ticks: u64,
    rss_bytes: u64,
}

#[derive(Clone, Debug)]
struct ProcessView {
    pid: u32,
    comm: String,
    state: String,
    cpu_percent: Option<f64>,
    rss_bytes: u64,
}

#[derive(Clone, Copy, Debug, Default)]
struct LoadAverage {
    one: f64,
    five: f64,
    fifteen: f64,
}

#[derive(Clone, Copy, Debug)]
struct MemorySnapshot {
    total_bytes: u64,
    available_bytes: u64,
    swap_total_bytes: u64,
    swap_free_bytes: u64,
}

impl MemorySnapshot {
    fn used_bytes(self) -> u64 {
        self.total_bytes.saturating_sub(self.available_bytes)
    }

    fn used_percent(self) -> f64 {
        percent(self.used_bytes(), self.total_bytes)
    }

    fn swap_used_bytes(self) -> u64 {
        self.swap_total_bytes.saturating_sub(self.swap_free_bytes)
    }
}

#[derive(Clone, Debug)]
struct DiskSnapshot {
    mount: String,
    total_bytes: u64,
    used_bytes: u64,
    available_bytes: u64,
}

impl DiskSnapshot {
    fn used_percent(&self) -> f64 {
        percent(
            self.used_bytes,
            self.used_bytes.saturating_add(self.available_bytes),
        )
    }
}

#[derive(Clone, Debug)]
struct EbpfSnapshot {
    btf_available: bool,
    prog_count: ToolCount,
    map_count: ToolCount,
    perf_event_paranoid: Option<i64>,
}

#[derive(Clone, Debug)]
enum ToolCount {
    Available(usize),
    Unavailable(String),
}

#[derive(Clone, Debug)]
struct ContainerSnapshot {
    status: String,
    containers: Vec<ContainerView>,
}

#[derive(Clone, Debug)]
struct ContainerView {
    name: String,
    status: String,
}

fn read_cpu_times() -> Option<CpuTimes> {
    let content = fs::read_to_string("/proc/stat").ok()?;
    let first = content.lines().next()?;
    let mut values = first
        .split_whitespace()
        .skip(1)
        .filter_map(|value| value.parse::<u64>().ok());

    let user = values.next()?;
    let nice = values.next()?;
    let system = values.next()?;
    let idle = values.next()?;
    let iowait = values.next().unwrap_or(0);
    let irq = values.next().unwrap_or(0);
    let softirq = values.next().unwrap_or(0);
    let steal = values.next().unwrap_or(0);
    let total = user + nice + system + idle + iowait + irq + softirq + steal;

    Some(CpuTimes {
        total,
        idle: idle + iowait,
    })
}

fn calculate_cpu_percent(before: &CpuTimes, after: &CpuTimes) -> Option<f64> {
    let total_delta = after.total.checked_sub(before.total)?;
    if total_delta == 0 {
        return None;
    }
    let idle_delta = after.idle.saturating_sub(before.idle);
    Some(percent(total_delta.saturating_sub(idle_delta), total_delta))
}

fn cpu_delta(previous: Option<&Baseline>, current: Option<&CpuTimes>) -> Option<u64> {
    previous
        .and_then(|baseline| baseline.cpu.as_ref().zip(current))
        .and_then(|(before, after)| after.total.checked_sub(before.total))
        .filter(|delta| *delta > 0)
}

fn read_process_samples() -> HashMap<u32, ProcessSample> {
    let mut samples = HashMap::new();
    let page_size = page_size_bytes();
    let Ok(entries) = fs::read_dir("/proc") else {
        return samples;
    };

    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        let stat_path = entry.path().join("stat");
        let Some(sample) = read_process_sample(pid, &stat_path, page_size) else {
            continue;
        };
        samples.insert(pid, sample);
    }

    samples
}

fn read_process_sample(pid: u32, stat_path: &Path, page_size: u64) -> Option<ProcessSample> {
    let content = fs::read_to_string(stat_path).ok()?;
    let open = content.find('(')?;
    let close = content.rfind(')')?;
    if close <= open {
        return None;
    }
    let comm = content[open + 1..close].to_string();
    let fields: Vec<&str> = content[close + 1..].split_whitespace().collect();
    let state = fields.first()?.to_string();
    let utime = fields.get(11)?.parse::<u64>().ok()?;
    let stime = fields.get(12)?.parse::<u64>().ok()?;
    let rss_pages = fields.get(21)?.parse::<i64>().ok()?.max(0) as u64;

    Some(ProcessSample {
        pid,
        comm,
        state,
        cpu_ticks: utime + stime,
        rss_bytes: rss_pages.saturating_mul(page_size),
    })
}

fn count_processes() -> usize {
    fs::read_dir("/proc")
        .ok()
        .into_iter()
        .flatten()
        .flatten()
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u32>().ok())
                .is_some()
        })
        .count()
}

fn top_cpu_processes(
    previous: &HashMap<u32, ProcessSample>,
    current: &HashMap<u32, ProcessSample>,
    total_cpu_delta: Option<u64>,
) -> Vec<ProcessView> {
    let mut processes: Vec<ProcessView> = current
        .values()
        .filter_map(|sample| {
            let before = previous.get(&sample.pid)?;
            let process_delta = sample.cpu_ticks.saturating_sub(before.cpu_ticks);
            if process_delta == 0 {
                return None;
            }
            let cpu_percent = total_cpu_delta.map(|total| percent(process_delta, total));
            Some(ProcessView {
                pid: sample.pid,
                comm: sample.comm.clone(),
                state: sample.state.clone(),
                cpu_percent,
                rss_bytes: sample.rss_bytes,
            })
        })
        .collect();

    processes.sort_by(|left, right| {
        right
            .cpu_percent
            .partial_cmp(&left.cpu_percent)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    processes.truncate(DEFAULT_TOP_LIMIT);
    processes
}

fn top_memory_processes(current: &HashMap<u32, ProcessSample>) -> Vec<ProcessView> {
    let mut processes: Vec<ProcessView> = current
        .values()
        .map(|sample| ProcessView {
            pid: sample.pid,
            comm: sample.comm.clone(),
            state: sample.state.clone(),
            cpu_percent: None,
            rss_bytes: sample.rss_bytes,
        })
        .collect();

    processes.sort_by_key(|process| std::cmp::Reverse(process.rss_bytes));
    processes.truncate(DEFAULT_TOP_LIMIT);
    processes
}

fn read_memory_snapshot() -> Option<MemorySnapshot> {
    let content = fs::read_to_string("/proc/meminfo").ok()?;
    let mut values = HashMap::new();

    for line in content.lines() {
        let mut parts = line.split_whitespace();
        let Some(key) = parts.next() else {
            continue;
        };
        let Some(value) = parts.next().and_then(|raw| raw.parse::<u64>().ok()) else {
            continue;
        };
        values.insert(
            key.trim_end_matches(':').to_string(),
            value.saturating_mul(1024),
        );
    }

    Some(MemorySnapshot {
        total_bytes: *values.get("MemTotal")?,
        available_bytes: *values.get("MemAvailable")?,
        swap_total_bytes: *values.get("SwapTotal").unwrap_or(&0),
        swap_free_bytes: *values.get("SwapFree").unwrap_or(&0),
    })
}

fn read_disk_snapshot(mount: &str) -> Option<DiskSnapshot> {
    let output = run_command_output("df", &["-kP", mount])?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout.lines().nth(1)?;
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 6 {
        return None;
    }
    let total_kib = fields.get(1)?.parse::<u64>().ok()?;
    let used_kib = fields.get(2)?.parse::<u64>().ok()?;
    let available_kib = fields.get(3)?.parse::<u64>().ok()?;

    Some(DiskSnapshot {
        mount: fields[5].to_string(),
        total_bytes: total_kib.saturating_mul(1024),
        used_bytes: used_kib.saturating_mul(1024),
        available_bytes: available_kib.saturating_mul(1024),
    })
}

fn read_load_average() -> Option<LoadAverage> {
    let content = fs::read_to_string("/proc/loadavg").ok()?;
    let mut parts = content.split_whitespace();
    Some(LoadAverage {
        one: parts.next()?.parse::<f64>().ok()?,
        five: parts.next()?.parse::<f64>().ok()?,
        fifteen: parts.next()?.parse::<f64>().ok()?,
    })
}

fn read_uptime_seconds() -> Option<u64> {
    let content = fs::read_to_string("/proc/uptime").ok()?;
    let raw = content.split_whitespace().next()?;
    raw.parse::<f64>().ok().map(|seconds| seconds as u64)
}

fn read_hostname() -> String {
    fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|value| value.trim().to_string())
        .unwrap_or_else(|_| "unknown-host".to_string())
}

fn read_ebpf_snapshot() -> EbpfSnapshot {
    EbpfSnapshot {
        btf_available: Path::new("/sys/kernel/btf/vmlinux").is_file(),
        prog_count: count_bpftool_objects("prog"),
        map_count: count_bpftool_objects("map"),
        perf_event_paranoid: fs::read_to_string("/proc/sys/kernel/perf_event_paranoid")
            .ok()
            .and_then(|value| value.trim().parse::<i64>().ok()),
    }
}

fn count_bpftool_objects(kind: &str) -> ToolCount {
    let args = [kind, "show"];
    match run_command_text("bpftool", &args)
        .or_else(|| run_command_text("sudo", &["-n", "bpftool", kind, "show"]))
    {
        Some(output) => ToolCount::Available(count_numbered_tool_rows(&output)),
        None => ToolCount::Unavailable("bpftool unavailable or needs interactive sudo".to_string()),
    }
}

fn count_numbered_tool_rows(output: &str) -> usize {
    output
        .lines()
        .filter(|line| {
            let Some((prefix, _)) = line.split_once(':') else {
                return false;
            };
            !prefix.is_empty() && prefix.chars().all(|ch| ch.is_ascii_digit())
        })
        .count()
}

fn read_container_snapshot() -> ContainerSnapshot {
    let args = ["ps", "--format", "{{.Names}}|{{.Status}}"];
    let output = run_command_text("docker", &args).or_else(|| {
        run_command_text(
            "sudo",
            &["-n", "docker", "ps", "--format", "{{.Names}}|{{.Status}}"],
        )
    });

    let Some(output) = output else {
        return ContainerSnapshot {
            status: "docker unavailable or needs interactive sudo".to_string(),
            containers: Vec::new(),
        };
    };

    let mut containers = Vec::new();
    for line in output.lines().filter(|line| !line.trim().is_empty()) {
        let (name, status) = line
            .split_once('|')
            .map(|(name, status)| (name.trim(), status.trim()))
            .unwrap_or((line.trim(), "unknown"));
        containers.push(ContainerView {
            name: name.to_string(),
            status: status.to_string(),
        });
    }

    ContainerSnapshot {
        status: if containers.is_empty() {
            "no running containers".to_string()
        } else {
            format!("{} running", containers.len())
        },
        containers,
    }
}

fn run_command_text(program: &str, args: &[&str]) -> Option<String> {
    let output = run_command_output(program, args)?;
    Some(String::from_utf8_lossy(&output.stdout).to_string())
}

fn run_command_output(program: &str, args: &[&str]) -> Option<Output> {
    let mut child = Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let deadline = Instant::now() + COMMAND_TIMEOUT;

    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                let output = child.wait_with_output().ok()?;
                return output.status.success().then_some(output);
            }
            Ok(None) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(20));
            }
            Ok(None) | Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

fn render_to_stdout(
    snapshot: &DropletSnapshot,
    clear_screen: bool,
    show_stop_hint: bool,
) -> Result<(), String> {
    let mut stdout = io::stdout();
    if clear_screen {
        stdout
            .write_all(b"\x1b[2J\x1b[H")
            .map_err(|err| format!("failed to clear terminal: {err}"))?;
    }
    stdout
        .write_all(render_snapshot(snapshot, show_stop_hint).as_bytes())
        .map_err(|err| format!("failed to write monitor output: {err}"))?;
    stdout
        .flush()
        .map_err(|err| format!("failed to flush monitor output: {err}"))
}

fn render_snapshot(snapshot: &DropletSnapshot, show_stop_hint: bool) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "ebpf-tracker monitor | host {} | unix_ms {}\n",
        truncate(&snapshot.hostname, 64),
        snapshot.timestamp_unix_ms
    ));
    out.push_str(&format!(
        "uptime {} | load {:.2} {:.2} {:.2} | processes {} | containers {}\n\n",
        format_duration(snapshot.uptime_seconds),
        snapshot.load.one,
        snapshot.load.five,
        snapshot.load.fifteen,
        snapshot.process_count,
        truncate(&snapshot.containers.status, 64)
    ));

    out.push_str("SYSTEM\n");
    let cpu_label = snapshot
        .cpu_percent
        .map(|value| format!("{:>5.1}%", value))
        .unwrap_or_else(|| "  n/a".to_string());
    out.push_str(&format!(
        "  cpu  [{}] {}\n",
        bar(snapshot.cpu_percent.unwrap_or(0.0), 28),
        cpu_label
    ));

    if let Some(memory) = snapshot.memory {
        out.push_str(&format!(
            "  mem  [{}] {:>5.1}%  used {} / total {}  avail {}\n",
            bar(memory.used_percent(), 28),
            memory.used_percent(),
            format_bytes(memory.used_bytes()),
            format_bytes(memory.total_bytes),
            format_bytes(memory.available_bytes)
        ));
        if memory.swap_total_bytes > 0 {
            out.push_str(&format!(
                "  swap [{}] {:>5.1}%  used {} / total {}\n",
                bar(
                    percent(memory.swap_used_bytes(), memory.swap_total_bytes),
                    28
                ),
                percent(memory.swap_used_bytes(), memory.swap_total_bytes),
                format_bytes(memory.swap_used_bytes()),
                format_bytes(memory.swap_total_bytes)
            ));
        }
    } else {
        out.push_str("  mem  unavailable\n");
    }

    if let Some(disk) = &snapshot.disk {
        out.push_str(&format!(
            "  disk [{}] {:>5.1}%  {} used {} / total {}  avail {}\n",
            bar(disk.used_percent(), 28),
            disk.used_percent(),
            truncate(&disk.mount, 48),
            format_bytes(disk.used_bytes),
            format_bytes(disk.total_bytes),
            format_bytes(disk.available_bytes)
        ));
    } else {
        out.push_str("  disk unavailable\n");
    }

    out.push_str("\neBPF\n");
    out.push_str(&format!(
        "  kernel BTF: {} | programs: {} | maps: {} | perf_event_paranoid: {}\n",
        if snapshot.ebpf.btf_available {
            "yes"
        } else {
            "no"
        },
        format_tool_count(&snapshot.ebpf.prog_count),
        format_tool_count(&snapshot.ebpf.map_count),
        snapshot
            .ebpf
            .perf_event_paranoid
            .map(|value| value.to_string())
            .unwrap_or_else(|| "n/a".to_string())
    ));

    out.push_str("\nCONTAINERS\n");
    if snapshot.containers.containers.is_empty() {
        out.push_str(&format!("  {}\n", snapshot.containers.status));
    } else {
        for container in snapshot
            .containers
            .containers
            .iter()
            .take(DEFAULT_CONTAINER_LIMIT)
        {
            out.push_str(&format!(
                "  {:<26} {}\n",
                truncate(&container.name, 26),
                truncate(&container.status, 48)
            ));
        }
        if snapshot.containers.containers.len() > DEFAULT_CONTAINER_LIMIT {
            out.push_str(&format!(
                "  ... {} more\n",
                snapshot.containers.containers.len() - DEFAULT_CONTAINER_LIMIT
            ));
        }
    }

    out.push_str("\nTOP CPU\n");
    if snapshot.top_cpu.is_empty() {
        out.push_str("  no process CPU deltas in this sample\n");
    } else {
        out.push_str(&render_process_table(&snapshot.top_cpu, true));
    }

    out.push_str("\nTOP MEMORY\n");
    if snapshot.top_memory.is_empty() {
        out.push_str("  no process memory data\n");
    } else {
        out.push_str(&render_process_table(&snapshot.top_memory, false));
    }

    if show_stop_hint {
        out.push_str("\nCtrl+C to stop. Use --once or --samples N for bounded output.\n");
    }
    out
}

fn render_process_table(processes: &[ProcessView], include_cpu: bool) -> String {
    let mut out = String::new();
    out.push_str("  pid      state cpu%   rss       comm\n");
    for process in processes {
        let cpu = if include_cpu {
            process
                .cpu_percent
                .map(|value| format!("{:>5.1}", value))
                .unwrap_or_else(|| "  n/a".to_string())
        } else {
            "    -".to_string()
        };
        out.push_str(&format!(
            "  {:<8} {:<5} {}  {:<9} {}\n",
            process.pid,
            truncate(&process.state, 5),
            cpu,
            format_bytes(process.rss_bytes),
            truncate(&process.comm, 34)
        ));
    }
    out
}

fn format_tool_count(count: &ToolCount) -> String {
    match count {
        ToolCount::Available(value) => value.to_string(),
        ToolCount::Unavailable(reason) => reason.clone(),
    }
}

fn page_size_bytes() -> u64 {
    const AT_PAGESZ: usize = 6;

    let page_size = (|| {
        let auxv = fs::read("/proc/self/auxv").ok()?;
        let word_size = std::mem::size_of::<usize>();
        for pair in auxv.chunks_exact(word_size * 2) {
            let key = usize::from_ne_bytes(pair[..word_size].try_into().ok()?);
            let value = usize::from_ne_bytes(pair[word_size..].try_into().ok()?);
            if key == AT_PAGESZ && value > 0 {
                return Some(value as u64);
            }
        }
        None
    })();

    page_size.unwrap_or(4096)
}

fn percent(numerator: u64, denominator: u64) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        (numerator as f64 / denominator as f64) * 100.0
    }
}

fn bar(percent_value: f64, width: usize) -> String {
    let clamped = percent_value.clamp(0.0, 100.0);
    let filled = ((clamped / 100.0) * width as f64).round() as usize;
    format!(
        "{}{}",
        "#".repeat(filled),
        "-".repeat(width.saturating_sub(filled))
    )
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0usize;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} {}", bytes, UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn format_duration(seconds: u64) -> String {
    let days = seconds / 86_400;
    let hours = (seconds % 86_400) / 3_600;
    let minutes = (seconds % 3_600) / 60;
    if days > 0 {
        format!("{days}d {hours}h {minutes}m")
    } else if hours > 0 {
        format!("{hours}h {minutes}m")
    } else {
        format!("{minutes}m")
    }
}

fn truncate(value: &str, max_chars: usize) -> String {
    let mut output = String::new();
    for ch in value.chars().take(max_chars) {
        output.push(if ch.is_control() { '?' } else { ch });
    }
    output
}

fn now_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{
        bar, format_bytes, page_size_bytes, parse_monitor_args, truncate, DiskSnapshot, MonitorArgs,
    };

    fn owned(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| arg.to_string()).collect()
    }

    #[test]
    fn parses_monitor_bounds_and_screen_options() {
        let parsed = parse_monitor_args(&owned(&[
            "--interval-ms",
            "250",
            "--samples=3",
            "--no-clear",
        ]))
        .expect("monitor args should parse");

        assert_eq!(
            parsed,
            MonitorArgs {
                interval_ms: 250,
                samples: Some(3),
                clear_screen: false,
            }
        );
    }

    #[test]
    fn monitor_once_maps_to_one_sample() {
        let parsed = parse_monitor_args(&owned(&["--once"])).expect("monitor args should parse");
        assert_eq!(parsed.samples, Some(1));
    }

    #[test]
    fn monitor_rejects_zero_interval() {
        let error = parse_monitor_args(&owned(&["--interval-ms=0"]))
            .expect_err("zero interval should fail");
        assert!(error.contains("greater than zero"));
    }

    #[test]
    fn monitor_rejects_conflicting_sample_limits() {
        let error = parse_monitor_args(&owned(&["--once", "--samples", "2"]))
            .expect_err("sample limit flags should be exclusive");
        assert!(error.contains("cannot be combined"));
    }

    #[test]
    fn renders_ascii_bar() {
        assert_eq!(bar(50.0, 10), "#####-----");
    }

    #[test]
    fn formats_binary_bytes() {
        assert_eq!(format_bytes(1536), "1.5 KiB");
    }

    #[test]
    fn disk_pressure_uses_space_available_to_unprivileged_users() {
        let disk = DiskSnapshot {
            mount: "/".to_string(),
            total_bytes: 100,
            used_bytes: 80,
            available_bytes: 10,
        };
        assert!((disk.used_percent() - 88.888).abs() < 0.01);
    }

    #[test]
    fn host_page_size_is_positive() {
        assert!(page_size_bytes() > 0);
    }

    #[test]
    fn sanitizes_terminal_control_characters() {
        assert_eq!(truncate("worker\x1b[2J\nnext", 11), "worker?[2J?");
    }
}
