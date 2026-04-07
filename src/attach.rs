use std::io::{self, BufRead, BufReader};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use ebpf_tracker_events::{stream_record_for_line, EventKind, StreamRecord};
use serde_json::Value;

const ATTACH_IG_CMD_ENV_NAME: &str = "EBPF_TRACKER_ATTACH_INSPEKTOR_GADGET_CMD";
const ATTACH_IG_TRACE_SET_ENV_NAME: &str = "EBPF_TRACKER_ATTACH_INSPEKTOR_GADGET_TRACE_SET";
const ATTACH_AWS_UPDATE_CMD_ENV_NAME: &str = "EBPF_TRACKER_ATTACH_AWS_UPDATE_CMD";
const ATTACH_KUBECTL_BIN_ENV_NAME: &str = "EBPF_TRACKER_ATTACH_KUBECTL_BIN";
const ATTACH_AWS_BIN_ENV_NAME: &str = "EBPF_TRACKER_ATTACH_AWS_BIN";
const ATTACH_ENV_PLATFORM: &str = "EBPF_TRACKER_ATTACH_PLATFORM";
const ATTACH_ENV_BACKEND: &str = "EBPF_TRACKER_ATTACH_BACKEND";
const ATTACH_ENV_NAMESPACE: &str = "EBPF_TRACKER_ATTACH_NAMESPACE";
const ATTACH_ENV_SELECTOR: &str = "EBPF_TRACKER_ATTACH_SELECTOR";
const ATTACH_ENV_POD: &str = "EBPF_TRACKER_ATTACH_POD";
const ATTACH_ENV_CLUSTER: &str = "EBPF_TRACKER_ATTACH_CLUSTER";
const ATTACH_ENV_REGION: &str = "EBPF_TRACKER_ATTACH_REGION";
const ATTACH_ENV_SERVICE: &str = "EBPF_TRACKER_ATTACH_SERVICE";
const ATTACH_ENV_TASK: &str = "EBPF_TRACKER_ATTACH_TASK";

#[derive(Clone, Copy)]
struct InspektorTraceSpec {
    subcommand: &'static str,
    kind: EventKind,
}

const DEFAULT_TRACE_SPECS: [InspektorTraceSpec; 4] = [
    InspektorTraceSpec {
        subcommand: "exec",
        kind: EventKind::Execve,
    },
    InspektorTraceSpec {
        subcommand: "open",
        kind: EventKind::OpenAt,
    },
    InspektorTraceSpec {
        subcommand: "write",
        kind: EventKind::Write,
    },
    InspektorTraceSpec {
        subcommand: "tcpconnect",
        kind: EventKind::Connect,
    },
];

struct AttachTraceCommand {
    label: String,
    default_kind: EventKind,
    command: Command,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AttachPlatform {
    Docker,
    Kubernetes,
    AwsEks,
    AwsEcs,
}

impl AttachPlatform {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            AttachPlatform::Docker => "docker",
            AttachPlatform::Kubernetes => "k8s",
            AttachPlatform::AwsEks => "aws-eks",
            AttachPlatform::AwsEcs => "aws-ecs",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AttachBackend {
    InspektorGadget,
    Tetragon,
}

impl AttachBackend {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            AttachBackend::InspektorGadget => "inspektor-gadget",
            AttachBackend::Tetragon => "tetragon",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AttachArgs {
    pub(crate) platform: AttachPlatform,
    pub(crate) backend: AttachBackend,
    pub(crate) namespace: Option<String>,
    pub(crate) selector: Option<String>,
    pub(crate) pod: Option<String>,
    pub(crate) cluster: Option<String>,
    pub(crate) region: Option<String>,
    pub(crate) service: Option<String>,
    pub(crate) task: Option<String>,
    pub(crate) container: Option<String>,
}

impl Default for AttachArgs {
    fn default() -> Self {
        Self {
            platform: AttachPlatform::Kubernetes,
            backend: AttachBackend::InspektorGadget,
            namespace: None,
            selector: None,
            pod: None,
            cluster: None,
            region: None,
            service: None,
            task: None,
            container: None,
        }
    }
}

#[derive(Debug)]
pub(crate) enum AttachParseOutcome {
    Help,
    Run(AttachArgs),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ResolvedAttachTarget {
    platform: AttachPlatform,
    backend: AttachBackend,
    namespace: Option<String>,
    selector: Option<String>,
    pod: Option<String>,
    cluster: Option<String>,
    region: Option<String>,
    service: Option<String>,
    task: Option<String>,
    container: Option<String>,
}

impl ResolvedAttachTarget {
    fn describe(&self) -> String {
        match self.platform {
            AttachPlatform::Docker => format!(
                "container {}",
                self.container.as_deref().unwrap_or("<missing-container>")
            ),
            AttachPlatform::Kubernetes => {
                let namespace = self.namespace.as_deref().unwrap_or("default");
                if let Some(pod) = self.pod.as_deref() {
                    format!("namespace {namespace}, pod {pod}")
                } else {
                    format!(
                        "namespace {namespace}, selector {}",
                        self.selector.as_deref().unwrap_or("<missing-selector>")
                    )
                }
            }
            AttachPlatform::AwsEks => {
                let mut parts = vec![format!(
                    "cluster {}",
                    self.cluster.as_deref().unwrap_or("<missing-cluster>")
                )];
                if let Some(region) = self.region.as_deref() {
                    parts.push(format!("region {region}"));
                }
                let namespace = self.namespace.as_deref().unwrap_or("default");
                parts.push(format!("namespace {namespace}"));
                if let Some(pod) = self.pod.as_deref() {
                    parts.push(format!("pod {pod}"));
                } else if let Some(selector) = self.selector.as_deref() {
                    parts.push(format!("selector {selector}"));
                }
                parts.join(", ")
            }
            AttachPlatform::AwsEcs => {
                let mut parts = vec![format!(
                    "cluster {}",
                    self.cluster.as_deref().unwrap_or("<missing-cluster>")
                )];
                if let Some(region) = self.region.as_deref() {
                    parts.push(format!("region {region}"));
                }
                if let Some(service) = self.service.as_deref() {
                    parts.push(format!("service {service}"));
                }
                if let Some(task) = self.task.as_deref() {
                    parts.push(format!("task {task}"));
                }
                parts.join(", ")
            }
        }
    }
}

impl AttachArgs {
    fn resolve(self) -> Result<ResolvedAttachTarget, String> {
        let resolved = ResolvedAttachTarget {
            platform: self.platform,
            backend: self.backend,
            namespace: normalized_option(self.namespace, "--namespace")?,
            selector: normalized_option(self.selector, "--selector")?,
            pod: normalized_option(self.pod, "--pod")?,
            cluster: normalized_option(self.cluster, "--cluster")?,
            region: normalized_option(self.region, "--region")?,
            service: normalized_option(self.service, "--service")?,
            task: normalized_option(self.task, "--task")?,
            container: normalized_option(self.container, "--container")?,
        };

        match resolved.platform {
            AttachPlatform::Docker => {
                if resolved.backend != AttachBackend::InspektorGadget {
                    return Err(
                        "docker attach currently only scaffolds the inspektor-gadget backend"
                            .to_string(),
                    );
                }
                require_present(resolved.container.as_deref(), "--container")?;
                reject_present(
                    resolved.namespace.as_deref(),
                    "--namespace",
                    resolved.platform,
                )?;
                reject_present(
                    resolved.selector.as_deref(),
                    "--selector",
                    resolved.platform,
                )?;
                reject_present(resolved.pod.as_deref(), "--pod", resolved.platform)?;
                reject_present(resolved.cluster.as_deref(), "--cluster", resolved.platform)?;
                reject_present(resolved.region.as_deref(), "--region", resolved.platform)?;
                reject_present(resolved.service.as_deref(), "--service", resolved.platform)?;
                reject_present(resolved.task.as_deref(), "--task", resolved.platform)?;
            }
            AttachPlatform::Kubernetes => {
                require_selector_or_pod(&resolved)?;
                reject_present(resolved.cluster.as_deref(), "--cluster", resolved.platform)?;
                reject_present(resolved.region.as_deref(), "--region", resolved.platform)?;
                reject_present(resolved.service.as_deref(), "--service", resolved.platform)?;
                reject_present(resolved.task.as_deref(), "--task", resolved.platform)?;
                reject_present(
                    resolved.container.as_deref(),
                    "--container",
                    resolved.platform,
                )?;
            }
            AttachPlatform::AwsEks => {
                require_present(resolved.cluster.as_deref(), "--cluster")?;
                require_selector_or_pod(&resolved)?;
                reject_present(resolved.service.as_deref(), "--service", resolved.platform)?;
                reject_present(resolved.task.as_deref(), "--task", resolved.platform)?;
                reject_present(
                    resolved.container.as_deref(),
                    "--container",
                    resolved.platform,
                )?;
            }
            AttachPlatform::AwsEcs => {
                if resolved.backend != AttachBackend::InspektorGadget {
                    return Err(
                        "aws-ecs attach currently only scaffolds the inspektor-gadget backend"
                            .to_string(),
                    );
                }
                require_present(resolved.cluster.as_deref(), "--cluster")?;
                if resolved.service.is_none() && resolved.task.is_none() {
                    return Err(
                        "aws-ecs attach requires either --service or --task to choose a workload"
                            .to_string(),
                    );
                }
                reject_present(
                    resolved.namespace.as_deref(),
                    "--namespace",
                    resolved.platform,
                )?;
                reject_present(
                    resolved.selector.as_deref(),
                    "--selector",
                    resolved.platform,
                )?;
                reject_present(resolved.pod.as_deref(), "--pod", resolved.platform)?;
                reject_present(
                    resolved.container.as_deref(),
                    "--container",
                    resolved.platform,
                )?;
            }
        }

        Ok(resolved)
    }
}

struct AttachPlan {
    approach: String,
    scope_notes: Vec<String>,
    repo_tasks: Vec<String>,
}

struct AttachReport {
    lines: Vec<String>,
}

impl AttachReport {
    fn print(&self) {
        for line in &self.lines {
            println!("{line}");
        }
    }
}

trait AttachBackendAdapter {
    fn plan(&self, target: &ResolvedAttachTarget) -> AttachPlan;
}

struct InspektorGadgetAdapter;
struct TetragonAdapter;

fn build_attach_plan(target: &ResolvedAttachTarget) -> AttachPlan {
    let adapter: &dyn AttachBackendAdapter = match target.backend {
        AttachBackend::InspektorGadget => &InspektorGadgetAdapter,
        AttachBackend::Tetragon => &TetragonAdapter,
    };
    adapter.plan(target)
}

fn build_attach_report(target: &ResolvedAttachTarget, plan: &AttachPlan) -> AttachReport {
    let mut lines = vec![
        "attach scaffold".to_string(),
        "status: experimental scaffold/plan mode; no live backend execution yet".to_string(),
        "this command prints a plan only and does not start tracing yet".to_string(),
        format!("platform: {}", target.platform.as_str()),
        format!("backend: {}", target.backend.as_str()),
        format!("target: {}", target.describe()),
        format!("integration approach: {}", plan.approach),
    ];

    for note in &plan.scope_notes {
        lines.push(format!("note: {note}"));
    }

    lines.push("next repo tasks:".to_string());
    for task in &plan.repo_tasks {
        lines.push(format!("- {task}"));
    }

    AttachReport { lines }
}

impl AttachBackendAdapter for InspektorGadgetAdapter {
    fn plan(&self, target: &ResolvedAttachTarget) -> AttachPlan {
        let approach = match target.platform {
            AttachPlatform::Docker => {
                "invoke `ig` on the Linux host and target the named Docker container".to_string()
            }
            AttachPlatform::Kubernetes => {
                "invoke `kubectl gadget` for the selected pod or label selector and normalize the events into the shared JSONL schema".to_string()
            }
            AttachPlatform::AwsEks => {
                "resolve AWS EKS cluster access, then invoke `kubectl gadget` for the selected workload and normalize the resulting events".to_string()
            }
            AttachPlatform::AwsEcs => {
                "resolve AWS ECS tasks on EC2-backed hosts, then run an `ig`-based host attach workflow and normalize the host-level events".to_string()
            }
        };

        let mut scope_notes = Vec::new();
        match target.platform {
            AttachPlatform::AwsEks => {
                scope_notes.push(
                    "AWS EKS first-wave scope is EC2-backed clusters only; Fargate is out of scope because host-level eBPF access is required".to_string(),
                );
            }
            AttachPlatform::AwsEcs => {
                scope_notes.push(
                    "AWS ECS first-wave scope is the EC2 launch type only; Fargate is out of scope because host-level eBPF access is required".to_string(),
                );
            }
            _ => {}
        }

        AttachPlan {
            approach,
            scope_notes,
            repo_tasks: vec![
                "expand live inspektor-gadget coverage beyond the first k8s/aws-eks execution path"
                    .to_string(),
                "map backend records into `ebpf-tracker-events` so dataset, viewer, and OTel stay backend-agnostic".to_string(),
                "add smoke coverage for platform-specific attach validation and error reporting"
                    .to_string(),
            ],
        }
    }
}

impl AttachBackendAdapter for TetragonAdapter {
    fn plan(&self, target: &ResolvedAttachTarget) -> AttachPlan {
        let approach = match target.platform {
            AttachPlatform::Kubernetes => {
                "subscribe to Tetragon JSON logs or gRPC for the selected workload and normalize those events into the shared JSONL schema".to_string()
            }
            AttachPlatform::AwsEks => {
                "resolve AWS EKS cluster access, then subscribe to Tetragon events for the selected workload and normalize the stream".to_string()
            }
            AttachPlatform::Docker | AttachPlatform::AwsEcs => {
                "Tetragon is scaffolded only for Kubernetes-style targets in this repo layout"
                    .to_string()
            }
        };

        let mut scope_notes = vec![
            "Tetragon should be treated as the long-running cluster attach backend, not the first local Docker path".to_string(),
        ];
        if target.platform == AttachPlatform::AwsEks {
            scope_notes.push(
                "AWS EKS first-wave scope is EC2-backed clusters only; Fargate is out of scope because host-level eBPF access is required".to_string(),
            );
        }

        AttachPlan {
            approach,
            scope_notes,
            repo_tasks: vec![
                "implement workload filtering and event subscription against a live Tetragon deployment"
                    .to_string(),
                "map Tetragon records into `ebpf-tracker-events` so downstream tooling can reuse the same schema".to_string(),
                "document operational differences between ad hoc attach and long-running cluster attach"
                    .to_string(),
            ],
        }
    }
}

pub(crate) fn parse_attach_args(args: &[String]) -> Result<AttachParseOutcome, String> {
    let Some(platform_raw) = args.first() else {
        return Err(
            "attach requires a target platform like docker, k8s, aws-eks, or aws-ecs".to_string(),
        );
    };

    if matches!(platform_raw.as_str(), "-h" | "--help") {
        return Ok(AttachParseOutcome::Help);
    }

    let mut parsed = AttachArgs {
        platform: parse_attach_platform(platform_raw)?,
        ..AttachArgs::default()
    };
    let mut index = 1usize;

    while index < args.len() {
        let arg = &args[index];
        match arg.as_str() {
            "-h" | "--help" => return Ok(AttachParseOutcome::Help),
            "--backend" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "missing value for --backend".to_string())?;
                parsed.backend = parse_attach_backend(value)?;
                index += 2;
            }
            "--namespace" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "missing value for --namespace".to_string())?;
                parsed.namespace = Some(parse_attach_value(value, "--namespace")?);
                index += 2;
            }
            "--selector" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "missing value for --selector".to_string())?;
                parsed.selector = Some(parse_attach_value(value, "--selector")?);
                index += 2;
            }
            "--pod" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "missing value for --pod".to_string())?;
                parsed.pod = Some(parse_attach_value(value, "--pod")?);
                index += 2;
            }
            "--cluster" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "missing value for --cluster".to_string())?;
                parsed.cluster = Some(parse_attach_value(value, "--cluster")?);
                index += 2;
            }
            "--region" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "missing value for --region".to_string())?;
                parsed.region = Some(parse_attach_value(value, "--region")?);
                index += 2;
            }
            "--service" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "missing value for --service".to_string())?;
                parsed.service = Some(parse_attach_value(value, "--service")?);
                index += 2;
            }
            "--task" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "missing value for --task".to_string())?;
                parsed.task = Some(parse_attach_value(value, "--task")?);
                index += 2;
            }
            "--container" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "missing value for --container".to_string())?;
                parsed.container = Some(parse_attach_value(value, "--container")?);
                index += 2;
            }
            _ if arg.starts_with("--backend=") => {
                parsed.backend = parse_attach_backend(arg.trim_start_matches("--backend="))?;
                index += 1;
            }
            _ if arg.starts_with("--namespace=") => {
                parsed.namespace = Some(parse_attach_value(
                    arg.trim_start_matches("--namespace="),
                    "--namespace",
                )?);
                index += 1;
            }
            _ if arg.starts_with("--selector=") => {
                parsed.selector = Some(parse_attach_value(
                    arg.trim_start_matches("--selector="),
                    "--selector",
                )?);
                index += 1;
            }
            _ if arg.starts_with("--pod=") => {
                parsed.pod = Some(parse_attach_value(arg.trim_start_matches("--pod="), "--pod")?);
                index += 1;
            }
            _ if arg.starts_with("--cluster=") => {
                parsed.cluster = Some(parse_attach_value(
                    arg.trim_start_matches("--cluster="),
                    "--cluster",
                )?);
                index += 1;
            }
            _ if arg.starts_with("--region=") => {
                parsed.region = Some(parse_attach_value(
                    arg.trim_start_matches("--region="),
                    "--region",
                )?);
                index += 1;
            }
            _ if arg.starts_with("--service=") => {
                parsed.service = Some(parse_attach_value(
                    arg.trim_start_matches("--service="),
                    "--service",
                )?);
                index += 1;
            }
            _ if arg.starts_with("--task=") => {
                parsed.task = Some(parse_attach_value(arg.trim_start_matches("--task="), "--task")?);
                index += 1;
            }
            _ if arg.starts_with("--container=") => {
                parsed.container = Some(parse_attach_value(
                    arg.trim_start_matches("--container="),
                    "--container",
                )?);
                index += 1;
            }
            _ if arg.starts_with('-') => return Err(format!("unknown attach flag: {arg}")),
            _ => {
                return Err(format!(
                    "unexpected attach argument: {arg}. use flags like --selector, --pod, or --container"
                ))
            }
        }
    }

    Ok(AttachParseOutcome::Run(parsed))
}

pub(crate) fn run_attach(args: AttachArgs) -> Result<i32, String> {
    let resolved = args.resolve()?;

    if is_live_inspektor_target(&resolved) {
        return run_live_inspektor_attach(&resolved);
    }

    let plan = build_attach_plan(&resolved);
    build_attach_report(&resolved, &plan).print();
    Ok(0)
}

fn is_live_inspektor_target(target: &ResolvedAttachTarget) -> bool {
    target.backend == AttachBackend::InspektorGadget
        && matches!(
            target.platform,
            AttachPlatform::Kubernetes | AttachPlatform::AwsEks
        )
}

fn run_live_inspektor_attach(target: &ResolvedAttachTarget) -> Result<i32, String> {
    ensure_inspektor_runtime_available(target)?;

    if target.platform == AttachPlatform::AwsEks {
        run_aws_eks_update_kubeconfig(target)?;
    }

    let mut trace_commands = build_inspektor_trace_commands(target)?;
    if trace_commands.len() == 1 {
        let trace = trace_commands
            .get_mut(0)
            .ok_or_else(|| "missing inspektor-gadget trace command".to_string())?;
        return run_attach_command(&mut trace.command, trace.default_kind);
    }

    run_attach_commands_parallel(trace_commands)
}

fn ensure_inspektor_runtime_available(target: &ResolvedAttachTarget) -> Result<(), String> {
    if read_nonempty_env(ATTACH_IG_CMD_ENV_NAME).is_some() {
        return Ok(());
    }

    let kubectl_bin =
        read_nonempty_env(ATTACH_KUBECTL_BIN_ENV_NAME).unwrap_or_else(|| "kubectl".to_string());

    check_command_status(
        &kubectl_bin,
        &["version", "--client"],
        "kubectl client preflight",
    )?;
    check_command_status(
        &kubectl_bin,
        &["gadget", "--help"],
        "kubectl gadget plugin preflight",
    )?;

    if target.platform == AttachPlatform::AwsEks
        && read_nonempty_env(ATTACH_AWS_UPDATE_CMD_ENV_NAME).is_none()
    {
        let aws_bin =
            read_nonempty_env(ATTACH_AWS_BIN_ENV_NAME).unwrap_or_else(|| "aws".to_string());
        check_command_status(&aws_bin, &["--version"], "aws CLI preflight")?;
    }

    Ok(())
}

fn build_inspektor_trace_commands(
    target: &ResolvedAttachTarget,
) -> Result<Vec<AttachTraceCommand>, String> {
    if let Some(override_command) = read_nonempty_env(ATTACH_IG_CMD_ENV_NAME) {
        let mut command = shell_command(&override_command);
        apply_attach_target_env(&mut command, target);
        return Ok(vec![AttachTraceCommand {
            label: "override".to_string(),
            default_kind: EventKind::Execve,
            command,
        }]);
    }

    let kubectl_bin =
        read_nonempty_env(ATTACH_KUBECTL_BIN_ENV_NAME).unwrap_or_else(|| "kubectl".to_string());
    let mut commands = Vec::new();
    let mut attempted = Vec::new();

    for spec in selected_trace_specs() {
        attempted.push(spec.subcommand.to_string());
        if !gadget_trace_subcommand_supported(&kubectl_bin, spec.subcommand) {
            continue;
        }

        let mut command = Command::new(&kubectl_bin);
        command
            .arg("gadget")
            .arg("trace")
            .arg(spec.subcommand)
            .arg("--output")
            .arg("json");

        if let Some(namespace) = target.namespace.as_deref() {
            command.arg("--namespace").arg(namespace);
        }

        if let Some(selector) = workload_selector(target) {
            command.arg("--selector").arg(selector);
        }

        apply_attach_target_env(&mut command, target);
        commands.push(AttachTraceCommand {
            label: spec.subcommand.to_string(),
            default_kind: spec.kind,
            command,
        });
    }

    if commands.is_empty() {
        return Err(format!(
            "no supported inspektor-gadget trace subcommands were detected (attempted: {}). ensure `kubectl gadget` is installed and supports at least one of exec/open/write/tcpconnect",
            attempted.join(", ")
        ));
    }

    Ok(commands)
}

fn run_aws_eks_update_kubeconfig(target: &ResolvedAttachTarget) -> Result<(), String> {
    let mut command =
        if let Some(override_command) = read_nonempty_env(ATTACH_AWS_UPDATE_CMD_ENV_NAME) {
            let mut override_cmd = shell_command(&override_command);
            apply_attach_target_env(&mut override_cmd, target);
            override_cmd
        } else {
            let aws_bin =
                read_nonempty_env(ATTACH_AWS_BIN_ENV_NAME).unwrap_or_else(|| "aws".to_string());
            let mut aws = Command::new(aws_bin);
            aws.arg("eks").arg("update-kubeconfig").arg("--name").arg(
                target
                    .cluster
                    .as_deref()
                    .ok_or_else(|| "attach target requires --cluster".to_string())?,
            );
            if let Some(region) = target.region.as_deref() {
                aws.arg("--region").arg(region);
            }
            apply_attach_target_env(&mut aws, target);
            aws
        };

    let status = command
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|err| format!("failed to run AWS EKS kubeconfig update command: {err}"))?;

    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "AWS EKS kubeconfig update command failed with exit code {}",
            exit_code(&status)
        ))
    }
}

fn run_attach_command(command: &mut Command, default_kind: EventKind) -> Result<i32, String> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("failed to spawn attach backend command: {err}"))?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "failed to capture attach backend stdout".to_string())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "failed to capture attach backend stderr".to_string())?;

    let stderr_handle = std::thread::spawn(move || -> io::Result<()> {
        let reader = BufReader::new(stderr);
        for line in reader.lines() {
            let line = line?;
            if !line.trim().is_empty() {
                eprintln!("{line}");
            }
        }
        Ok(())
    });

    let stdout_reader = BufReader::new(stdout);
    for line in stdout_reader.lines() {
        let line =
            line.map_err(|err| format!("failed reading attach backend stdout line: {err}"))?;
        if line.trim().is_empty() {
            continue;
        }

        if let Some(record) = stream_record_for_attach_line(&line, default_kind) {
            let serialized = serde_json::to_string(&record)
                .map_err(|err| format!("failed to serialize attach stream record: {err}"))?;
            println!("{serialized}");
        } else {
            eprintln!("{line}");
        }
    }

    let status = child
        .wait()
        .map_err(|err| format!("failed waiting on attach backend command: {err}"))?;

    let stderr_result = stderr_handle
        .join()
        .map_err(|_| "attach stderr forwarding thread panicked".to_string())?;
    stderr_result.map_err(|err| format!("failed to forward attach backend stderr: {err}"))?;

    Ok(exit_code(&status))
}

fn run_attach_commands_parallel(mut commands: Vec<AttachTraceCommand>) -> Result<i32, String> {
    let stdout_lock = Arc::new(Mutex::new(()));
    let mut handles = Vec::new();

    for mut trace in commands.drain(..) {
        let label = trace.label.clone();
        let lock = Arc::clone(&stdout_lock);
        let handle =
            std::thread::spawn(move || -> Result<(String, i32), String> {
                let mut child = trace
                    .command
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .map_err(|err| {
                        format!("failed to spawn attach backend command `{label}`: {err}")
                    })?;

                let stdout = child.stdout.take().ok_or_else(|| {
                    format!("failed to capture attach backend stdout for `{label}`")
                })?;
                let stderr = child.stderr.take().ok_or_else(|| {
                    format!("failed to capture attach backend stderr for `{label}`")
                })?;

                let stderr_label = label.clone();
                let stderr_handle = std::thread::spawn(move || -> io::Result<()> {
                    let reader = BufReader::new(stderr);
                    for line in reader.lines() {
                        let line = line?;
                        if !line.trim().is_empty() {
                            eprintln!("[attach:{stderr_label}] {line}");
                        }
                    }
                    Ok(())
                });

                let stdout_reader = BufReader::new(stdout);
                for line in stdout_reader.lines() {
                    let line = line.map_err(|err| {
                        format!("failed reading attach backend stdout line for `{label}`: {err}")
                    })?;
                    if line.trim().is_empty() {
                        continue;
                    }

                    if let Some(record) = stream_record_for_attach_line(&line, trace.default_kind) {
                        let serialized = serde_json::to_string(&record).map_err(|err| {
                            format!("failed to serialize attach stream record for `{label}`: {err}")
                        })?;
                        let _guard = lock
                            .lock()
                            .map_err(|_| "attach stdout lock is poisoned".to_string())?;
                        println!("{serialized}");
                    } else {
                        eprintln!("[attach:{label}] {line}");
                    }
                }

                let status = child.wait().map_err(|err| {
                    format!("failed waiting on attach backend command `{label}`: {err}")
                })?;
                let stderr_result = stderr_handle.join().map_err(|_| {
                    format!("attach stderr forwarding thread panicked for `{label}`")
                })?;
                stderr_result.map_err(|err| {
                    format!("failed to forward attach backend stderr for `{label}`: {err}")
                })?;
                Ok((label, exit_code(&status)))
            });
        handles.push(handle);
    }

    let mut failing = Vec::new();
    let mut highest = 0;
    for handle in handles {
        let (label, code) = handle
            .join()
            .map_err(|_| "attach parallel trace thread panicked".to_string())??;
        if code != 0 {
            failing.push((label, code));
            highest = highest.max(code);
        }
    }

    if failing.is_empty() {
        Ok(0)
    } else {
        let summary = failing
            .into_iter()
            .map(|(label, code)| format!("{label}={code}"))
            .collect::<Vec<_>>()
            .join(", ");
        eprintln!("attach warning: one or more trace commands failed ({summary})");
        Ok(highest)
    }
}

fn selected_trace_specs() -> Vec<InspektorTraceSpec> {
    let Some(raw) = read_nonempty_env(ATTACH_IG_TRACE_SET_ENV_NAME) else {
        return DEFAULT_TRACE_SPECS.to_vec();
    };

    let mut specs = Vec::new();
    for token in raw.split(',') {
        let normalized = token.trim().to_ascii_lowercase();
        let spec = match normalized.as_str() {
            "exec" | "execve" => Some(InspektorTraceSpec {
                subcommand: "exec",
                kind: EventKind::Execve,
            }),
            "open" | "openat" => Some(InspektorTraceSpec {
                subcommand: "open",
                kind: EventKind::OpenAt,
            }),
            "write" => Some(InspektorTraceSpec {
                subcommand: "write",
                kind: EventKind::Write,
            }),
            "connect" | "tcpconnect" => Some(InspektorTraceSpec {
                subcommand: "tcpconnect",
                kind: EventKind::Connect,
            }),
            _ => None,
        };
        if let Some(spec) = spec {
            specs.push(spec);
        }
    }

    if specs.is_empty() {
        DEFAULT_TRACE_SPECS.to_vec()
    } else {
        specs
    }
}

fn gadget_trace_subcommand_supported(kubectl_bin: &str, subcommand: &str) -> bool {
    check_command_status(
        kubectl_bin,
        &["gadget", "trace", subcommand, "--help"],
        "kubectl gadget trace capability check",
    )
    .is_ok()
}

fn check_command_status(program: &str, args: &[&str], label: &str) -> Result<(), String> {
    let status = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|err| format!("{label} failed to start `{program}`: {err}"))?;

    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "{label} returned exit code {} while running `{program} {}`",
            exit_code(&status),
            args.join(" ")
        ))
    }
}

fn stream_record_for_attach_line(line: &str, default_kind: EventKind) -> Option<StreamRecord> {
    if let Some(record) = stream_record_for_line(line) {
        return Some(record);
    }

    let json: Value = serde_json::from_str(line).ok()?;
    parse_inspektor_gadget_json_record(&json, default_kind)
}

fn parse_inspektor_gadget_json_record(
    value: &Value,
    default_kind: EventKind,
) -> Option<StreamRecord> {
    let comm = extract_value_as_string(
        value,
        &[
            &["comm"],
            &["process"],
            &["proc"],
            &["command"],
            &["common", "comm"],
            &["event", "comm"],
            &["event", "process", "comm"],
            &["k8s", "containerName"],
        ],
    )?;

    let pid = extract_value_as_u32(
        value,
        &[
            &["pid"],
            &["tid"],
            &["process_id"],
            &["common", "pid"],
            &["event", "pid"],
            &["event", "process", "pid"],
        ],
    )?;

    let kind = extract_event_kind(value).unwrap_or(default_kind);
    let file = extract_value_as_string(
        value,
        &[
            &["file"],
            &["path"],
            &["filename"],
            &["event", "file"],
            &["event", "path"],
            &["event", "filename"],
            &["event", "args", "filename"],
            &["event", "args", "path"],
        ],
    );
    let bytes = extract_value_as_u64(
        value,
        &[
            &["bytes"],
            &["count"],
            &["len"],
            &["size"],
            &["event", "bytes"],
            &["event", "args", "count"],
            &["event", "args", "size"],
            &["event", "args", "len"],
        ],
    );
    let fd = extract_value_as_i32(
        value,
        &[
            &["fd"],
            &["sockfd"],
            &["event", "fd"],
            &["event", "args", "fd"],
            &["event", "args", "sockfd"],
        ],
    );

    Some(StreamRecord::Syscall {
        timestamp_unix_ms: current_timestamp_millis(),
        kind,
        comm,
        pid,
        file,
        bytes,
        fd,
    })
}

fn extract_event_kind(value: &Value) -> Option<EventKind> {
    for path in [
        &["event"][..],
        &["type"][..],
        &["operation"][..],
        &["syscall"][..],
        &["gadget"][..],
        &["event", "type"][..],
        &["event", "name"][..],
        &["event", "operation"][..],
    ] {
        if let Some(raw) = json_lookup(value, path).and_then(Value::as_str) {
            if let Some(kind) = parse_event_kind(raw) {
                return Some(kind);
            }
        }
    }
    None
}

fn parse_event_kind(raw: &str) -> Option<EventKind> {
    let normalized = raw.to_ascii_lowercase();
    if normalized.contains("open") {
        Some(EventKind::OpenAt)
    } else if normalized.contains("write") {
        Some(EventKind::Write)
    } else if normalized.contains("connect") {
        Some(EventKind::Connect)
    } else if normalized.contains("exec") {
        Some(EventKind::Execve)
    } else {
        None
    }
}

fn json_lookup<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = value;
    for segment in path {
        current = current.as_object()?.get(*segment)?;
    }
    Some(current)
}

fn extract_value_as_string(value: &Value, paths: &[&[&str]]) -> Option<String> {
    for path in paths {
        if let Some(raw) = json_lookup(value, path).and_then(Value::as_str) {
            let trimmed = raw.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

fn extract_value_as_u32(value: &Value, paths: &[&[&str]]) -> Option<u32> {
    for path in paths {
        if let Some(raw) = json_lookup(value, path) {
            if let Some(parsed) = json_value_to_u64(raw) {
                if parsed <= u32::MAX as u64 {
                    return Some(parsed as u32);
                }
            }
        }
    }
    None
}

fn extract_value_as_u64(value: &Value, paths: &[&[&str]]) -> Option<u64> {
    for path in paths {
        if let Some(raw) = json_lookup(value, path) {
            if let Some(parsed) = json_value_to_u64(raw) {
                return Some(parsed);
            }
        }
    }
    None
}

fn extract_value_as_i32(value: &Value, paths: &[&[&str]]) -> Option<i32> {
    for path in paths {
        if let Some(raw) = json_lookup(value, path) {
            if let Some(parsed) = json_value_to_i64(raw) {
                if parsed >= i32::MIN as i64 && parsed <= i32::MAX as i64 {
                    return Some(parsed as i32);
                }
            }
        }
    }
    None
}

fn json_value_to_u64(value: &Value) -> Option<u64> {
    if let Some(parsed) = value.as_u64() {
        return Some(parsed);
    }

    if let Some(parsed) = value.as_i64() {
        if parsed >= 0 {
            return Some(parsed as u64);
        }
    }

    value
        .as_str()
        .and_then(|text| text.trim().parse::<u64>().ok())
}

fn json_value_to_i64(value: &Value) -> Option<i64> {
    if let Some(parsed) = value.as_i64() {
        return Some(parsed);
    }

    if let Some(parsed) = value.as_u64() {
        if parsed <= i64::MAX as u64 {
            return Some(parsed as i64);
        }
    }

    value
        .as_str()
        .and_then(|text| text.trim().parse::<i64>().ok())
}

fn current_timestamp_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn shell_command(raw_command: &str) -> Command {
    let mut command = Command::new("/bin/sh");
    command.arg("-lc").arg(raw_command);
    command
}

fn read_nonempty_env(name: &str) -> Option<String> {
    let value = std::env::var(name).ok()?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn workload_selector(target: &ResolvedAttachTarget) -> Option<String> {
    if let Some(selector) = target.selector.as_deref() {
        return Some(selector.to_string());
    }
    target
        .pod
        .as_deref()
        .map(|pod| format!("k8s.pod.name={pod}"))
}

fn apply_attach_target_env(command: &mut Command, target: &ResolvedAttachTarget) {
    command.env(ATTACH_ENV_PLATFORM, target.platform.as_str());
    command.env(ATTACH_ENV_BACKEND, target.backend.as_str());
    if let Some(namespace) = target.namespace.as_deref() {
        command.env(ATTACH_ENV_NAMESPACE, namespace);
    }
    if let Some(selector) = target.selector.as_deref() {
        command.env(ATTACH_ENV_SELECTOR, selector);
    }
    if let Some(pod) = target.pod.as_deref() {
        command.env(ATTACH_ENV_POD, pod);
    }
    if let Some(cluster) = target.cluster.as_deref() {
        command.env(ATTACH_ENV_CLUSTER, cluster);
    }
    if let Some(region) = target.region.as_deref() {
        command.env(ATTACH_ENV_REGION, region);
    }
    if let Some(service) = target.service.as_deref() {
        command.env(ATTACH_ENV_SERVICE, service);
    }
    if let Some(task) = target.task.as_deref() {
        command.env(ATTACH_ENV_TASK, task);
    }
}

fn exit_code(status: &ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }

    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return 128 + signal;
        }
    }

    1
}

fn parse_attach_platform(raw: &str) -> Result<AttachPlatform, String> {
    match raw {
        "docker" => Ok(AttachPlatform::Docker),
        "k8s" | "kubernetes" => Ok(AttachPlatform::Kubernetes),
        "aws-eks" => Ok(AttachPlatform::AwsEks),
        "aws-ecs" => Ok(AttachPlatform::AwsEcs),
        _ => Err(format!(
            "unsupported attach platform: {raw}. expected docker, k8s, aws-eks, or aws-ecs"
        )),
    }
}

fn parse_attach_backend(raw: &str) -> Result<AttachBackend, String> {
    match raw {
        "inspektor-gadget" => Ok(AttachBackend::InspektorGadget),
        "tetragon" => Ok(AttachBackend::Tetragon),
        _ => Err(format!(
            "unsupported attach backend: {raw}. expected inspektor-gadget or tetragon"
        )),
    }
}

fn normalized_option(value: Option<String>, flag: &str) -> Result<Option<String>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(format!("{flag} must not be empty"));
    }
    Ok(Some(trimmed.to_string()))
}

fn parse_attach_value(value: &str, flag: &str) -> Result<String, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(format!("{flag} must not be empty"));
    }
    Ok(trimmed.to_string())
}

fn require_present(value: Option<&str>, flag: &str) -> Result<(), String> {
    if value.is_some() {
        Ok(())
    } else {
        Err(format!("attach target requires {flag}"))
    }
}

fn reject_present(value: Option<&str>, flag: &str, platform: AttachPlatform) -> Result<(), String> {
    if value.is_some() {
        Err(format!(
            "{flag} is not supported for attach platform {}",
            platform.as_str()
        ))
    } else {
        Ok(())
    }
}

fn require_selector_or_pod(target: &ResolvedAttachTarget) -> Result<(), String> {
    if target.selector.is_some() || target.pod.is_some() {
        Ok(())
    } else {
        Err("attach target requires either --selector or --pod".to_string())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Mutex, OnceLock};

    use ebpf_tracker_events::{EventKind, StreamRecord};

    use super::{
        build_attach_plan, build_attach_report, parse_attach_args, run_attach,
        selected_trace_specs, stream_record_for_attach_line, workload_selector, AttachBackend,
        AttachParseOutcome, AttachPlatform, ATTACH_AWS_UPDATE_CMD_ENV_NAME, ATTACH_IG_CMD_ENV_NAME,
        ATTACH_IG_TRACE_SET_ENV_NAME, ATTACH_KUBECTL_BIN_ENV_NAME,
    };

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .expect("env lock should not be poisoned")
    }

    #[test]
    fn parse_attach_args_defaults_to_inspektor_gadget() {
        let parsed = parse_attach_args(&[
            "k8s".to_string(),
            "--selector".to_string(),
            "app=payments".to_string(),
        ])
        .expect("attach args should parse");

        match parsed {
            AttachParseOutcome::Run(args) => {
                assert_eq!(args.platform, AttachPlatform::Kubernetes);
                assert_eq!(args.backend, AttachBackend::InspektorGadget);
                assert_eq!(args.selector.as_deref(), Some("app=payments"));
            }
            AttachParseOutcome::Help => panic!("expected run outcome"),
        }
    }

    #[test]
    fn parse_attach_args_supports_aws_eks_flags() {
        let parsed = parse_attach_args(&[
            "aws-eks".to_string(),
            "--backend=tetragon".to_string(),
            "--cluster=prod-cluster".to_string(),
            "--region=us-east-1".to_string(),
            "--namespace=payments".to_string(),
            "--pod=api-7d9".to_string(),
        ])
        .expect("attach args should parse");

        match parsed {
            AttachParseOutcome::Run(args) => {
                assert_eq!(args.platform, AttachPlatform::AwsEks);
                assert_eq!(args.backend, AttachBackend::Tetragon);
                assert_eq!(args.cluster.as_deref(), Some("prod-cluster"));
                assert_eq!(args.region.as_deref(), Some("us-east-1"));
                assert_eq!(args.namespace.as_deref(), Some("payments"));
                assert_eq!(args.pod.as_deref(), Some("api-7d9"));
            }
            AttachParseOutcome::Help => panic!("expected run outcome"),
        }
    }

    #[test]
    fn parse_attach_args_rejects_empty_normalized_values() {
        let error = parse_attach_args(&["docker".to_string(), "--container=   ".to_string()])
            .expect_err("blank attach values should fail");

        assert_eq!(error, "--container must not be empty");
    }

    #[test]
    fn parse_attach_args_rejects_unknown_flags_with_clear_message() {
        let error = parse_attach_args(&[
            "k8s".to_string(),
            "--selector=app=payments".to_string(),
            "--mystery".to_string(),
        ])
        .expect_err("unknown attach flag should fail");

        assert_eq!(error, "unknown attach flag: --mystery");
    }

    #[test]
    fn run_attach_rejects_tetragon_for_docker_targets() {
        let parsed = parse_attach_args(&[
            "docker".to_string(),
            "--backend=tetragon".to_string(),
            "--container=payments-api".to_string(),
        ])
        .expect("attach args should parse");

        match parsed {
            AttachParseOutcome::Run(args) => {
                let error = run_attach(args).expect_err("docker+tetragon should fail");
                assert_eq!(
                    error,
                    "docker attach currently only scaffolds the inspektor-gadget backend"
                );
            }
            AttachParseOutcome::Help => panic!("expected run outcome"),
        }
    }

    #[test]
    fn run_attach_requires_cluster_for_aws_eks() {
        let parsed =
            parse_attach_args(&["aws-eks".to_string(), "--selector=app=payments".to_string()])
                .expect("attach args should parse");

        match parsed {
            AttachParseOutcome::Run(args) => {
                let error = run_attach(args).expect_err("aws-eks without cluster should fail");
                assert_eq!(error, "attach target requires --cluster");
            }
            AttachParseOutcome::Help => panic!("expected run outcome"),
        }
    }

    #[test]
    fn run_attach_builds_an_explicit_scaffold_report() {
        let parsed = parse_attach_args(&["k8s".to_string(), "--selector=app=payments".to_string()])
            .expect("attach args should parse");

        match parsed {
            AttachParseOutcome::Run(args) => {
                let resolved = args.resolve().expect("attach target should resolve");
                let plan = build_attach_plan(&resolved);
                let report = build_attach_report(&resolved, &plan);

                assert_eq!(report.lines[0], "attach scaffold");
                assert_eq!(
                    report.lines[1],
                    "status: experimental scaffold/plan mode; no live backend execution yet"
                );
                assert_eq!(
                    report.lines[2],
                    "this command prints a plan only and does not start tracing yet"
                );
                assert!(report.lines.iter().any(|line| line == "next repo tasks:"));
            }
            AttachParseOutcome::Help => panic!("expected run outcome"),
        }
    }

    #[test]
    fn aws_eks_plan_calls_out_fargate_scope_explicitly() {
        let parsed = parse_attach_args(&[
            "aws-eks".to_string(),
            "--cluster=prod-cluster".to_string(),
            "--selector=app=payments".to_string(),
        ])
        .expect("attach args should parse");

        match parsed {
            AttachParseOutcome::Run(args) => {
                let plan =
                    build_attach_plan(&args.resolve().expect("attach target should resolve"));
                assert!(plan.scope_notes.iter().any(|note| note.contains("Fargate")));
                assert!(plan
                    .scope_notes
                    .iter()
                    .any(|note| note.contains("EC2-backed")));
            }
            AttachParseOutcome::Help => panic!("expected run outcome"),
        }
    }

    #[test]
    fn aws_ecs_plan_calls_out_ec2_and_fargate_scope() {
        let parsed = parse_attach_args(&[
            "aws-ecs".to_string(),
            "--cluster=prod-cluster".to_string(),
            "--service=payments-api".to_string(),
        ])
        .expect("attach args should parse");

        match parsed {
            AttachParseOutcome::Run(args) => {
                let plan =
                    build_attach_plan(&args.resolve().expect("attach target should resolve"));
                assert!(plan.scope_notes.iter().any(|note| note.contains("Fargate")));
                assert!(plan
                    .scope_notes
                    .iter()
                    .any(|note| note.contains("EC2 launch type")));
            }
            AttachParseOutcome::Help => panic!("expected run outcome"),
        }
    }

    #[test]
    fn stream_record_for_attach_line_parses_json_exec_shape() {
        let record = stream_record_for_attach_line(
            r#"{"event":"trace_exec","comm":"payments-api","pid":42}"#,
            EventKind::Execve,
        )
        .expect("json line should parse");

        match record {
            StreamRecord::Syscall {
                kind, comm, pid, ..
            } => {
                assert_eq!(kind, EventKind::Execve);
                assert_eq!(comm, "payments-api");
                assert_eq!(pid, 42);
            }
            _ => panic!("expected syscall record"),
        }
    }

    #[test]
    fn stream_record_for_attach_line_parses_nested_gadget_json_shape() {
        let record = stream_record_for_attach_line(
            r#"{"event":{"type":"tcpconnect","args":{"fd":"7","size":"512","path":"/tmp/out"}},"common":{"comm":"api","pid":"99"}}"#,
            EventKind::Execve,
        )
        .expect("nested gadget json should parse");

        match record {
            StreamRecord::Syscall {
                kind,
                comm,
                pid,
                file,
                bytes,
                fd,
                ..
            } => {
                assert_eq!(kind, EventKind::Connect);
                assert_eq!(comm, "api");
                assert_eq!(pid, 99);
                assert_eq!(file.as_deref(), Some("/tmp/out"));
                assert_eq!(bytes, Some(512));
                assert_eq!(fd, Some(7));
            }
            _ => panic!("expected syscall record"),
        }
    }

    #[test]
    fn run_attach_executes_live_inspektor_path_for_k8s_targets() {
        let _guard = env_lock();
        std::env::set_var(ATTACH_IG_CMD_ENV_NAME, "exit 7");
        std::env::set_var(ATTACH_KUBECTL_BIN_ENV_NAME, "/bin/echo");

        let parsed = parse_attach_args(&["k8s".to_string(), "--selector=app=payments".to_string()])
            .expect("attach args should parse");

        let exit_code = match parsed {
            AttachParseOutcome::Run(args) => {
                run_attach(args).expect("attach command should execute backend command")
            }
            AttachParseOutcome::Help => panic!("expected run outcome"),
        };
        assert_eq!(exit_code, 7);

        std::env::remove_var(ATTACH_IG_CMD_ENV_NAME);
        std::env::remove_var(ATTACH_KUBECTL_BIN_ENV_NAME);
    }

    #[test]
    fn run_attach_aws_eks_runs_kubeconfig_preflight_before_backend_command() {
        let _guard = env_lock();
        std::env::set_var(ATTACH_AWS_UPDATE_CMD_ENV_NAME, "exit 0");
        std::env::set_var(ATTACH_IG_CMD_ENV_NAME, "exit 0");
        std::env::set_var(ATTACH_KUBECTL_BIN_ENV_NAME, "/bin/echo");

        let parsed = parse_attach_args(&[
            "aws-eks".to_string(),
            "--cluster=prod".to_string(),
            "--region=us-east-1".to_string(),
            "--selector=app=payments".to_string(),
        ])
        .expect("attach args should parse");

        let exit_code = match parsed {
            AttachParseOutcome::Run(args) => {
                run_attach(args).expect("attach command should succeed")
            }
            AttachParseOutcome::Help => panic!("expected run outcome"),
        };
        assert_eq!(exit_code, 0);

        std::env::remove_var(ATTACH_AWS_UPDATE_CMD_ENV_NAME);
        std::env::remove_var(ATTACH_IG_CMD_ENV_NAME);
        std::env::remove_var(ATTACH_KUBECTL_BIN_ENV_NAME);
    }

    #[test]
    fn aws_eks_preflight_failure_is_reported_with_exit_code() {
        let _guard = env_lock();
        std::env::set_var(ATTACH_AWS_UPDATE_CMD_ENV_NAME, "exit 23");
        std::env::set_var(ATTACH_IG_CMD_ENV_NAME, "exit 0");
        std::env::set_var(ATTACH_KUBECTL_BIN_ENV_NAME, "/bin/echo");

        let parsed = parse_attach_args(&[
            "aws-eks".to_string(),
            "--cluster=prod".to_string(),
            "--selector=app=payments".to_string(),
        ])
        .expect("attach args should parse");

        let error = match parsed {
            AttachParseOutcome::Run(args) => {
                run_attach(args).expect_err("aws preflight failure should return an error")
            }
            AttachParseOutcome::Help => panic!("expected run outcome"),
        };
        assert!(error.contains("exit code 23"));

        std::env::remove_var(ATTACH_AWS_UPDATE_CMD_ENV_NAME);
        std::env::remove_var(ATTACH_IG_CMD_ENV_NAME);
        std::env::remove_var(ATTACH_KUBECTL_BIN_ENV_NAME);
    }

    #[test]
    fn run_attach_reports_kubectl_preflight_failures_when_override_is_not_set() {
        let _guard = env_lock();
        std::env::set_var(
            ATTACH_KUBECTL_BIN_ENV_NAME,
            "/definitely/not/a/real/kubectl",
        );

        let parsed = parse_attach_args(&["k8s".to_string(), "--selector=app=payments".to_string()])
            .expect("attach args should parse");

        let error = match parsed {
            AttachParseOutcome::Run(args) => {
                run_attach(args).expect_err("missing kubectl binary should fail preflight")
            }
            AttachParseOutcome::Help => panic!("expected run outcome"),
        };
        assert!(error.contains("kubectl client preflight"));

        std::env::remove_var(ATTACH_KUBECTL_BIN_ENV_NAME);
    }

    #[test]
    fn selected_trace_specs_honors_environment_override() {
        let _guard = env_lock();
        std::env::set_var(ATTACH_IG_TRACE_SET_ENV_NAME, "open, connect,unknown");
        let specs = selected_trace_specs();
        assert_eq!(specs.len(), 2);
        assert_eq!(specs[0].subcommand, "open");
        assert_eq!(specs[1].subcommand, "tcpconnect");
        std::env::remove_var(ATTACH_IG_TRACE_SET_ENV_NAME);
    }

    #[test]
    fn workload_selector_prefers_explicit_selector_then_pod_fallback() {
        let selector_target =
            parse_attach_args(&["k8s".to_string(), "--selector=app=payments".to_string()])
                .expect("attach args should parse");
        let pod_target = parse_attach_args(&["k8s".to_string(), "--pod=api-7d9".to_string()])
            .expect("attach args should parse");

        match selector_target {
            AttachParseOutcome::Run(args) => {
                let resolved = args.resolve().expect("selector target should resolve");
                assert_eq!(
                    workload_selector(&resolved).as_deref(),
                    Some("app=payments")
                );
            }
            AttachParseOutcome::Help => panic!("expected run outcome"),
        }

        match pod_target {
            AttachParseOutcome::Run(args) => {
                let resolved = args.resolve().expect("pod target should resolve");
                assert_eq!(
                    workload_selector(&resolved).as_deref(),
                    Some("k8s.pod.name=api-7d9")
                );
            }
            AttachParseOutcome::Help => panic!("expected run outcome"),
        }
    }
}
