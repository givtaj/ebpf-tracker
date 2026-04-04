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
                "implement backend command execution instead of the current scaffold output"
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
    let plan = build_attach_plan(&resolved);
    build_attach_report(&resolved, &plan).print();

    Ok(0)
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
    use super::{
        build_attach_plan, build_attach_report, parse_attach_args, run_attach, AttachBackend,
        AttachParseOutcome, AttachPlatform,
    };

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
}
