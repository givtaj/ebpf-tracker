use std::path::Path;
use std::process::Command;

use crate::runtime::{configure_runtime_command, RuntimeProfile};
use crate::{interactive_pty_enabled, TransportMode, INTERACTIVE_PTY_ENV_NAME};

pub(crate) struct ComposeRunConfig<'a> {
    pub(crate) compose_file: &'a Path,
    pub(crate) runtime_override_file: Option<&'a Path>,
    pub(crate) project_dir: &'a Path,
    pub(crate) runtime_profile: RuntimeProfile,
    pub(crate) transport_mode: TransportMode,
    pub(crate) extra_env: &'a [(String, String)],
    pub(crate) probe_file: Option<&'a str>,
    pub(crate) perf_events: Option<&'a str>,
    pub(crate) wrapped_command: &'a [String],
}

pub(crate) fn build_compose_command(config: ComposeRunConfig<'_>) -> Command {
    let mut command = Command::new("docker");
    command.arg("compose").arg("-f").arg(config.compose_file);

    if let Some(runtime_override_file) = config.runtime_override_file {
        command.arg("-f").arg(runtime_override_file);
    }

    command.arg("run").arg("--build").arg("--rm");
    command.arg("-e").arg(format!(
        "EBPF_TRACKER_TRANSPORT={}",
        config.transport_mode.as_str()
    ));
    configure_runtime_command(&mut command, config.project_dir, config.runtime_profile);

    if let Some(probe_file) = config.probe_file {
        command
            .arg("-e")
            .arg(format!("EBPF_TRACKER_PROBE={probe_file}"));
    }

    if let Some(perf_events) = config.perf_events {
        command
            .arg("-e")
            .arg(format!("EBPF_TRACKER_PERF_EVENTS={perf_events}"));
    }

    if interactive_pty_enabled() {
        command
            .arg("-e")
            .arg(format!("{INTERACTIVE_PTY_ENV_NAME}=1"));
    }

    for (key, value) in config.extra_env {
        command.arg("-e").arg(format!("{key}={value}"));
    }

    command
        .arg("bpftrace")
        .args(config.wrapped_command)
        .env("PROJECT_DIR", config.project_dir);

    command
}

#[cfg(test)]
mod tests {
    use super::{build_compose_command, ComposeRunConfig};
    use crate::{
        runtime::{container_cargo_home_dir, container_cargo_target_dir, RuntimeProfile},
        TransportMode,
    };
    use std::path::Path;

    #[test]
    fn compose_run_config_builds_explicit_command_shape() {
        let extra_env = vec![("DEMO".to_string(), "1".to_string())];
        let wrapped_command = vec!["cargo".to_string(), "run".to_string()];
        let command = build_compose_command(ComposeRunConfig {
            compose_file: Path::new("/tmp/docker-compose.yml"),
            runtime_override_file: Some(Path::new("/tmp/docker-compose.override.yml")),
            project_dir: Path::new("/workspace/demo"),
            runtime_profile: RuntimeProfile::Rust,
            transport_mode: TransportMode::Bpftrace,
            extra_env: &extra_env,
            probe_file: Some("/probes/custom.bt"),
            perf_events: None,
            wrapped_command: &wrapped_command,
        });

        assert_eq!(command.get_program().to_string_lossy(), "docker");
        let args = command
            .get_args()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect::<Vec<_>>();
        assert_eq!(
            args,
            vec![
                "compose".to_string(),
                "-f".to_string(),
                "/tmp/docker-compose.yml".to_string(),
                "-f".to_string(),
                "/tmp/docker-compose.override.yml".to_string(),
                "run".to_string(),
                "--build".to_string(),
                "--rm".to_string(),
                "-e".to_string(),
                "EBPF_TRACKER_TRANSPORT=bpftrace".to_string(),
                "-e".to_string(),
                format!(
                    "CARGO_HOME={}",
                    container_cargo_home_dir(Path::new("/workspace/demo"))
                ),
                "-e".to_string(),
                format!(
                    "CARGO_TARGET_DIR={}",
                    container_cargo_target_dir(Path::new("/workspace/demo"))
                ),
                "-e".to_string(),
                "EBPF_TRACKER_PROBE=/probes/custom.bt".to_string(),
                "-e".to_string(),
                "DEMO=1".to_string(),
                "bpftrace".to_string(),
                "cargo".to_string(),
                "run".to_string(),
            ]
        );
    }
}
