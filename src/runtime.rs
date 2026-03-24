use std::collections::hash_map::DefaultHasher;
use std::env;
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::process::Command;

const DEFAULT_COMPOSE_FILE_NAME: &str = "docker-compose.bpftrace.yml";
const NODE_COMPOSE_FILE_NAME: &str = "docker-compose.bpftrace.node.yml";
const RUST_DOCKERFILE_NAME: &str = "docker/bpftrace-rust.Dockerfile";
const NODE_DOCKERFILE_NAME: &str = "docker/bpftrace-node.Dockerfile";
const GENERATED_RUNTIME_ROOT_PREFIX: &str = "runtime-v";
const CONTAINER_CARGO_TARGET_ROOT: &str = "/cargo-target";
const CONTAINER_NPM_CACHE_ROOT: &str = "/npm-cache";
const RUN_SCRIPT_NAME: &str = "scripts/run-bpftrace-wrap.sh";
const EXEC_HELPER_SOURCE_NAME: &str = "scripts/exec-target-from-env.rs";
const DEFAULT_PROBE_NAME: &str = "probes/execve.bt";

const EMBEDDED_RUST_COMPOSE: &str = include_str!("../docker-compose.bpftrace.yml");
const EMBEDDED_NODE_COMPOSE: &str = include_str!("../docker-compose.bpftrace.node.yml");
const EMBEDDED_RUST_DOCKERFILE: &str = include_str!("../docker/bpftrace-rust.Dockerfile");
const EMBEDDED_NODE_DOCKERFILE: &str = include_str!("../docker/bpftrace-node.Dockerfile");
const EMBEDDED_RUN_SCRIPT: &str = include_str!("../scripts/run-bpftrace-wrap.sh");
const EMBEDDED_EXEC_HELPER_SOURCE: &str = include_str!("../scripts/exec-target-from-env.rs");
const EMBEDDED_PROBE_EXECVE: &str = include_str!("../probes/execve.bt");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RuntimeSelection {
    Auto,
    Rust,
    Node,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RuntimeProfile {
    Rust,
    Node,
}

pub(crate) fn parse_runtime_selection(raw: &str) -> Result<RuntimeSelection, String> {
    match raw {
        "auto" => Ok(RuntimeSelection::Auto),
        "rust" => Ok(RuntimeSelection::Rust),
        "node" => Ok(RuntimeSelection::Node),
        _ => Err(format!("unsupported runtime: {raw}")),
    }
}

pub(crate) fn resolve_runtime_profile(
    selection: RuntimeSelection,
    wrapped_command: &[String],
) -> RuntimeProfile {
    match selection {
        RuntimeSelection::Auto => infer_runtime_profile(wrapped_command),
        RuntimeSelection::Rust => RuntimeProfile::Rust,
        RuntimeSelection::Node => RuntimeProfile::Node,
    }
}

pub(crate) fn resolve_compose_file(profile: RuntimeProfile) -> Result<PathBuf, String> {
    if let Ok(path) = env::var("EBPF_TRACKER_COMPOSE_FILE") {
        let compose = PathBuf::from(path);
        if compose.is_file() {
            return Ok(compose);
        }
        return Err(format!(
            "compose file from EBPF_TRACKER_COMPOSE_FILE not found: {}",
            compose.display()
        ));
    }

    let current_dir =
        env::current_dir().map_err(|err| format!("failed to read current dir: {err}"))?;
    for candidate_name in compose_file_candidates(profile) {
        let candidate = current_dir.join(candidate_name);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }

    let exe =
        env::current_exe().map_err(|err| format!("failed to resolve executable path: {err}"))?;
    for ancestor in exe.ancestors() {
        for candidate_name in compose_file_candidates(profile) {
            let candidate = ancestor.join(candidate_name);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }

    ensure_embedded_runtime(profile)
}

pub(crate) fn configure_runtime_command(
    command: &mut Command,
    project_dir: &Path,
    profile: RuntimeProfile,
) {
    match profile {
        RuntimeProfile::Rust => {
            command.arg("-e").arg(format!(
                "CARGO_TARGET_DIR={}",
                container_cargo_target_dir(project_dir)
            ));
        }
        RuntimeProfile::Node => {
            command.arg("-e").arg(format!(
                "NPM_CONFIG_CACHE={}",
                container_npm_cache_dir(project_dir)
            ));
        }
    }
}

pub(crate) fn container_cargo_target_dir(project_dir: &Path) -> String {
    format!(
        "{CONTAINER_CARGO_TARGET_ROOT}/{:016x}",
        project_dir_hash(project_dir)
    )
}

pub(crate) fn container_npm_cache_dir(project_dir: &Path) -> String {
    format!(
        "{CONTAINER_NPM_CACHE_ROOT}/{:016x}",
        project_dir_hash(project_dir)
    )
}

fn infer_runtime_profile(wrapped_command: &[String]) -> RuntimeProfile {
    let Some(raw_command) = wrapped_command.first() else {
        return RuntimeProfile::Rust;
    };

    match normalized_command_name(raw_command).as_str() {
        "node" | "nodejs" | "npm" | "npx" | "pnpm" | "yarn" | "yarnpkg" | "corepack" => {
            RuntimeProfile::Node
        }
        _ => RuntimeProfile::Rust,
    }
}

fn normalized_command_name(raw_command: &str) -> String {
    let file_name = Path::new(raw_command)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or(raw_command);
    file_name
        .trim_end_matches(".cmd")
        .trim_end_matches(".exe")
        .to_ascii_lowercase()
}

fn compose_file_candidates(profile: RuntimeProfile) -> &'static [&'static str] {
    match profile {
        RuntimeProfile::Rust => &[DEFAULT_COMPOSE_FILE_NAME],
        RuntimeProfile::Node => &[NODE_COMPOSE_FILE_NAME],
    }
}

fn ensure_embedded_runtime(profile: RuntimeProfile) -> Result<PathBuf, String> {
    let mut errors = Vec::new();

    for root in cache_root_candidates() {
        let runtime_dir = root.join(format!(
            "{GENERATED_RUNTIME_ROOT_PREFIX}{}",
            env!("CARGO_PKG_VERSION")
        ));
        let result = (|| -> Result<PathBuf, String> {
            write_runtime_assets(&runtime_dir)?;
            Ok(runtime_dir.join(compose_file_name(profile)))
        })();

        match result {
            Ok(compose_file) => return Ok(compose_file),
            Err(err) => errors.push(err),
        }
    }

    Err(format!(
        "failed to materialize runtime assets: {}",
        errors.join("; ")
    ))
}

fn write_runtime_assets(runtime_dir: &Path) -> Result<(), String> {
    write_if_changed(
        &runtime_dir.join(DEFAULT_COMPOSE_FILE_NAME),
        EMBEDDED_RUST_COMPOSE,
    )?;
    write_if_changed(
        &runtime_dir.join(NODE_COMPOSE_FILE_NAME),
        EMBEDDED_NODE_COMPOSE,
    )?;
    write_if_changed(
        &runtime_dir.join(RUST_DOCKERFILE_NAME),
        EMBEDDED_RUST_DOCKERFILE,
    )?;
    write_if_changed(
        &runtime_dir.join(NODE_DOCKERFILE_NAME),
        EMBEDDED_NODE_DOCKERFILE,
    )?;
    write_if_changed(&runtime_dir.join(RUN_SCRIPT_NAME), EMBEDDED_RUN_SCRIPT)?;
    write_if_changed(
        &runtime_dir.join(EXEC_HELPER_SOURCE_NAME),
        EMBEDDED_EXEC_HELPER_SOURCE,
    )?;
    write_if_changed(&runtime_dir.join(DEFAULT_PROBE_NAME), EMBEDDED_PROBE_EXECVE)?;
    Ok(())
}

fn compose_file_name(profile: RuntimeProfile) -> &'static str {
    match profile {
        RuntimeProfile::Rust => DEFAULT_COMPOSE_FILE_NAME,
        RuntimeProfile::Node => NODE_COMPOSE_FILE_NAME,
    }
}

fn cache_root_candidates() -> Vec<PathBuf> {
    let mut roots = Vec::new();

    if let Ok(path) = env::var("EBPF_TRACKER_CACHE_DIR") {
        roots.push(PathBuf::from(path));
        return roots;
    }

    if let Ok(path) = env::var("XDG_CACHE_HOME") {
        roots.push(PathBuf::from(path).join("ebpf-tracker"));
    }

    if let Ok(path) = env::var("HOME") {
        roots.push(PathBuf::from(path).join(".cache").join("ebpf-tracker"));
    }

    roots.push(env::temp_dir().join("ebpf-tracker"));
    roots
}

pub(crate) fn write_if_changed(path: &Path, content: &str) -> Result<(), String> {
    if path.exists() {
        let existing = fs::read_to_string(path)
            .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
        if existing == content {
            return Ok(());
        }
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
    }

    fs::write(path, content).map_err(|err| format!("failed to write {}: {err}", path.display()))?;
    Ok(())
}

fn project_dir_hash(project_dir: &Path) -> u64 {
    let mut hasher = DefaultHasher::new();
    project_dir.to_string_lossy().hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::{
        container_cargo_target_dir, container_npm_cache_dir, parse_runtime_selection,
        resolve_runtime_profile, RuntimeProfile, RuntimeSelection,
    };
    use std::path::Path;

    #[test]
    fn runtime_selection_parser_accepts_supported_values() {
        assert_eq!(
            parse_runtime_selection("auto").expect("auto should parse"),
            RuntimeSelection::Auto
        );
        assert_eq!(
            parse_runtime_selection("rust").expect("rust should parse"),
            RuntimeSelection::Rust
        );
        assert_eq!(
            parse_runtime_selection("node").expect("node should parse"),
            RuntimeSelection::Node
        );
    }

    #[test]
    fn runtime_selection_parser_rejects_unknown_values() {
        assert!(parse_runtime_selection("python").is_err());
    }

    #[test]
    fn auto_runtime_detects_node_commands() {
        for command in [
            "npm",
            "npx",
            "pnpm",
            "yarn",
            "node",
            "nodejs",
            "/usr/local/bin/npm",
            "npm.cmd",
        ] {
            assert_eq!(
                resolve_runtime_profile(RuntimeSelection::Auto, &[command.to_string()]),
                RuntimeProfile::Node
            );
        }
    }

    #[test]
    fn auto_runtime_defaults_to_rust_for_other_commands() {
        assert_eq!(
            resolve_runtime_profile(
                RuntimeSelection::Auto,
                &["cargo".to_string(), "run".to_string()]
            ),
            RuntimeProfile::Rust
        );
        assert_eq!(
            resolve_runtime_profile(RuntimeSelection::Auto, &["/bin/true".to_string()]),
            RuntimeProfile::Rust
        );
    }

    #[test]
    fn explicit_runtime_selection_overrides_auto_detection() {
        assert_eq!(
            resolve_runtime_profile(RuntimeSelection::Node, &["cargo".to_string()]),
            RuntimeProfile::Node
        );
        assert_eq!(
            resolve_runtime_profile(RuntimeSelection::Rust, &["npm".to_string()]),
            RuntimeProfile::Rust
        );
    }

    #[test]
    fn runtime_cache_dirs_are_stable_for_a_project() {
        let project_dir = Path::new("/tmp/payment-engine");

        assert_eq!(
            container_cargo_target_dir(project_dir),
            container_cargo_target_dir(project_dir)
        );
        assert_eq!(
            container_npm_cache_dir(project_dir),
            container_npm_cache_dir(project_dir)
        );
    }

    #[test]
    fn runtime_cache_dirs_differ_between_projects() {
        let first = Path::new("/tmp/payment-engine");
        let second = Path::new("/tmp/session-io-demo");

        assert_ne!(
            container_cargo_target_dir(first),
            container_cargo_target_dir(second)
        );
        assert_ne!(
            container_npm_cache_dir(first),
            container_npm_cache_dir(second)
        );
    }
}
