use std::path::PathBuf;
use std::process::Command;

fn empty_cache_path(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "ebpf-tracker-discovery-{}-{label}",
        std::process::id()
    ))
}

#[test]
fn version_and_replay_help_need_no_external_tools_or_cache() {
    let cache = empty_cache_path("help");
    assert!(!cache.exists(), "test cache must start absent");
    for args in [vec!["--version"], vec!["-V"], vec!["replay", "--help"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_ebpf-tracker"))
            .args(&args)
            .env("PATH", "")
            .env("EBPF_TRACKER_CACHE_DIR", &cache)
            .output()
            .expect("tracker should run without external tools");
        assert!(output.status.success(), "{:?}: {:?}", args, output);
        if args[0] == "replay" {
            assert!(String::from_utf8_lossy(&output.stderr).contains("Usage: ebpf-tracker replay"));
        } else {
            assert_eq!(
                String::from_utf8_lossy(&output.stdout).trim(),
                concat!("ebpf-tracker ", env!("CARGO_PKG_VERSION"))
            );
        }
        assert!(
            !cache.exists(),
            "discovery must not materialize runtime assets"
        );
    }
}

#[test]
fn missing_replay_file_fails_before_starting_a_viewer_or_runtime() {
    let cache = empty_cache_path("missing");
    assert!(!cache.exists(), "test cache must start absent");
    let missing = cache.join("missing.jsonl");
    let output = Command::new(env!("CARGO_BIN_EXE_ebpf-tracker"))
        .arg("replay")
        .arg(&missing)
        .env("PATH", "")
        .env("EBPF_TRACKER_CACHE_DIR", &cache)
        .output()
        .expect("tracker should run without external tools");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("cannot read replay file"));
    assert!(
        !cache.exists(),
        "invalid replay must not materialize runtime assets"
    );
}
