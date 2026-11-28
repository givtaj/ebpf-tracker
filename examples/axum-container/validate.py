#!/usr/bin/env python3
"""Validate saved evidence from the real Axum/PostgreSQL container smoke."""
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])


def require(condition, message):
    if not condition:
        raise SystemExit(f"in-container smoke: FAIL: {message}")


health = json.loads((root / "health.json").read_text())
identity = json.loads((root / "identity.json").read_text())
exercise = json.loads((root / "exercise.json").read_text())
require(health == {"ok": True}, "health route response")
require(exercise == {
    "database_marker": "ebpf-alpha-fixture", "answer": 42,
    "file_written": True, "descendant_finished": True,
}, "real PostgreSQL query and fixture route response")
missing_file_path = "/data/fixture-missing-input.txt"
control_file_path = "/data/file-open-control.txt"
missing_file_requests = int((root / "missing-file-request-count.txt").read_text())
require(missing_file_requests == 4, "four missing-file requests must run")
for request in range(1, missing_file_requests + 1):
    require((root / f"missing-file-{request}.status").read_text().strip() == "500",
            f"missing-file request {request} must reproduce HTTP 500")
    require(json.loads((root / f"missing-file-{request}.json").read_text()) == {
        "error": "fixture_missing_file", "path": missing_file_path,
        "errno": 2, "control_read": True,
    }, f"missing-file request {request} must report ENOENT after reading its control")
status = identity["status"]
require([int(value) for value in status["Uid"].split()] == [10001] * 4,
        "application real/effective/saved/fs UIDs must all be 10001")
require([int(value) for value in status["Gid"].split()] == [10001] * 4,
        "application real/effective/saved/fs GIDs must all be 10001")
require(set(map(int, status["Groups"].split())) <= {10001},
        "application must not retain unrelated supplementary groups")
for capability in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
    require(int(status[capability], 16) == 0, f"application {capability} must be zero")
require(status["NoNewPrivs"] == "1", "application must have no_new_privs")

for filename, expected in (
    ("startup-marker.txt", "fixture-startup-marker\n"),
    ("file-open-control.txt", "fixture-file-open-control\n"),
    ("route-marker.txt", "fixture-route-marker\n"),
    ("descendant-marker.txt", "fixture-descendant-marker\n"),
    ("shutdown-marker.txt", "fixture-graceful-shutdown\n"),
):
    require((root / "data" / filename).read_text() == expected, f"retained {filename}")
require(not (root / "data" / "fixture-missing-input.txt").exists(),
        "missing-file scenario must not create its absent input")
require((root / "stop-exit-code.txt").read_text().strip() == "0", "graceful stop exit status")
require((root / "noise-proof.txt").read_text() == "unrelated", "independent noise workload did not execute")

trace_text = (root / "events.jsonl").read_text()
require("fixture-stdout-marker" not in trace_text, "stdout contaminated JSONL")
require("fixture-stderr-marker" not in trace_text, "stderr contaminated JSONL")
records = []
for number, line in enumerate(trace_text.splitlines(), 1):
    try:
        record = json.loads(line)
    except ValueError as error:
        raise SystemExit(f"in-container smoke: FAIL: invalid JSONL at line {number}: {error}")
    require(isinstance(record, dict), f"JSONL line {number} must be an object")
    require(record.get("type") in {"session", "syscall", "aggregate"}, f"unknown record at line {number}")
    if record["type"] == "syscall":
        require(record.get("kind") in {"execve", "open_at", "write", "connect"}, f"unknown syscall kind at line {number}")
    records.append(record)
syscalls = [record for record in records if record["type"] == "syscall"]
require({"execve", "open_at", "write", "connect"} <= {record.get("kind") for record in syscalls},
        "trace must contain all four syscall kinds")
app_pid = identity["pid"]
app_events = [record for record in syscalls if record.get("pid") == app_pid]
require(any(record.get("kind") == "execve" for record in app_events), "primary application exec attempt")
require(any(record.get("kind") == "open_at" and record.get("file") == "/data/startup-marker.txt"
            and record.get("comm") == "axum-fixture" for record in app_events),
        "primary application startup file open before worker creation")
require(any(record.get("kind") == "write" and record.get("comm") == "axum-fixture"
            for record in app_events), "primary application thread write attempt")
require(any(record.get("kind") == "connect" for record in app_events), "app PostgreSQL connect attempt")
require(any(record.get("kind") == "write" for record in app_events), "app write attempt")
require(any(record.get("kind") == "open_at" and record.get("file") == "/data/route-marker.txt"
            for record in app_events), "known app file open")
require(any(record.get("kind") == "open_at" and record.get("file") == "/data/descendant-marker.txt"
            and record.get("pid") != app_pid for record in syscalls), "descendant file open")
open_events = [record for record in syscalls if record.get("kind") == "open_at"]
for record in open_events:
    result, error = record.get("return_value"), record.get("errno")
    require(type(result) is int and type(error) is int,
            "installed alpha.4 must report an integer result and errno for every completed open")
    require(error == (0 if result >= 0 else -result),
            "file-open result and errno must agree")
missing_file_events = [record for record in open_events if record.get("file") == missing_file_path]
require(len(missing_file_events) == missing_file_requests,
        "one completed failed open must be captured for each missing-file request")
for record in missing_file_events:
    require(record.get("pid") == app_pid and record.get("comm") in {"axum-fixture", "axum-worker"},
            "missing-file evidence must identify the API process and its worker")
    require(record["return_value"] == -2 and record["errno"] == 2,
            "missing file must have kernel result -ENOENT, independently of the HTTP body")
control_file_events = [record for record in open_events if record.get("file") == control_file_path]
require(len(control_file_events) >= missing_file_requests + 1,
        "successful control creation and all request reads must be captured")
for record in control_file_events:
    require(record.get("pid") == app_pid and record.get("comm") in {"axum-fixture", "axum-worker"},
            "control file evidence must identify the API process and its worker")
    require(record["return_value"] >= 0 and record["errno"] == 0,
            "successful control opens must not inherit a concurrent missing-file error")
require(all(record["return_value"] >= 0 and record["errno"] == 0
            for record in open_events if record.get("file") == "/data/descendant-marker.txt"),
        "descendant opens must not inherit worker errors")
for record in syscalls:
    require(record.get("comm") not in {"outside-noise", "host-noise"}, "unrelated process leaked into trace")
    require(not any(marker in record.get("file", "") for marker in ("unrelated-noise-marker", "host-noise-marker")),
            "unrelated file activity leaked into trace")

stdout = (root / "app.stdout.log").read_text()
stderr = (root / "app.stderr.log").read_text()
require("fixture-stdout-marker" in stdout, "original application stdout missing")
require("fixture-stderr-marker" in stderr, "original application stderr missing")
require("fixture-stderr-marker" not in stdout and "fixture-stdout-marker" not in stderr,
        "application stdout/stderr streams were mixed")
require("fixture-shutdown-complete" in stdout, "application did not complete graceful shutdown")
negative_cases = json.loads((root / "negative-cases.json").read_text())
require(negative_cases == {"exit23": 23, "missing-command": 127, "missing-permission": 125, "nonroot-agent": 125, "existing-output": 125},
        "required exit/permission cases were not verified")
lifecycle = json.loads((root / "lifecycle/summary.json").read_text())
require({name: result["exit_code"] for name, result in lifecycle.items()} == {
    "ignore-term": 137, "sigint": 0, "collector-failure": 125,
}, "required signal/collector-failure cases were not verified")
require(all(result["app_reaped"] for result in lifecycle.values()), "lifecycle case left its app running")

summary = {
    "result": "passed", "fixture": "Axum 0.8 + separate PostgreSQL",
    "app_pid": app_pid, "uid": 10001, "gid": 10001,
    "app_capabilities": "all zero", "no_new_privs": True,
    "trace_records": len(records), "syscall_records": len(syscalls),
    "syscall_kinds": sorted({record["kind"] for record in syscalls}),
    "graceful_exit": 0, "noise_excluded": True,
    "missing_file": {
        "path": missing_file_path, "http_status": 500,
        "requests": missing_file_requests, "completed_opens": len(missing_file_events),
        "return_value": -2, "errno": 2,
    },
    "file_open_control": {
        "path": control_file_path, "successful_opens": len(control_file_events), "errno": 0,
    },
    "negative_cases": negative_cases,
    "lifecycle": lifecycle,
}
(root / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
print(json.dumps(summary, indent=2))
