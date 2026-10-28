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
    ("route-marker.txt", "fixture-route-marker\n"),
    ("descendant-marker.txt", "fixture-descendant-marker\n"),
    ("shutdown-marker.txt", "fixture-graceful-shutdown\n"),
):
    require((root / "data" / filename).read_text() == expected, f"retained {filename}")
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
require(any(record.get("kind") == "connect" for record in app_events), "app PostgreSQL connect attempt")
require(any(record.get("kind") == "write" for record in app_events), "app write attempt")
require(any(record.get("kind") == "open_at" and record.get("file") == "/data/route-marker.txt"
            for record in app_events), "known app file open")
require(any(record.get("kind") == "open_at" and record.get("file") == "/data/descendant-marker.txt"
            and record.get("pid") != app_pid for record in syscalls), "descendant file open")
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
    "negative_cases": negative_cases,
    "lifecycle": lifecycle,
}
(root / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
print(json.dumps(summary, indent=2))
