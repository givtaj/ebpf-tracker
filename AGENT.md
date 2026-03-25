# Agent Workflow Notes

## Subagent Notes

- Keep `subagents/` visible in local git status while work is in progress.
- Do not include `subagents/` in feature or implementation commits during the task.
- Commit `subagents/` separately at the end, as documentation, once the task is finished and the notes are ready to keep.
- Use selective staging so `subagents/` stays out of intermediate commits without hiding it locally.

## Commit Logging

- Keep [CHANGELOG.md](/Users/aidin/code/canvas/eBPF-Rust/CHANGELOG.md) updated as work progresses.
- Before making a commit, add a concise changelog entry that matches the change being committed.
- Prefer including the changelog update in the same commit as the code or docs change it describes.

## Task Logging

- Keep [TASKLOG.md](/Users/aidin/code/canvas/eBPF-Rust/TASKLOG.md) updated as work progresses.
- Before starting substantial work or spawning a subagent, add or update the task entry in `TASKLOG.md`.
- Log the task title, assigned agent or owner, status, and output file when available.
- Update the same task entry as the work moves from planned to running to completed.
