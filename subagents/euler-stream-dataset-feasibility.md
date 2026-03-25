# Euler Stream Dataset Feasibility

- Agent: `Euler`
- Agent ID: `019d2415-2829-77f3-a808-ccb2fa154f77`
- Scope: feasibility review for a local agent or extension that reads streaming output and turns each run into a structured dataset
- Status: completed and carried forward into implementation

## What We Confirmed

The repo already had the right boundaries for this direction:

- typed stream records in `crates/ebpf-tracker-events/src/lib.rs`
- JSONL emission and replay log creation in `src/lib.rs`
- replay and live viewer consumption in `crates/ebpf-tracker-viewer/assets/live-trace-matrix.js`
- a reusable post-run summary shape that could be shared across consumers

The cleanest first path was confirmed to be:

- keep the raw dataset contract model-based, not viewer-based
- build a local dataset consumer crate first
- add model analysis as a second layer on top of saved dataset bundles
- make the model connection provider-based so local LM Studio works now and better models can be swapped in later

## What Is Implemented

The current implementation now exists in the repo:

- `crates/ebpf-tracker-dataset/src/lib.rs`
  - ingests JSONL from `stdin` or replay logs
  - writes `run.json`, `events.jsonl`, `processes.json`, `aggregates.json`, and `features.json`
- `crates/ebpf-tracker-dataset/src/analysis.rs`
  - analyzes a saved dataset bundle through a provider adapter
  - defaults to LM Studio at `http://127.0.0.1:1234/v1`
  - defaults to model `qwen/qwen3.5-9b`
  - supports a generic OpenAI-compatible backend for future model swaps
- `crates/ebpf-tracker-events/src/lib.rs`
  - now owns the shared per-run trace builder so dataset and OTel consumers can reuse the same logic
- `.cargo/config.toml`
  - now includes `cargo dataset`

Current commands:

- `eBPF_tracker --emit jsonl cargo run | cargo dataset --test-name cargo-run-smoke`
- `cargo dataset --replay logs/ebpf-tracker-YYYYMMDD-HHMMSS.log`
- `cargo dataset analyze --run datasets/<run-id> --provider lm-studio --model qwen/qwen3.5-9b`

## Core Ideas To Preserve

- Local-first:
  use LM Studio and a local Qwen model first so iteration is cheap and private.
- Adapter-based:
  model calls should go through a provider abstraction, not be coupled to LM Studio.
- Dataset-first:
  saved run bundles are the source of truth; model analysis is derived, replaceable output.
- Stable artifact format:
  upgrading models later should not require changing the dataset layout.
- Test-learning oriented:
  the main value is learning from repeated runs, not one-off summaries.

## Plan

### Phase 1. Capture Every Interesting Run Reliably

- Keep the dataset writer as the first-stage contract.
- Wire test and smoke scripts to pass:
  - `--test-name`
  - `--git-sha`
  - `--transport`
  - `--runtime`
  - exit metadata
- Prefer producing a dataset bundle for every important scripted run.

Why:
Without consistent run metadata, the model layer will stay interesting but not very useful for regression learning.

### Phase 2. Make Local Model Analysis Repeatable

- Treat LM Studio as the default local backend for now.
- Keep `lm-studio` and `openai-compatible` as explicit provider names.
- Store outputs under `datasets/<run-id>/analysis/` as:
  - markdown for human review
  - raw JSON for future reprocessing
- Keep prompts compact and grounded in:
  - `run.json`
  - `features.json`
  - `processes.json`
  - `aggregates.json`
  - sampled `events.jsonl`

Why:
This keeps prompt costs low and prevents the adapter from depending on one model's quirks.

### Phase 3. Turn Analysis Into Learning Signals

- Define a stable schema for model conclusions, for example:
  - summary
  - app signal
  - tooling noise level
  - anomalies
  - likely regressions
  - next steps
- Add simple scoring or tagging fields later, such as:
  - `looks_normal`
  - `noise_heavy`
  - `suspicious_connect_pattern`
  - `write_volume_jump`
- Keep these tags machine-readable so future dashboards or reports can aggregate them.

Why:
Free-form markdown is useful for reading, but not enough for comparing many runs over time.

### Phase 4. Compare Models Without Rewriting The Pipeline

- Keep the provider interface stable.
- Add alternate backends later through config, not dataset format changes.
- Use the same saved dataset bundle to compare:
  - LM Studio local Qwen
  - stronger local models
  - remote OpenAI-compatible models

Why:
The dataset bundle should outlive any one model choice.

### Phase 5. Close The Feedback Loop

- Add a lightweight review flow where good or bad model analyses can be marked.
- Save reviewer feedback next to the run bundle.
- Use that to refine prompts, heuristics, and later labeling.

Why:
If we want to learn from tests over time, we need a way to separate helpful analyses from noisy ones.

## Near-Term Next Steps

- Add wrapper support in smoke and demo scripts so important runs automatically write dataset metadata.
- Add a structured JSON summary alongside markdown model output.
- Add run-to-run comparison mode, for example current run vs last successful run of the same `test_name`.
- Surface dataset analysis in the viewer or report scripts only after the dataset and analysis formats stabilize.

## Risks And Constraints

- The current stream still contains full-session noise from Cargo and runtime tooling.
- Replay logs do not yet include a final typed run-completion record.
- Local model availability depends on LM Studio actually serving the OpenAI-compatible endpoint.
- Prompt quality will matter more than model size early on because the input is trace-heavy and noisy.

## Source Task

Spawned to answer the possibility of having an extension where we can run a local agent against stream output and create a dataset from each output so we can learn from our tests.
