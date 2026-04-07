# Customer UX E2E Spec

This document defines the customer-facing outcomes that `ebpf-tracker` should
deliver and the end-to-end checks that should protect them.

The test goal is not "did the code run." The goal is "did the customer get the
result they came for, with the least surprise."

## Suite Controls

The journey scripts use `SKIP` for missing host capabilities by default. That
means Docker or loopback prerequisites can be reported as skips instead of
hard failures when the underlying customer outcome still makes sense.

Use these controls when you want stricter behavior:
- `bash scripts/customer-ux-check.sh --strict-prereqs` forces Docker and loopback
  capability gaps to fail the suite
- `bash scripts/customer-ux-check.sh --fail-on-skip` makes the umbrella runner
  fail if any individual journey reports `SKIP`
- `EBPF_TRACKER_E2E_STRICT_PREREQS=1` applies the same strict behavior to the
  individual journey scripts
- `bash scripts/customer-data-e2e.sh --analyze-endpoint <url>` switches the
  dataset/intelligence journey to an external OpenAI-compatible endpoint and
  avoids the local loopback mock-server path

## 1. First-Run CLI

User goal: confirm the tool installs and starts cleanly on a real machine.

Setup and prereqs:
- `ebpf-tracker` is installed or built locally
- Docker is available and can start the tracing runtime

Command:
- `ebpf-tracker /bin/true`

Expected observable outcome:
- the command exits `0`
- the runtime starts and the command completes without manual intervention
- the user sees a successful end-to-end wrapper session, not just a help screen
- the output makes it clear that the traced command actually ran

Failure signals:
- non-zero exit for a trivial command
- Docker/runtime startup errors
- the command hangs before the wrapped process starts
- the tool prints only internal plumbing without showing completion

## 2. Trace Your App

User goal: run a real command under tracing and see the full session, not just
the final app process.

Setup and prereqs:
- a small example project is available
- Docker is available
- the customer can run a normal project command such as `cargo run`

Command:
- `ebpf-tracker cargo run` or an equivalent real project command

Expected observable outcome:
- the wrapped command builds and runs successfully
- the user sees build/toolchain activity before the app starts when that is part
  of the workflow
- the command's exit code matches the underlying project command
- the session produces usable trace output or logs for later inspection

Failure signals:
- the wrapper hides the real command output
- only the final app is traced and the build/toolchain steps disappear
- the wrapper exits successfully while the underlying command fails
- tracing adds an obvious breakage to a normal project run

## 3. Product-First Demo

User goal: open a polished demo or dashboard first, without needing to learn the
repository layout.

Setup and prereqs:
- the demo path is available from a checkout or from a repo-built binary with
  demo assets available
- the browser can open the dashboard

Command:
- `ebpf-tracker see`
- `ebpf-tracker demo --dashboard session-io-demo`

Expected observable outcome:
- the dashboard opens
- the default demo session is visible and recognizable
- replay artifacts are preserved for later review
- the user can see what the product does without reading repo internals

Failure signals:
- the command claims success but no dashboard appears
- the demo launches without visible replay data or library content
- the experience depends on undocumented repo-only state
- the first-run demo path is slower or more confusing than the plain CLI path

## 4. Replay And Viewer

User goal: inspect a recorded session and move through it without the live trace
still running.

Setup and prereqs:
- a replay log exists from a prior run
- the viewer can bind a local port and open a browser

Command:
- `cargo viewer --replay logs/ebpf-tracker-YYYYMMDD-HHMMSS.log`
- or an equivalent replay command for the current checkout

Expected observable outcome:
- the viewer loads the replay successfully
- the session is visible in the browser
- replay controls work in a way a customer can feel: play, pause, step, speed,
  and jump
- the session can be revisited later from the stored log

Failure signals:
- the replay cannot open or immediately crashes
- controls do not affect playback
- the viewer does not expose the session that was recorded
- the replay path silently falls back to a blank or unrelated state

## 5. Dataset And Intelligence

User goal: turn a real trace into a dataset bundle and, when enabled, get a
useful analysis summary instead of raw logs only.

Setup and prereqs:
- a trace exists that can be fed into dataset capture
- for analysis, a local or mocked OpenAI-compatible endpoint is available
- the customer can opt into intelligence mode explicitly

Command:
- `ebpf-tracker --emit jsonl cargo run | cargo dataset --test-name <name>`
- `cargo see --intelligence-dataset session-io-demo`
- or an equivalent dataset/intelligence command for the current checkout

Expected observable outcome:
- a dataset bundle is written for the run
- the analysis path writes a summary when enabled
- the dashboard or CLI shows the dataset/intelligence flow as progressing
- the user gets a readable outcome they can act on, not just a raw artifact
- if an external endpoint is used, the analysis path still produces the same
  bundle outputs and the customer can avoid the local mock-server prerequisite

Failure signals:
- the dataset bundle is missing or incomplete
- analysis never appears after the run completes
- the customer cannot tell whether the supervised flow succeeded or failed
- optional model availability breaks the entire trace experience

## 6. Attach Boundary

User goal: understand what attach can do today and what is intentionally still
out of scope.

Setup and prereqs:
- the customer knows the target platform they want to attach to

Command:
- `ebpf-tracker attach k8s --selector app=payments`
- `ebpf-tracker attach aws-eks --cluster prod --region us-east-1 --selector app=payments`
- `ebpf-tracker attach docker --container payments-api`
- `ebpf-tracker attach aws-ecs --cluster prod --service api`

Expected observable outcome:
- supported paths are explicit about what they are doing
- unsupported paths fail fast with a clear explanation instead of pretending to
  attach
- the customer can tell whether they are in a live path or a scaffold path

Intentionally out of scope today:
- full attach coverage for every backend and platform combination
- a promise that `attach` behaves like a general-purpose fleet agent
- undocumented support for `aws-ecs` Fargate
- undocumented support for any backend that is only a placeholder in the repo

Failure signals:
- the command silently claims support for an unsupported target
- the command hangs without explaining scope
- the tool returns a vague plan when the customer expected live behavior
- the boundary between live support and scaffold support is unclear

## Script Mapping

These are the intended E2E scripts for the customer journeys above:
- `scripts/customer-cli-e2e.sh`
- `scripts/customer-viewer-e2e.sh`
- `scripts/customer-data-e2e.sh`
- `scripts/customer-ux-check.sh`

## CI And Release Integration

- `scripts/customer-ux-check.sh` is the umbrella runner for the customer journey suite.
- `bash scripts/release-check.sh --with-customer-ux` is the maintainer-facing release gate for full customer UX coverage.
- GitHub release verification prefers `scripts/customer-ux-check.sh` when present, and otherwise falls back to `dashboard-smoke` plus `dataset-smoke`.
- The default CI/release generic gates remain intentionally cheaper (`fmt`, `test`, `build`) so routine automation stays fast.
