# Task Log

This file tracks user-requested work and delegated agent tasks in progress on this branch.

## Workflow

- Add or update a task entry before starting substantial work.
- Add or update a task entry before spawning a subagent.
- Keep the task status current as work moves from planned to running to completed.
- Link any resulting notes in `subagents/` when they exist.
- Group related tasks under the most relevant category so the log stays easy to scan.

## Active

### Focused Alpha Release

- 2026-10-28 | Task: Deliver the authorized same-container Axum tracing alpha: native launcher, Bookworm package, Docker/CI recipe, and isolated live acceptance; leave Roots unchanged | Owner: Codex | Status: implemented; arm64 live package acceptance and offline replay passed; amd64 CI and publication pending | Output: `docs/in-container.md`, `docs/alpha-validation.md`, package and fixture
- 2026-10-28 | Task: Implement the native Linux tracing launcher with privilege dropping, signal forwarding, exit status, and JSONL output | Agent: alpha-scope-audit | Status: completed; removed diagnostics; known-bad kernel rejected before launch; two kernel guard tests passed | Output: `crates/ebpf-tracker-agent/`
- 2026-10-28 | Task: Build the Bookworm runtime Debian package and integrate verified release assets | Agent: alpha-release-audit | Status: completed; arm64 package installed; final workflow review passed; downloaded-checksum guidance corrected | Output: package build scripts, Docker builder, release workflow
- 2026-10-28 | Task: Add an isolated Axum/PostgreSQL fixture and same-container runtime acceptance in CI | Agent: alpha-ci-fix | Status: completed; stronger startup/exit-23 capture checks and kernel evidence retained; 13 wrapper regressions passed; amd64 rerun pending | Output: `examples/axum-container/`, runtime smoke script, CI workflow

- 2026-10-26 | Task: Align the alpha with the user's clarified target: a Linux Docker Axum server, using Roots as the reference application | Owner: Codex | Status: superseded by the 2026-10-28 authorized same-container launcher decision; Roots remains unchanged | Output: Roots source audit and revised `docs/alpha-scope.md`
- 2026-10-26 | Task: Inspect Roots Axum runtime and disposable integration requirements without changing Roots | Agent: roots-axum-audit | Status: completed (read-only) | Output: Axum 0.8 / Docker / PostgreSQL source facts, existing-container recommendation, thread/container isolation and service continuity acceptance; no Roots files or services changed

- 2026-10-26 | Task: Prepare a focused alpha release around a supported development workflow and verify current release readiness | Owner: Codex | Status: foundations verified; Axum integration and publication pending | Verification: strict Linux PR CI passed on `9b549db` (https://github.com/givtaj/ebpf-tracker/actions/runs/40313892899); local release gate passed, 130 workspace tests plus helper quoting test, 11 exit-status regressions, 4 command-resolution regressions, viewer/replay and dataset smoke passed; private vulnerability reporting enabled | Output: `docs/alpha-scope.md`, release preparation and gates
- 2026-10-26 | Task: Audit and repair release tooling, packaging, versioning, and validation blockers | Agent: alpha-release-audit | Status: completed | Output: prerelease workflow, version checks, archive regression checks
- 2026-10-26 | Task: Review the product surface and implement installed replay and version discovery for the focused alpha | Agent: alpha-scope-audit | Status: completed | Output: root replay/version commands, unit/integration tests, offline replay smoke
- 2026-10-26 | Task: Repair customer CLI command resolution and strengthen live alpha acceptance | Agent: alpha-ci-fix | Status: completed | Output: command-resolution regression checks; JSONL, four-probe demo, and exit-status gates; live verification pending Linux CI
- 2026-10-26 | Task: Preserve the wrapped workload exit status through bpftrace collection | Agent: alpha-runtime-exit | Status: completed | Output: supervised status handoff; 11 wrapper regressions and quoting unit test passed; live Linux gate pending
- 2026-10-26 | Task: Verify packaged Linux binaries without the build checkout, including embedded assets and Node tracing | Agent: alpha-release-audit | Status: implemented; live verification pending release workflow | Output: installed alpha gate in release asset assembly

### Platform Attach And Cloud Targets

- 2026-03-25 | Task: Follow up with an `inspektor-gadget` attach backend implementation for Kubernetes and AWS EKS targets | Owner: Codex | Status: deferred during focused alpha | Output: `docs/alpha-scope.md`
- 2026-03-25 | Task: Follow up with a `tetragon` attach backend implementation for long-running Kubernetes and AWS EKS targets | Owner: Codex | Status: deferred during focused alpha | Output: `docs/alpha-scope.md`
- 2026-03-25 | Task: Evaluate and scope `aws-ecs` attach support for EC2 launch type after the EKS path is stable | Owner: Codex | Status: deferred during focused alpha | Output: `docs/alpha-scope.md`

## Completed

### Open-Source Alpha Hardening

- 2026-09-27 | Task: Turn the current experimental workbench into a trustworthy open-source alpha by isolating trace scope, documenting the privileged runtime boundary, repairing CI/release delivery, and validating one supported end-to-end workflow | Owner: Codex | Status: completed | Verification: strict v0.1.1 release gate passed twice; 121 tests passed; live bpftrace runtime, descendant isolation, all three customer journeys, and synthetic platform-archive checks passed | Output: runtime/probe changes, CI/release updates, focused public docs, verification evidence
- 2026-09-27 | Task: Design and implement workload-scoped tracing for wrapped commands without losing child-process coverage | Agent: trace-isolation | Status: completed | Output: `scripts/`, `src/`, probe/runtime tests and docs notes
- 2026-09-27 | Task: Repair CI and GitHub release readiness, including strict product-path verification and packaging audit | Agent: release-readiness | Status: completed | Output: `.github/workflows/`, release scripts/docs
- 2026-09-27 | Task: Tighten the public product story, security boundary, compatibility promise, and known documentation drift | Agent: oss-docs | Status: completed | Output: `README.md`, `docs/`, `SECURITY.md`, crate docs

### First Release Readiness

- 2026-04-03 | Task: Realign the first-release workflow around a solo-maintainer, product-first verification split | Owner: Codex | Status: completed | Output: `scripts/runtime-smoke.sh`, `scripts/release-check.sh`, `README.md`, `docs/cli.md`, `CONTRIBUTING.md`, `.github/pull_request_template.md`, `RELEASE.md`
- 2026-04-03 | Task: Audit packaging strategy and manifest metadata for an initial public release | Agent: Einstein | Status: completed | Output: `Cargo.toml`, `crates/ebpf-tracker-viewer/Cargo.toml`
- 2026-04-03 | Task: Add a baseline GitHub CI workflow for format, build, and test verification | Agent: Sagan | Status: completed | Output: `.github/workflows/ci.yml`
- 2026-04-03 | Task: Add a tagged release workflow for publishing GitHub release artifacts | Agent: Chandrasekhar | Status: completed | Output: `.github/workflows/release.yml`
- 2026-04-03 | Task: Draft contributor guidance for external users and first-time maintainers | Agent: Ptolemy | Status: completed | Output: `CONTRIBUTING.md`
- 2026-04-03 | Task: Add a basic security policy and disclosure process | Agent: Jason | Status: completed | Output: `SECURITY.md`
- 2026-04-03 | Task: Add GitHub issue templates and a pull request template for public collaboration | Agent: Leibniz | Status: completed | Output: `.github/ISSUE_TEMPLATE/`, `.github/pull_request_template.md`
- 2026-04-03 | Task: Audit install and onboarding docs for a first release and tighten gaps | Agent: Banach | Status: completed | Output: `README.md`, `docs/cli.md`
- 2026-04-03 | Task: Verify example and demo documentation for external users | Agent: Cicero | Status: completed | Output: `examples/README.md`
- 2026-04-03 | Task: Draft a maintainer-facing release checklist and runbook | Agent: Boole | Status: completed | Output: `RELEASE.md`
- 2026-04-03 | Task: Sweep remaining release risks across tests, scripts, and tracked artifacts | Agent: McClintock | Status: completed | Output: `.gitignore`, `.github/workflows/release.yml`, `SECURITY.md`, `README.md`

### Developer Tooling

- 2026-03-29 | Task: Verify the Docker cleanup helper is commit-ready as a standalone topic and only targets this repo's Compose projects by default | Owner: Codex | Status: completed | Output: dry-run verification notes, commit-ready verdict: yes
- 2026-03-29 | Task: Restrict the Docker cleanup helper so it only removes `ebpf-tracker`-owned Compose stacks for this repo instead of generic cache volumes | Owner: Codex | Status: completed | Output: `scripts/docker-cleanup.sh`, `README.md`, `CHANGELOG.md`, `TASKLOG.md`
- 2026-03-25 | Task: Add a repo-local Docker cleanup script for reclaiming disk space from tracing runtimes and Jaeger helpers | Owner: Codex | Status: completed | Output: `scripts/docker-cleanup.sh`, `README.md`, `TASKLOG.md`

### Workflow And Project Hygiene

- 2026-03-25 | Task: Add task tracking workflow and root task log | Owner: Codex | Status: completed | Output: `AGENT.md`, `TASKLOG.md`
- 2026-03-25 | Task: Reorganize `TASKLOG.md` into related categories for easier scanning | Owner: Codex | Status: completed | Output: `TASKLOG.md`
- 2026-03-25 | Task: Review worktree and commit ready changes with selective staging | Agent: Kepler | Status: completed | Output: `3a2a22e`, `AGENT.md`, `TASKLOG.md`, `subagents/meridian-docs-audit.md`, `subagents/initiative-completion-audit.md`

### Repository Understanding And Onboarding

- 2026-03-25 | Task: Explore repository structure and onboarding flow | Agent: Halley | Status: completed | Output: `subagents/halley-repo-onboarding-summary.md`

### Dashboard And Frontend Review

- 2026-03-25 | Task: Review dashboard extension from a frontend perspective and identify top improvements | Agent: Einstein | Status: completed | Output: `subagents/einstein-dashboard-frontend-review.md`

### Customer Experience Review

- 2026-03-25 | Task: Review repository from the customer experience standpoint and identify top improvements | Agent: Euclid | Status: completed | Output: `subagents/euclid-customer-experience-review.md`

### Platform Attach And Cloud Targets

- 2026-03-29 | Task: Verify the `attach` scaffold is commit-ready as a standalone topic, including its AWS scope wording and tests | Owner: Codex | Status: completed | Output: attach CLI verification notes, commit-ready verdict: yes
- 2026-03-29 | Task: Audit the `attach` scaffold/docs for a commit-ready boundary and tighten first-wave AWS scope wording in the scaffold output | Owner: Codex | Status: completed | Output: `src/attach.rs`, `README.md`, `TASKLOG.md`
- 2026-03-29 | Task: Explicitly document `aws-eks` and `aws-ecs` Fargate limitations for attach mode and keep them out of the first-wave scope | Owner: Codex | Status: completed | Output: `src/attach.rs`, `README.md`, `TASKLOG.md`
- 2026-03-25 | Task: Scaffold a new `attach` command and backend adapter layer while preserving the existing managed-runtime flow | Owner: Codex | Status: completed | Output: `src/attach.rs`, `src/lib.rs`, `README.md`, `TASKLOG.md`
- 2026-03-25 | Task: Define and document the first-wave AWS attach target around EKS on EC2 with existing eBPF backends | Owner: Codex | Status: completed | Output: `src/attach.rs`, `src/lib.rs`, `README.md`, `TASKLOG.md`

### Dataset And Learning Pipeline Exploration

- 2026-03-29 | Task: Verify the supervised `--intelligence-dataset` flow is commit-ready as a standalone topic and identify whether current evidence artifacts should be regenerated or excluded | Owner: Codex | Status: completed | Output: dataset tests green, commit-ready verdict: not yet, stale `datasets/run-*` evidence should be excluded or regenerated
- 2026-03-29 | Task: Stabilize the supervised `--intelligence-dataset` flow and audit stale LM Studio evidence artifacts for commit readiness | Owner: Codex | Status: completed | Output: `crates/ebpf-tracker-dataset/src/analysis.rs`, `CHANGELOG.md`, `TASKLOG.md`
- 2026-03-25 | Task: Evaluate a local agent or extension for turning stream output into a reusable dataset | Agent: Euler | Status: completed | Output: `subagents/euler-stream-dataset-feasibility.md`
- 2026-03-25 | Task: Demonstrate the dataset feature by running it on a real trace and verifying it with tests | Owner: Codex | Status: completed | Output: `datasets/replay-demo-20260324-212957/`, `datasets/synthetic-jsonl-demo/`
- 2026-03-25 | Task: Run the full end-to-end `cargo demo --emit jsonl ... | cargo dataset ...` flow and verify local Docker-backed tracing support | Owner: Codex | Status: completed | Output: `datasets/e2e-session-io-demo/`, terminal verification notes
- 2026-03-25 | Task: Add a supervised `--intelligence-dataset` flow with live viewer status and LM Studio handoff | Owner: Codex | Status: completed | Output: `src/intelligence.rs`, `src/lib.rs`, `crates/ebpf-tracker-dataset/src/lib.rs`, `crates/ebpf-tracker-viewer/assets/live-trace-matrix.js`, `datasets/run-1774432023773-live/`

### Product Entry And CLI Ergonomics

- 2026-10-04 | Task: Run Rust workload tracing R&D with `rusta-pitest` and tighten the Rust Docker runtime cache/docs based on the findings | Owner: Codex | Status: completed | Verification: `cargo test --locked` passed locally after adding persisted Cargo-home cache coverage | Output: `docker-compose.bpftrace.yml`, `src/runtime.rs`, `src/compose.rs`, `docs/cli.md`, `README.md`, `CHANGELOG.md`
- 2026-08-15 | Task: Add a terminal-first droplet monitor for host metrics and eBPF health | Owner: Codex | Status: completed | Verification: installed the approved `pkg-config` and `libssl-dev` build prerequisites; `cargo test --all --locked` passed 120 tests; `cargo monitor --once --no-clear` rendered successfully | Output: `src/monitor.rs`, `src/lib.rs`, `.cargo/config.toml`, `docs/cli.md`, `docs/host-monitoring.md`, `docs/droplet-host-ebpf-plan.md`, `README.md`, `CHANGELOG.md`, `TASKLOG.md`
- 2026-04-05 | Task: Harden customer UX E2E prereq handling with `SKIP` semantics, strict-prereq mode, and external analyze-endpoint support, then align CI/release fallback behavior with host capabilities | Owner: Codex | Status: completed | Output: `scripts/customer-cli-e2e.sh`, `scripts/customer-viewer-e2e.sh`, `scripts/customer-data-e2e.sh`, `scripts/customer-ux-check.sh`, `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `scripts/release-check.sh`, `RELEASE.md`
- 2026-04-04 | Task: Refresh first-run onboarding copy and viewer layout while clarifying that demo manifests require a checkout or repo-built binary | Owner: Codex | Status: completed | Output: `README.md`, `docs/cli.md`, `examples/README.md`, `src/lib.rs`, `crates/ebpf-tracker-viewer/assets/live-trace-matrix.js`, `CHANGELOG.md`, `TASKLOG.md`
- 2026-04-04 | Task: Add a customer UX end-to-end suite and ignore generated `output/` artifacts so the branch stays finishable | Owner: Codex | Status: completed | Output: `docs/customer-ux-e2e.md`, `scripts/customer-cli-e2e.sh`, `scripts/customer-viewer-e2e.sh`, `scripts/customer-data-e2e.sh`, `scripts/customer-ux-check.sh`, `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `scripts/release-check.sh`, `RELEASE.md`, `.gitignore`, `CHANGELOG.md`, `TASKLOG.md`
- 2026-04-04 | Task: Add black-box release verification for the main product flows, including viewer replay and dataset ingest/analyze checks in CI and release workflows | Owner: Codex | Status: completed | Output: `scripts/runtime-smoke.sh`, `scripts/dataset-smoke.sh`, `scripts/release-check.sh`, `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `RELEASE.md`, `.cargo/config.toml`, `CHANGELOG.md`, `TASKLOG.md`
- 2026-03-29 | Task: Make viewer help discovery side-effect free and align replay docs with the actual Cargo alias invocation | Owner: Codex | Status: completed | Output: `crates/ebpf-tracker-viewer/src/main.rs`, `crates/ebpf-tracker-viewer/README.md`, `README.md`, `examples/README.md`, `examples/session-io-demo/README.md`, `docs/trace-payment-engine.md`, `CHANGELOG.md`, `TASKLOG.md`
- 2026-03-25 | Task: Add a short CLI action to launch the product demo experience | Owner: Codex | Status: completed | Output: `src/lib.rs`, `.cargo/config.toml`, `README.md`

### Documentation And Onboarding

- 2026-03-29 | Task: Review repo AI-agent friendliness and add a prioritized onboarding checklist | Owner: Codex | Status: completed | Output: `docs/ai-agent-onboarding-checklist.md`, `CHANGELOG.md`, `TASKLOG.md`
- 2026-03-25 | Task: Audit and refresh README/documentation files for the current product surface | Agent: Meridian | Status: completed | Output: `README.md`, `docs/trace-payment-engine.md`, `examples/README.md`, `examples/session-io-demo/README.md`, `crates/ebpf-tracker-viewer/README.md`, `crates/ebpf-tracker-dataset/README.md`, `subagents/meridian-docs-audit.md`

### Initiative Review And Closure

- 2026-03-25 | Task: Review prior subagent outputs and determine whether the initiative is complete | Agent: Atlas | Status: completed | Output: `subagents/initiative-completion-audit.md`, `TASKLOG.md`
