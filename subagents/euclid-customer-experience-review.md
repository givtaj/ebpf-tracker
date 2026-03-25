# Euclid Customer Experience Review

- Agent: `Euclid`
- Agent ID: `019d2410-92e6-7343-9fac-180144e2431b`
- Scope: repo review from the customer experience standpoint
- Status: completed

## Top 3 Improvements

### 1. Create one explicit first-run journey instead of making users assemble it from contributor docs

Why it matters:
The current onboarding mixes installable-binary usage, repo-only aliases, dashboard flows, examples, and workspace internals, so users have to infer what is supported after `cargo install` versus what only works from a clone.

Relevant surfaces:
- `README.md:59`
- `README.md:65`
- `README.md:130`
- `README.md:244`
- `examples/README.md:5`
- `src/lib.rs:255`

Recommendation:
Put a `Choose your path` section near the top with two blessed flows, `trace my own project` and `try the demo/dashboard`, each with prerequisites, one copy-paste command, expected output, and a clear note about clone-only commands.

### 2. Make the dashboard and replay flow a clearly supported customer feature, not a contributor-only side path

Why it matters:
The code already embeds viewer assets for installed binaries, but the docs still present dashboard usage as from a local clone, and the viewer defaults to a repo-specific target command, which makes the best visual experience feel internal rather than productized.

Relevant surfaces:
- `README.md:130`
- `README.md:311`
- `src/lib.rs:277`
- `src/lib.rs:1425`
- `crates/ebpf-tracker-viewer/src/lib.rs:10`
- `crates/ebpf-tracker-viewer/assets/live-trace-matrix.js:10`

Recommendation:
Document one supported installed-binary dashboard command, expose replay and viewer entry points more directly in help, and replace repo-centric viewer defaults with user-facing guidance.

### 3. Improve the default first-run signal-to-noise so customers see value immediately

Why it matters:
The README repeatedly warns that a normal run includes Cargo, npm, and container noise and that the default output is raw whole-session tracing, which makes the first successful run harder to interpret and weakens the product's aha moment.

Relevant surfaces:
- `README.md:19`
- `README.md:117`
- `README.md:173`
- `examples/README.md:92`
- `README.md:376`
- `README.md:388`

Recommendation:
Ship an opinionated `minimal` or app-focused preset for docs, demos, and dashboard, with a visible way to expand back to full-session tracing when users want the raw detail.
