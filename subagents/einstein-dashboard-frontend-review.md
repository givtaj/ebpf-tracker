# Einstein Dashboard Frontend Review

- Agent: `Einstein`
- Agent ID: `019d240d-869d-7643-8a52-27abc6f4bed7`
- Scope: dashboard frontend review
- Status: completed

The dashboard frontend is primarily in `crates/ebpf-tracker-viewer/assets/live-trace-matrix.js`, with the Rust wrapper in `crates/ebpf-tracker-viewer/src/lib.rs`.

## Top 3 Improvements

### 1. Break up the single-file frontend into real modules and add test seams

Why it matters:
The viewer is a 2,424-line monolith that mixes Node server logic, SSE transport, HTML, CSS, rendering, replay controls, and canvas animation in one file. That makes even small UI changes risky and hard to review.

Relevant files and components:
- `crates/ebpf-tracker-viewer/assets/live-trace-matrix.js:985`
- `crates/ebpf-tracker-viewer/assets/live-trace-matrix.js:1580`
- `crates/ebpf-tracker-viewer/src/lib.rs:6`

Recommendation:
Split server and routes, client state and rendering, and styles into separate assets; move pure helpers into testable modules; add at least a replay-control smoke test plus snapshot-render tests.

### 2. Stop doing full snapshot recompute and full DOM replacement on every syscall

Why it matters:
Every syscall rebuilds and broadcasts a full snapshot, including sorted process and file lists, then the browser replaces multiple large sections with `innerHTML`. Combined with the always-on matrix animation, this will get janky under real trace volume.

Relevant files and components:
- `crates/ebpf-tracker-viewer/assets/live-trace-matrix.js:768`
- `crates/ebpf-tracker-viewer/assets/live-trace-matrix.js:813`
- `crates/ebpf-tracker-viewer/assets/live-trace-matrix.js:1689`
- `crates/ebpf-tracker-viewer/assets/live-trace-matrix.js:1795`
- `crates/ebpf-tracker-viewer/assets/live-trace-matrix.js:2399`

Recommendation:
Throttle snapshot pushes, send deltas where possible, patch only changed UI regions instead of resetting `innerHTML`, and pause or degrade the background animation under load or for reduced-motion users.

### 3. Fix the replay and control UX and accessibility before adding more visual polish

Why it matters:
The main interaction surface is brittle. The control grid is defined for 5 columns but renders 6 buttons, the knobs are invisible range inputs, there is no explicit SSE error state, and responsive handling is minimal.

Relevant files and components:
- `crates/ebpf-tracker-viewer/assets/live-trace-matrix.js:1166`
- `crates/ebpf-tracker-viewer/assets/live-trace-matrix.js:1462`
- `crates/ebpf-tracker-viewer/assets/live-trace-matrix.js:1495`
- `crates/ebpf-tracker-viewer/assets/live-trace-matrix.js:1664`
- `crates/ebpf-tracker-viewer/assets/live-trace-matrix.js:1818`

Recommendation:
Make the control bar layout explicit and responsive, add connection and error UI for `EventSource`, add `aria-live`, clear labels, and keyboard-friendly controls, and provide a simpler mobile-safe control treatment instead of hidden full-surface sliders.
