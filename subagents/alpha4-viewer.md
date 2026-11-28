# Alpha.4 file-open replay review

Implemented in the existing viewer and replay smoke path:

- `open_at` result labels distinguish a validated success, a validated kernel error, and an unknown result. Both `return_value` and consistent nonnegative `errno` are required. Legacy or malformed outcomes remain unknown; file descriptor zero is a valid success.
- Failed File Opens retains the latest 32 failures separately from ordinary recent events. It shows the complete captured path, command, PID, return value and an error label, with ENOENT/EACCES names and a numeric fallback. The summary counts failures, successes and unknowns across the capture at the current replay position. Replay rewind/reset clears these values.
- The panel uses all captured processes rather than the viewer's heuristic focus, and explicitly disclaims HTTP attribution. The existing files list now describes open attempts rather than asserting successful opens.
- All event-derived failure text is escaped before HTML insertion. No dependencies were added.

Validation: `node --test crates/ebpf-tracker-viewer/tests/open-outcomes.test.cjs` passed all three tests, including actual inline UI rendering, error/path/PID text, HTML escaping, legacy/malformed outcomes, descriptor zero, persistence, bounded retention and reset. `node --check` and `bash -n scripts/replay-smoke.sh` passed.

`scripts/replay-smoke.sh` now runs those tests and verifies outcome counts and retained failure fields through the actual CLI replay. The Axum missing-file path must remain visible after shutdown when supplied in the trace. Parent owns rebuilt/embedded CLI verification, live native capture and browser inspection. No Docker, Roots, database or publication operations were performed by this agent.

Cross-review correction: session journey labels and the related hero/path summary now preserve failed/opened/unknown distinctions and never infer a read or output-file creation from an open. A fourth test executes the inline UI for failed, successful and legacy opens and checks those journey/hero labels.

Browser follow-up: separated error and process text with an explicit line break in each failure row; scoped the detail cell to shrink and wrap long paths/process text. The existing rendered UI test verifies the separation and wrapping rule. All four tests pass after this fix.

## Integrated result

Implementation commit: `3d7359fd7bc400fde442bcccf19c179e1fffeffa`. Parent verified
138 workspace tests, 14 Linux agent tests, the native ARM64 installed-package
fixture, actual-capture and legacy offline replay with Docker blocked, and the
final browser display. Four HTTP500/ENOENT reproductions matched four captured
failures; five control opens succeeded. Explicit worker naming fixed the first
validator failure; journey wording and failure-row layout were corrected.
The tests establish concurrent requests, not distinct overlapping thread IDs
or request attribution. Native amd64 CI and publication remain pending. No
Roots source, services or database were accessed. See `docs/alpha-validation.md`.
