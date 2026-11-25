# Alpha.4 missing-file fixture

- Added `GET /missing-file` to the standalone Axum example. Each request reads
  `/data/file-open-control.txt`, then attempts the deliberately absent
  `/data/fixture-missing-input.txt`; the expected response is HTTP 500 with
  `errno: 2`. The handler never opens a database connection or modifies files.
- Installed-package smoke launches four bounded concurrent missing-file
  requests alongside the existing exercise route, saves each body/status, and
  reaps owned clients on failure. The existing scoped cleanup remains intact.
- Validation requires four independent kernel `open_at` completions with
  `return_value: -2` / `errno: 2`, the application PID/worker names, successful
  controls, consistent outcome fields, and unaffected descendant outcomes.
  Existing exclusion, identity, lifecycle and database-fixture checks remain.
- README provides the alpha.4 source-package and offline-replay flow, explains
  the expected HTTP failure, and preserves whole-session attribution limits.

Validation: fixture `cargo check --locked`, formatting, Bash syntax, Python
parsing and `git diff --check` passed. A temporary synthetic saved receipt passed
the validator; seven mutations were rejected: wrong errno/result, missing
outcomes, wrong PID, failed control, inconsistent errno, dropped completion,
and unexpected HTTP 200. Bash 3.2 empty/populated cleanup arrays also passed.

No Docker commands were run by this agent. Native installed-package acceptance
and offline replay remain with the parent. Roots and its database were not
accessed. No commit made.

Follow-up: the parent's first ARM64 run observed all four expected ENOENT
completions and five successful controls, but exposed a Tokio-default thread
name mismatch in the validator. The fixture now explicitly names runtime
threads `axum-worker`; validation accepts only that name and `axum-fixture`.
The original failed live receipt remains retained by the parent, who will
rerun the final fixture. This agent did not invoke Docker.
Fixture compilation/formatting passed after this change. A temporary synthetic
copy of the saved receipt accepted `axum-worker` and rejected an unrelated
worker name; the original receipt was unchanged. This validates the name gate,
not execution of the new fixture binary.

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
