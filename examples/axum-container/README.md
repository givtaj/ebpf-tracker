# Debug a missing file in an Axum Docker API

The alpha.4 example deliberately returns HTTP 500 from
`GET /missing-file` after trying to read `/data/fixture-missing-input.txt`.
Its saved trace shows the API process, the file path, and the completed
`open_at` result: `return_value: -2`, `errno: 2` (`ENOENT`). A successful read
of `/data/file-open-control.txt` provides a control with `return_value >= 0`
and `errno: 0`. The route only reads these synthetic files; it never queries
or changes a database.

This standalone Axum 0.8 application also verifies an installed
`ebpf-tracker-runtime` Debian package. PostgreSQL runs as a separate Compose
service with disposable synthetic credentials/data. The application runs as
`roots` (UID/GID 10001); the agent starts as root and drops the application's
groups, capabilities and ability to gain new privileges before executing it.

The current tracing recipe uses `privileged: true` and `pid: host`. Run it only
on an isolated, trusted Linux development host or Docker VM. It is not a
least-privilege production deployment recipe.

From the repository root, build the package for the Docker host architecture,
then run the test (use `linux/arm64` and `_arm64.deb` on an ARM64 Docker host):

```bash
bash scripts/build-runtime-deb.sh --platform linux/amd64 --output-dir dist/runtime
bash scripts/in-container-smoke.sh \
  --package dist/runtime/ebpf-tracker-runtime_0.2.0~alpha.4_amd64.deb \
  --output-dir target/axum-missing-file-alpha4

# Replay the completed capture after the test has stopped its containers.
# Node.js is needed on the replay host; Docker is not needed for replay.
cargo run --locked -- replay target/axum-missing-file-alpha4/events.jsonl
```

This builds alpha.4 from the checkout. To exercise the released bytes instead,
follow the [alpha.4 download and checksum recipe](../../docs/in-container.md#obtain-the-package)
and pass `--package vendor/ebpf-tracker-runtime.deb` to the smoke command.
For native ARM64 source builds, change both the build platform and package
suffix as described above. In replay, inspect **Failed File Opens** for
`/data/fixture-missing-input.txt`; the error is observed by the collector,
independently of the HTTP response. Older captures without outcome fields
have an unknown result and must not be read as successful opens.

The smoke sends four concurrent missing-file requests alongside the existing
`/exercise` request. It deliberately accepts the four expected HTTP 500
responses; transport failures, another status, or another error fail the test.
Each response is saved as `missing-file-N.json` with its HTTP status in
`missing-file-N.status`. `summary.json` records the failed-open evidence and
the successful controls. An example response is:

```json
{"error":"fixture_missing_file","path":"/data/fixture-missing-input.txt","errno":2,"control_read":true}
```

The capture covers the complete API process lifetime, including startup and
shutdown. It does not associate individual syscalls with individual HTTP
requests. A failed file open alone does not prove it caused an HTTP failure;
this fixture's known handler and independently checked response establish
the controlled reproduction.

The output directory must be new. The test retains HTTP responses, process
credentials, JSONL, original application logs and a summary. Its cleanup removes
only the containers and disposable volumes created for its unique Compose
project; it does not prune Docker resources.

Acceptance requires the primary application's exec and a known startup file
write before Tokio creates worker threads. It covers `/health`, `/identity`,
`/missing-file` (failed and successful file opens during concurrent requests), and
`/exercise` (a real PostgreSQL connection/query, a file write, a descendant
process and stdout/stderr markers), followed by graceful SIGTERM. It also checks
exit 23 together with the primary shell's exec/open/write trace, a missing
command, denied tracing permissions, a nonroot agent invocation, and refusal to overwrite an
existing capture or start its workload. An unrelated container
generates concurrent activity; Linux hosts additionally run a host noise
process. Neither may appear in the workload trace.

Additional real-collector checks send SIGINT to an application with a handler,
verify a TERM-ignoring application is killed after its configured deadline, and
kill only the test agent's own collector to require capture failure and workload
shutdown. Captures and logs are retained for each case, and the test checks that
the application process no longer exists.

The fixture uses its own Cargo workspace and committed lockfile. It does not
depend on Roots source, data, or running services.
