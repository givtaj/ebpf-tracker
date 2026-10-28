# Same-container runtime acceptance fixture

This standalone Axum 0.8 application verifies an installed
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
  --package dist/runtime/ebpf-tracker-runtime_0.2.0~alpha.1_amd64.deb \
  --output-dir target/in-container-evidence
```

The output directory must be new. The test retains HTTP responses, process
credentials, JSONL, original application logs and a summary. Its cleanup removes
only the containers and disposable volumes created for its unique Compose
project; it does not prune Docker resources.

Acceptance covers `/health`, `/identity`, and `/exercise` (a real PostgreSQL
connection/query, a file write, a descendant process and stdout/stderr markers),
followed by graceful SIGTERM. It also checks exit 23, a missing command, denied
tracing permissions, a nonroot agent invocation, and refusal to overwrite an
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
