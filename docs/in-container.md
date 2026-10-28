# Trace an API inside its Docker container

The `ebpf-tracker-runtime` Debian package installs `ebpf-tracker-agent` and its
Bookworm dependencies. The agent is the container entrypoint: it starts
bpftrace, launches your API as its existing non-root user, and saves normalized
JSONL separately from application logs. No Rust/Axum source changes, Docker
socket, nested Docker daemon, or viewer are needed inside the API image.

This alpha supports **trusted development and CI workloads on an isolated
Linux Docker host**, with Debian 12 Bookworm application images. The supplied
recipe uses a privileged container and the host PID namespace. These settings
give broad host access; dropping the API's privileges and filtering its events
do not make the container a security sandbox. Production, shared runners,
untrusted pull requests, rootless Docker, and ordinary private PID namespaces
are outside this alpha's contract. See [SECURITY.md](../SECURITY.md).

## Obtain the package

Download the matching runtime `.deb` and `SHA256SUMS` from the
[GitHub release](https://github.com/givtaj/ebpf-tracker/releases). The published
runtime package targets amd64. On Linux, verify the files you downloaded with
`sha256sum --check --ignore-missing SHA256SUMS`. If the desired release or
architecture has no package yet, build it from this checkout. The builder
compiles inside Bookworm and exports a `.deb`; it does not install anything
on your host:

```bash
# For an x86_64 Linux Docker host:
bash scripts/build-runtime-deb.sh --platform linux/amd64 --output-dir dist/runtime

# For an arm64 Linux Docker host or an Apple Silicon Docker VM, use instead:
# bash scripts/build-runtime-deb.sh --platform linux/arm64 --output-dir dist/runtime

(cd dist/runtime && shasum -a 256 -c SHA256SUMS.runtime)
```

The current package name is
`ebpf-tracker-runtime_0.2.0~alpha.1_amd64.deb` (or `_arm64.deb`). Debian spells
the prerelease separator as `~`; the agent prints version `0.2.0-alpha.1`.
Select the architecture of the **application image**, not the machine running
your editor. Published package support depends on passing that architecture's
live acceptance gate; a successful cross-build alone is insufficient.

For the amd64 release, run this from your application's Docker build context
on Linux (after the release assets are available):

```bash
mkdir -p vendor
(
  set -eu
  cd vendor
  release=https://github.com/givtaj/ebpf-tracker/releases/download/v0.2.0-alpha.1
  package=ebpf-tracker-runtime_0.2.0~alpha.1_amd64.deb
  curl --fail --location --output "$package" "$release/$package"
  curl --fail --location --output SHA256SUMS "$release/SHA256SUMS"
  sha256sum --check --ignore-missing SHA256SUMS
  cp "$package" ebpf-tracker-runtime.deb
)
```

For a source build, copy the verified package into that build context as
`vendor/ebpf-tracker-runtime.deb`. Pin and checksum the package in CI. The
launcher is a different executable from the host `ebpf-tracker` CLI, which
orchestrates Docker and provides replay.

## Add it to the application image

Keep your application's existing build stage and binary copy. Add this to its
final Bookworm stage, replacing its final `USER` / `ENTRYPOINT` / `CMD` as
appropriate:

```dockerfile
USER root
COPY vendor/ebpf-tracker-runtime.deb /tmp/tracker.deb
RUN apt-get update \
 && apt-get install -y --no-install-recommends /tmp/tracker.deb \
 && rm /tmp/tracker.deb \
 && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["ebpf-tracker-agent", "--app-user", "roots", \
            "--output", "/traces/events.jsonl", "--"]
CMD ["roots-api"]
```

Replace `roots` and `roots-api` with the existing application user and command.
Create that user as before; the agent does not create accounts. Its UID must
be nonzero. The collector runs as root, while the application has its UID/GID,
groups, capabilities, and `no_new_privs` set by the launcher. The application
keeps its working directory, arguments, ordinary environment, and stdout/stderr;
internal `EBPF_TRACKER_` control variables are removed. Set `HOME` explicitly
to the application home if it relies on that value: changing Docker's default
user can change Docker-provided environment defaults.

The image's default user is now root. Consequently Docker healthchecks and
`docker exec` commands also default to root; use `docker exec --user roots ...`
and an explicit user-switching healthcheck if those commands require the
original non-root identity. This change is visible and intentional in the
development image. Keep the normal application image for other deployments.

If the image already has an entrypoint that performs setup, include that
program after the agent's `--` and verify its user and signal behavior. Do not
silently discard required migrations or initialization.

## Add the tracing override

For a Compose service named `api`, save this as `compose.tracing.yaml`:

```yaml
services:
  api:
    privileged: true
    pid: host
    stop_grace_period: 20s
    volumes:
      - ./traces:/traces
```

Use your actual service name (`roots-dev-api` in the inspected Roots setup).
Keep its existing network, ports, environment, healthcheck, and database
dependencies in the main Compose file. The agent's tracefs setup and host-PID
scoping require the documented privileges; a restricted container must fail
clearly rather than silently starting an untraced application.

Check the merged configuration with `docker compose -f compose.yaml -f
compose.tracing.yaml config`. An existing service-level `user:` or `entrypoint:`
overrides the Dockerfile: update it to the root supervisor and agent entrypoint
for this tracing configuration. Do not leave an override that bypasses the
agent or runs the collector as the application user.

```bash
mkdir -p traces
docker compose -f compose.yaml -f compose.tracing.yaml \
  up --build --detach --wait

# Exercise the API using HTTP tests that point to this container.

docker compose -f compose.yaml -f compose.tracing.yaml stop api
```

Recording follows the application process lifetime. Stopping this traced
container stops the application, forwards its shutdown signal, allows bounded
draining, and flushes the trace. This is not attachment to an already-running
container. Adding the agent requires rebuilding and recreating the service.

Use a fresh output location for each test session. The agent refuses to replace
an existing output file, so restarting a container with the same capture path
requires archiving that capture first or choosing another directory. Traces contain file paths
and process metadata; choose artifact access and retention accordingly.

## CI integration

Run on a disposable Linux runner whose Docker engine permits the tracing
configuration. Use synthetic application data and the project's existing
isolated test-stack setup. Apply the tracing override consistently to startup,
stop, and cleanup commands. Preserve the test command's exit status.

After the existing build/start and HTTP-test steps, add the equivalent of:

```yaml
- name: Stop API and flush its capture
  if: always()
  run: docker compose -f compose.yaml -f compose.tracing.yaml stop -t 20 api

- name: Save API trace
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: api-traces
    path: traces/
    if-no-files-found: error
    retention-days: 7
```

Use the project's own scoped cleanup afterward. Do not add global Docker
cleanup or database-volume removal as part of installing the tracker.

Tests must send requests to the traced API. A test harness that launches its
own server does not test this container. Roots' existing Compose HTTP smoke
uses `roots-cli api smoke`; its separate testkit starts another API process.
Roots is a reference configuration only; this project does not modify it.

## Try the isolated Axum example

The repository includes a separate Axum/PostgreSQL fixture with synthetic
data. Its smoke test installs the actual package and verifies the launcher and
capture contract:

```bash
bash scripts/in-container-smoke.sh \
  --package dist/runtime/ebpf-tracker-runtime_0.2.0~alpha.1_amd64.deb
```

Use the `_arm64.deb` package for a native arm64 Docker engine. The fixture does
not access Roots, its services, or its data.

## Inspect a capture

Install or build the separate host CLI and replay the saved JSONL:

```bash
cargo install --path . --locked
ebpf-tracker replay traces/events.jsonl
```

Replay needs Node.js on the viewing machine, but does not need Docker or the
application to be running. The runtime package itself needs neither Node nor
Cargo inside the application image.

The four probes report process execution, file opens, writes, and connection
attempts for the launched process tree. They do not capture HTTP bodies,
database contents, SQL statements, successful-I/O results, destination
addresses, route names, request IDs, latency, or request-to-syscall causality.
Long or whitespace-containing paths retain the shared parser's limitations.
