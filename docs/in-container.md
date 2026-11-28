# Trace an API inside its Docker container

This guide targets **alpha.4**, including completed file-open results and a
[missing-file debugging walkthrough](../examples/axum-container/README.md).
Use the matching alpha.4 runtime and replay CLI to inspect the file path,
process and error. Older captures without outcome fields remain unknown.
See [alpha validation](./alpha-validation.md) for publication status and evidence.

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

The host kernel `7.0.0-1017-azure` is rejected because an
[upstream regression](https://github.com/actions/runner-images/issues/15003)
silently drops syscall events outside one CPU. Changing the container image
does not fix its host kernel. Use a fixed Linux host. Native release gates use
GitHub Actions `ubuntu-22.04` for amd64 and `ubuntu-22.04-arm` for arm64, with
the same full capture assertions.

## Obtain the package

The alpha.4 release gates a runtime `.deb` for each native Linux architecture:

| Application image and Docker host | Runtime package suffix |
| --- | --- |
| Linux x86_64 / amd64 | `_amd64.deb` |
| Linux AArch64 / arm64, including a native Apple Silicon Docker VM | `_arm64.deb` |

Select the architecture of the **application image and native Docker host**,
not the machine running your editor. Emulated cross-architecture live tracing
is outside this release's validation. Each package must pass its own native
installed-package gate; a successful cross-build alone is insufficient.

After the assets are available on the
[GitHub release](https://github.com/givtaj/ebpf-tracker/releases/tag/v0.2.0-alpha.4),
run this from your application's Docker build context. Set `runtime_arch` to
`arm64` for a native ARM64 image/engine, or leave `amd64` for native x86_64:

```bash
(
  set -euo pipefail
  runtime_arch=amd64
  case "$runtime_arch" in
    amd64|arm64) ;;
    *) printf 'Unsupported runtime architecture: %s\n' "$runtime_arch" >&2; exit 1 ;;
  esac
  mkdir -p vendor
  cd vendor
  release=https://github.com/givtaj/ebpf-tracker/releases/download/v0.2.0-alpha.4
  package="ebpf-tracker-runtime_0.2.0-alpha.4_${runtime_arch}.deb"
  curl --fail --location --output "$package" "$release/$package"
  curl --fail --location --output SHA256SUMS "$release/SHA256SUMS"
  checksum="$(awk -v name="$package" '$2 == name { print }' SHA256SUMS)"
  test -n "$checksum" || { printf 'Package missing from SHA256SUMS\n' >&2; exit 1; }
  if command -v sha256sum >/dev/null 2>&1; then
    printf '%s\n' "$checksum" | sha256sum --check -
  else
    printf '%s\n' "$checksum" | shasum -a 256 --check -
  fi
  cp "$package" ebpf-tracker-runtime.deb
)
```

This checks the selected package against the original release manifest without
rewriting it. The checksum tool fallback supports macOS download hosts.

To build from this checkout instead, use one of these native platforms. The
builder compiles inside Bookworm and exports a `.deb`; it installs nothing on
your host:

```bash
bash scripts/build-runtime-deb.sh --platform linux/amd64 --output-dir dist/runtime
# For a native arm64 Docker host, use --platform linux/arm64 instead.
(cd dist/runtime && shasum -a 256 -c SHA256SUMS.runtime)
```

Local builds use Debian-style names such as
`ebpf-tracker-runtime_0.2.0~alpha.4_arm64.deb`. Release downloads use
`ebpf-tracker-runtime_0.2.0-alpha.4_arm64.deb` because GitHub rewrites `~` in
asset names. The same rule applies to amd64. Both forms contain Debian package
version `0.2.0~alpha.4`; the agent prints `0.2.0-alpha.4`. Copy a verified
source build into the application context as `vendor/ebpf-tracker-runtime.deb`.

Pin and checksum the package in CI. The launcher is different from the host
`ebpf-tracker` CLI, which orchestrates Docker and provides replay.

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
Roots supplied the reference configuration. Its separately authorized
[source-built ARM64 pilot](./roots-pilot-2026-11-25.md) exercised a read-only
health request; the release gates use only the standalone synthetic fixture.

## Try the isolated Axum example

The repository includes a separate Axum/PostgreSQL fixture with synthetic
data. Its smoke test installs the actual package, reproduces four expected
HTTP 500 responses from `/missing-file`, and checks the corresponding captured
`ENOENT` results plus successful file-open controls. To use the verified package
from the download recipe above:

```bash
bash scripts/in-container-smoke.sh --package vendor/ebpf-tracker-runtime.deb
```

For a locally built package instead:

```bash
bash scripts/in-container-smoke.sh \
  --package dist/runtime/ebpf-tracker-runtime_0.2.0~alpha.4_amd64.deb
```

Use the `_arm64.deb` package for a native arm64 Docker engine. The fixture does
not access Roots, its services, or its data. See the
[example walkthrough](../examples/axum-container/README.md) for response files,
replay instructions and the distinction between HTTP and syscall evidence.

## Inspect a capture

Install or build the separate host CLI and replay the saved JSONL:

```bash
cargo install --path . --locked
ebpf-tracker replay traces/events.jsonl
```

Replay needs Node.js on the viewing machine, but does not need Docker or the
application to be running. The runtime package itself needs neither Node nor
Cargo inside the application image.

Prebuilt host CLI archives target Linux x86_64 and Intel macOS. The ARM64
runtime package does not supply an ARM64 host CLI; use the source installation
above when that is the viewer host's architecture.

The four event kinds report process execution, file opens, writes, and connection
attempts for the launched process tree. Alpha.4 in-container file-open records
add return values and errno; alpha.3 and generic command captures leave these
outcomes unknown. A successful open does not prove a successful read or write.
The probes do not capture HTTP bodies,
database contents, SQL statements, read/write completion, destination
addresses, route names, request IDs, latency, or request-to-syscall causality.
Long paths can be truncated by the collector, and paths containing newlines
retain raw-format limitations.
