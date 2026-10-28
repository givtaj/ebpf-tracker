# Security Policy

## Project Maturity And Support

`ebpf-tracker` is experimental alpha software. It has no stable API, hardened
multi-tenant deployment model, or production-support promise. Security fixes
are made on the default branch and, when a release is published, on the newest
release line at maintainer discretion. Older tags should be treated as
unsupported unless a maintainer says otherwise in a security advisory.

## Local Tracing Trust Boundary

The in-container agent uses the same privileged, host-PID development boundary.
It does not require the Docker socket or a source-code bind mount. The agent
runs its collector as root, then starts the application as the specified
non-root user with capabilities removed and `no_new_privs` set. This reduces
the application's privileges but does not isolate the privileged container
from the host. Docker healthchecks and `docker exec` still default to the
image's root user unless explicitly configured otherwise.

The agent's fixed probes filter to the launched process tree. Its output
contains syscall metadata, not application logs, environment values, HTTP
bodies, or file contents. The output file is created with mode 0644 (subject to
the process umask) for CI collection; protect the parent directory and artifact
access. Existing output files are rejected so a restart cannot silently erase
an earlier capture. Collector/startup failures fail the diagnostic session;
the launcher does not silently continue an untraced workload.

Run mode is powerful by design. The shipped Docker Compose runtimes currently:

- set `privileged: true`;
- join the Docker host PID namespace with `pid: host`; and
- bind-mount the selected project read-write at `/workspace`.

These settings give the container broad access to the Linux Docker host (or to
the Linux VM used by Docker Desktop), expose host process metadata, and let the
wrapped command change files in the mounted project. eBPF/perf collection is
observation, not sandboxing: it does not make a command safer to execute.

Only trace code, dependencies, commands, and fixtures you trust. Never use the
run-mode container for an untrusted pull request, arbitrary downloaded project,
shared CI worker, multi-tenant host, or production machine. Prefer a disposable
VM or droplet with no credentials, secrets, or sensitive neighboring workloads.

Built-in generated probes can apply workload filtering, but that is a data
scope control rather than a privilege boundary. An arbitrary custom `--probe`
program cannot be safely rewritten or externally constrained by the CLI and
therefore fails closed unless the operator supplies
`--allow-host-wide-probe`. The direct runtime wrapper requires the equivalent
`EBPF_TRACKER_ALLOW_HOST_WIDE_PROBE=1` acknowledgement. Neither switch adds
containment: treat the probe as potentially host-wide, review it yourself, and
never accept one from an untrusted source.

Runtime CPU, memory, CPU-set, and PID limits reduce resource consumption; they
do not remove container privilege or host visibility.

## Attach Trust Boundary

The live `k8s` and `aws-eks` Inspektor Gadget paths execute local `kubectl`,
`kubectl gadget`, and, for EKS, AWS CLI operations using the caller's existing
credentials and kubeconfig. Review the selected cluster, context, namespace,
and workload before running them. EKS attach may update kubeconfig.

Other target/backend combinations are scaffold-only or rejected. A scaffold
prints a plan and does not establish a security boundary or start tracing. See
the [attach support matrix](./docs/cli.md#attach-mode-experimental).

## Trace Data And External Services

Treat trace artifacts as potentially sensitive. Depending on enabled probes,
JSONL, replay logs, datasets, terminal output, and exported spans can contain:

- command and process names;
- process IDs and file paths;
- file descriptors and byte counts;
- traced command metadata; and
- activity from other processes visible to an insufficiently scoped probe.

The project does not intentionally capture file contents in its normalized
event schema, but paths and process metadata alone can reveal private
information. Inspect and redact artifacts before sharing them. The dataset
analyzer and OTLP exporter send derived trace data to the endpoint you
configure; use only endpoints you trust and understand.

## Reporting A Vulnerability

Use [GitHub private vulnerability reporting](https://github.com/givtaj/ebpf-tracker/security/advisories/new)
from the repository's **Security** tab (enabled for this alpha). Include the affected version or commit, impact,
reproduction steps, and a minimal proof of concept.

Do not open a public issue or discussion containing exploit details, secrets,
or sensitive trace output. If private vulnerability reporting is unavailable,
open only a non-sensitive issue asking the maintainer to establish a private
reporting channel.

Maintainers should acknowledge reports as soon as practical, assess impact,
coordinate a fix or mitigation, and publish an advisory before detailed public
disclosure. Do not publish a release that claims a private reporting path until
that path has been verified.
