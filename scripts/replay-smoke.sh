#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"
tracker="${repo_root}/target/debug/ebpf-tracker"
trace_file=""
require_embedded=0

usage() {
    echo 'Usage: bash scripts/replay-smoke.sh [--tracker <binary>] [--trace <session-io-demo.jsonl>] [--require-embedded]'
    echo 'Verify root CLI replay from a temporary directory with Docker blocked.'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tracker|--trace)
      [[ $# -ge 2 ]] || { usage >&2; exit 1; }
      if [[ "$1" == --tracker ]]; then tracker="$2"; else trace_file="$2"; fi
      shift 2
      ;;
    --require-embedded) require_embedded=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 1 ;;
  esac
done

command -v node >/dev/null || { echo 'replay-smoke: Node.js is required' >&2; exit 1; }
[[ -x "${tracker}" ]] || { echo "replay-smoke: build the tracker first or supply --tracker: ${tracker}" >&2; exit 1; }

node - "${repo_root}" "${tracker}" "${trace_file}" "${require_embedded}" <<'NODE'
const assert = require('assert/strict');
const fs = require('fs');
const http = require('http');
const net = require('net');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');

const [repoRoot, trackerArg, traceArg, requireEmbedded] = process.argv.slice(2);
const tracker = path.resolve(trackerArg);
const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'ebpf-tracker-replay-smoke-'));
let child;
let output = '';
let spawnError;

const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
const snapshot = url => new Promise((resolve, reject) => {
  const request = http.get(`${url}/snapshot`, response => {
    let body = '';
    response.setEncoding('utf8');
    response.on('data', data => { body += data; });
    response.on('end', () => {
      try { resolve(JSON.parse(body)); } catch (error) { reject(error); }
    });
  });
  request.setTimeout(1000, () => request.destroy(new Error('snapshot timed out')));
  request.on('error', reject);
});

async function main() {
  const bin = path.join(temporary, 'bin');
  fs.mkdirSync(bin);
  fs.symlinkSync(process.execPath, path.join(bin, 'node'));
  const dockerMarker = path.join(temporary, 'docker-was-invoked');
  fs.writeFileSync(path.join(bin, 'docker'), '#!/bin/sh\nprintf invoked > "$EBPF_TRACKER_SMOKE_DOCKER_MARKER"\nexit 97\n', {mode: 0o755});
  for (const opener of ['open', 'xdg-open']) {
    fs.writeFileSync(path.join(bin, opener), '#!/bin/sh\nexit 0\n', {mode: 0o755});
  }
  const trace = path.join(temporary, 'trace with spaces.jsonl');
  fs.copyFileSync(traceArg ? path.resolve(traceArg) : path.join(repoRoot, 'crates/ebpf-tracker-viewer/demo-library/session-io-demo.jsonl'), trace);

  const listener = net.createServer();
  await new Promise((resolve, reject) => {
    listener.once('error', reject);
    listener.listen(0, '127.0.0.1', resolve);
  });
  const port = listener.address().port;
  await new Promise(resolve => listener.close(resolve));

  const replayArgs = ['replay', trace, '--port', String(port), '--interval-ms', '1'];
  if (!traceArg) replayArgs.push('--focus-comm', 'session-io-demo');
  child = spawn(tracker, replayArgs, {
    cwd: temporary,
    detached: true,
    stdio: ['ignore', 'pipe', 'pipe'],
    env: {...process.env, PATH: bin, EBPF_TRACKER_CACHE_DIR: path.join(temporary, 'cache'), EBPF_TRACKER_SMOKE_DOCKER_MARKER: dockerMarker},
  });
  child.on('error', error => { spawnError = error; });
  const record = data => { output = (output + data.toString()).slice(-64000); };
  child.stdout.on('data', record);
  child.stderr.on('data', record);

  const deadline = Date.now() + 20000;
  let result;
  while (Date.now() < deadline) {
    if (spawnError) throw spawnError;
    if (child.exitCode !== null || child.signalCode !== null) throw new Error('root replay exited before verification');
    const announced = output.match(/live trace viewer on (http:\/\/127\.0\.0\.1:\d+)/);
    if (announced) {
      try {
        result = await snapshot(announced[1]);
        if (result.tracerEnded && result.progress.emitted === result.progress.total) break;
      } catch (_) { /* Retry while the viewer starts. */ }
    }
    await pause(100);
  }
  assert.ok(result, 'viewer did not expose a snapshot within 20 seconds');
  assert.equal(result.mode, 'replay');
  assert.equal(result.tracerEnded, true);
  assert.equal(result.progress.emitted, result.progress.total);
  assert.ok(result.progress.total > 0, 'replay must contain records');
  if (traceArg) {
    for (const kind of ['open_at', 'connect', 'write']) {
      assert.ok(result.counters[kind] > 0, `saved capture replay must contain ${kind}`);
    }
  } else {
    assert.equal(result.counters.open_at, 2);
    assert.equal(result.counters.connect, 1);
    assert.equal(result.counters.write, 1);
    assert.ok(result.recentEvents.some(event => event.file === 'input/message.txt'));
    assert.ok(result.topProcesses.every(item => item.comm === 'session-io-demo'), 'focus filter must exclude cargo');
  }
  assert.equal(fs.existsSync(dockerMarker), false, 'offline replay must never invoke Docker');
  if (requireEmbedded === '1') {
    const cache = path.join(temporary, 'cache');
    const viewerRoots = fs.readdirSync(cache).filter(name => name.startsWith('viewer-v'));
    assert.equal(viewerRoots.length, 1, 'installed replay must materialize exactly one embedded viewer');
    assert.ok(fs.statSync(path.join(cache, viewerRoots[0], 'live-trace-matrix.js')).isFile());
    console.log('[replay-smoke] verified embedded viewer assets from the installed binary');
  }
  console.log('[replay-smoke] PASS: root CLI replay, external directory, saved records, no Docker');
}

main().catch(error => {
  console.error(`replay-smoke: ${error.stack || error}\n${output}`);
  process.exitCode = 1;
}).finally(async () => {
  if (child && child.pid) {
    try { process.kill(-child.pid, 'SIGTERM'); } catch (error) { if (error.code !== 'ESRCH') throw error; }
    await pause(150);
    try { process.kill(-child.pid, 'SIGKILL'); } catch (error) { if (error.code !== 'ESRCH') throw error; }
  }
  fs.rmSync(temporary, {recursive: true, force: true});
});
NODE
