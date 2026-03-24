#!/usr/bin/env node

const fs = require("fs");
const http = require("http");
const { spawn } = require("child_process");

const DEFAULT_PORT = 43115;
const DEFAULT_HOST = "127.0.0.1";
const DEFAULT_TARGET = ["./target/debug/eBPF_tracker", "demo", "session-io-demo"];

function main() {
  const options = parseArgs(process.argv.slice(2));
  const state = createState();
  state.command = formatSourceLabel(options);
  state.mode = options.replayFile ? "replay" : "live";
  state.status = "starting";

  const server = http.createServer((req, res) => routeRequest(req, res, state));
  const source = options.replayFile
    ? startReplay(options, state, (code, signal) => finishSource(state, code, signal))
    : startTracer(options, state, (code, signal) => finishSource(state, code, signal));
  state.source = source;

  server.listen(options.port, options.host, () => {
    const url = `http://${options.host}:${options.port}`;
    state.url = url;
    state.status = "running";
    console.error(`live trace viewer on ${url}`);
    console.error(`${state.mode === "replay" ? "replaying" : "tracing"}: ${state.command.join(" ")}`);
    broadcast(state, "status", {
      status: "running",
      command: state.command,
      mode: state.mode,
      progress: state.progress,
      replay: state.replay,
      url
    });
  });

  const shutdown = (signal) => {
    if (!state.tracerEnded) {
      state.status = "stopping";
      broadcast(state, "status", { status: "stopping", signal });
    }
    source.stop(signal);
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 1000).unref();
  };

  process.on("SIGINT", () => shutdown("SIGINT"));
  process.on("SIGTERM", () => shutdown("SIGTERM"));
}

function parseArgs(args) {
  let port = DEFAULT_PORT;
  let host = DEFAULT_HOST;
  let replayFile = null;
  let replaySpeed = 1;
  let replayIntervalMs = null;
  let focusComm = null;
  const command = [];

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--port") {
      port = Number(args[index + 1]);
      index += 1;
      continue;
    }
    if (arg === "--host") {
      host = args[index + 1];
      index += 1;
      continue;
    }
    if (arg === "--replay") {
      replayFile = args[index + 1];
      index += 1;
      continue;
    }
    if (arg === "--speed") {
      replaySpeed = Number(args[index + 1]);
      index += 1;
      continue;
    }
    if (arg === "--interval-ms") {
      replayIntervalMs = Number(args[index + 1]);
      index += 1;
      continue;
    }
    if (arg === "--focus-comm") {
      focusComm = args[index + 1];
      index += 1;
      continue;
    }
    if (arg === "--") {
      command.push(...args.slice(index + 1));
      break;
    }
    command.push(arg);
  }

  if (replayFile) {
    return {
      port,
      host,
      replayFile,
      replaySpeed: Number.isFinite(replaySpeed) && replaySpeed > 0 ? replaySpeed : 1,
      replayIntervalMs:
        Number.isFinite(replayIntervalMs) && replayIntervalMs > 0 ? replayIntervalMs : null,
      focusComm
    };
  }

  const finalCommand = ensureViewerCommand(command);

  return { port, host, command: finalCommand, replayFile: null, focusComm: null, replaySpeed: 1, replayIntervalMs: null };
}

function ensureViewerCommand(command) {
  const finalCommand = command.length ? command.slice() : DEFAULT_TARGET.slice();

  if (isTrackerBinary(finalCommand[0])) {
    return [finalCommand[0], ...ensureTrackerArgsJsonl(finalCommand.slice(1))];
  }

  if (finalCommand[0] === "demo") {
    return [DEFAULT_TARGET[0], ...ensureTrackerArgsJsonl(finalCommand)];
  }

  return [DEFAULT_TARGET[0], ...ensureTrackerArgsJsonl(finalCommand)];
}

function ensureTrackerArgsJsonl(args) {
  if (!args.length) {
    return ["--emit", "jsonl"];
  }

  if (args[0] === "demo") {
    return ["demo", ...replaceEmitWithJsonl(args.slice(1))];
  }

  return replaceEmitWithJsonl(args);
}

function replaceEmitWithJsonl(args) {
  const filtered = [];

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--emit") {
      index += 1;
      continue;
    }
    if (arg.startsWith("--emit=")) {
      continue;
    }
    filtered.push(arg);
  }

  return ["--emit", "jsonl", ...filtered];
}

function isTrackerBinary(program) {
  if (!program) {
    return false;
  }
  return program === "eBPF_tracker" || program === "./target/debug/eBPF_tracker" || program.endsWith("/eBPF_tracker");
}

function createState() {
  return {
    clients: new Set(),
    recentEvents: [],
    counters: emptyCounters(),
    processCounts: new Map(),
    fileCounts: new Map(),
    writes: [],
    startedAt: Date.now(),
    tracerEnded: false,
    exitCode: null,
    exitSignal: null,
    url: null,
    command: [],
    mode: "live",
    status: "starting",
    progress: { emitted: 0, total: 0 },
    replay: {
      supported: false,
      paused: false,
      speed: 1,
      stepSize: 8,
      ended: false
    },
    source: null
  };
}

function startTracer(options, state, onEnd) {
  const [program, ...programArgs] = options.command;
  const child = spawn(program, programArgs, {
    stdio: ["ignore", "pipe", "pipe"],
    env: process.env
  });

  let stdoutBuffer = "";
  child.stdout.on("data", (chunk) => {
    stdoutBuffer += chunk.toString("utf8");
    const lines = stdoutBuffer.split(/\r?\n/);
    stdoutBuffer = lines.pop() || "";
    for (const line of lines) {
      handleTraceLine(line, state);
    }
  });

  child.stderr.on("data", (chunk) => {
    const text = chunk.toString("utf8");
    broadcast(state, "stderr", { text });
  });

  child.on("error", (error) => {
    broadcast(state, "status", { status: "error", message: error.message });
    onEnd(1, null);
  });

  child.on("close", (code, signal) => {
    if (stdoutBuffer.trim()) {
      handleTraceLine(stdoutBuffer, state);
    }
    onEnd(code, signal);
  });

  return {
    stop(signal) {
      child.kill(signal === "SIGINT" ? "SIGINT" : "SIGTERM");
    },
    control() {
      return {
        ok: false,
        message: "transport controls are only available in replay mode"
      };
    }
  };
}

function startReplay(options, state, onEnd) {
  const replayRecords = loadReplayRecords(options.replayFile, options.focusComm);
  state.progress.total = replayRecords.length;
  state.replay.supported = true;
  state.replay.speed = options.replayIntervalMs ? 1 : options.replaySpeed;
  state.replay.stepSize = 8;
  state.replay.paused = false;
  state.replay.ended = false;

  let timer = null;
  let index = 0;
  let stopped = false;
  let paused = false;
  let speed = options.replayIntervalMs ? 1 : options.replaySpeed;
  let intervalMs = options.replayIntervalMs;
  let stepSize = 8;
  let ended = false;

  const publishReplayState = () => {
    state.progress.emitted = index;
    state.progress.total = replayRecords.length;
    state.replay = {
      supported: true,
      paused,
      speed,
      stepSize,
      ended
    };
    broadcast(state, "snapshot", buildSnapshot(state));
    broadcast(state, "status", {
      status: state.status,
      command: state.command,
      mode: state.mode,
      progress: state.progress,
      replay: state.replay,
      url: state.url
    });
  };

  const clearTimer = () => {
    if (timer) {
      clearTimeout(timer);
      timer = null;
    }
  };

  const scheduleNext = (overrideDelayMs) => {
    if (stopped || paused || ended) {
      return;
    }
    clearTimer();
    const delayMs =
      overrideDelayMs === undefined
        ? replayDelayMs(replayRecords, index, speed, intervalMs)
        : overrideDelayMs;
    timer = setTimeout(tick, delayMs);
  };

  const resetReplay = ({ autoPlay }) => {
    clearTimer();
    index = 0;
    ended = false;
    paused = !autoPlay;
    state.status = "running";
    state.tracerEnded = false;
    state.exitCode = null;
    state.exitSignal = null;
    clearTraceState(state);
    publishReplayState();
    if (autoPlay) {
      scheduleNext(120);
    }
  };

  const emitOne = () => {
    if (stopped || ended) {
      return false;
    }
    if (index >= replayRecords.length) {
      ended = true;
      publishReplayState();
      onEnd(0, null);
      return false;
    }

    const record = {
      ...replayRecords[index],
      timestamp_unix_ms: Date.now()
    };
    index += 1;
    state.progress.emitted = index;
    handleTraceRecord(record, state);

    if (index >= replayRecords.length) {
      ended = true;
      publishReplayState();
      onEnd(0, null);
      return false;
    }

    publishReplayState();
    return true;
  };

  const tick = () => {
    if (stopped) {
      return;
    }
    if (paused || ended) {
      return;
    }
    const emitted = emitOne();
    if (emitted) {
      scheduleNext();
    }
  };

  scheduleNext(120);

  return {
    stop(signal) {
      stopped = true;
      clearTimer();
      onEnd(null, signal === "SIGINT" ? "SIGINT" : "SIGTERM");
    },
    control(action, payload = {}) {
      switch (action) {
        case "play":
          if (ended) {
            resetReplay({ autoPlay: true });
            return { ok: true };
          }
          paused = false;
          state.status = "running";
          publishReplayState();
          scheduleNext(0);
          return { ok: true };
        case "pause":
          paused = true;
          state.status = "paused";
          clearTimer();
          publishReplayState();
          return { ok: true };
        case "restart":
          resetReplay({ autoPlay: true });
          return { ok: true };
        case "step": {
          paused = true;
          state.status = "paused";
          clearTimer();
          const steps = Math.max(1, Math.min(Number(payload.count || 1), 64));
          for (let cursor = 0; cursor < steps; cursor += 1) {
            if (!emitOne()) {
              break;
            }
          }
          publishReplayState();
          return { ok: true };
        }
        case "forward": {
          const jump = Math.max(1, Math.min(Number(payload.count || stepSize), 64));
          const wasPaused = paused;
          clearTimer();
          paused = true;
          state.status = "paused";
          for (let cursor = 0; cursor < jump; cursor += 1) {
            if (!emitOne()) {
              break;
            }
          }
          paused = wasPaused && !ended;
          state.status = ended ? "exited" : paused ? "paused" : "running";
          publishReplayState();
          if (!paused && !ended) {
            scheduleNext(0);
          }
          return { ok: true };
        }
        case "set_speed": {
          const nextSpeed = Number(payload.value);
          if (!Number.isFinite(nextSpeed) || nextSpeed <= 0) {
            return { ok: false, message: "invalid replay speed" };
          }
          intervalMs = null;
          speed = nextSpeed;
          publishReplayState();
          if (!paused && !ended) {
            scheduleNext();
          }
          return { ok: true };
        }
        case "set_step_size": {
          const nextStepSize = Math.max(1, Math.min(Number(payload.value || 8), 64));
          stepSize = nextStepSize;
          publishReplayState();
          return { ok: true };
        }
        default:
          return { ok: false, message: `unknown control action: ${action}` };
      }
    }
  };
}

function finishSource(state, code, signal) {
  if (state.tracerEnded) {
    return;
  }
  state.exitCode = code;
  state.exitSignal = signal;
  state.tracerEnded = true;
  state.status = signal ? "stopped" : "exited";
  broadcast(state, "snapshot", buildSnapshot(state));
  broadcast(state, "status", {
    status: state.status,
    code,
    signal,
    progress: state.progress,
    replay: state.replay
  });
}

function formatSourceLabel(options) {
  if (options.replayFile) {
    const pieces = [
      "replay",
      options.replayFile
    ];
    if (options.focusComm) {
      pieces.push(`focus=${options.focusComm}`);
    }
    if (options.replayIntervalMs) {
      pieces.push(`interval=${options.replayIntervalMs}ms`);
    } else {
      pieces.push(`speed=${options.replaySpeed}x`);
    }
    return pieces;
  }
  return options.command.slice();
}

function loadReplayRecords(replayFile, focusComm) {
  const text = fs.readFileSync(replayFile, "utf8");
  const records = [];

  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) {
      continue;
    }

    let record;
    try {
      record = JSON.parse(trimmed);
    } catch {
      continue;
    }

    if (
      focusComm &&
      record.type === "syscall" &&
      record.comm !== focusComm
    ) {
      continue;
    }

    records.push(record);
  }

  return records;
}

function replayDelayMs(records, nextIndex, speed, intervalMs) {
  if (intervalMs) {
    return intervalMs;
  }

  const current = records[nextIndex - 1];
  const next = records[nextIndex];
  if (!current || !next) {
    return 0;
  }

  const delta = Math.max(
    Number(next.timestamp_unix_ms || 0) - Number(current.timestamp_unix_ms || 0),
    0
  );
  const scaled = delta / speed;
  return Math.max(40, Math.min(Math.round(scaled), 350));
}

function clearTraceState(state) {
  state.recentEvents = [];
  state.counters = emptyCounters();
  state.processCounts = new Map();
  state.fileCounts = new Map();
  state.writes = [];
  state.startedAt = Date.now();
  state.progress.emitted = 0;
}

function emptyCounters() {
  return { open_at: 0, execve: 0, connect: 0, write: 0, other: 0, bytes: 0 };
}

function handleTraceLine(line, state) {
  const trimmed = line.trim();
  if (!trimmed) {
    return;
  }

  let event;
  try {
    event = JSON.parse(trimmed);
  } catch {
    broadcast(state, "stderr", { text: `${trimmed}\n` });
    return;
  }

  handleTraceRecord(event, state);
}

function handleTraceRecord(event, state) {
  if (event.type === "syscall") {
    ingestSyscall(event, state);
  }
  if (event.type === "aggregate") {
    broadcast(state, "aggregate", event);
    broadcast(state, "snapshot", buildSnapshot(state));
  }

  broadcast(state, "event", decorateEvent(event, state.startedAt));
}

function ingestSyscall(event, state) {
  const kind = event.kind || "other";
  if (Object.hasOwn(state.counters, kind)) {
    state.counters[kind] += 1;
  } else {
    state.counters.other += 1;
  }

  if (kind === "write") {
    state.counters.bytes += Number(event.bytes || 0);
    state.writes.unshift({
      comm: event.comm || "unknown",
      bytes: Number(event.bytes || 0),
      timestamp_unix_ms: event.timestamp_unix_ms
    });
    state.writes = state.writes.slice(0, 16);
  }

  const comm = event.comm || "unknown";
  state.processCounts.set(comm, (state.processCounts.get(comm) || 0) + 1);

  if (kind === "open_at" && event.file) {
    state.fileCounts.set(event.file, (state.fileCounts.get(event.file) || 0) + 1);
  }

  state.recentEvents.unshift(decorateEvent(event, state.startedAt));
  state.recentEvents = state.recentEvents.slice(0, 180);

  broadcast(state, "snapshot", buildSnapshot(state));
}

function decorateEvent(event, startedAt) {
  const sinceStartMs = Math.max(Number(event.timestamp_unix_ms || Date.now()) - startedAt, 0);
  const glyph = glyphForKind(event.kind);
  const text = eventText(event);
  return {
    ...event,
    glyph,
    text,
    since_start_ms: sinceStartMs
  };
}

function buildSnapshot(state) {
  return {
    counters: state.counters,
    recentEvents: state.recentEvents.slice(0, 24),
    topProcesses: [...state.processCounts.entries()]
      .sort((left, right) => right[1] - left[1])
      .slice(0, 8)
      .map(([comm, count]) => ({ comm, count })),
    topFiles: [...state.fileCounts.entries()]
      .filter(([file]) => isInterestingFile(file))
      .sort((left, right) => right[1] - left[1])
      .slice(0, 8)
      .map(([file, count]) => ({ file, count })),
    writes: state.writes.slice(0, 8),
    tracerEnded: state.tracerEnded,
    exitCode: state.exitCode,
    exitSignal: state.exitSignal,
    url: state.url,
    command: state.command,
    mode: state.mode,
    status: state.status,
    progress: state.progress,
    replay: state.replay
  };
}

function routeRequest(req, res, state) {
  if (req.url === "/") {
    res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    res.end(renderHtml());
    return;
  }

  if (req.url === "/events") {
    res.writeHead(200, {
      "content-type": "text/event-stream; charset=utf-8",
      "cache-control": "no-cache, no-transform",
      connection: "keep-alive"
    });
    res.write(`event: snapshot\ndata: ${JSON.stringify(buildSnapshot(state))}\n\n`);
    state.clients.add(res);
    req.on("close", () => {
      state.clients.delete(res);
    });
    return;
  }

  if (req.url === "/control" && req.method === "POST") {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk.toString("utf8");
      if (body.length > 32 * 1024) {
        body = body.slice(0, 32 * 1024);
      }
    });
    req.on("end", () => {
      let payload = {};
      if (body.trim()) {
        try {
          payload = JSON.parse(body);
        } catch (error) {
          respondJson(res, 400, {
            ok: false,
            message: `invalid control payload: ${error.message}`
          });
          return;
        }
      }

      const action = String(payload.action || "");
      if (!action) {
        respondJson(res, 400, { ok: false, message: "missing control action" });
        return;
      }
      if (!state.source || typeof state.source.control !== "function") {
        respondJson(res, 409, { ok: false, message: "control surface unavailable" });
        return;
      }

      const result = state.source.control(action, payload);
      respondJson(res, result.ok ? 200 : 422, result);
    });
    return;
  }

  res.writeHead(404);
  res.end("not found");
}

function broadcast(state, eventName, payload) {
  const data = `event: ${eventName}\ndata: ${JSON.stringify(payload)}\n\n`;
  for (const client of state.clients) {
    client.write(data);
  }
}

function respondJson(res, statusCode, payload) {
  res.writeHead(statusCode, { "content-type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(payload));
}

function glyphForKind(kind) {
  switch (kind) {
    case "open_at":
      return "O";
    case "execve":
      return "X";
    case "connect":
      return "C";
    case "write":
      return "W";
    default:
      return "?";
  }
}

function eventText(event) {
  switch (event.kind) {
    case "open_at":
      return `${event.comm || "unknown"} open_at ${shortPath(event.file || "unknown")}`;
    case "execve":
      return `${event.comm || "unknown"} execve pid=${event.pid || "?"}`;
    case "connect":
      return `${event.comm || "unknown"} connect fd=${event.fd ?? "?"}`;
    case "write":
      return `${event.comm || "unknown"} write ${Number(event.bytes || 0)}B`;
    case "aggregate":
      return `${event.metric}=${event.value}`;
    default:
      return JSON.stringify(event);
  }
}

function shortPath(file) {
  if (file.length <= 62) {
    return file;
  }
  return `${file.slice(0, 20)}...${file.slice(-38)}`;
}

function isInterestingFile(file) {
  return !(
    file.startsWith("/usr") ||
    file.startsWith("/lib") ||
    file.startsWith("/etc") ||
    file.startsWith("/proc") ||
    file.startsWith("/sys") ||
    file.startsWith("/dev") ||
    file.includes(".so") ||
    file.includes("/cargo-target/") ||
    file.includes("/rustup/toolchains/") ||
    file.includes("/tls/") ||
    file.includes("/atomics/") ||
    isNoiseBasename(file)
  );
}

function isNoiseBasename(file) {
  const base = String(file).split("/").pop()?.toLowerCase() || "";
  return (
    base === "ld.so.cache" ||
    base === "locale-archive" ||
    /^lib(c|gcc|pthread|m|dl|stdc\+\+)([-._]|$)/.test(base)
  );
}

function renderHtml() {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Live eBPF Matrix</title>
    <style>
      :root {
        --bg: #05080f;
        --panel: rgba(5, 10, 18, 0.84);
        --panel-border: rgba(57, 255, 20, 0.18);
        --text: #dfffe1;
        --muted: rgba(165, 255, 180, 0.68);
        --green: #3cff14;
        --green-soft: rgba(60, 255, 20, 0.16);
        --amber: #ffd84d;
        --blue: #72b6ff;
        --red: #ff5f7a;
      }

      * {
        box-sizing: border-box;
      }

      body {
        margin: 0;
        font-family: "IBM Plex Sans", "Avenir Next", sans-serif;
        color: var(--text);
        background: radial-gradient(circle at top, rgba(60, 255, 20, 0.08), transparent 25%), var(--bg);
        overflow-x: hidden;
      }

      #matrix {
        position: fixed;
        inset: 0;
        width: 100vw;
        height: 100vh;
        opacity: 0.32;
        z-index: 0;
      }

      main {
        position: relative;
        z-index: 1;
        max-width: 1500px;
        margin: 0 auto;
        padding: 18px 18px 32px;
      }

      .hero {
        display: grid;
        gap: 16px;
        grid-template-columns: 1.1fr 0.9fr;
        margin-bottom: 16px;
        align-items: start;
      }

      .panel {
        background: var(--panel);
        border: 1px solid var(--panel-border);
        border-radius: 22px;
        backdrop-filter: blur(10px);
        box-shadow: 0 18px 50px rgba(0, 0, 0, 0.45);
      }

      .hero-copy {
        padding: 22px 24px;
      }

      .eyebrow {
        margin: 0 0 10px;
        color: var(--muted);
        text-transform: uppercase;
        letter-spacing: 0.16em;
        font: 700 0.74rem/1.2 "IBM Plex Mono", monospace;
      }

      h1 {
        margin: 0 0 10px;
        font-size: clamp(2.6rem, 5vw, 4.8rem);
        line-height: 0.9;
      }

      .lede {
        margin: 0;
        max-width: 44rem;
        color: var(--muted);
      }

      .status-box {
        padding: 22px 24px;
        display: grid;
        gap: 12px;
        align-content: start;
      }

      .status-chip {
        display: inline-flex;
        align-items: center;
        gap: 10px;
        width: fit-content;
        padding: 10px 14px;
        border-radius: 999px;
        background: rgba(60, 255, 20, 0.12);
        border: 1px solid rgba(60, 255, 20, 0.22);
        font: 700 0.78rem/1 "IBM Plex Mono", monospace;
        text-transform: uppercase;
      }

      .transport-deck {
        margin-top: 6px;
        padding: 14px;
        border-radius: 18px;
        background:
          linear-gradient(180deg, rgba(255,255,255,0.05), rgba(255,255,255,0.02)),
          rgba(0,0,0,0.22);
        border: 1px solid rgba(60, 255, 20, 0.14);
      }

      .transport-deck.disabled {
        opacity: 0.58;
      }

      .transport-head {
        display: flex;
        justify-content: space-between;
        gap: 12px;
        align-items: baseline;
        margin-bottom: 12px;
      }

      .transport-head strong {
        letter-spacing: 0.12em;
        text-transform: uppercase;
        font: 700 0.78rem/1.2 "IBM Plex Mono", monospace;
      }

      .transport-head small {
        color: var(--muted);
      }

      .transport-buttons {
        display: grid;
        grid-template-columns: repeat(5, minmax(0, 1fr));
        gap: 8px;
      }

      .transport-btn {
        padding: 12px 8px;
        border: 1px solid rgba(60, 255, 20, 0.18);
        border-radius: 14px;
        background: rgba(60,255,20,0.06);
        color: var(--text);
        font: 700 0.76rem/1 "IBM Plex Mono", monospace;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        cursor: pointer;
      }

      .transport-btn:hover:not(:disabled) {
        background: rgba(60,255,20,0.12);
      }

      .transport-btn:disabled {
        opacity: 0.45;
        cursor: not-allowed;
      }

      .knob-row {
        display: grid;
        grid-template-columns: repeat(2, minmax(0, 1fr));
        gap: 14px;
        margin-top: 14px;
      }

      .knob {
        position: relative;
        display: grid;
        justify-items: center;
        gap: 8px;
        padding: 8px 6px 2px;
        border-radius: 16px;
        background: rgba(0,0,0,0.14);
      }

      .knob-input {
        position: absolute;
        inset: 0;
        opacity: 0;
        cursor: pointer;
      }

      .knob-input:disabled {
        cursor: not-allowed;
      }

      .knob-dial {
        --angle: -135deg;
        position: relative;
        width: 78px;
        height: 78px;
        border-radius: 50%;
        background:
          radial-gradient(circle at 30% 28%, rgba(255,255,255,0.16), transparent 24%),
          linear-gradient(145deg, rgba(255,255,255,0.08), rgba(0,0,0,0.36));
        border: 1px solid rgba(255,255,255,0.08);
        box-shadow:
          inset 0 1px 1px rgba(255,255,255,0.08),
          0 12px 24px rgba(0,0,0,0.28);
      }

      .knob-dial::after {
        content: "";
        position: absolute;
        inset: 8px;
        border-radius: 50%;
        border: 1px solid rgba(60, 255, 20, 0.12);
      }

      .knob-indicator {
        position: absolute;
        left: 50%;
        top: 50%;
        width: 4px;
        height: 28px;
        margin-left: -2px;
        margin-top: -29px;
        border-radius: 999px;
        background: linear-gradient(180deg, #eaffef, var(--green));
        box-shadow: 0 0 12px rgba(60,255,20,0.5);
        transform-origin: 50% calc(100% - 4px);
        transform: rotate(var(--angle));
      }

      .knob-label {
        color: var(--muted);
        font: 700 0.72rem/1.2 "IBM Plex Mono", monospace;
        text-transform: uppercase;
        letter-spacing: 0.12em;
      }

      .knob strong {
        font: 700 0.92rem/1.2 "IBM Plex Mono", monospace;
      }

      .metrics {
        display: grid;
        gap: 12px;
        grid-template-columns: repeat(5, minmax(0, 1fr));
        margin-bottom: 16px;
      }

      .metric {
        padding: 16px;
      }

      .metric .label {
        display: block;
        color: var(--muted);
        font: 700 0.72rem/1.2 "IBM Plex Mono", monospace;
        text-transform: uppercase;
        letter-spacing: 0.14em;
      }

      .metric .value {
        display: block;
        margin-top: 10px;
        font-size: 2rem;
        font-weight: 700;
      }

      .metric .hint {
        display: block;
        margin-top: 8px;
        color: var(--muted);
        font-size: 0.9rem;
      }

      .layout {
        display: grid;
        gap: 16px;
        grid-template-columns: 1.2fr 0.8fr;
        align-items: start;
      }

      .stack {
        display: grid;
        gap: 16px;
      }

      .section {
        padding: 20px;
      }

      h2 {
        margin: 0 0 14px;
        font-size: 1.15rem;
      }

      .diagram-shell {
        border-radius: 18px;
        background:
          linear-gradient(180deg, rgba(60,255,20,0.04), rgba(60,255,20,0.01)),
          rgba(0,0,0,0.3);
        border: 1px solid rgba(60, 255, 20, 0.12);
        overflow: hidden;
      }

      .diagram-shell svg {
        display: block;
        width: 100%;
        height: auto;
      }

      .code-rain {
        height: 300px;
        border-radius: 18px;
        background:
          linear-gradient(180deg, rgba(60,255,20,0.04), rgba(60,255,20,0.01)),
          rgba(0,0,0,0.36);
        border: 1px solid rgba(60, 255, 20, 0.12);
        overflow: hidden;
        padding: 12px 14px;
        font: 0.88rem/1.18 "IBM Plex Mono", monospace;
      }

      .rain-line {
        white-space: nowrap;
        text-shadow: 0 0 10px rgba(60,255,20,0.45);
        animation: fadein 220ms ease;
      }

      .rain-line.open_at { color: #7bffb9; }
      .rain-line.execve { color: var(--amber); }
      .rain-line.connect { color: var(--blue); }
      .rain-line.write { color: #9dff6d; }
      .rain-line.aggregate { color: #ff8ca1; }

      .list {
        display: grid;
        gap: 10px;
      }

      .row {
        display: grid;
        grid-template-columns: auto 1fr auto;
        gap: 12px;
        align-items: center;
        padding: 12px 14px;
        border-radius: 14px;
        background: rgba(60,255,20,0.05);
        border: 1px solid rgba(60,255,20,0.1);
        font-size: 0.94rem;
      }

      .pill {
        padding: 7px 10px;
        border-radius: 999px;
        font: 700 0.72rem/1 "IBM Plex Mono", monospace;
        text-transform: uppercase;
      }

      .pill.open_at { background: rgba(123,255,185,0.12); color: #7bffb9; }
      .pill.execve { background: rgba(255,216,77,0.14); color: var(--amber); }
      .pill.connect { background: rgba(114,182,255,0.14); color: var(--blue); }
      .pill.write { background: rgba(255,95,122,0.14); color: var(--red); }
      .pill.file { background: rgba(60,255,20,0.14); color: var(--green); }

      .row strong,
      .row code {
        display: block;
      }

      .row small {
        color: var(--muted);
      }

      .bar-list {
        display: grid;
        gap: 12px;
      }

      .bar-row {
        display: grid;
        gap: 8px;
      }

      .bar-label {
        display: flex;
        justify-content: space-between;
        gap: 10px;
        font: 700 0.82rem/1.2 "IBM Plex Mono", monospace;
      }

      .bar {
        height: 12px;
        border-radius: 999px;
        overflow: hidden;
        background: rgba(255,255,255,0.06);
      }

      .bar-fill {
        height: 100%;
        border-radius: 999px;
        background: linear-gradient(90deg, rgba(60,255,20,0.45), rgba(114,182,255,0.95));
      }

      pre {
        margin: 0;
        max-height: 200px;
        overflow: auto;
        padding: 14px;
        border-radius: 16px;
        background: rgba(0,0,0,0.42);
        border: 1px solid rgba(60,255,20,0.12);
        color: #d8ffe0;
        font: 0.82rem/1.45 "IBM Plex Mono", monospace;
      }

      #recent-events {
        max-height: 980px;
        overflow: auto;
        padding-right: 4px;
      }

      #file-list,
      #write-list {
        max-height: 360px;
        overflow: auto;
        padding-right: 4px;
      }

      @keyframes fadein {
        from { opacity: 0; transform: translateY(-3px); }
        to { opacity: 1; transform: translateY(0); }
      }

      @media (max-width: 1120px) {
        .hero, .layout, .metrics {
          grid-template-columns: 1fr;
        }
      }
    </style>
  </head>
  <body>
    <canvas id="matrix"></canvas>
    <main>
      <section class="hero">
        <div class="panel hero-copy">
          <p class="eyebrow">Live eBPF stream</p>
          <h1>Matrix mode for real syscalls.</h1>
          <p class="lede">
            This page is attached to a running <code>eBPF_tracker --emit jsonl</code> session.
            The background rain is synthetic, but every foreground line and counter comes from the live
            syscall stream as it arrives.
          </p>
        </div>
        <aside class="panel status-box">
          <div class="status-chip" id="status-chip">connecting</div>
          <div><strong>mode</strong><br><small id="mode-box">live</small></div>
          <div><strong>progress</strong><br><small id="progress-box">0 / 0</small></div>
          <div><strong>viewer</strong><br><small id="viewer-url">waiting for server</small></div>
          <div><strong>command</strong><pre id="command-box">starting...</pre></div>
          <section class="transport-deck" id="transport-deck">
            <div class="transport-head">
              <strong>Replay Deck</strong>
              <small id="transport-note">live stream, controls bypassed</small>
            </div>
            <div class="transport-buttons">
              <button class="transport-btn" id="restart-btn" type="button">restart</button>
              <button class="transport-btn" id="play-btn" type="button">play</button>
              <button class="transport-btn" id="pause-btn" type="button">pause</button>
              <button class="transport-btn" id="step-btn" type="button">step</button>
              <button class="transport-btn" id="forward-btn" type="button">ffwd</button>
            </div>
            <div class="knob-row">
              <label class="knob" id="speed-knob-wrap">
                <input class="knob-input" id="speed-knob" type="range" min="0.25" max="8" step="0.25" value="1">
                <span class="knob-dial"><span class="knob-indicator"></span></span>
                <span class="knob-label">tempo</span>
                <strong id="speed-readout">1.00x</strong>
              </label>
              <label class="knob" id="jump-knob-wrap">
                <input class="knob-input" id="jump-knob" type="range" min="1" max="24" step="1" value="8">
                <span class="knob-dial"><span class="knob-indicator"></span></span>
                <span class="knob-label">jump</span>
                <strong id="jump-readout">8 ev</strong>
              </label>
            </div>
          </section>
        </aside>
      </section>

      <section class="metrics">
        <article class="panel metric"><span class="label">open_at</span><span class="value" id="metric-open">0</span><span class="hint">file access</span></article>
        <article class="panel metric"><span class="label">execve</span><span class="value" id="metric-exec">0</span><span class="hint">process boundaries</span></article>
        <article class="panel metric"><span class="label">connect</span><span class="value" id="metric-connect">0</span><span class="hint">network activity</span></article>
        <article class="panel metric"><span class="label">write</span><span class="value" id="metric-write">0</span><span class="hint">output churn</span></article>
        <article class="panel metric"><span class="label">bytes</span><span class="value" id="metric-bytes">0 B</span><span class="hint">write volume</span></article>
      </section>

      <section class="layout">
        <div class="stack">
          <section class="panel section">
            <h2>Trace Waterfall</h2>
            <div class="diagram-shell" id="trace-waterfall"></div>
          </section>
          <section class="panel section">
            <h2>Live Flood</h2>
            <div class="code-rain" id="code-rain"></div>
          </section>
          <section class="panel section">
            <h2>Recent Events</h2>
            <div class="list" id="recent-events"></div>
          </section>
        </div>
        <div class="stack">
          <section class="panel section">
            <h2>Session Map</h2>
            <div class="diagram-shell" id="trace-map"></div>
          </section>
          <section class="panel section">
            <h2>Processes</h2>
            <div class="bar-list" id="process-bars"></div>
          </section>
          <section class="panel section">
            <h2>Interesting Files</h2>
            <div class="list" id="file-list"></div>
          </section>
          <section class="panel section">
            <h2>Largest Writes</h2>
            <div class="list" id="write-list"></div>
          </section>
          <section class="panel section">
            <h2>Tracer Stderr</h2>
            <pre id="stderr-box"></pre>
          </section>
        </div>
      </section>
    </main>
    <script>
      const eventSource = new EventSource("/events");
      const state = {
        recentRain: [],
        stderr: []
      };

      const els = {
        codeRain: document.getElementById("code-rain"),
        traceWaterfall: document.getElementById("trace-waterfall"),
        traceMap: document.getElementById("trace-map"),
        recentEvents: document.getElementById("recent-events"),
        processBars: document.getElementById("process-bars"),
        fileList: document.getElementById("file-list"),
        writeList: document.getElementById("write-list"),
        stderrBox: document.getElementById("stderr-box"),
        commandBox: document.getElementById("command-box"),
        viewerUrl: document.getElementById("viewer-url"),
        transportDeck: document.getElementById("transport-deck"),
        transportNote: document.getElementById("transport-note"),
        restartBtn: document.getElementById("restart-btn"),
        playBtn: document.getElementById("play-btn"),
        pauseBtn: document.getElementById("pause-btn"),
        stepBtn: document.getElementById("step-btn"),
        forwardBtn: document.getElementById("forward-btn"),
        speedKnobWrap: document.getElementById("speed-knob-wrap"),
        speedKnob: document.getElementById("speed-knob"),
        speedReadout: document.getElementById("speed-readout"),
        jumpKnobWrap: document.getElementById("jump-knob-wrap"),
        jumpKnob: document.getElementById("jump-knob"),
        jumpReadout: document.getElementById("jump-readout"),
        modeBox: document.getElementById("mode-box"),
        progressBox: document.getElementById("progress-box"),
        statusChip: document.getElementById("status-chip"),
        open: document.getElementById("metric-open"),
        exec: document.getElementById("metric-exec"),
        connect: document.getElementById("metric-connect"),
        write: document.getElementById("metric-write"),
        bytes: document.getElementById("metric-bytes")
      };

      eventSource.addEventListener("snapshot", (message) => {
        const snapshot = JSON.parse(message.data);
        renderSnapshot(snapshot);
      });

      eventSource.addEventListener("event", (message) => {
        const event = JSON.parse(message.data);
        addRainLine(event);
      });

      eventSource.addEventListener("stderr", (message) => {
        const payload = JSON.parse(message.data);
        state.stderr.push(payload.text);
        state.stderr = state.stderr.slice(-40);
        els.stderrBox.textContent = state.stderr.join("");
      });

      eventSource.addEventListener("status", (message) => {
        const payload = JSON.parse(message.data);
        els.statusChip.textContent = payload.status;
        if (payload.command) {
          els.commandBox.textContent = payload.command.join(" ");
        }
        if (payload.mode) {
          els.modeBox.textContent = payload.mode;
        }
        if (payload.progress) {
          els.progressBox.textContent = payload.progress.emitted + " / " + payload.progress.total;
        }
        if (payload.replay) {
          applyReplayState(payload.replay, payload.progress || null);
        }
        if (payload.url) {
          els.viewerUrl.textContent = payload.url;
        }
      });

      els.restartBtn.addEventListener("click", () => sendControl("restart"));
      els.playBtn.addEventListener("click", () => sendControl("play"));
      els.pauseBtn.addEventListener("click", () => sendControl("pause"));
      els.stepBtn.addEventListener("click", () => sendControl("step"));
      els.forwardBtn.addEventListener("click", () =>
        sendControl("forward", { count: Number(els.jumpKnob.value) })
      );
      els.speedKnob.addEventListener("input", () => {
        const value = Number(els.speedKnob.value);
        updateKnob(els.speedKnobWrap, value, 0.25, 8, (current) => current.toFixed(2) + "x", els.speedReadout);
      });
      els.speedKnob.addEventListener("change", () =>
        sendControl("set_speed", { value: Number(els.speedKnob.value) })
      );
      els.jumpKnob.addEventListener("input", () => {
        const value = Number(els.jumpKnob.value);
        updateKnob(els.jumpKnobWrap, value, 1, 24, (current) => current + " ev", els.jumpReadout);
      });
      els.jumpKnob.addEventListener("change", () =>
        sendControl("set_step_size", { value: Number(els.jumpKnob.value) })
      );

      function renderSnapshot(snapshot) {
        if (snapshot.command?.length) {
          els.commandBox.textContent = snapshot.command.join(" ");
        }
        if (snapshot.url) {
          els.viewerUrl.textContent = snapshot.url;
        }
        if (snapshot.status) {
          els.statusChip.textContent = snapshot.status;
        }
        if (snapshot.mode) {
          els.modeBox.textContent = snapshot.mode;
        }
        if (snapshot.progress) {
          els.progressBox.textContent = snapshot.progress.emitted + " / " + snapshot.progress.total;
        }
        applyReplayState(snapshot.replay || { supported: false }, snapshot.progress || null);
        els.open.textContent = formatNumber(snapshot.counters.open_at);
        els.exec.textContent = formatNumber(snapshot.counters.execve);
        els.connect.textContent = formatNumber(snapshot.counters.connect);
        els.write.textContent = formatNumber(snapshot.counters.write);
        els.bytes.textContent = formatBytes(snapshot.counters.bytes);
        const displayEvents = selectDisplayEvents(snapshot.recentEvents || []);
        els.traceWaterfall.innerHTML = renderWaterfall(displayEvents);
        els.traceMap.innerHTML = renderTraceMap(snapshot);
        if (!snapshot.recentEvents?.length) {
          state.recentRain = [];
          addRainFrame();
        }
        if (!state.recentRain.length && snapshot.recentEvents?.length) {
          state.recentRain = snapshot.recentEvents.slice(0, 18);
          addRainFrame();
        }

        els.recentEvents.innerHTML = displayEvents.map((event) => {
          return '<div class="row">' +
            '<span class="pill ' + escapeClass(event.kind || "other") + '">' + escapeHtml(event.kind || "other") + '</span>' +
            '<div><strong>' + escapeHtml(event.text) + '</strong><small>' +
            escapeHtml(event.comm || "unknown") + ' pid ' + escapeHtml(String(event.pid || "?")) +
            '</small></div>' +
            '<small>+' + formatMs(event.since_start_ms || 0) + '</small>' +
          '</div>';
        }).join("");

        const maxProcess = snapshot.topProcesses[0]?.count || 1;
        els.processBars.innerHTML = snapshot.topProcesses.map((entry) => {
          const width = (entry.count / maxProcess) * 100;
          return '<div class="bar-row">' +
            '<div class="bar-label"><span>' + escapeHtml(entry.comm) + '</span><span>' + formatNumber(entry.count) + '</span></div>' +
            '<div class="bar"><div class="bar-fill" style="width:' + width.toFixed(2) + '%"></div></div>' +
          '</div>';
        }).join("");

        els.fileList.innerHTML = snapshot.topFiles.length
          ? snapshot.topFiles.map((entry) => {
              return '<div class="row">' +
                '<span class="pill file">file</span>' +
                '<div><code>' + escapeHtml(entry.file) + '</code><small>opened ' + formatNumber(entry.count) + ' times</small></div>' +
                '<small></small>' +
              '</div>';
            }).join("")
          : '<div class="row"><span class="pill file">file</span><div><strong>No non-system files yet.</strong></div><small></small></div>';

        els.writeList.innerHTML = snapshot.writes.length
          ? snapshot.writes.map((entry) => {
              return '<div class="row">' +
                '<span class="pill write">write</span>' +
                '<div><strong>' + escapeHtml(entry.comm) + '</strong><small>' + formatBytes(entry.bytes) + '</small></div>' +
                '<small>' + new Date(entry.timestamp_unix_ms).toLocaleTimeString() + '</small>' +
              '</div>';
            }).join("")
          : '<div class="row"><span class="pill write">write</span><div><strong>No writes yet.</strong></div><small></small></div>';
      }

      function addRainLine(event) {
        state.recentRain.unshift(event);
        state.recentRain = state.recentRain.slice(0, 24);
        addRainFrame();
      }

      function addRainFrame() {
        els.codeRain.innerHTML = state.recentRain.map((entry) => {
          return '<div class="rain-line ' + escapeClass(entry.kind || "other") + '">' +
            escapeHtml(entry.glyph || "?") + ' ' +
            escapeHtml(new Date(entry.timestamp_unix_ms || Date.now()).toISOString()) +
            ' :: ' + escapeHtml(entry.text || "") +
          '</div>';
        }).join("");
      }

      function selectDisplayEvents(events) {
        const filtered = events.filter((event) => {
          return event.kind !== "open_at" || isInterestingPath(event.file || "");
        });
        return filtered.length ? filtered : events;
      }

      function applyReplayState(replay, progress) {
        const supported = Boolean(replay?.supported);
        const paused = Boolean(replay?.paused);
        const ended = Boolean(replay?.ended);
        els.transportDeck.classList.toggle("disabled", !supported);
        els.restartBtn.disabled = !supported;
        els.playBtn.disabled = !supported || (!paused && !ended);
        els.pauseBtn.disabled = !supported || paused || ended;
        els.stepBtn.disabled = !supported;
        els.forwardBtn.disabled = !supported;
        els.speedKnob.disabled = !supported;
        els.jumpKnob.disabled = !supported;

        if (!supported) {
          els.transportNote.textContent = "live stream, controls bypassed";
        } else if (ended) {
          els.transportNote.textContent = "replay ended, hit restart or play";
        } else if (paused) {
          const current = progress ? progress.emitted : 0;
          const total = progress ? progress.total : 0;
          els.transportNote.textContent = "paused at " + current + " / " + total;
        } else {
          els.transportNote.textContent = "rolling with producer controls armed";
        }

        const speed = Number(replay?.speed || els.speedKnob.value || 1);
        const stepSize = Number(replay?.stepSize || els.jumpKnob.value || 8);
        els.speedKnob.value = String(speed);
        els.jumpKnob.value = String(stepSize);
        updateKnob(els.speedKnobWrap, speed, 0.25, 8, (current) => current.toFixed(2) + "x", els.speedReadout);
        updateKnob(els.jumpKnobWrap, stepSize, 1, 24, (current) => current + " ev", els.jumpReadout);
      }

      async function sendControl(action, extra = {}) {
        try {
          const response = await fetch("/control", {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ action, ...extra })
          });
          if (!response.ok) {
            const payload = await response.json().catch(() => ({ message: response.statusText }));
            els.transportNote.textContent = payload.message || "control request failed";
          }
        } catch (error) {
          els.transportNote.textContent = error instanceof Error ? error.message : String(error);
        }
      }

      function updateKnob(wrapper, value, min, max, formatValue, readout) {
        const normalized = (Number(value) - min) / Math.max(max - min, 1);
        const angle = -135 + normalized * 270;
        wrapper.style.setProperty("--angle", angle.toFixed(1) + "deg");
        const dial = wrapper.querySelector(".knob-dial");
        if (dial) {
          dial.style.setProperty("--angle", angle.toFixed(1) + "deg");
        }
        readout.textContent = formatValue(Number(value));
      }

      function renderWaterfall(events) {
        const ordered = (events || []).slice().reverse();
        if (!ordered.length) {
          return '<svg viewBox="0 0 860 240" role="img" aria-label="Empty trace waterfall">' +
            '<rect width="860" height="240" fill="rgba(0,0,0,0.18)"></rect>' +
            '<text x="430" y="124" text-anchor="middle" fill="rgba(165,255,180,0.68)" font-size="18" font-family="IBM Plex Mono, monospace">Waiting for syscall events...</text>' +
          '</svg>';
        }

        const lanes = [
          { kind: "open_at", y: 54, color: "#7bffb9" },
          { kind: "execve", y: 98, color: "#ffd84d" },
          { kind: "connect", y: 142, color: "#72b6ff" },
          { kind: "write", y: 186, color: "#ff5f7a" }
        ];
        const width = 860;
        const height = 240;
        const left = 92;
        const right = 24;
        const min = Math.min.apply(null, ordered.map((event) => Number(event.since_start_ms || 0)));
        const max = Math.max.apply(null, ordered.map((event) => Number(event.since_start_ms || 0)));
        const span = Math.max(max - min, 1);

        const laneLines = lanes.map((lane) => {
          return '<line x1="' + left + '" y1="' + lane.y + '" x2="' + (width - right) + '" y2="' + lane.y + '" stroke="rgba(255,255,255,0.08)" stroke-width="1"></line>' +
            '<text x="20" y="' + (lane.y + 4) + '" fill="rgba(165,255,180,0.72)" font-size="12" font-family="IBM Plex Mono, monospace">' + lane.kind + '</text>';
        }).join("");

        const points = ordered.map((event) => {
          const lane = lanes.find((candidate) => candidate.kind === event.kind) || { y: 210, color: "#dfffe1" };
          const x = left + ((Number(event.since_start_ms || 0) - min) / span) * (width - left - right);
          return {
            x,
            y: lane.y,
            color: lane.color,
            event
          };
        });

        const path = points.map((point, index) => (index === 0 ? "M" : "L") + point.x.toFixed(1) + " " + point.y).join(" ");
        const circles = points.map((point, index) => {
          const radius = point.event.kind === "write" ? 6 : 5;
          const label = index === points.length - 1
            ? '<text x="' + Math.min(point.x + 10, width - 160) + '" y="' + (point.y - 12) + '" fill="' + point.color + '" font-size="11" font-family="IBM Plex Mono, monospace">' + escapeHtml(shortEventLabel(point.event)) + '</text>'
            : '';
          return '<circle cx="' + point.x.toFixed(1) + '" cy="' + point.y + '" r="' + radius + '" fill="' + point.color + '" stroke="rgba(4,8,15,0.9)" stroke-width="2"></circle>' + label;
        }).join("");

        return '<svg viewBox="0 0 ' + width + ' ' + height + '" role="img" aria-label="Trace waterfall">' +
          '<rect width="' + width + '" height="' + height + '" fill="rgba(0,0,0,0.14)"></rect>' +
          laneLines +
          '<path d="' + path + '" fill="none" stroke="rgba(223,255,225,0.26)" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"></path>' +
          circles +
          '<text x="' + left + '" y="24" fill="rgba(165,255,180,0.68)" font-size="12" font-family="IBM Plex Mono, monospace">start +' + formatMs(min) + '</text>' +
          '<text x="' + (width - right) + '" y="24" text-anchor="end" fill="rgba(165,255,180,0.68)" font-size="12" font-family="IBM Plex Mono, monospace">latest +' + formatMs(max) + '</text>' +
        '</svg>';
      }

      function renderTraceMap(snapshot) {
        const primary = pickPrimaryProcess(snapshot);
        const width = 860;
        const height = 430;
        const shellX = 20;
        const shellY = 18;
        const shellWidth = 820;
        const shellHeight = 394;
        const centerX = 430;
        const centerY = 176;
        const centerWidth = 216;
        const centerHeight = 136;
        const leftX = 232;
        const rightX = 628;
        const inputs = buildSessionInputNodes(snapshot).slice(0, 4);
        const outputs = buildSessionOutputNodes(snapshot, primary).slice(0, 4);
        const journey = buildSessionJourney(snapshot, primary).slice(0, 4);
        const centerStats = summarizePrimaryStats(snapshot, primary);

        if (!inputs.length && !outputs.length && !journey.length) {
          return '<svg viewBox="0 0 860 430" role="img" aria-label="Empty session map">' +
            '<rect width="860" height="430" fill="rgba(0,0,0,0.18)"></rect>' +
            '<text x="430" y="214" text-anchor="middle" fill="rgba(165,255,180,0.68)" font-size="18" font-family="IBM Plex Mono, monospace">No trace relationships yet.</text>' +
          '</svg>';
        }

        const leftNodes = inputs.map((entry, index) => ({
          ...entry,
          x: leftX,
          y: 104 + index * 72,
          anchor: "end"
        }));

        const rightNodes = outputs.map((entry, index) => ({
          ...entry,
          x: rightX,
          y: 104 + index * 72,
          anchor: "start"
        }));

        const leftEdges = leftNodes.map((node, index) =>
          renderSessionEdge({
            fromX: node.x,
            fromY: node.y,
            toX: centerX - centerWidth / 2,
            toY: centerY - 28 + index * 10,
            color: node.color,
            label: node.edgeLabel
          })
        ).join("");

        const rightEdges = rightNodes.map((node, index) =>
          renderSessionEdge({
            fromX: centerX + centerWidth / 2,
            fromY: centerY - 16 + index * 12,
            toX: node.x,
            toY: node.y,
            color: node.color,
            label: node.edgeLabel
          })
        ).join("");

        const leftBoxes = leftNodes.map((node) => renderMapNode(node)).join("");
        const rightBoxes = rightNodes.map((node) => renderMapNode(node)).join("");
        const statChips = renderCenterStatChips(centerX, centerY + 18, centerStats);
        const journeyStrip = journey.length
          ? renderJourneyStrip(journey, width, 318)
          : '<text x="430" y="348" text-anchor="middle" fill="rgba(165,255,180,0.58)" font-size="12" font-family="IBM Plex Mono, monospace">No recent flow cues yet.</text>';

        return '<svg viewBox="0 0 ' + width + ' ' + height + '" role="img" aria-label="Session map">' +
          '<rect width="' + width + '" height="' + height + '" fill="rgba(0,0,0,0.14)"></rect>' +
          '<rect x="' + shellX + '" y="' + shellY + '" width="' + shellWidth + '" height="' + shellHeight + '" rx="36" fill="rgba(4,10,16,0.62)" stroke="rgba(60,255,20,0.22)" stroke-width="2"></rect>' +
          '<text x="44" y="42" fill="rgba(165,255,180,0.72)" font-size="12" font-family="IBM Plex Mono, monospace">inputs</text>' +
          '<text x="430" y="42" text-anchor="middle" fill="rgba(165,255,180,0.72)" font-size="12" font-family="IBM Plex Mono, monospace">workload</text>' +
          '<text x="816" y="42" text-anchor="end" fill="rgba(165,255,180,0.72)" font-size="12" font-family="IBM Plex Mono, monospace">outputs</text>' +
          '<line x1="46" y1="66" x2="814" y2="66" stroke="rgba(60,255,20,0.12)" stroke-width="1"></line>' +
          leftEdges +
          rightEdges +
          leftBoxes +
          rightBoxes +
          renderCenterNode(centerX, centerY, centerWidth, centerHeight, primary, centerStats) +
          statChips +
          '<text x="48" y="296" fill="rgba(165,255,180,0.72)" font-size="12" font-family="IBM Plex Mono, monospace">journey</text>' +
          journeyStrip +
        '</svg>';
      }

      function buildSessionInputNodes(snapshot) {
        const nodes = [];
        for (const entry of snapshot.topFiles || []) {
          const role = classifySessionFile(entry.file);
          if (role === "artifact") {
            continue;
          }
          nodes.push({
            title: mapPathLabel(entry.file),
            detail: formatNumber(entry.count) + " open_at",
            color: role === "template" ? "#8af2d3" : "#7bffb9",
            edgeLabel: role === "template" ? "template" : "open_at"
          });
        }
        return nodes;
      }

      function buildSessionOutputNodes(snapshot, primary) {
        const nodes = [];

        for (const entry of snapshot.topFiles || []) {
          if (classifySessionFile(entry.file) !== "artifact") {
            continue;
          }
          nodes.push({
            title: mapPathLabel(entry.file),
            detail: formatNumber(entry.count) + " artifact open",
            color: "#b7ff6d",
            edgeLabel: "artifact"
          });
        }

        if ((snapshot.counters.connect || 0) > 0) {
          nodes.push({
            title: "network",
            detail: formatNumber(snapshot.counters.connect) + " connect",
            color: "#72b6ff",
            edgeLabel: "connect"
          });
        }
        if ((snapshot.counters.write || 0) > 0) {
          nodes.push({
            title: "writes",
            detail: formatBytes(snapshot.counters.bytes || 0),
            color: "#ff5f7a",
            edgeLabel: "write"
          });
        }

        const otherProcesses = (snapshot.topProcesses || [])
          .filter((entry) => entry.comm !== primary && !isWrapperProcess(entry.comm))
          .slice(0, 2);
        for (const entry of otherProcesses) {
          nodes.push({
            title: entry.comm,
            detail: formatNumber(entry.count) + " events",
            color: "#ffd84d",
            edgeLabel: "execve"
          });
        }

        return nodes;
      }

      function summarizePrimaryStats(snapshot, primary) {
        const recentPrimaryEvents = (snapshot.recentEvents || []).filter((event) => event.comm === primary);
        const counts = { open_at: 0, connect: 0, write: 0, execve: 0 };
        for (const event of recentPrimaryEvents) {
          if (Object.hasOwn(counts, event.kind)) {
            counts[event.kind] += 1;
          }
        }

        return [
          {
            label: "open",
            value: formatNumber(counts.open_at || snapshot.counters.open_at || 0),
            color: "#7bffb9"
          },
          {
            label: "connect",
            value: formatNumber(counts.connect || snapshot.counters.connect || 0),
            color: "#72b6ff"
          },
          {
            label: "write",
            value: formatNumber(counts.write || snapshot.counters.write || 0),
            color: "#ff5f7a"
          }
        ];
      }

      function buildSessionJourney(snapshot, primary) {
        const steps = [];
        const ordered = selectDisplayEvents(snapshot.recentEvents || []).slice().reverse();
        for (const event of ordered) {
          const step = journeyStepForEvent(event, primary);
          if (!step) {
            continue;
          }
          const previous = steps[steps.length - 1];
          if (previous && previous.title === step.title && previous.kind === step.kind) {
            continue;
          }
          steps.push(step);
          if (steps.length >= 4) {
            break;
          }
        }

        if (!steps.length && (snapshot.counters.connect || 0) > 0) {
          steps.push({ kind: "connect", title: "network", detail: formatNumber(snapshot.counters.connect) + " connect", color: "#72b6ff" });
        }
        if (steps.length < 4 && (snapshot.counters.write || 0) > 0) {
          steps.push({ kind: "write", title: "writes", detail: formatBytes(snapshot.counters.bytes || 0), color: "#ff5f7a" });
        }

        return steps.slice(0, 4);
      }

      function journeyStepForEvent(event, primary) {
        if (event.kind === "open_at") {
          const role = classifySessionFile(event.file || "");
          return {
            kind: "open_at",
            title: mapPathLabel(event.file || "file"),
            detail: role === "artifact" ? "artifact open" : role === "template" ? "template read" : "input read",
            color: role === "artifact" ? "#b7ff6d" : "#7bffb9"
          };
        }
        if (event.kind === "connect") {
          return {
            kind: "connect",
            title: "network",
            detail: "socket connect",
            color: "#72b6ff"
          };
        }
        if (event.kind === "write") {
          return {
            kind: "write",
            title: event.comm === primary ? "writes" : event.comm,
            detail: formatBytes(event.bytes || 0),
            color: "#ff5f7a"
          };
        }
        if (event.kind === "execve") {
          return {
            kind: "execve",
            title: event.comm || "process",
            detail: "exec boundary",
            color: "#ffd84d"
          };
        }
        return null;
      }

      function renderSessionEdge({ fromX, fromY, toX, toY, color, label }) {
        const midX = (fromX + toX) / 2;
        const path = '<path d="M ' + fromX + ' ' + fromY +
          ' C ' + midX + ' ' + fromY + ', ' + midX + ' ' + toY + ', ' + toX + ' ' + toY +
          '" fill="none" stroke="' + color + '" stroke-opacity="0.44" stroke-width="3"></path>';
        const labelX = midX;
        const labelY = (fromY + toY) / 2 - 8;
        const pill = '<g>' +
          '<rect x="' + (labelX - 26) + '" y="' + (labelY - 10) + '" width="52" height="18" rx="9" fill="rgba(8,14,24,0.92)" stroke="' + color + '" stroke-opacity="0.34"></rect>' +
          '<text x="' + labelX + '" y="' + (labelY + 3) + '" text-anchor="middle" fill="' + color + '" font-size="10" font-family="IBM Plex Mono, monospace">' + escapeHtml(label) + '</text>' +
        '</g>';
        return path + pill;
      }

      function renderCenterNode(centerX, centerY, width, height, primary, stats) {
        return '<g>' +
          '<rect x="' + (centerX - width / 2) + '" y="' + (centerY - height / 2) + '" width="' + width + '" height="' + height + '" rx="30" fill="rgba(25,76,25,0.34)" stroke="rgba(114,255,128,0.52)" stroke-width="2"></rect>' +
          '<rect x="' + (centerX - width / 2 + 12) + '" y="' + (centerY - height / 2 + 12) + '" width="' + (width - 24) + '" height="' + (height - 24) + '" rx="22" fill="rgba(9,20,14,0.8)" stroke="rgba(123,255,185,0.16)"></rect>' +
          '<text x="' + centerX + '" y="' + (centerY - 28) + '" text-anchor="middle" fill="#e7ffe9" font-size="16" font-weight="700" font-family="IBM Plex Sans, sans-serif">' + escapeHtml(primary) + '</text>' +
          '<text x="' + centerX + '" y="' + (centerY - 8) + '" text-anchor="middle" fill="rgba(165,255,180,0.72)" font-size="11" font-family="IBM Plex Mono, monospace">current traced workload</text>' +
          '<text x="' + centerX + '" y="' + (centerY + 62) + '" text-anchor="middle" fill="rgba(165,255,180,0.66)" font-size="11" font-family="IBM Plex Mono, monospace">' + stats.map((entry) => entry.value + " " + entry.label).join(" / ") + '</text>' +
        '</g>';
      }

      function renderCenterStatChips(centerX, y, stats) {
        const chipWidth = 56;
        const gap = 12;
        const totalWidth = stats.length * chipWidth + (stats.length - 1) * gap;
        const startX = centerX - totalWidth / 2;

        return stats.map((entry, index) => {
          const x = startX + index * (chipWidth + gap);
          return '<g>' +
            '<rect x="' + x + '" y="' + y + '" width="' + chipWidth + '" height="32" rx="12" fill="rgba(8,14,24,0.88)" stroke="' + entry.color + '" stroke-opacity="0.34"></rect>' +
            '<text x="' + (x + chipWidth / 2) + '" y="' + (y + 13) + '" text-anchor="middle" fill="' + entry.color + '" font-size="10" font-family="IBM Plex Mono, monospace">' + escapeHtml(entry.label) + '</text>' +
            '<text x="' + (x + chipWidth / 2) + '" y="' + (y + 25) + '" text-anchor="middle" fill="#e7ffe9" font-size="11" font-weight="700" font-family="IBM Plex Mono, monospace">' + escapeHtml(entry.value) + '</text>' +
          '</g>';
        }).join("");
      }

      function renderJourneyStrip(steps, width, y) {
        const pillWidth = 154;
        const pillHeight = 54;
        const gap = 16;
        const totalWidth = steps.length * pillWidth + (steps.length - 1) * gap;
        const startX = (width - totalWidth) / 2;

        return steps.map((step, index) => {
          const x = startX + index * (pillWidth + gap);
          const arrow = index < steps.length - 1
            ? '<path d="M ' + (x + pillWidth + 4) + ' ' + (y + pillHeight / 2) + ' L ' + (x + pillWidth + 12) + ' ' + (y + pillHeight / 2) + ' M ' + (x + pillWidth + 8) + ' ' + (y + pillHeight / 2 - 4) + ' L ' + (x + pillWidth + 12) + ' ' + (y + pillHeight / 2) + ' L ' + (x + pillWidth + 8) + ' ' + (y + pillHeight / 2 + 4) + '" fill="none" stroke="rgba(165,255,180,0.42)" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"></path>'
            : "";
          return '<g>' +
            '<rect x="' + x + '" y="' + y + '" width="' + pillWidth + '" height="' + pillHeight + '" rx="18" fill="rgba(8,14,24,0.92)" stroke="' + step.color + '" stroke-opacity="0.32"></rect>' +
            '<text x="' + (x + 16) + '" y="' + (y + 20) + '" fill="' + step.color + '" font-size="10" font-family="IBM Plex Mono, monospace">' + escapeHtml(step.kind) + '</text>' +
            '<text x="' + (x + 16) + '" y="' + (y + 34) + '" fill="#e7ffe9" font-size="13" font-weight="700" font-family="IBM Plex Sans, sans-serif">' + escapeHtml(step.title) + '</text>' +
            '<text x="' + (x + 16) + '" y="' + (y + 47) + '" fill="rgba(165,255,180,0.68)" font-size="11" font-family="IBM Plex Mono, monospace">' + escapeHtml(step.detail) + '</text>' +
            arrow +
          '</g>';
        }).join("");
      }

      function renderMapNode(node) {
        const width = 184;
        const height = 60;
        const boxX = node.anchor === "end" ? node.x - width : node.x;
        const textX = node.anchor === "end" ? node.x - 16 : node.x + 16;
        const textAnchor = node.anchor === "end" ? "end" : "start";
        return '<g>' +
          '<rect x="' + boxX + '" y="' + (node.y - height / 2) + '" width="' + width + '" height="' + height + '" rx="18" fill="rgba(8,14,24,0.94)" stroke="' + node.color + '" stroke-opacity="0.28"></rect>' +
          '<text x="' + textX + '" y="' + (node.y - 6) + '" text-anchor="' + textAnchor + '" fill="#e7ffe9" font-size="13" font-weight="700" font-family="IBM Plex Sans, sans-serif">' + escapeHtml(node.title) + '</text>' +
          '<text x="' + textX + '" y="' + (node.y + 14) + '" text-anchor="' + textAnchor + '" fill="rgba(165,255,180,0.68)" font-size="11" font-family="IBM Plex Mono, monospace">' + escapeHtml(node.detail) + '</text>' +
        '</g>';
      }

      function classifySessionFile(file) {
        const path = String(file || "").toLowerCase();
        if (
          path.includes("/logs/") ||
          path.includes("/dist/") ||
          path.includes("summary") ||
          path.endsWith(".svg") ||
          path.endsWith(".html")
        ) {
          return "artifact";
        }
        if (path.includes("/templates/")) {
          return "template";
        }
        return "input";
      }

      function mapPathLabel(file) {
        const parts = String(file || "").split("/").filter(Boolean);
        if (!parts.length) {
          return "unknown";
        }
        if (parts.length === 1) {
          return parts[0];
        }
        return parts.slice(-2).join("/");
      }

      function isWrapperProcess(comm) {
        return ["cargo", "rustc", "exec-target-fro", "containerd", "cc", "ld"].includes(comm);
      }

      function pickPrimaryProcess(snapshot) {
        const scores = new Map();
        const wrapperPenalty = new Set(["cargo", "rustc", "exec-target-fro", "containerd", "cc", "ld"]);
        for (const event of snapshot.recentEvents || []) {
          const comm = event.comm || "unknown";
          let score = scores.get(comm) || 0;
          if (event.kind === "connect") score += 16;
          if (event.kind === "write") score += 10 + Math.min(Number(event.bytes || 0) / 64, 12);
          if (event.kind === "open_at") score += isInterestingPath(event.file || "") ? 6 : 1;
          if (event.kind === "execve") score += 5;
          if (wrapperPenalty.has(comm)) score -= 4;
          scores.set(comm, score);
        }

        let best = snapshot.topProcesses?.[0]?.comm || "app";
        let bestScore = -Infinity;
        for (const [comm, score] of scores.entries()) {
          if (score > bestScore) {
            best = comm;
            bestScore = score;
          }
        }
        return best;
      }

      function shortEventLabel(event) {
        if (event.kind === "open_at") return shortPath(event.file || "file");
        if (event.kind === "connect") return "socket connect";
        if (event.kind === "write") return formatBytes(event.bytes || 0);
        if (event.kind === "execve") return (event.comm || "proc") + " exec";
        return event.kind || "event";
      }

      function formatNumber(value) {
        return new Intl.NumberFormat("en-US").format(Number(value || 0));
      }

      function formatBytes(value) {
        const bytes = Number(value || 0);
        if (bytes < 1024) return formatNumber(bytes) + " B";
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
        return (bytes / (1024 * 1024)).toFixed(1) + " MB";
      }

      function formatMs(value) {
        const ms = Number(value || 0);
        if (ms < 1000) return Math.round(ms) + " ms";
        return (ms / 1000).toFixed(2) + " s";
      }

      function escapeHtml(value) {
        return String(value)
          .replaceAll("&", "&amp;")
          .replaceAll("<", "&lt;")
          .replaceAll(">", "&gt;")
          .replaceAll('"', "&quot;");
      }

      function escapeClass(value) {
        return String(value).replace(/[^a-zA-Z0-9_-]/g, "_");
      }

      function shortPath(value) {
        const path = String(value || "");
        if (path.length <= 30) return path;
        return path.slice(0, 12) + "..." + path.slice(-15);
      }

      function isInterestingPath(file) {
        const path = String(file || "");
        return !(
          path.startsWith("/usr") ||
          path.startsWith("/lib") ||
          path.startsWith("/etc") ||
          path.startsWith("/proc") ||
          path.startsWith("/sys") ||
          path.startsWith("/dev") ||
          path.includes(".so") ||
          path.includes("/cargo-target/") ||
          path.includes("/rustup/toolchains/") ||
          path.includes("/tls/") ||
          path.includes("/atomics/") ||
          isNoiseBase(path)
        );
      }

      function isNoiseBase(file) {
        const base = String(file || "").split("/").pop()?.toLowerCase() || "";
        return (
          base === "ld.so.cache" ||
          base === "locale-archive" ||
          /^lib(c|gcc|pthread|m|dl|stdc\\+\\+)([-._]|$)/.test(base)
        );
      }

      const canvas = document.getElementById("matrix");
      const ctx = canvas.getContext("2d");
      let drops = [];
      let columns = 0;
      const glyphs = "01OXCW{}[]<>/\\\\|:-=+*";

      function resize() {
        canvas.width = window.innerWidth * window.devicePixelRatio;
        canvas.height = window.innerHeight * window.devicePixelRatio;
        canvas.style.width = window.innerWidth + "px";
        canvas.style.height = window.innerHeight + "px";
        ctx.setTransform(window.devicePixelRatio, 0, 0, window.devicePixelRatio, 0, 0);
        columns = Math.floor(window.innerWidth / 18);
        drops = Array.from({ length: columns }, () => Math.random() * window.innerHeight / 18);
      }

      function draw() {
        ctx.fillStyle = "rgba(5, 8, 15, 0.12)";
        ctx.fillRect(0, 0, window.innerWidth, window.innerHeight);
        ctx.font = "16px IBM Plex Mono, monospace";

        for (let i = 0; i < drops.length; i += 1) {
          const char = glyphs[Math.floor(Math.random() * glyphs.length)];
          const x = i * 18;
          const y = drops[i] * 18;
          ctx.fillStyle = i % 7 === 0 ? "rgba(190,255,200,0.95)" : "rgba(60,255,20,0.75)";
          ctx.fillText(char, x, y);
          if (y > window.innerHeight && Math.random() > 0.972) {
            drops[i] = 0;
          }
          drops[i] += 1 + Math.random() * 0.35;
        }
        requestAnimationFrame(draw);
      }

      window.addEventListener("resize", resize);
      resize();
      draw();
    </script>
  </body>
</html>`;
}

main();
