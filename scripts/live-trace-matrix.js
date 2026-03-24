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

  const finalCommand = command.length ? command : DEFAULT_TARGET.slice();
  if (!finalCommand.includes("--emit")) {
    if (finalCommand[0] === "./target/debug/eBPF_tracker" || finalCommand[0].endsWith("/eBPF_tracker")) {
      finalCommand.splice(1, 0, "--emit", "jsonl");
    } else if (finalCommand[0] === "demo") {
      finalCommand.splice(1, 0, "--emit", "jsonl");
      finalCommand.unshift("./target/debug/eBPF_tracker");
    } else {
      finalCommand.unshift("--emit", "jsonl");
      finalCommand.unshift("./target/debug/eBPF_tracker");
    }
  } else if (finalCommand[0] !== "./target/debug/eBPF_tracker" && !finalCommand[0].endsWith("/eBPF_tracker")) {
    finalCommand.unshift("./target/debug/eBPF_tracker");
  }

  return { port, host, command: finalCommand, replayFile: null, focusComm: null, replaySpeed: 1, replayIntervalMs: null };
}

function createState() {
  return {
    clients: new Set(),
    recentEvents: [],
    counters: { open_at: 0, execve: 0, connect: 0, write: 0, other: 0, bytes: 0 },
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
    progress: { emitted: 0, total: 0 }
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
    }
  };
}

function startReplay(options, state, onEnd) {
  const replayRecords = loadReplayRecords(options.replayFile, options.focusComm);
  state.progress.total = replayRecords.length;

  let timer = null;
  let index = 0;
  let stopped = false;

  const tick = () => {
    if (stopped) {
      return;
    }
    if (index >= replayRecords.length) {
      onEnd(0, null);
      return;
    }

    const record = {
      ...replayRecords[index],
      timestamp_unix_ms: Date.now()
    };
    state.progress.emitted = index + 1;
    handleTraceRecord(record, state);
    index += 1;

    if (index >= replayRecords.length) {
      onEnd(0, null);
      return;
    }

    timer = setTimeout(tick, replayDelayMs(replayRecords, index, options));
  };

  timer = setTimeout(tick, 120);

  return {
    stop(signal) {
      stopped = true;
      if (timer) {
        clearTimeout(timer);
      }
      onEnd(null, signal === "SIGINT" ? "SIGINT" : "SIGTERM");
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
    progress: state.progress
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

function replayDelayMs(records, nextIndex, options) {
  if (options.replayIntervalMs) {
    return options.replayIntervalMs;
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
  const scaled = delta / options.replaySpeed;
  return Math.max(40, Math.min(Math.round(scaled), 350));
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
    progress: state.progress
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

  res.writeHead(404);
  res.end("not found");
}

function broadcast(state, eventName, payload) {
  const data = `event: ${eventName}\ndata: ${JSON.stringify(payload)}\n\n`;
  for (const client of state.clients) {
    client.write(data);
  }
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
    file.includes(".so")
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
        if (payload.url) {
          els.viewerUrl.textContent = payload.url;
        }
      });

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
        els.open.textContent = formatNumber(snapshot.counters.open_at);
        els.exec.textContent = formatNumber(snapshot.counters.execve);
        els.connect.textContent = formatNumber(snapshot.counters.connect);
        els.write.textContent = formatNumber(snapshot.counters.write);
        els.bytes.textContent = formatBytes(snapshot.counters.bytes);
        els.traceWaterfall.innerHTML = renderWaterfall(snapshot.recentEvents);
        els.traceMap.innerHTML = renderTraceMap(snapshot);
        if (!state.recentRain.length && snapshot.recentEvents?.length) {
          state.recentRain = snapshot.recentEvents.slice(0, 18);
          addRainFrame();
        }

        els.recentEvents.innerHTML = snapshot.recentEvents.map((event) => {
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
        const fileNodes = (snapshot.topFiles || []).slice(0, 3);
        const outputNodes = [];

        if ((snapshot.counters.connect || 0) > 0) {
          outputNodes.push({ label: "network", detail: formatNumber(snapshot.counters.connect) + " connect", color: "#72b6ff" });
        }
        if ((snapshot.counters.write || 0) > 0) {
          outputNodes.push({ label: "writes", detail: formatBytes(snapshot.counters.bytes || 0), color: "#ff5f7a" });
        }

        const otherProcesses = (snapshot.topProcesses || [])
          .filter((entry) => entry.comm !== primary)
          .slice(0, 2);
        for (const entry of otherProcesses) {
          outputNodes.push({ label: entry.comm, detail: formatNumber(entry.count) + " events", color: "#ffd84d" });
        }

        if (!fileNodes.length && !outputNodes.length) {
          return '<svg viewBox="0 0 860 320" role="img" aria-label="Empty session map">' +
            '<rect width="860" height="320" fill="rgba(0,0,0,0.18)"></rect>' +
            '<text x="430" y="164" text-anchor="middle" fill="rgba(165,255,180,0.68)" font-size="18" font-family="IBM Plex Mono, monospace">No trace relationships yet.</text>' +
          '</svg>';
        }

        const width = 860;
        const height = 320;
        const centerX = 430;
        const centerY = 160;
        const leftX = 150;
        const rightX = 710;

        const leftNodes = fileNodes.map((entry, index) => ({
          x: leftX,
          y: 88 + index * 78,
          title: shortPath(entry.file),
          detail: formatNumber(entry.count) + " open_at",
          color: "#7bffb9"
        }));

        const rightNodes = outputNodes.map((entry, index) => ({
          x: rightX,
          y: 88 + index * 78,
          title: entry.label,
          detail: entry.detail,
          color: entry.color
        }));

        const leftEdges = leftNodes.map((node) => {
          return '<path d="M ' + (node.x + 90) + ' ' + node.y + ' C 270 ' + node.y + ', 320 160, 358 160" fill="none" stroke="' + node.color + '" stroke-opacity="0.46" stroke-width="3"></path>';
        }).join("");

        const rightEdges = rightNodes.map((node) => {
          return '<path d="M 502 160 C 560 160, 590 ' + node.y + ', ' + (node.x - 90) + ' ' + node.y + '" fill="none" stroke="' + node.color + '" stroke-opacity="0.46" stroke-width="3"></path>';
        }).join("");

        const leftBoxes = leftNodes.map((node) => renderMapNode(node.x, node.y, node.title, node.detail, node.color, "end")).join("");
        const rightBoxes = rightNodes.map((node) => renderMapNode(node.x, node.y, node.title, node.detail, node.color, "start")).join("");

        return '<svg viewBox="0 0 ' + width + ' ' + height + '" role="img" aria-label="Session map">' +
          '<rect width="' + width + '" height="' + height + '" fill="rgba(0,0,0,0.14)"></rect>' +
          '<text x="30" y="30" fill="rgba(165,255,180,0.68)" font-size="12" font-family="IBM Plex Mono, monospace">inputs</text>' +
          '<text x="' + (width - 30) + '" y="30" text-anchor="end" fill="rgba(165,255,180,0.68)" font-size="12" font-family="IBM Plex Mono, monospace">outputs</text>' +
          leftEdges +
          rightEdges +
          leftBoxes +
          rightBoxes +
          '<g>' +
            '<rect x="360" y="118" width="140" height="84" rx="22" fill="rgba(60,255,20,0.09)" stroke="rgba(60,255,20,0.35)" stroke-width="2"></rect>' +
            '<text x="430" y="148" text-anchor="middle" fill="#dfffe1" font-size="18" font-weight="700" font-family="IBM Plex Sans, sans-serif">' + escapeHtml(primary) + '</text>' +
            '<text x="430" y="172" text-anchor="middle" fill="rgba(165,255,180,0.72)" font-size="12" font-family="IBM Plex Mono, monospace">' + formatNumber((snapshot.recentEvents || []).filter((event) => event.comm === primary).length) + ' recent events</text>' +
            '<text x="430" y="188" text-anchor="middle" fill="rgba(165,255,180,0.72)" font-size="12" font-family="IBM Plex Mono, monospace">' + formatNumber(snapshot.counters.open_at || 0) + ' opens / ' + formatNumber(snapshot.counters.write || 0) + ' writes</text>' +
          '</g>' +
        '</svg>';
      }

      function renderMapNode(x, y, title, detail, color, anchor) {
        const width = 180;
        const boxX = anchor === "end" ? x - width : x;
        const textX = anchor === "end" ? x - 18 : x + 18;
        const textAnchor = anchor === "end" ? "end" : "start";
        return '<g>' +
          '<rect x="' + boxX + '" y="' + (y - 28) + '" width="' + width + '" height="56" rx="18" fill="rgba(8,14,24,0.92)" stroke="' + color + '" stroke-opacity="0.34"></rect>' +
          '<text x="' + textX + '" y="' + (y - 4) + '" text-anchor="' + textAnchor + '" fill="#dfffe1" font-size="13" font-weight="700" font-family="IBM Plex Sans, sans-serif">' + escapeHtml(title) + '</text>' +
          '<text x="' + textX + '" y="' + (y + 14) + '" text-anchor="' + textAnchor + '" fill="rgba(165,255,180,0.72)" font-size="11" font-family="IBM Plex Mono, monospace">' + escapeHtml(detail) + '</text>' +
        '</g>';
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
          path.includes(".so")
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
