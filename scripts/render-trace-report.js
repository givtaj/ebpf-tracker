#!/usr/bin/env node

const fs = require("fs");
const path = require("path");

const IGNORED_COMMS = new Set([
  "cargo",
  "rustc",
  "cc",
  "ld",
  "clang",
  "as",
  "collect2",
  "exec-target-fro",
  "containerd"
]);

const KIND_ORDER = ["open_at", "execve", "connect", "write"];
const KIND_LABELS = {
  open_at: "open_at",
  execve: "execve",
  connect: "connect",
  write: "write"
};
const KIND_COLORS = {
  open_at: "#67d5b5",
  execve: "#ffd166",
  connect: "#7aa8ff",
  write: "#ff7b72"
};

function main() {
  const [inputPath, outputPath, requestedFocusComm] = process.argv.slice(2);
  if (!inputPath || !outputPath) {
    console.error(
      "usage: node scripts/render-trace-report.js <trace.jsonl> <report.html> [focus-comm]"
    );
    process.exit(1);
  }

  const trace = parseTrace(inputPath);
  const focusComm = inferFocusComm(trace.syscalls, requestedFocusComm);
  const html = renderReport(trace, inputPath, focusComm);

  fs.writeFileSync(outputPath, html);
  console.error(`wrote ${outputPath}`);
}

function parseTrace(inputPath) {
  const text = fs.readFileSync(inputPath, "utf8");
  const syscalls = [];
  const aggregates = [];

  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) {
      continue;
    }

    let record;
    try {
      record = JSON.parse(trimmed);
    } catch (error) {
      throw new Error(`failed to parse JSONL line: ${error.message}`);
    }

    if (record.type === "syscall") {
      syscalls.push(record);
    } else if (record.type === "aggregate") {
      aggregates.push(record);
    }
  }

  syscalls.sort((left, right) => {
    if (left.timestamp_unix_ms !== right.timestamp_unix_ms) {
      return left.timestamp_unix_ms - right.timestamp_unix_ms;
    }
    return String(left.kind).localeCompare(String(right.kind));
  });

  return { syscalls, aggregates };
}

function inferFocusComm(syscalls, requestedFocusComm) {
  if (requestedFocusComm) {
    return requestedFocusComm;
  }

  const scores = new Map();
  for (const event of syscalls) {
    const comm = event.comm || "unknown";
    const current = scores.get(comm) || 0;
    let score = current;
    switch (event.kind) {
      case "connect":
        score += 120;
        break;
      case "write":
        score += 12 + Math.min(Number(event.bytes || 0) / 64, 10);
        break;
      case "execve":
        score += 40;
        break;
      case "open_at":
        score += 2;
        break;
      default:
        score += 1;
        break;
    }
    if (IGNORED_COMMS.has(comm)) {
      score *= 0.15;
    }
    scores.set(comm, score);
  }

  return [...scores.entries()].sort((left, right) => right[1] - left[1])[0]?.[0] || "unknown";
}

function renderReport(trace, inputPath, focusComm) {
  const syscalls = trace.syscalls;
  const focusEvents = syscalls.filter((event) => event.comm === focusComm);
  const firstTimestamp = syscalls[0]?.timestamp_unix_ms || 0;
  const lastTimestamp = syscalls[syscalls.length - 1]?.timestamp_unix_ms || 0;
  const durationMs = Math.max(lastTimestamp - firstTimestamp, 0);
  const kindCounts = countBy(syscalls, (event) => event.kind || "unknown");
  const processCounts = countBy(syscalls, (event) => event.comm || "unknown");
  const aggregateMetrics = new Map(
    trace.aggregates.map((record) => [record.metric, Number(record.value || 0)])
  );
  const totalWriteBytes = syscalls
    .filter((event) => event.kind === "write")
    .reduce((sum, event) => sum + Number(event.bytes || 0), 0);
  const topProcesses = [...processCounts.entries()]
    .sort((left, right) => right[1] - left[1])
    .slice(0, 8);
  const topWrites = syscalls
    .filter((event) => event.kind === "write")
    .sort((left, right) => Number(right.bytes || 0) - Number(left.bytes || 0))
    .slice(0, 8);
  const interestingFiles = collectInterestingFiles(focusEvents, syscalls);
  const focusTimeline = (focusEvents.length ? focusEvents : syscalls).slice(-18);

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>eBPF Trace Report</title>
    <style>
      :root {
        --bg: #09111f;
        --panel: rgba(14, 24, 41, 0.86);
        --panel-border: rgba(148, 163, 184, 0.12);
        --text: #e7edf7;
        --muted: #9aa9c2;
        --accent: #7aa8ff;
        --open: ${KIND_COLORS.open_at};
        --exec: ${KIND_COLORS.execve};
        --connect: ${KIND_COLORS.connect};
        --write: ${KIND_COLORS.write};
        --glow: 0 24px 80px rgba(0, 0, 0, 0.45);
      }

      * {
        box-sizing: border-box;
      }

      body {
        margin: 0;
        color: var(--text);
        font-family: "IBM Plex Sans", "Avenir Next", "Segoe UI", sans-serif;
        background:
          radial-gradient(circle at 20% 0%, rgba(122,168,255,0.22), transparent 25%),
          radial-gradient(circle at 100% 20%, rgba(255,123,114,0.18), transparent 28%),
          linear-gradient(180deg, #0a1324 0%, #09111f 100%);
      }

      main {
        max-width: 1400px;
        margin: 0 auto;
        padding: 32px 18px 56px;
      }

      .hero {
        display: grid;
        gap: 18px;
        grid-template-columns: 1.2fr 0.8fr;
        margin-bottom: 18px;
      }

      .panel {
        background: var(--panel);
        border: 1px solid var(--panel-border);
        border-radius: 24px;
        box-shadow: var(--glow);
      }

      .hero-copy {
        padding: 28px;
      }

      .eyebrow {
        margin: 0 0 10px;
        color: #7aa8ff;
        text-transform: uppercase;
        letter-spacing: 0.18em;
        font: 700 0.76rem/1.2 "IBM Plex Mono", "SFMono-Regular", monospace;
      }

      h1 {
        margin: 0 0 10px;
        font-size: clamp(2.6rem, 5vw, 4.8rem);
        line-height: 0.92;
      }

      .lede {
        margin: 0;
        max-width: 44rem;
        color: var(--muted);
        font-size: 1.06rem;
      }

      .badge-row {
        display: flex;
        flex-wrap: wrap;
        gap: 10px;
        margin-top: 18px;
      }

      .badge {
        padding: 9px 12px;
        border-radius: 999px;
        background: rgba(255, 255, 255, 0.04);
        border: 1px solid rgba(148, 163, 184, 0.16);
        font: 700 0.76rem/1 "IBM Plex Mono", "SFMono-Regular", monospace;
      }

      .focus {
        padding: 24px;
        display: grid;
        gap: 14px;
        align-content: start;
      }

      .focus-card {
        padding: 16px 18px;
        border-radius: 18px;
        background: rgba(255, 255, 255, 0.04);
        border: 1px solid rgba(148, 163, 184, 0.12);
      }

      .focus-card span {
        display: block;
        color: var(--muted);
        font: 700 0.72rem/1.2 "IBM Plex Mono", "SFMono-Regular", monospace;
        text-transform: uppercase;
        letter-spacing: 0.12em;
      }

      .focus-card strong {
        display: block;
        margin-top: 8px;
        font-size: 1.25rem;
      }

      .metrics {
        display: grid;
        gap: 14px;
        grid-template-columns: repeat(4, minmax(0, 1fr));
        margin-bottom: 18px;
      }

      .metric {
        padding: 18px;
      }

      .metric .label {
        display: block;
        margin-bottom: 10px;
        color: var(--muted);
        text-transform: uppercase;
        letter-spacing: 0.14em;
        font: 700 0.72rem/1.2 "IBM Plex Mono", "SFMono-Regular", monospace;
      }

      .metric .value {
        display: block;
        font-size: 2rem;
        font-weight: 700;
      }

      .metric .hint {
        display: block;
        margin-top: 8px;
        color: var(--muted);
        font-size: 0.92rem;
      }

      .layout {
        display: grid;
        gap: 18px;
        grid-template-columns: 1.12fr 0.88fr;
      }

      .column {
        display: grid;
        gap: 18px;
        align-content: start;
      }

      .section {
        padding: 22px;
      }

      h2 {
        margin: 0 0 14px;
        font-size: 1.25rem;
      }

      .sparkline-wrap {
        overflow: hidden;
        border-radius: 18px;
        background: rgba(255,255,255,0.03);
        border: 1px solid rgba(148, 163, 184, 0.12);
        padding: 12px;
      }

      .legend {
        display: flex;
        flex-wrap: wrap;
        gap: 10px;
        margin-top: 12px;
      }

      .legend span {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        color: var(--muted);
        font: 700 0.76rem/1 "IBM Plex Mono", "SFMono-Regular", monospace;
      }

      .legend i {
        width: 10px;
        height: 10px;
        border-radius: 50%;
        display: inline-block;
      }

      .list {
        display: grid;
        gap: 10px;
      }

      .row {
        display: grid;
        gap: 12px;
        grid-template-columns: auto 1fr auto;
        align-items: center;
        padding: 12px 14px;
        border-radius: 16px;
        background: rgba(255,255,255,0.03);
        border: 1px solid rgba(148, 163, 184, 0.1);
      }

      .row strong {
        display: block;
      }

      .row small {
        color: var(--muted);
      }

      .pill {
        padding: 7px 10px;
        border-radius: 999px;
        font: 700 0.72rem/1 "IBM Plex Mono", "SFMono-Regular", monospace;
        text-transform: uppercase;
        letter-spacing: 0.08em;
      }

      .pill-open_at { background: rgba(103,213,181,0.14); color: var(--open); }
      .pill-execve { background: rgba(255,209,102,0.14); color: var(--exec); }
      .pill-connect { background: rgba(122,168,255,0.14); color: var(--connect); }
      .pill-write { background: rgba(255,123,114,0.14); color: var(--write); }

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
        gap: 12px;
        font: 700 0.82rem/1.2 "IBM Plex Mono", "SFMono-Regular", monospace;
      }

      .bar {
        height: 12px;
        border-radius: 999px;
        background: rgba(255,255,255,0.06);
        overflow: hidden;
      }

      .bar-fill {
        height: 100%;
        border-radius: 999px;
        background: linear-gradient(90deg, rgba(122,168,255,0.8), rgba(103,213,181,0.9));
      }

      pre {
        margin: 0;
        max-height: 320px;
        overflow: auto;
        padding: 16px;
        border-radius: 18px;
        background: rgba(5, 9, 18, 0.82);
        color: #dce8f4;
        border: 1px solid rgba(148, 163, 184, 0.12);
        font: 0.82rem/1.55 "IBM Plex Mono", "SFMono-Regular", monospace;
      }

      code {
        font-family: "IBM Plex Mono", "SFMono-Regular", monospace;
      }

      @media (max-width: 1100px) {
        .hero,
        .layout,
        .metrics {
          grid-template-columns: 1fr;
        }
      }
    </style>
  </head>
  <body>
    <main>
      <section class="hero">
        <div class="panel hero-copy">
          <p class="eyebrow">eBPF syscall trace report</p>
          <h1>See the trace, not the wrapper.</h1>
          <p class="lede">
            This view is rendered from real <code>--emit jsonl</code> output. It shows the dominant syscall
            mix, the inferred focus process, the recent event timeline, hot write calls, and the most
            interesting file opens from the workload itself.
          </p>
          <div class="badge-row">
            <span class="badge">trace file ${escapeHtml(path.basename(inputPath))}</span>
            <span class="badge">focus ${escapeHtml(focusComm)}</span>
            <span class="badge">${formatNumber(syscalls.length)} syscall events</span>
            <span class="badge">${formatMs(durationMs)} total span</span>
          </div>
        </div>
        <aside class="panel focus">
          <div class="focus-card">
            <span>Focus process</span>
            <strong>${escapeHtml(focusComm)}</strong>
          </div>
          <div class="focus-card">
            <span>Focus events</span>
            <strong>${formatNumber(focusEvents.length)}</strong>
          </div>
          <div class="focus-card">
            <span>Total write volume</span>
            <strong>${formatBytes(totalWriteBytes)}</strong>
          </div>
          <div class="focus-card">
            <span>Aggregates</span>
            <strong>openat ${formatNumber(aggregateMetrics.get("openat") || kindCounts.get("open_at") || 0)}</strong>
          </div>
        </aside>
      </section>

      <section class="metrics">
        ${renderMetric("open_at", aggregateMetrics.get("openat") || kindCounts.get("open_at") || 0, "files touched", "Mostly loader, config, and app input reads.")}
        ${renderMetric("write", aggregateMetrics.get("writes") || kindCounts.get("write") || 0, "write syscalls", `${formatBytes(totalWriteBytes)} total bytes emitted.`)}
        ${renderMetric("execve", kindCounts.get("execve") || 0, "process launches", "Child process boundaries show up clearly here.")}
        ${renderMetric("connect", aggregateMetrics.get("connects") || kindCounts.get("connect") || 0, "network connects", "A clean signal for localhost or external socket work.")}
      </section>

      <section class="layout">
        <div class="column">
          <section class="panel section">
            <h2>Focus Timeline</h2>
            <div class="sparkline-wrap">
              ${renderSparkline(focusEvents.length ? focusEvents : syscalls.slice(-64))}
            </div>
            <div class="legend">
              ${KIND_ORDER.map(
                (kind) =>
                  `<span><i style="background:${KIND_COLORS[kind]}"></i>${KIND_LABELS[kind]}</span>`
              ).join("")}
            </div>
          </section>

          <section class="panel section">
            <h2>Recent Focus Events</h2>
            <div class="list">
              ${focusTimeline.map((event) => renderEventRow(event, firstTimestamp)).join("")}
            </div>
          </section>

          <section class="panel section">
            <h2>Interesting Files</h2>
            <div class="list">
              ${interestingFiles.map(renderFileRow).join("") || `<div class="row"><strong>No non-system file opens stood out.</strong></div>`}
            </div>
          </section>
        </div>

        <div class="column">
          <section class="panel section">
            <h2>Process Mix</h2>
            <div class="bar-list">
              ${topProcesses.map(([comm, count]) => renderBarRow(comm, count, topProcesses[0][1])).join("")}
            </div>
          </section>

          <section class="panel section">
            <h2>Largest Writes</h2>
            <div class="list">
              ${topWrites.map(renderWriteRow).join("") || `<div class="row"><strong>No write events in this trace.</strong></div>`}
            </div>
          </section>

          <section class="panel section">
            <h2>Raw Aggregate Snapshot</h2>
            <pre>${escapeHtml(
              JSON.stringify(
                {
                  focus_comm: focusComm,
                  total_syscalls: syscalls.length,
                  duration_ms: durationMs,
                  kind_counts: Object.fromEntries(kindCounts),
                  aggregate_metrics: Object.fromEntries(aggregateMetrics),
                  top_processes: topProcesses
                },
                null,
                2
              )
            )}</pre>
          </section>
        </div>
      </section>
    </main>
  </body>
</html>`;
}

function renderMetric(kind, value, label, hint) {
  return `<article class="panel metric">
    <span class="label">${escapeHtml(KIND_LABELS[kind])}</span>
    <span class="value" style="color:${KIND_COLORS[kind]}">${formatNumber(value)}</span>
    <span class="hint">${escapeHtml(label)}. ${escapeHtml(hint)}</span>
  </article>`;
}

function renderSparkline(events) {
  if (!events.length) {
    return `<svg viewBox="0 0 860 260" width="100%" height="260" role="img" aria-label="Empty trace timeline">
      <rect width="860" height="260" rx="18" fill="rgba(255,255,255,0.02)"/>
      <text x="430" y="136" text-anchor="middle" fill="#9aa9c2" font-size="18" font-family="IBM Plex Mono, monospace">No events</text>
    </svg>`;
  }

  const width = 860;
  const height = 260;
  const minTime = events[0].timestamp_unix_ms;
  const maxTime = events[events.length - 1].timestamp_unix_ms;
  const span = Math.max(maxTime - minTime, 1);
  const rowY = { open_at: 44, execve: 102, connect: 160, write: 218 };

  const guides = KIND_ORDER.map(
    (kind) =>
      `<line x1="16" x2="${width - 16}" y1="${rowY[kind]}" y2="${rowY[kind]}" stroke="rgba(255,255,255,0.08)" stroke-width="1"/>`
  ).join("");

  const labels = KIND_ORDER.map(
    (kind) =>
      `<text x="18" y="${rowY[kind] - 12}" fill="#8ea0bc" font-size="12" font-family="IBM Plex Mono, monospace">${kind}</text>`
  ).join("");

  const dots = events
    .map((event, index) => {
      const x = 30 + ((event.timestamp_unix_ms - minTime) / span) * (width - 60);
      const y = rowY[event.kind] || 230;
      const radius = event.kind === "write" ? 5 : 4;
      const opacity = 0.45 + index / Math.max(events.length, 1) * 0.45;
      return `<circle cx="${x.toFixed(1)}" cy="${y}" r="${radius}" fill="${KIND_COLORS[event.kind] || "#ffffff"}" opacity="${opacity.toFixed(2)}"/>`;
    })
    .join("");

  return `<svg viewBox="0 0 ${width} ${height}" width="100%" height="260" role="img" aria-label="Trace timeline">
    <rect width="${width}" height="${height}" rx="18" fill="rgba(255,255,255,0.02)"/>
    ${guides}
    ${labels}
    ${dots}
  </svg>`;
}

function renderEventRow(event, baseTimestamp) {
  const detail = describeEvent(event);
  return `<div class="row">
    <span class="pill pill-${escapeHtml(event.kind)}">${escapeHtml(event.kind)}</span>
    <div>
      <strong>${escapeHtml(detail.title)}</strong>
      <small>${escapeHtml(detail.subtitle)}</small>
    </div>
    <small>+${formatMs(Math.max(event.timestamp_unix_ms - baseTimestamp, 0))}</small>
  </div>`;
}

function renderFileRow(fileEntry) {
  return `<div class="row">
    <span class="pill pill-open_at">file</span>
    <div>
      <strong>${escapeHtml(fileEntry.display)}</strong>
      <small>${escapeHtml(fileEntry.detail)}</small>
    </div>
    <small>${formatNumber(fileEntry.count)}x</small>
  </div>`;
}

function renderWriteRow(event) {
  return `<div class="row">
    <span class="pill pill-write">write</span>
    <div>
      <strong>${escapeHtml(event.comm || "unknown")} wrote ${formatBytes(Number(event.bytes || 0))}</strong>
      <small>pid ${escapeHtml(String(event.pid || "?"))} at ${new Date(event.timestamp_unix_ms).toISOString()}</small>
    </div>
    <small>${formatNumber(Number(event.bytes || 0))} B</small>
  </div>`;
}

function renderBarRow(label, value, maxValue) {
  const width = maxValue ? (value / maxValue) * 100 : 0;
  return `<div class="bar-row">
    <div class="bar-label">
      <span>${escapeHtml(label)}</span>
      <span>${formatNumber(value)}</span>
    </div>
    <div class="bar"><div class="bar-fill" style="width:${width.toFixed(2)}%"></div></div>
  </div>`;
}

function describeEvent(event) {
  switch (event.kind) {
    case "open_at":
      return {
        title: shortPath(event.file || "unknown file"),
        subtitle: `open_at by ${event.comm || "unknown"} pid ${event.pid || "?"}`
      };
    case "connect":
      return {
        title: `socket connect on fd ${event.fd ?? "?"}`,
        subtitle: `connect by ${event.comm || "unknown"} pid ${event.pid || "?"}`
      };
    case "execve":
      return {
        title: `${event.comm || "unknown"} crossed an exec boundary`,
        subtitle: `execve by pid ${event.pid || "?"}`
      };
    case "write":
      return {
        title: `wrote ${formatBytes(Number(event.bytes || 0))}`,
        subtitle: `write by ${event.comm || "unknown"} pid ${event.pid || "?"}`
      };
    default:
      return {
        title: event.kind || "unknown",
        subtitle: `${event.comm || "unknown"} pid ${event.pid || "?"}`
      };
  }
}

function collectInterestingFiles(focusEvents, syscalls) {
  const focusFiles = summarizeFiles(
    focusEvents.filter((event) => event.kind === "open_at").map((event) => event.file)
  );
  if (focusFiles.length) {
    return focusFiles.slice(0, 8);
  }

  return summarizeFiles(
    syscalls.filter((event) => event.kind === "open_at").map((event) => event.file)
  ).slice(0, 8);
}

function summarizeFiles(files) {
  const counts = new Map();
  for (const file of files) {
    if (!file || isSystemPath(file)) {
      continue;
    }
    counts.set(file, (counts.get(file) || 0) + 1);
  }

  return [...counts.entries()]
    .sort((left, right) => right[1] - left[1])
    .map(([file, count]) => ({
      display: shortPath(file),
      detail: file,
      count
    }));
}

function isSystemPath(file) {
  return (
    file.startsWith("/lib") ||
    file.startsWith("/usr") ||
    file.startsWith("/etc") ||
    file.startsWith("/proc") ||
    file.startsWith("/sys") ||
    file.startsWith("/dev") ||
    file.includes(".so") ||
    file.endsWith(".cache")
  );
}

function shortPath(file) {
  if (!file) {
    return "unknown";
  }
  if (file.length <= 58) {
    return file;
  }
  return `${file.slice(0, 22)}...${file.slice(-32)}`;
}

function countBy(values, keyFn) {
  const counts = new Map();
  for (const value of values) {
    const key = keyFn(value);
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  return counts;
}

function formatNumber(value) {
  return new Intl.NumberFormat("en-US").format(Number(value || 0));
}

function formatBytes(value) {
  const bytes = Number(value || 0);
  if (bytes < 1024) {
    return `${formatNumber(bytes)} B`;
  }
  if (bytes < 1024 * 1024) {
    return `${(bytes / 1024).toFixed(1)} KB`;
  }
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function formatMs(value) {
  const ms = Number(value || 0);
  if (ms < 1000) {
    return `${Math.round(ms)} ms`;
  }
  return `${(ms / 1000).toFixed(2)} s`;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

main();
