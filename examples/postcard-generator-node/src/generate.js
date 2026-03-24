const fs = require("fs");
const net = require("net");
const { spawnSync } = require("child_process");

async function main() {
  const title = readTrimmed("input/title.txt");
  const message = readTrimmed("input/message.txt");
  const palette = readPalette("input/palette.txt");
  const template = fs.readFileSync("templates/postcard.html.tpl", "utf8");
  const generatedAt = runDateStamp();
  const serverReply = await requestStampApproval(title, message);

  fs.mkdirSync("dist", { recursive: true });

  const svg = renderSvg(title, message, palette, serverReply, generatedAt);
  fs.writeFileSync("dist/postcard.svg", svg);

  const summaryJson = renderSummaryJson(title, message, generatedAt, serverReply);
  fs.writeFileSync("dist/summary.json", summaryJson);

  const html = renderHtml(
    template,
    title,
    message,
    generatedAt,
    serverReply,
    summaryJson,
    palette
  );
  fs.writeFileSync("dist/postcard.html", html);

  console.log("generated dist/postcard.html");
  console.log("generated dist/postcard.svg");
  console.log("generated dist/summary.json");
}

function readTrimmed(path) {
  return fs.readFileSync(path, "utf8").trim();
}

function readPalette(path) {
  const palette = {};
  for (const line of fs.readFileSync(path, "utf8").split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) {
      continue;
    }
    const [key, value] = trimmed.split("=");
    palette[key.trim()] = value.trim();
  }
  return palette;
}

function runDateStamp() {
  const result = spawnSync("date", ["-u", "+%Y-%m-%dT%H:%M:%SZ"], { encoding: "utf8" });
  if (result.status !== 0) {
    throw new Error(`date failed: ${result.stderr}`);
  }
  return result.stdout.trim();
}

async function requestStampApproval(title, message) {
  return await new Promise((resolve, reject) => {
    const server = net.createServer((socket) => {
      socket.once("data", (chunk) => {
        const payload = chunk.toString("utf8").trim();
        socket.end(`Stamp office approved ${title} after reading ${payload}`);
      });
    });

    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const client = net.createConnection(address.port, "127.0.0.1");
      let response = "";
      client.on("connect", () => {
        client.write(`${message.length} chars`);
      });
      client.on("data", (chunk) => {
        response += chunk.toString("utf8");
      });
      client.on("end", () => {
        server.close(() => resolve(response.trim()));
      });
      client.on("error", reject);
    });
  });
}

function renderSvg(title, message, palette, serverReply, generatedAt) {
  const shortReply = truncate(serverReply, 48);
  const lines = wrapMessage(truncate(message, 96), 30);
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 960 600" role="img" aria-labelledby="title desc">
  <title id="title">${xmlEscape(title)}</title>
  <desc id="desc">${xmlEscape(message)}</desc>
  <defs>
    <linearGradient id="sky" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="${palette.paper}" />
      <stop offset="100%" stop-color="#ffffff" />
    </linearGradient>
    <filter id="paper-shadow" x="-20%" y="-20%" width="140%" height="140%">
      <feDropShadow dx="0" dy="18" stdDeviation="20" flood-color="${palette.shadow}" flood-opacity="0.35"/>
    </filter>
  </defs>
  <rect width="960" height="600" fill="url(#sky)"/>
  <rect x="70" y="70" width="820" height="460" rx="28" fill="${palette.paper}" filter="url(#paper-shadow)"/>
  <rect x="92" y="92" width="776" height="416" rx="22" fill="none" stroke="${palette.accent}" stroke-width="4" stroke-dasharray="18 10"/>
  <line x1="610" y1="120" x2="610" y2="480" stroke="${palette.shadow}" stroke-width="2" stroke-dasharray="10 12"/>
  <circle cx="736" cy="180" r="68" fill="none" stroke="${palette.stamp}" stroke-width="10"/>
  <circle cx="736" cy="180" r="46" fill="none" stroke="${palette.accent}" stroke-width="3" stroke-dasharray="4 9"/>
  <text x="150" y="170" fill="${palette.ink}" font-family="Georgia, serif" font-size="52" font-weight="700">${xmlEscape(title)}</text>
  <text x="150" y="220" fill="${palette.ink}" font-family="Georgia, serif" font-size="24">${xmlEscape(shortReply)}</text>
  <text x="150" y="286" fill="${palette.ink}" font-family="Georgia, serif" font-size="28">${xmlEscape(lines[0] || "")}</text>
  <text x="150" y="330" fill="${palette.ink}" font-family="Georgia, serif" font-size="28">${xmlEscape(lines[1] || "")}</text>
  <text x="150" y="374" fill="${palette.ink}" font-family="Georgia, serif" font-size="28">${xmlEscape(lines[2] || "")}</text>
  <text x="150" y="462" fill="${palette.accent}" font-family="'Courier New', monospace" font-size="18">Stamped ${xmlEscape(generatedAt)}</text>
  <text x="662" y="172" fill="${palette.stamp}" font-family="'Courier New', monospace" font-size="22" letter-spacing="4">APPROVED</text>
  <text x="660" y="205" fill="${palette.ink}" font-family="'Courier New', monospace" font-size="14">LOCAL STAMP</text>
  <text x="650" y="296" fill="${palette.accent}" font-family="'Courier New', monospace" font-size="22">TO:</text>
  <text x="650" y="334" fill="${palette.ink}" font-family="Georgia, serif" font-size="28">Visual Debugger</text>
  <text x="650" y="372" fill="${palette.ink}" font-family="Georgia, serif" font-size="22">127 Trace Street</text>
  <text x="650" y="406" fill="${palette.ink}" font-family="Georgia, serif" font-size="22">Docker City, LN</text>
</svg>
`;
}

function renderHtml(template, title, message, generatedAt, serverReply, summaryJson, palette) {
  return template
    .replaceAll("{{title}}", htmlEscape(title))
    .replaceAll("{{message}}", htmlEscape(message))
    .replaceAll("{{generated_at}}", htmlEscape(generatedAt))
    .replaceAll("{{server_reply}}", htmlEscape(serverReply))
    .replaceAll("{{summary_json}}", htmlEscape(summaryJson))
    .replaceAll("{{paper}}", palette.paper)
    .replaceAll("{{ink}}", palette.ink)
    .replaceAll("{{accent}}", palette.accent)
    .replaceAll("{{stamp}}", palette.stamp)
    .replaceAll("{{shadow}}", palette.shadow);
}

function renderSummaryJson(title, message, generatedAt, serverReply) {
  return JSON.stringify(
    {
      title,
      message,
      generated_at: generatedAt,
      server_reply: serverReply
    },
    null,
    2
  ) + "\n";
}

function truncate(value, maxChars) {
  if ([...value].length <= maxChars) {
    return value;
  }
  return [...value].slice(0, maxChars).join("") + "...";
}

function wrapMessage(message, width) {
  const words = message.split(/\s+/);
  const lines = [];
  let current = "";
  for (const word of words) {
    const candidate = current ? `${current} ${word}` : word;
    if (candidate.length > width && current) {
      lines.push(current);
      current = word;
    } else {
      current = candidate;
    }
  }
  if (current) {
    lines.push(current);
  }
  return lines;
}

function htmlEscape(value) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function xmlEscape(value) {
  return htmlEscape(value).replaceAll("'", "&apos;");
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
