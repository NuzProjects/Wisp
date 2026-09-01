import http from "node:http";
import net from "node:net";
import dns from "node:dns/promises";
import process from "node:process";
import fs from "node:fs";
import path from "node:path";
import { server as wispServer } from "@mercuryworkshop/wisp-js/server";

const rawStdoutWrite = process.stdout.write.bind(process.stdout);
const rawStderrWrite = process.stderr.write.bind(process.stderr);

function filterLogs(chunk, enc, cb) {
  const s = typeof chunk === "string" ? chunk : chunk.toString(enc || "utf8");
  if (s.includes("-") && s.includes("[") && s.includes("]")) {
    if (cb) cb();
    return true;
  }
  return rawStdoutWrite(chunk, enc, cb);
}
process.stdout.write = filterLogs;
process.stderr.write = (chunk, enc, cb) =>
  filterLogs(chunk, enc, cb) || rawStderrWrite(chunk, enc, cb);

const PORT = Number(process.env.PORT) || 3000;
const HOST = "0.0.0.0";
const DATA_FILE = path.resolve("./clients.json");
const TMP_FILE = path.resolve("./clients.json.tmp");
const knownIps = new Map();

try {
  if (fs.existsSync(DATA_FILE)) {
    const p = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
    const e = p && p.clients ? p.clients : p;
    if (e)
      for (const [ip, c] of Object.entries(e))
        if (ip !== "totalUniqueIps") knownIps.set(ip, c || 1);
  }
} catch {}

let saveTimeout = null;
function scheduleSave() {
  if (saveTimeout) return;
  saveTimeout = setTimeout(() => {
    saveTimeout = null;
    try {
      fs.writeFile(
        TMP_FILE,
        JSON.stringify({
          totalUniqueIps: knownIps.size,
          clients: Object.fromEntries(knownIps),
        }),
        "utf8",
        (err) => {
          if (!err) fs.rename(TMP_FILE, DATA_FILE, () => {});
        }
      );
    } catch {}
  }, 5000);
}

const c = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  cyan: "\x1b[36m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  magenta: "\x1b[35m",
  red: "\x1b[31m",
};
const getTimestamp = () => `${c.dim}[${new Date().toLocaleTimeString()}]${c.reset}`;

function getClientIp(req) {
  const h = req.headers;
  return (
    h["cf-connecting-ip"] ||
    h["x-real-ip"] ||
    (h["x-forwarded-for"] ? h["x-forwarded-for"].split(",")[0].trim() : null) ||
    req.socket.remoteAddress ||
    "Unknown IP"
  );
}

function parseWispFrames(buffer) {
  const events = [];
  let i = 0;
  while (i + 6 <= buffer.length) {
    const opcode = buffer[i] & 0x0f;
    if (opcode !== 0x02 && opcode !== 0x00 && opcode !== 0x01) {
      i++;
      continue;
    }
    const b1 = buffer[i + 1];
    const isMasked = (b1 & 0x80) !== 0;
    let payloadLen = b1 & 0x7f,
      headerLen = 2;
    if (payloadLen === 126) {
      if (i + 4 > buffer.length) break;
      payloadLen = buffer.readUInt16BE(i + 2);
      headerLen = 4;
    } else if (payloadLen === 127) {
      if (i + 10 > buffer.length) break;
      payloadLen = Number(buffer.readBigUInt64BE(i + 2));
      headerLen = 10;
    }
    const maskOffset = i + headerLen,
      dataOffset = maskOffset + (isMasked ? 4 : 0);
    if (dataOffset > buffer.length) break;
    const avail = Math.min(payloadLen, buffer.length - dataOffset);
    const payload = Buffer.allocUnsafe(avail);
    if (isMasked) {
      const mask = buffer.subarray(maskOffset, maskOffset + 4);
      for (let j = 0; j < avail; j++)
        payload[j] = buffer[dataOffset + j] ^ mask[j % 4];
    } else {
      buffer.copy(payload, 0, dataOffset, dataOffset + avail);
    }
    if (payload.length >= 8 && payload[0] === 0x01) {
      const streamId = payload.readUInt32LE(1),
        port = payload.readUInt16LE(6),
        rawHost = payload.subarray(8).toString("utf8");
      const m = rawHost.match(/^([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
      if (m && m[1]) events.push({ type: "connect", streamId, hostname: m[1], port });
    } else if (payload.length >= 5 && payload[0] === 0x04) {
      events.push({ type: "close", streamId: payload.readUInt32LE(1) });
    }
    i = dataOffset + payloadLen;
  }
  return events;
}

function handleUserConnection(req, socket) {
  const ip = getClientIp(req);
  const rawOrig = req.headers["origin"] || req.headers["referer"] || "Direct";
  let orig = rawOrig;
  try {
    if (rawOrig !== "Direct")
      orig = new URL(rawOrig.startsWith("http") ? rawOrig : `https://${rawOrig}`).origin;
  } catch {}

  const isRet = knownIps.has(ip);
  knownIps.set(ip, (knownIps.get(ip) || 0) + 1);
  scheduleSave();

  const color = isRet ? c.cyan : c.green;
  rawStdoutWrite(
    `\n${color}────────────────────────────────────────────────────────────${c.reset}\n` +
      `${getTimestamp()} ${
        isRet
          ? `${c.bold}${c.cyan}[RETURNING CLIENT]`
          : `${c.bold}${c.green}[NEW CLIENT]`
      } ${c.yellow}${ip}${c.reset} ${c.dim}(Origin: ${c.magenta}${orig}${c.reset}${c.dim})${c.reset}\n` +
      `${color}────────────────────────────────────────────────────────────${c.reset}\n`
  );

  const activeStreams = new Set();
  socket.on("data", (chunk) => {
    try {
      const events = parseWispFrames(chunk);
      for (const event of events) {
        if (event.type === "connect" && !activeStreams.has(event.streamId)) {
          activeStreams.add(event.streamId);
          const fullUrl = `${event.port === 80 ? "http" : "https"}://${
            event.hostname
          }${event.port !== 443 && event.port !== 80 ? `:${event.port}` : ""}`;
          rawStdoutWrite(
            `${getTimestamp()} ${c.cyan}[STREAM]${c.reset} ${c.yellow}${ip}${
              c.reset
            } ${c.dim}→${c.reset} ${c.magenta}${fullUrl}${c.reset}\n`
          );
        } else if (event.type === "close") {
          activeStreams.delete(event.streamId);
        }
      }
    } catch {}
  });

  socket.on("error", (e) =>
    rawStdoutWrite(
      `${getTimestamp()} ${c.bold}${c.red}[SOCKET ERROR]${c.reset} ${c.yellow}${
        e.message
      }${c.reset}\n`
    )
  );
  socket.on("close", () => {
    activeStreams.clear();
    rawStdoutWrite(
      `\n${c.yellow}────────────────────────────────────────────────────────────${c.reset}\n` +
        `${getTimestamp()} ${c.bold}${c.yellow}[DISCONNECT]${c.reset} ${c.yellow}${ip}${c.reset} ${c.dim}closed connection${c.reset}\n` +
        `${c.yellow}────────────────────────────────────────────────────────────${c.reset}\n`
    );
  });
}

function readCgroupValue(filePath) {
  try {
    if (fs.existsSync(filePath)) {
      const val = fs.readFileSync(filePath, "utf8").trim();
      if (val !== "max" && !isNaN(val)) return Number(val);
    }
  } catch {}
  return null;
}

function getContainerMemLimit() {
  const v2 = readCgroupValue("/sys/fs/cgroup/memory.max");
  if (v2 !== null && v2 > 0) return v2;
  const v1 = readCgroupValue("/sys/fs/cgroup/memory/memory.limit_in_bytes");
  if (v1 !== null && v1 > 0 && v1 < 9223372036854771712) return v1;
  return null;
}

function getContainerMemUsage() {
  const v2 = readCgroupValue("/sys/fs/cgroup/memory.current");
  if (v2 !== null && v2 > 0) return v2;
  const v1 = readCgroupValue("/sys/fs/cgroup/memory/memory.usage_in_bytes");
  if (v1 !== null && v1 > 0) return v1;
  return null;
}

function getContainerCpuUsageMicros() {
  try {
    if (fs.existsSync("/sys/fs/cgroup/cpu.stat")) {
      const stat = fs.readFileSync("/sys/fs/cgroup/cpu.stat", "utf8");
      const match = stat.match(/usage_usec\s+(\d+)/);
      if (match) return Number(match[1]);
    }
    const v1 = readCgroupValue("/sys/fs/cgroup/cpu/cpuacct.usage");
    if (v1 !== null) return Math.round(v1 / 1000);
  } catch {}
  return null;
}

function getContainerCpuQuotaCores() {
  try {
    if (fs.existsSync("/sys/fs/cgroup/cpu.max")) {
      const [quota, period] = fs.readFileSync("/sys/fs/cgroup/cpu.max", "utf8").trim().split(" ");
      if (quota !== "max" && !isNaN(quota) && !isNaN(period) && Number(period) > 0) {
        return Number(quota) / Number(period);
      }
    }
    const quotaV1 = readCgroupValue("/sys/fs/cgroup/cpu/cpu.cfs_quota_us");
    const periodV1 = readCgroupValue("/sys/fs/cgroup/cpu/cpu.cfs_period_us");
    if (quotaV1 !== null && periodV1 !== null && quotaV1 > 0 && periodV1 > 0) {
      return quotaV1 / periodV1;
    }
  } catch {}
  return null;
}

let lastCpuCheckTime = process.hrtime.bigint();
let lastProcessCpu = process.cpuUsage();
let lastCgroupCpuUsec = getContainerCpuUsageMicros();

function getMetrics() {
  const now = process.hrtime.bigint();
  const elapsedMicros = Number(now - lastCpuCheckTime) / 1000;
  lastCpuCheckTime = now;

  let cpuPercent = 0;
  const currentCgroupCpuUsec = getContainerCpuUsageMicros();

  if (currentCgroupCpuUsec !== null && lastCgroupCpuUsec !== null && elapsedMicros > 0) {
    const deltaUsec = currentCgroupCpuUsec - lastCgroupCpuUsec;
    lastCgroupCpuUsec = currentCgroupCpuUsec;
    const cores = getContainerCpuQuotaCores() || 1;
    cpuPercent = Math.max(0, Math.min(100, Math.round((deltaUsec / (elapsedMicros * cores)) * 100)));
  } else if (elapsedMicros > 0) {
    const currentProcessCpu = process.cpuUsage();
    const userDiff = currentProcessCpu.user - lastProcessCpu.user;
    const systemDiff = currentProcessCpu.system - lastProcessCpu.system;
    lastProcessCpu = currentProcessCpu;
    cpuPercent = Math.max(0, Math.min(100, Math.round(((userDiff + systemDiff) / elapsedMicros) * 100)));
  }

  const containerMemUsage = getContainerMemUsage();
  const containerMemLimit = getContainerMemLimit();
  let usedBytes = 0;
  let totalBytes = 0;

  if (containerMemLimit !== null) {
    usedBytes = containerMemUsage !== null ? containerMemUsage : process.memoryUsage().rss;
    totalBytes = containerMemLimit;
  } else {
    usedBytes = process.memoryUsage().rss;
    totalBytes = 1073741824;
  }

  const memPercent = totalBytes > 0 ? Math.max(0, Math.min(100, Math.round((usedBytes / totalBytes) * 100))) : 0;
  const usedMB = Math.round(usedBytes / (1024 * 1024));
  const totalMB = Math.round(totalBytes / (1024 * 1024));

  return {
    cpu: cpuPercent,
    mem: memPercent,
    usedMem: usedMB >= 1024 ? (usedMB / 1024).toFixed(1) + " GB" : usedMB + " MB",
    totalMem: totalMB >= 1024 ? (totalMB / 1024).toFixed(1) + " GB" : totalMB + " MB",
  };
}

const server = http.createServer((req, res) => {
  if (req.url === "/api/metrics") {
    res.writeHead(200, {
      "Content-Type": "application/json",
      "Cache-Control": "no-cache, no-store, must-revalidate",
    });
    res.end(JSON.stringify(getMetrics()));
    return;
  }

  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
  res.end(`<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Wisp Server</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@500;600&family=Manrope:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
      :root {
        --bg-page: #090d16;
        --card-bg: #111726;
        --card-surface: #172033;
        --text-primary: #f8fafc;
        --text-secondary: #94a3b8;
        --text-muted: #64748b;
        --green: #10b981;
        --code-bg: #0b1120;
      }
      * {
        box-sizing: border-box;
      }
      body {
        font-family: 'Manrope', -apple-system, BlinkMacSystemFont, sans-serif;
        background-color: var(--bg-page);
        color: var(--text-primary);
        display: flex;
        align-items: center;
        justify-content: center;
        min-height: 100vh;
        margin: 0;
        padding: 1.5rem;
        -webkit-font-smoothing: antialiased;
      }
      .card {
        background: var(--card-bg);
        box-shadow: 0 20px 40px -15px rgba(0, 0, 0, 0.6);
        border-radius: 28px;
        max-width: 400px;
        width: 100%;
        padding: 2.25rem;
      }
      .header {
        text-align: center;
        margin-bottom: 1.5rem;
      }
      h1 {
        font-size: 1.45rem;
        font-weight: 800;
        letter-spacing: -0.025em;
        margin: 0;
        color: var(--text-primary);
      }
      .status-box, .metric-box {
        background: var(--card-surface);
        border-radius: 18px;
        padding: 1rem 1.25rem;
        display: flex;
        align-items: center;
        justify-content: space-between;
        margin-bottom: 0.75rem;
      }
      .status-label, .metric-label {
        font-size: 0.75rem;
        font-weight: 600;
        color: var(--text-muted);
        text-transform: uppercase;
        letter-spacing: 0.05em;
      }
      .status-value {
        font-size: 0.95rem;
        font-weight: 700;
        color: var(--green);
        display: flex;
        align-items: center;
        gap: 6px;
      }
      .status-dot {
        width: 8px;
        height: 8px;
        background-color: var(--green);
        border-radius: 50%;
      }
      .metric-value {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.85rem;
        font-weight: 600;
        color: var(--text-primary);
        display: flex;
        align-items: center;
        gap: 8px;
      }
      .metric-badge {
        background: var(--code-bg);
        color: var(--text-secondary);
        padding: 0.25rem 0.6rem;
        border-radius: 9999px;
      }
      .route-card {
        background: var(--card-surface);
        border-radius: 18px;
        padding: 1rem 1.25rem;
        display: flex;
        align-items: center;
        justify-content: space-between;
      }
      .route-label {
        font-size: 0.85rem;
        font-weight: 600;
        color: var(--text-secondary);
      }
      .copy-btn {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.8rem;
        font-weight: 600;
        background: var(--code-bg);
        color: var(--text-secondary);
        padding: 0.35rem 0.75rem;
        border-radius: 9999px;
        border: none;
        cursor: pointer;
        transition: all 0.2s ease;
      }
      .copy-btn:hover {
        color: var(--text-primary);
      }
      .copy-btn.copied {
        color: var(--green);
        background: rgba(16, 185, 129, 0.1);
      }
    </style>
  </head>
  <body>
    <div class="card">
      <div class="header">
        <h1>Wisp Server</h1>
      </div>
      <div class="status-box">
        <span class="status-label">Status</span>
        <div class="status-value">
          <span class="status-dot"></span>
          Online
        </div>
      </div>
      <div class="metric-box">
        <span class="metric-label">CPU Usage</span>
        <div class="metric-value">
          <span id="cpuUsage" class="metric-badge">--%</span>
        </div>
      </div>
      <div class="metric-box">
        <span class="metric-label">Memory Usage</span>
        <div class="metric-value">
          <span id="memUsage" class="metric-badge">--%</span>
        </div>
      </div>
      <div class="route-card">
        <span class="route-label">Endpoint Route</span>
        <button id="copyBtn" class="copy-btn" onclick="copyWss()">Copy</button>
      </div>
    </div>
    <script>
      function copyWss() {
        const wssUrl = (location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/wisp/';
        navigator.clipboard.writeText(wssUrl).then(() => {
          const btn = document.getElementById('copyBtn');
          btn.textContent = 'Copied!';
          btn.classList.add('copied');
          setTimeout(() => {
            btn.textContent = 'Copy';
            btn.classList.remove('copied');
          }, 2000);
        });
      }

      async function updateMetrics() {
        try {
          const res = await fetch('/api/metrics');
          if (res.ok) {
            const data = await res.json();
            document.getElementById('cpuUsage').textContent = data.cpu + '%';
            document.getElementById('memUsage').textContent = data.mem + '% (' + data.usedMem + ' / ' + data.totalMem + ')';
          }
        } catch {}
      }

      updateMetrics();
      setInterval(updateMetrics, 1500);
    </script>
  </body>
</html>`);
});

server.on("upgrade", (req, socket, head) => {
  if ((req.url || "").startsWith("/wisp")) {
    handleUserConnection(req, socket);
    wispServer.routeRequest(req, socket, head);
  } else {
    socket.destroy();
  }
});

async function runDiagnostics() {
  try {
    await dns.lookup("duckduckgo.com");
    rawStdoutWrite(
      `${getTimestamp()} ${c.green}[DNS]${c.reset} ${c.dim}Outbound domain resolution operational${c.reset}\n`
    );
  } catch (e) {
    rawStdoutWrite(`${getTimestamp()} ${c.red}[DNS FAIL] ${e.message}${c.reset}\n`);
  }
  await new Promise((res) => {
    const s = net.createConnection(
      { host: "1.1.1.1", port: 443, timeout: 4000 },
      () => {
        rawStdoutWrite(
          `${getTimestamp()} ${c.green}[TCP]${c.reset} ${c.dim}Outbound TCP connection open${c.reset}\n`
        );
        s.destroy();
        res();
      }
    );
    s.on("error", (e) => {
      rawStdoutWrite(`${getTimestamp()} ${c.red}[TCP FAIL] ${e.message}${c.reset}\n`);
      res();
    });
    s.on("timeout", () => {
      rawStdoutWrite(
        `${getTimestamp()} ${c.red}[TCP TIMEOUT] Outbound connection blocked${c.reset}\n`
      );
      s.destroy();
      res();
    });
  });
  if (typeof wispServer.routeRequest === "function")
    rawStdoutWrite(
      `${getTimestamp()} ${c.green}[WISP]${c.reset} ${c.dim}Wisp protocol engine initialized cleanly${c.reset}\n\n`
    );
}

server.listen(PORT, HOST, async () => {
  rawStdoutWrite(
    `\n${c.green}────────────────────────────────────────────────────────────${c.reset}\n` +
      `${c.bold}${c.cyan}[WISP]${c.reset} ${c.green}Server listening on ${HOST}:${PORT}${c.reset}\n` +
      `${c.green}────────────────────────────────────────────────────────────${c.reset}\n\n`
  );
  await runDiagnostics();
});
