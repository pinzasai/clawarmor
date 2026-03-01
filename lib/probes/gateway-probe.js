// ClawArmor v0.6 — Live gateway behavioral probes
// Uses ONLY Node.js built-ins: net, http, os, crypto
// All probes timeout at 2000ms. Fails gracefully if gateway not running.

import net from 'net';
import http from 'http';
import os from 'os';

const TIMEOUT = 2000;

function tcpProbe(host, port) {
  return new Promise(resolve => {
    const sock = net.createConnection({ host, port });
    const timer = setTimeout(() => { sock.destroy(); resolve(false); }, TIMEOUT);
    sock.on('connect', () => { clearTimeout(timer); sock.destroy(); resolve(true); });
    sock.on('error', () => { clearTimeout(timer); resolve(false); });
  });
}

function httpGet(url) {
  return new Promise(resolve => {
    const timer = setTimeout(() => resolve(null), TIMEOUT);
    try {
      http.get(url, res => {
        clearTimeout(timer);
        let body = '';
        res.on('data', d => { body += d; if (body.length > 8192) res.destroy(); });
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
        res.on('error', () => resolve(null));
      }).on('error', () => { clearTimeout(timer); resolve(null); });
    } catch { clearTimeout(timer); resolve(null); }
  });
}

function httpOptions(url, origin) {
  return new Promise(resolve => {
    const parsed = new URL(url);
    const timer = setTimeout(() => resolve(null), TIMEOUT);
    const opts = {
      hostname: parsed.hostname, port: parsed.port, path: parsed.pathname || '/',
      method: 'OPTIONS',
      headers: { Origin: origin, 'Access-Control-Request-Method': 'GET' },
    };
    try {
      const req = http.request(opts, res => {
        clearTimeout(timer);
        resolve({ status: res.statusCode, headers: res.headers });
      });
      req.on('error', () => { clearTimeout(timer); resolve(null); });
      req.end();
    } catch { clearTimeout(timer); resolve(null); }
  });
}

// Minimal WebSocket handshake without auth token — check if server accepts it
function wsProbeNoAuth(host, port) {
  return new Promise(resolve => {
    const timer = setTimeout(() => { sock.destroy(); resolve('timeout'); }, TIMEOUT);
    const key = Buffer.from(Math.random().toString(36)).toString('base64');
    const sock = net.createConnection({ host, port });

    sock.on('error', () => { clearTimeout(timer); resolve('error'); });

    sock.on('connect', () => {
      const handshake = [
        `GET / HTTP/1.1`,
        `Host: ${host}:${port}`,
        `Upgrade: websocket`,
        `Connection: Upgrade`,
        `Sec-WebSocket-Key: ${key}`,
        `Sec-WebSocket-Version: 13`,
        `\r\n`,
      ].join('\r\n');
      sock.write(handshake);
    });

    let buf = '';
    sock.on('data', data => {
      buf += data.toString();
      clearTimeout(timer);
      sock.destroy();
      // 101 = upgrade accepted (WS open without auth)
      if (buf.includes('HTTP/1.1 101') || buf.includes('HTTP/1.0 101')) {
        resolve('accepted');
      } else if (buf.includes('401') || buf.includes('403') || buf.includes('400')) {
        resolve('rejected');
      } else {
        resolve('rejected');
      }
    });
  });
}

export async function probeGatewayLive(config, { host = '127.0.0.1', port: portOverride = null } = {}) {
  const port = portOverride || config?.gateway?.port || 18789;
  const results = [];

  // ── PROBE 1: Is gateway actually running? ─────────────────────────────────
  const running = await tcpProbe(host, port);
  results.push({
    id: 'probe.gateway_running',
    severity: 'INFO',
    passed: true,
    title: running ? `Gateway running on port ${port}` : `Gateway not running on port ${port}`,
    passedMsg: running ? `Gateway running on port ${port}` : `Gateway not running on port ${port}`,
    live: true,
    gatewayRunning: running,
  });

  if (!running) {
    // Skip remaining probes — gateway is not up
    return results;
  }

  // ── PROBE 2: Is gateway reachable on non-loopback interfaces? ────────────
  const ifaces = os.networkInterfaces();
  const nonLoopback = [];
  for (const [, addrs] of Object.entries(ifaces)) {
    for (const a of (addrs || [])) {
      if (!a.internal && a.family === 'IPv4') nonLoopback.push(a.address);
    }
  }

  const exposedOn = [];
  for (const ip of nonLoopback) {
    const reachable = await tcpProbe(ip, port);
    if (reachable) exposedOn.push(ip);
  }

  if (exposedOn.length > 0) {
    results.push({
      id: 'probe.network_exposed',
      severity: 'HIGH',
      passed: false,
      title: `Gateway reachable on network interface(s): ${exposedOn.join(', ')}`,
      description: `Live probe: gateway responds on non-loopback IP(s).\nEven if config says "loopback", the process is listening on 0.0.0.0.\nAnyone on your network can connect.\nExposed on: ${exposedOn.join(', ')}`,
      fix: `openclaw config set gateway.bind loopback\nopenctl gateway restart`,
      live: true,
    });
  } else {
    results.push({
      id: 'probe.network_exposed',
      severity: 'HIGH',
      passed: true,
      passedMsg: 'Not reachable on network interfaces (probed live)',
      live: true,
    });
  }

  // ── PROBE 3: Does gateway require auth? (WebSocket probe) ─────────────────
  const wsResult = await wsProbeNoAuth(host, port);
  if (wsResult === 'accepted') {
    results.push({
      id: 'probe.ws_auth',
      severity: 'CRITICAL',
      passed: false,
      title: 'Gateway WebSocket accepts connections without authentication',
      description: `Live probe: WebSocket upgrade accepted without an auth token.\nAny local process (malicious scripts, browser tabs) can connect and\nissue tool calls to your agent with no credentials.\nAttack: malicious web page uses ws://${host}:${port} to hijack agent.`,
      fix: `openclaw config set gateway.auth.mode token\nopenctl config set gateway.auth.token $(node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))")\nopenctl gateway restart`,
      live: true,
    });
  } else {
    results.push({
      id: 'probe.ws_auth',
      severity: 'CRITICAL',
      passed: true,
      passedMsg: wsResult === 'timeout'
        ? 'Authentication required (WebSocket probe timed out — auth likely blocking)'
        : 'Authentication required (WebSocket probe confirmed)',
      live: true,
    });
  }

  // ── PROBE 4: Does /health leak sensitive data? ────────────────────────────
  const healthRes = await httpGet(`http://${host}:${port}/health`);
  if (healthRes) {
    const LEAK_KEYS = ['botToken', 'password', 'apiKey', 'token', 'secret', 'credential', 'privateKey'];
    const leakedFields = [];
    try {
      const parsed = JSON.parse(healthRes.body);
      const flat = JSON.stringify(parsed);
      for (const k of LEAK_KEYS) {
        const re = new RegExp(`"${k}"\\s*:\\s*"[^"]{8,}"`, 'i');
        if (re.test(flat)) leakedFields.push(k);
      }
    } catch {
      // Raw text response — check for token-like values
      for (const k of LEAK_KEYS) {
        if (new RegExp(`${k}[\"':\\s]+[A-Za-z0-9+/]{16,}`, 'i').test(healthRes.body)) {
          leakedFields.push(k);
        }
      }
    }

    if (leakedFields.length > 0) {
      results.push({
        id: 'probe.health_leak',
        severity: 'MEDIUM',
        passed: false,
        title: `/health endpoint leaks sensitive fields: ${leakedFields.join(', ')}`,
        description: `Live probe: GET /health returned plaintext values for: ${leakedFields.join(', ')}.\nAny local process can read these credentials without authentication.`,
        fix: `File issue with OpenClaw to redact sensitive keys from /health.\nWorkaround: firewall /health with a local reverse proxy.`,
        live: true,
      });
    } else {
      results.push({
        id: 'probe.health_leak',
        severity: 'MEDIUM',
        passed: true,
        passedMsg: '/health endpoint does not leak sensitive data',
        live: true,
      });
    }
  } else {
    results.push({
      id: 'probe.health_leak',
      severity: 'MEDIUM',
      passed: true,
      passedMsg: '/health endpoint not reachable or not present',
      live: true,
    });
  }

  // ── PROBE 5: CORS headers ─────────────────────────────────────────────────
  const evilOrigin = 'https://evil.example.com';
  const corsRes = await httpOptions(`http://${host}:${port}/`, evilOrigin);
  if (corsRes) {
    const acao = (corsRes.headers['access-control-allow-origin'] || '').trim();
    const corsOpen = acao === '*' || acao === evilOrigin;
    if (corsOpen) {
      results.push({
        id: 'probe.cors',
        severity: 'HIGH',
        passed: false,
        title: `CORS misconfigured — allows arbitrary origins (${acao})`,
        description: `Live probe: OPTIONS with Origin: ${evilOrigin}\nreturned Access-Control-Allow-Origin: ${acao}.\nAny web page can make cross-origin requests to your gateway.\nAttack: malicious site reads agent responses via CORS.`,
        fix: `openclaw config set gateway.cors.allowedOrigins '["http://localhost"]'\nopenctl gateway restart`,
        live: true,
      });
    } else {
      results.push({
        id: 'probe.cors',
        severity: 'HIGH',
        passed: true,
        passedMsg: acao ? `CORS restricted (allowed: ${acao})` : 'CORS not open to arbitrary origins',
        live: true,
      });
    }
  } else {
    results.push({
      id: 'probe.cors',
      severity: 'HIGH',
      passed: true,
      passedMsg: 'CORS probe: no OPTIONS response (not exposed or not applicable)',
      live: true,
    });
  }

  return results;
}
