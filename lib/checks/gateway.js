import { get } from '../config.js';
import { execSync } from 'child_process';

const WEAK_TOKEN_PATTERNS = [
  /^change.?me$/i, /^your.?token/i, /^example/i, /^test/i,
  /^demo/i, /^default/i, /^openclaw$/i, /^secret$/i,
  /^password$/i, /^12345/, /^token$/i,
];

function isWeakToken(t) {
  if (!t || typeof t !== 'string') return true;
  if (t.length < 16) return true;
  if (/^(.)\1+$/.test(t)) return true;
  if (WEAK_TOKEN_PATTERNS.some(p => p.test(t))) return true;
  if (t.length < 20 && /^[a-z]+$/.test(t)) return true;
  return false;
}

export function checkGatewayBind(config) {
  const bind = get(config, 'gateway.bind', '');
  const mode = get(config, 'gateway.mode', '');
  const authMode = get(config, 'gateway.auth.mode', '');
  const isLoopback = !bind || bind === 'loopback' || bind === 'localhost' || bind === '127.0.0.1' || mode === 'local';
  const isExposed = !isLoopback;
  const hasAuth = authMode && authMode !== 'none';

  if (isExposed && !hasAuth) {
    return { id: 'gateway.bind_no_auth', severity: 'CRITICAL', passed: false,
      title: 'Gateway exposed to network with NO authentication',
      description: `gateway.bind="${bind}", auth.mode="${authMode||'none'}" — anyone on your network\nor the internet can connect, read conversations, and run tool calls.\nAttack scenario: attacker sends exec("cat ~/.openclaw/agent-accounts.json")\nto your open gateway and gets all your API keys in seconds.`,
      fix: `openclaw config set gateway.auth.mode token\nopenctl config set gateway.auth.token $(node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))")\nopenctl config set gateway.bind loopback\nopenctl gateway restart` };
  }
  if (isExposed) {
    return { id: 'gateway.bind', severity: 'HIGH', passed: false,
      title: 'Gateway exposed to network',
      description: `gateway.bind="${bind}" — reachable from your network. Auth is set but\ntoken brute-force and protocol exploits are possible over the network.\nAttack scenario: attacker on same LAN brute-forces your short token.`,
      fix: `openclaw config set gateway.bind loopback\nopenctl gateway restart\nUse Tailscale Serve for secure remote access instead.` };
  }
  return { id: 'gateway.bind', severity: 'CRITICAL', passed: true, passedMsg: 'Gateway bound to loopback only' };
}

export function checkTailscaleFunnel(config) {
  const tsMode = get(config, 'gateway.tailscale.mode', 'off');
  const authMode = get(config, 'gateway.auth.mode', '');
  if (tsMode === 'funnel' && !['password','token'].includes(authMode)) {
    return { id: 'tailscale.funnel', severity: 'CRITICAL', passed: false,
      title: 'Tailscale Funnel without authentication',
      description: `Funnel is active — gateway is on the public internet. auth.mode="${authMode||'none'}"\nmeans anyone with your Tailscale URL can access your agent.\nAttack: your Funnel URL is <machine>.ts.net — trivially discoverable.`,
      fix: `openclaw config set gateway.auth.mode password` };
  }
  return { id: 'tailscale.funnel', severity: 'CRITICAL', passed: true,
    passedMsg: tsMode === 'funnel' ? 'Funnel active with auth' : 'Tailscale Funnel not enabled' };
}

export function checkAuthToken(config) {
  const authMode = get(config, 'gateway.auth.mode', '');
  if (authMode !== 'token') return { id: 'gateway.auth.token', severity: 'MEDIUM', passed: true,
    passedMsg: `Auth mode: "${authMode||'none'}"` };
  const token = get(config, 'gateway.auth.token', '');
  if (isWeakToken(token)) {
    return { id: 'gateway.auth.token', severity: 'MEDIUM', passed: false,
      title: 'Weak gateway auth token',
      description: `Token is short, simple, or a known default. Brute-forceable.\nAttack: automated tools try common tokens in seconds.`,
      fix: `node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"\nopenctl config set gateway.auth.token <output>` };
  }
  return { id: 'gateway.auth.token', severity: 'MEDIUM', passed: true, passedMsg: 'Auth token is strong' };
}

export function checkDangerousFlags(config) {
  const checks = [
    ['gateway.controlUi.dangerouslyDisableDeviceAuth', 'Disables device pairing — any browser can access Control UI'],
    ['gateway.controlUi.dangerouslyAllowHostHeaderOriginFallback', 'DNS rebinding attacks possible'],
    ['gateway.controlUi.allowInsecureAuth', 'Downgrades Control UI auth security'],
  ];
  const on = checks.filter(([p]) => get(config, p, false) === true);
  if (on.length) {
    return { id: 'gateway.dangerous_flags', severity: 'CRITICAL', passed: false,
      title: `Dangerous flags enabled (${on.length})`,
      description: on.map(([p,d]) => `• ${p.split('.').pop()}: ${d}`).join('\n'),
      fix: on.map(([p]) => `openclaw config set ${p} false`).join('\n') };
  }
  return { id: 'gateway.dangerous_flags', severity: 'CRITICAL', passed: true, passedMsg: 'No dangerous flags enabled' };
}

export function checkMdns(config) {
  const mode = get(config, 'discovery.mdns.mode', 'minimal');
  if (mode === 'full') {
    return { id: 'discovery.mdns', severity: 'MEDIUM', passed: false,
      title: 'mDNS leaking CLI path and SSH port on LAN',
      description: `mdns.mode="full" broadcasts your binary path (reveals username) and SSH port\nto everyone on your local network — passive reconnaissance, no auth needed.`,
      fix: `openclaw config set discovery.mdns.mode minimal` };
  }
  return { id: 'discovery.mdns', severity: 'MEDIUM', passed: true, passedMsg: `mDNS mode: "${mode}" (not leaking sensitive data)` };
}

export function checkRealIpFallback(config) {
  if (get(config, 'gateway.allowRealIpFallback', false) === true) {
    return { id: 'gateway.realip', severity: 'HIGH', passed: false,
      title: 'Real-IP fallback enables IP spoofing',
      description: `allowRealIpFallback=true means forged X-Real-IP: 127.0.0.1 headers\ncan make attacker requests appear to come from localhost, bypassing local trust checks.`,
      fix: `openclaw config set gateway.allowRealIpFallback false` };
  }
  return { id: 'gateway.realip', severity: 'HIGH', passed: true, passedMsg: 'Real-IP fallback disabled' };
}

export default [checkGatewayBind, checkTailscaleFunnel, checkAuthToken, checkDangerousFlags, checkMdns, checkRealIpFallback, checkTrustedProxies, checkMultiUserTrustModel];


// Check: trustedProxies configured when behind reverse proxy
export function checkTrustedProxies(config) {
  const gw = config.gateway || {};
  const trustedProxies = gw.trustedProxies || config.trustedProxies;
  // Read bind from multiple possible config locations
  const bind = gw.bind || config.bind || '127.0.0.1';

  // Only relevant if bind is not loopback (i.e., they're behind a proxy or exposed)
  const isLoopback = bind === '127.0.0.1' || bind === 'localhost' || bind === '::1' || bind === '' || bind === 'loopback';
  if (isLoopback) {
    return { id: 'gateway.trusted_proxies', severity: 'INFO', passed: true,
      passedMsg: 'Gateway is loopback-only — trustedProxies not needed' };
  }

  if (!trustedProxies || !Array.isArray(trustedProxies) || trustedProxies.length === 0) {
    return {
      id: 'gateway.trusted_proxies',
      severity: 'HIGH',
      passed: false,
      title: 'No trustedProxies configured for public-facing gateway',
      description: 'Gateway is not loopback-only but trustedProxies is not set. ' +
        'Without this, proxy IP spoofing can bypass authentication checks. ' +
        'Attack: attacker sends X-Forwarded-For header to impersonate a trusted IP.',
      fix: 'openclaw config set gateway.trustedProxies \'["<your-proxy-ip>"]\''
    };
  }
  return { id: 'gateway.trusted_proxies', severity: 'INFO', passed: true,
    passedMsg: `trustedProxies configured (${trustedProxies.length} proxy IPs)` };
}

// Check: multi-user heuristic — multiple channels with different users but no sandbox
export function checkMultiUserTrustModel(config) {
  const channels = config.channels || {};
  const channelCount = Object.keys(channels).filter(k =>
    channels[k] && typeof channels[k] === 'object' && channels[k].enabled !== false
  ).length;

  const groups = Object.values(channels).flatMap(ch => {
    if (ch && ch.groups) return Object.values(ch.groups);
    return [];
  });
  const hasGroups = groups.length > 0;

  const sandboxMode = config.agents?.defaults?.sandbox?.mode;
  const sandboxEnabled = sandboxMode && sandboxMode !== 'off';

  // Multi-user signal: groups with non-allowlisted access and no sandbox
  // Single-operator allowlisted groups are fine without sandbox
  const hasOpenGroups = groups.some(g => {
    const policy = g.policy || g.groupPolicy || 'allowlist';
    const allowFrom = g.allowFrom || [];
    return policy !== 'allowlist' && policy !== 'disabled' && 
           (allowFrom.length === 0 || allowFrom.includes('*'));
  });
  if (hasOpenGroups && !sandboxEnabled) {
    return {
      id: 'security.trust_model.multi_user',
      severity: 'MEDIUM',
      passed: false,
      title: 'Multi-user setup without sandbox isolation',
      description: `You have ${channelCount} channel(s)${hasGroups ? ' with group access' : ''} but no sandbox isolation. ` +
        'Multiple users sharing an agent without sandboxing means one user\'s session can affect another\'s workspace. ' +
        'Attack: user A triggers a task that reads or writes workspace files belonging to user B.',
      fix: 'Install Docker, then: openclaw config set agents.defaults.sandbox.mode non-main'
    };
  }
  return { id: 'security.trust_model.multi_user', severity: 'INFO', passed: true,
    passedMsg: 'Trust model appropriate for current channel configuration' };
}
