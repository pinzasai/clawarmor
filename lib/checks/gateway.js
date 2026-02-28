// Gateway checks: bind address, tailscale funnel, auth token strength
import { get } from '../config.js';

// Default/weak token patterns — check without logging the actual value
const WEAK_TOKEN_PATTERNS = [
  /^change.?me$/i,
  /^your.?token/i,
  /^example/i,
  /^test.?token/i,
  /^demo/i,
  /^default/i,
  /^openclaw$/i,
  /^secret$/i,
  /^password$/i,
  /^12345/,
  /^token$/i,
];

function isWeakToken(token) {
  if (!token || typeof token !== 'string') return true;
  if (token.length < 16) return true;
  if (/^(.)\1+$/.test(token)) return true; // all same char
  if (WEAK_TOKEN_PATTERNS.some(p => p.test(token))) return true;
  // Check entropy: if all lowercase letters with no special chars and < 20 chars
  if (token.length < 20 && /^[a-z]+$/.test(token)) return true;
  return false;
}

export function checkGatewayBind(config) {
  const bind = get(config, 'gateway.bind', '');
  const mode = get(config, 'gateway.mode', '');

  // If mode is explicitly local and no bind, that's fine
  const isExposed = bind === '0.0.0.0' || bind === '::' ||
    (bind !== 'loopback' && bind !== 'localhost' && bind !== '127.0.0.1' && bind !== '' && mode !== 'local');

  if (isExposed) {
    return {
      id: 'gateway.bind',
      severity: 'CRITICAL',
      passed: false,
      title: 'Gateway exposed to network',
      description: `gateway.bind is "${bind}" — your OpenClaw control port\nis reachable by anyone on your network or the internet.`,
      fix: `Set "bind": "loopback" in your openclaw.json\nthen run: openclaw gateway restart`,
    };
  }

  return {
    id: 'gateway.bind',
    severity: 'CRITICAL',
    passed: true,
    title: 'Gateway bind',
    passedMsg: `Gateway bound to loopback (secure)`,
  };
}

export function checkTailscaleFunnel(config) {
  const tsMode = get(config, 'gateway.tailscale.mode', 'off');
  const authMode = get(config, 'gateway.auth.mode', '');

  const funnelActive = tsMode === 'funnel';
  const hasPassword = authMode === 'password';

  if (funnelActive && !hasPassword) {
    return {
      id: 'tailscale.funnel',
      severity: 'CRITICAL',
      passed: false,
      title: 'Tailscale Funnel without authentication',
      description: `tailscale.mode is "funnel" but auth.mode is not "password".\nAnyone with your Tailscale URL can access your agent.`,
      fix: `openclaw config set gateway.auth.mode password`,
    };
  }

  return {
    id: 'tailscale.funnel',
    severity: 'CRITICAL',
    passed: true,
    title: 'Tailscale Funnel',
    passedMsg: funnelActive
      ? 'Tailscale Funnel active with password auth (secure)'
      : 'Tailscale Funnel not enabled',
  };
}

export function checkAuthToken(config) {
  const authMode = get(config, 'gateway.auth.mode', '');
  const token = get(config, 'gateway.auth.token', '');

  if (authMode !== 'token') {
    return {
      id: 'gateway.auth.token',
      severity: 'MEDIUM',
      passed: true,
      title: 'Gateway auth token',
      passedMsg: `Gateway not using token auth (auth mode: ${authMode || 'none'})`,
    };
  }

  if (isWeakToken(token)) {
    return {
      id: 'gateway.auth.token',
      severity: 'MEDIUM',
      passed: false,
      title: 'Weak or default gateway auth token',
      description: `gateway.auth.mode is "token" but the token appears to be\nweak, short, or a default/example value.`,
      fix: `Generate a strong token:\n  node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"\nthen: openclaw config set gateway.auth.token <new-token>`,
    };
  }

  return {
    id: 'gateway.auth.token',
    severity: 'MEDIUM',
    passed: true,
    title: 'Gateway auth token',
    passedMsg: 'Gateway auth token appears strong',
  };
}

export default [checkGatewayBind, checkTailscaleFunnel, checkAuthToken];
