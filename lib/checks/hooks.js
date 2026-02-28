import { get } from '../config.js';

export function checkHooksSessionKey(config) {
  if (get(config, 'hooks.allowRequestSessionKey', false) === true) {
    const prefixes = get(config, 'hooks.allowedSessionKeyPrefixes', null);
    if (!prefixes || (Array.isArray(prefixes) && prefixes.length === 0)) {
      return { id: 'hooks.sessionKey', severity: 'HIGH', passed: false,
        title: 'Webhooks allow external session key control (unbounded)',
        description: `hooks.allowRequestSessionKey=true with no allowedSessionKeyPrefixes.\nExternal callers can inject into ANY session by choosing its key.\nAttack: attacker sends webhook with sessionKey="main" to hijack your primary session.`,
        fix: `openclaw config set hooks.allowRequestSessionKey false\nOR set hooks.allowedSessionKeyPrefixes to restrict shapes` };
    }
    return { id: 'hooks.sessionKey', severity: 'MEDIUM', passed: false,
      title: 'Webhooks allow external session key control (prefixes set)',
      description: `hooks.allowRequestSessionKey=true — external callers can pick session keys\nmatching your allowedSessionKeyPrefixes. Review if this is intentional.`,
      fix: `Set hooks.allowRequestSessionKey false if not needed` };
  }
  return { id: 'hooks.sessionKey', severity: 'HIGH', passed: true,
    passedMsg: 'Webhooks cannot control session routing' };
}

export function checkHooksTokenLength(config) {
  const token = get(config, 'hooks.token', null);
  if (!token) return { id: 'hooks.token', severity: 'LOW', passed: true, passedMsg: 'No webhook token configured' };
  if (token.length < 16) {
    return { id: 'hooks.token', severity: 'MEDIUM', passed: false,
      title: 'Webhook token is too short (brute-forceable)',
      description: `hooks.token is ${token.length} chars — minimum 16 required.\nAttack: attacker brute-forces short token to trigger arbitrary webhook sessions.`,
      fix: `node -e "console.log(require('crypto').randomBytes(24).toString('base64url'))"\nopenctl config set hooks.token <output>` };
  }
  return { id: 'hooks.token', severity: 'MEDIUM', passed: true, passedMsg: `Webhook token length: ${token.length} chars (sufficient)` };
}

export default [checkHooksSessionKey, checkHooksTokenLength];
