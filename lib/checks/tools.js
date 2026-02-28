import { get } from '../config.js';

export function checkElevatedTools(config) {
  const elevated = get(config, 'tools.elevated', null);
  const allowFrom = get(config, 'tools.elevated.allowFrom', null);
  if (!elevated) return { id: 'tools.elevated', severity: 'MEDIUM', passed: true, passedMsg: 'Elevated tools not configured' };
  const restricted = Array.isArray(allowFrom) && allowFrom.length > 0 &&
    !allowFrom.includes('*') && !allowFrom.includes('all');
  if (!restricted) {
    return { id: 'tools.elevated', severity: 'MEDIUM', passed: false,
      title: 'Elevated tools not restricted to trusted sources',
      description: `tools.elevated.allowFrom is unrestricted.\nElevated exec runs on the host bypassing any sandbox.\nAttack: anyone who can reach the agent can trigger host-level commands.`,
      fix: `openclaw config set tools.elevated.allowFrom ["your-session-key"]` };
  }
  return { id: 'tools.elevated', severity: 'MEDIUM', passed: true, passedMsg: 'Elevated tools restricted to allowlist' };
}

export function checkWorkspaceOnly(config) {
  const wo = get(config, 'tools.fs.workspaceOnly', null);
  if (wo !== true) {
    return { id: 'tools.fs.workspaceOnly', severity: 'LOW', passed: false,
      title: 'Agent can read/write anywhere on filesystem',
      description: `tools.fs.workspaceOnly is not true — the agent can read/write any file\nyour user account can access: SSH keys, ~/.zshenv, browser profiles, etc.\nAttack: prompt injection causes read("~/.ssh/id_rsa") and exfiltrates your private key.`,
      fix: `openclaw config set tools.fs.workspaceOnly true` };
  }
  return { id: 'tools.fs.workspaceOnly', severity: 'LOW', passed: true, passedMsg: 'Filesystem restricted to workspace' };
}

export function checkApplyPatchWorkspaceOnly(config) {
  const wo = get(config, 'tools.exec.applyPatch.workspaceOnly', true);
  if (wo === false) {
    return { id: 'tools.applyPatch.workspaceOnly', severity: 'MEDIUM', passed: false,
      title: 'apply_patch can write files outside workspace',
      description: `tools.exec.applyPatch.workspaceOnly=false allows apply_patch to create\nor delete files anywhere on your system, even without exec permissions.\nAttack: attacker uses apply_patch to overwrite ~/.zshenv or crontabs.`,
      fix: `openclaw config set tools.exec.applyPatch.workspaceOnly true` };
  }
  return { id: 'tools.applyPatch.workspaceOnly', severity: 'MEDIUM', passed: true, passedMsg: 'apply_patch restricted to workspace' };
}

export function checkBrowserSsrf(config) {
  const allowPrivate = get(config, 'browser.ssrfPolicy.dangerouslyAllowPrivateNetwork', true);
  if (allowPrivate !== false) {
    return { id: 'browser.ssrf', severity: 'MEDIUM', passed: false,
      title: 'Browser tool can access private/internal network',
      description: `browser.ssrfPolicy.dangerouslyAllowPrivateNetwork is not explicitly false.\nDefault allows browser to reach 192.168.x.x, 10.x.x.x, 172.16.x.x, localhost.\nAttack: prompt injection causes browser.navigate("http://192.168.1.1/admin")\nand exfiltrates your router admin panel or internal services.`,
      fix: `openclaw config set browser.ssrfPolicy.dangerouslyAllowPrivateNetwork false` };
  }
  return { id: 'browser.ssrf', severity: 'MEDIUM', passed: true, passedMsg: 'Browser SSRF to private networks blocked' };
}

export function checkPluginAllowlist(config) {
  const plugins = get(config, 'plugins', null);
  const allow = get(config, 'plugins.allow', null);
  if (plugins && (!allow || (Array.isArray(allow) && allow.length === 0))) {
    return { id: 'plugins.allowlist', severity: 'MEDIUM', passed: false,
      title: 'Plugins loaded without explicit allowlist',
      description: `plugins are configured but plugins.allow is not set.\nPlugins run in-process with the gateway — treat as fully trusted code.\nAttack: malicious ClawHub plugin installed without review, runs arbitrary code\nin the gateway process, reads all credentials and sessions.`,
      fix: `openclaw config set plugins.allow ["your-trusted-plugin-id"]` };
  }
  return { id: 'plugins.allowlist', severity: 'MEDIUM', passed: true, passedMsg: 'Plugin allowlist configured' };
}

export function checkLogRedaction(config) {
  const redact = get(config, 'logging.redactSensitive', 'tools');
  if (redact === false || redact === 'off' || redact === 'none') {
    return { id: 'logging.redact', severity: 'MEDIUM', passed: false,
      title: 'Log redaction disabled — tokens leak to disk logs',
      description: `logging.redactSensitive="${redact}" — gateway logs will contain\nraw API keys, bot tokens, and tool arguments in plaintext.\nAttack: attacker with log read access extracts all credentials passively.`,
      fix: `openclaw config set logging.redactSensitive tools` };
  }
  return { id: 'logging.redact', severity: 'MEDIUM', passed: true, passedMsg: 'Log redaction enabled' };
}

export default [checkElevatedTools, checkWorkspaceOnly, checkApplyPatchWorkspaceOnly,
  checkBrowserSsrf, checkPluginAllowlist, checkLogRedaction];
