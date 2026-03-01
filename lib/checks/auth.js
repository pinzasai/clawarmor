import { get } from '../config.js';
import { execSync } from 'child_process';

function dockerAvailable() {
  try { execSync('docker --version', { stdio: 'ignore', timeout: 2000 }); return true; }
  catch { return false; }
}

export function checkAgentSandbox(config) {
  const mode = get(config, 'agents.defaults.sandbox.mode', null);
  const mainKey = get(config, 'agents.mainKey', 'main');
  const hasCustomMainKey = mainKey !== 'main';
  const secureModes = ['non-main', 'all', 'strict'];

  if (secureModes.includes(mode)) {
    const mainKeyNote = hasCustomMainKey
      ? ` (mainKey="${mainKey}" — verify non-main scope is correct)`
      : '';
    return { id: 'agents.sandbox', severity: 'HIGH', passed: true,
      passedMsg: `Agent sandbox mode: "${mode}" (sessions isolated)${mainKeyNote}` };
  }
  if (!dockerAvailable()) {
    return { id: 'agents.sandbox', severity: 'LOW', passed: false,
      title: 'Sandbox isolation not configured (Docker not installed)',
      description: `Sandbox isolation is not enabled. OpenClaw sandboxes require Docker.\nDocker is not installed on this machine — sandbox cannot be enabled yet.\nInstall Docker first, then enable sandbox isolation.`,
      fix: `1. Install Docker: brew install --cask docker\n2. Open Docker.app to complete setup\n3. openclaw config set agents.defaults.sandbox.mode non-main\n4. openclaw gateway restart` };
  }
  const mainKeyNote = hasCustomMainKey
    ? `\nNote: agents.mainKey="${mainKey}" — "non-main" sandbox mode will isolate sessions that are not "${mainKey}".`
    : '';
  return { id: 'agents.sandbox', severity: 'HIGH', passed: false,
    title: 'Agent sessions have no sandbox isolation',
    description: `agents.defaults.sandbox.mode not set — tool calls from Telegram/Discord\nrun directly on your host with no container boundary.\nAttack: prompt injection via fetched webpage causes exec with full host access.${mainKeyNote}`,
    fix: `openclaw config set agents.defaults.sandbox.mode non-main\nopenctl gateway restart` };
}

export function checkSandboxExecFootgun(config) {
  const sandboxMode = get(config, 'agents.defaults.sandbox.mode', null);
  const execHost = get(config, 'tools.exec.host', null);
  if (execHost === 'sandbox' && (!sandboxMode || sandboxMode === 'off')) {
    return { id: 'tools.exec.sandbox_off', severity: 'HIGH', passed: false,
      title: 'exec host=sandbox but sandbox mode is off (silent footgun)',
      description: `tools.exec.host="sandbox" suggests exec should run in a container.\nBut agents.defaults.sandbox.mode is "${sandboxMode||'off'}" — exec runs on your HOST.\nYou think you're sandboxed. You're not.\nAttack: any exec call bypasses the sandbox you expected.`,
      fix: `openclaw config set agents.defaults.sandbox.mode non-main\nOR: openclaw config set tools.exec.host gateway` };
  }
  return { id: 'tools.exec.sandbox_off', severity: 'HIGH', passed: true,
    passedMsg: 'exec sandbox configuration is consistent' };
}

export function checkThinkingStream(config) {
  const thinking = get(config, 'agents.defaults.thinkingDefault', 'off');
  const stream = get(config, 'agents.defaults.stream', null);
  if (thinking === 'on' && stream === 'stream') {
    return { id: 'agents.thinking.stream', severity: 'LOW', passed: false,
      title: 'Thinking mode streaming leaks reasoning to channel observers',
      description: `thinkingDefault="on" with stream mode — partial chain-of-thought\nvisible to channel participants before agent finishes reasoning.`,
      fix: `openclaw config set agents.defaults.thinkingDefault off` };
  }
  return { id: 'agents.thinking.stream', severity: 'LOW', passed: true,
    passedMsg: 'Thinking stream not leaking reasoning' };
}

export default [checkAgentSandbox, checkSandboxExecFootgun, checkThinkingStream];
