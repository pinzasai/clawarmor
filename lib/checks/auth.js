// Auth + agent sandbox checks
import { get } from '../config.js';

export function checkAgentSandbox(config) {
  const sandbox = get(config, 'agents.defaults.sandbox', null);

  const secureModes = ['non-main', 'all', 'strict'];
  const isSecure = sandbox != null && secureModes.includes(sandbox);

  if (!isSecure) {
    const msg = sandbox == null
      ? 'agents.defaults.sandbox is not set — agent sessions for channel\ncommunication (Telegram, Discord) run with no isolation from your\nmain agent context.'
      : `agents.defaults.sandbox is "${sandbox}" — not a recognized secure\nsandbox mode.`;

    return {
      id: 'agents.sandbox',
      severity: 'HIGH',
      passed: false,
      title: 'Agent sessions have no sandbox isolation',
      description: msg,
      fix: `openclaw config set agents.defaults.sandbox non-main\nThis isolates channel agent sessions from your primary agent context.`,
    };
  }

  return {
    id: 'agents.sandbox',
    severity: 'HIGH',
    passed: true,
    title: 'Agent sandbox isolation',
    passedMsg: `Agent sandbox mode: ${sandbox} (isolated)`,
  };
}

export function checkThinkingStream(config) {
  const thinking = get(config, 'agents.defaults.thinkingDefault', 'off');
  const stream = get(config, 'agents.defaults.stream', null);

  // Only flag if BOTH thinking is 'on' AND stream mode is 'stream'
  // This can leak partial reasoning to channel observers
  const isRisky = thinking === 'on' && stream === 'stream';

  if (isRisky) {
    return {
      id: 'agents.thinking.stream',
      severity: 'LOW',
      passed: false,
      title: 'Thinking mode streaming may leak reasoning',
      description: `thinkingDefault is "on" with stream mode enabled.\nPartial chain-of-thought may be visible to channel participants\nbefore the agent decides whether to respond.`,
      fix: `openclaw config set agents.defaults.thinkingDefault off\nOr disable streaming: openclaw config set agents.defaults.stream off`,
    };
  }

  return {
    id: 'agents.thinking.stream',
    severity: 'LOW',
    passed: true,
    title: 'Thinking mode streaming',
    passedMsg: thinking === 'off'
      ? 'Thinking mode is off (no stream leak risk)'
      : `Thinking mode is "${thinking}" (stream: ${stream || 'off'})`,
  };
}

export default [checkAgentSandbox, checkThinkingStream];
