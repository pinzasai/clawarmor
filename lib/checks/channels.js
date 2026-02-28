import { get } from '../config.js';

export function checkTelegramDmPolicy(config) {
  const tg = get(config, 'channels.telegram', null);
  if (!tg?.enabled) return { id: 'telegram.dmPolicy', severity: 'HIGH', passed: true, passedMsg: 'Telegram not enabled' };
  const dmPolicy = tg.dmPolicy || '';
  const allowFrom = tg.allowFrom || tg.dmAllowFrom || null;
  if (dmPolicy === 'open' && !allowFrom) {
    return { id: 'telegram.dmPolicy', severity: 'HIGH', passed: false,
      title: 'Telegram DMs open to anyone',
      description: `dmPolicy="open" with no allowFrom — anyone who finds your bot can\nsend commands. Attack: attacker DMs bot "exec cat ~/.openclaw/openclaw.json".`,
      fix: `openclaw config set channels.telegram.dmPolicy pairing` };
  }
  return { id: 'telegram.dmPolicy', severity: 'HIGH', passed: true,
    passedMsg: `Telegram DM policy: "${dmPolicy}" (restricted)` };
}

export function checkGroupPolicies(config) {
  const openGroups = [];
  for (const [chan, cfg] of Object.entries(get(config, 'channels', {}))) {
    if (!cfg?.enabled) continue;
    if (cfg.groupPolicy === 'open') openGroups.push(`channels.${chan}.groupPolicy`);
    const groups = cfg.groups || {};
    for (const [gid, gcfg] of Object.entries(groups)) {
      if (gcfg?.groupPolicy === 'open') openGroups.push(`channels.${chan}.groups.${gid}.groupPolicy`);
    }
  }
  if (openGroups.length) {
    return { id: 'channel.groupPolicy', severity: 'MEDIUM', passed: false,
      title: 'Group policy allows anyone to trigger agent',
      description: `Open group policies found:\n${openGroups.map(p=>`  • ${p}`).join('\n')}\nAnyone in those groups can send commands to your agent.\nAttack: attacker joins group, sends injected content, triggers tool calls.`,
      fix: `openclaw config set channels.telegram.groupPolicy allowlist` };
  }
  return { id: 'channel.groupPolicy', severity: 'MEDIUM', passed: true, passedMsg: 'All group policies use allowlist' };
}

export function checkOpenGroupsWithElevated(config) {
  // CRITICAL combo: open groups + elevated tools = attacker can run elevated exec
  const elevatedEnabled = get(config, 'tools.elevated.enabled', false) ||
    get(config, 'tools.elevated', null) !== null;
  const hasOpenGroup = Object.values(get(config, 'channels', {})).some(cfg =>
    cfg?.enabled && cfg?.groupPolicy === 'open'
  );
  if (hasOpenGroup && elevatedEnabled) {
    return { id: 'security.open_groups_elevated', severity: 'CRITICAL', passed: false,
      title: 'CRITICAL: Open groups + elevated tools = remote code execution',
      description: `You have group channels with groupPolicy="open" AND elevated tools enabled.\nAnyone in those groups can send a message that causes elevated exec on your host.\nAttack: attacker joins group, sends "run rm -rf /" — agent executes it with elevated perms.\nThis is the highest-risk configuration possible.`,
      fix: `openclaw config set channels.telegram.groupPolicy allowlist\nOR: openclaw config set tools.elevated.enabled false` };
  }
  return { id: 'security.open_groups_elevated', severity: 'CRITICAL', passed: true,
    passedMsg: 'No open groups with elevated tools (safe)' };
}

export function checkDmSessionScope(config) {
  const dmScope = get(config, 'session.dmScope', 'main');
  // Only flag if multiple users could DM (open DM policy or large allowFrom)
  const tgAllowFrom = get(config, 'channels.telegram.allowFrom', []);
  const multiUser = Array.isArray(tgAllowFrom) && tgAllowFrom.length > 1;
  if (multiUser && dmScope === 'main') {
    return { id: 'session.dmScope', severity: 'MEDIUM', passed: false,
      title: 'Multiple DM users share the same session context',
      description: `session.dmScope="main" with ${tgAllowFrom.length} allowed DM users — all share\none conversation context. User A can ask agent to recall what User B said.\nAttack: authorized user extracts another authorized user's conversation history.`,
      fix: `openclaw config set session.dmScope per-channel-peer` };
  }
  return { id: 'session.dmScope', severity: 'MEDIUM', passed: true,
    passedMsg: dmScope === 'per-channel-peer' ? 'DM sessions are isolated per user' : 'Single-user DM (session isolation not needed)' };
}

export default [checkTelegramDmPolicy, checkGroupPolicies, checkOpenGroupsWithElevated, checkDmSessionScope];
