// Channel policy checks: Telegram DM policy, group policies
import { get } from '../config.js';

export function checkTelegramDmPolicy(config) {
  const telegram = get(config, 'channels.telegram', null);

  if (!telegram || !telegram.enabled) {
    return {
      id: 'telegram.dmPolicy',
      severity: 'HIGH',
      passed: true,
      title: 'Telegram DM policy',
      passedMsg: 'Telegram channel not enabled',
    };
  }

  const dmPolicy = telegram.dmPolicy || '';
  const allowFrom = telegram.allowFrom || telegram.dmAllowFrom || null;
  const isOpen = dmPolicy === 'open' && !allowFrom;

  if (isOpen) {
    return {
      id: 'telegram.dmPolicy',
      severity: 'HIGH',
      passed: false,
      title: 'Telegram DMs open to anyone',
      description: `channels.telegram.dmPolicy is "open" with no allowFrom set.\nAnyone who finds your bot can send commands to your agent.`,
      fix: `openclaw config set channels.telegram.dmPolicy pairing\nOr restrict to specific users:\n  openclaw config set channels.telegram.allowFrom [your-telegram-id]`,
    };
  }

  return {
    id: 'telegram.dmPolicy',
    severity: 'HIGH',
    passed: true,
    title: 'Telegram DM policy',
    passedMsg: dmPolicy === 'pairing'
      ? 'Telegram DMs require pairing (secure)'
      : `Telegram DM policy: ${dmPolicy}`,
  };
}

export function checkGroupPolicies(config) {
  // Check all channel group policies
  const telegram = get(config, 'channels.telegram', null);
  const discord = get(config, 'channels.discord', null);

  const openGroups = [];

  // Check top-level telegram groupPolicy
  if (telegram?.enabled) {
    const topPolicy = telegram.groupPolicy;
    if (topPolicy === 'open') {
      openGroups.push('channels.telegram.groupPolicy');
    }

    // Check individual group policies
    const groups = telegram.groups || {};
    for (const [groupId, groupCfg] of Object.entries(groups)) {
      if (groupCfg.groupPolicy === 'open') {
        openGroups.push(`channels.telegram.groups.${groupId}.groupPolicy`);
      }
    }
  }

  if (discord?.enabled) {
    if (discord.groupPolicy === 'open') {
      openGroups.push('channels.discord.groupPolicy');
    }
  }

  if (openGroups.length > 0) {
    return {
      id: 'channel.groupPolicy',
      severity: 'MEDIUM',
      passed: false,
      title: 'Group policy allows anyone to message agent',
      description: `The following group policies are set to "open":\n${openGroups.map(p => `  • ${p}`).join('\n')}\nAnyone in those groups can send commands to your agent.`,
      fix: `openclaw config set channels.telegram.groupPolicy allowlist\nThen specify allowed users:\n  openclaw config set channels.telegram.groupAllowFrom [your-telegram-id]`,
    };
  }

  return {
    id: 'channel.groupPolicy',
    severity: 'MEDIUM',
    passed: true,
    title: 'Channel group policies',
    passedMsg: 'All channel group policies use allowlist (secure)',
  };
}

export default [checkTelegramDmPolicy, checkGroupPolicies];
