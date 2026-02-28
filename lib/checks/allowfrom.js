// ClawArmor v0.6 — allowFrom permissiveness check
// Scans all channel configs for dangerously open allowFrom settings.

import { get } from '../config.js';

const CHANNEL_KEYS = ['telegram', 'discord', 'whatsapp', 'signal', 'slack', 'imessage', 'matrix', 'email'];

function isWildcard(arr) {
  if (!Array.isArray(arr)) return false;
  return arr.some(v => v === '*' || (typeof v === 'string' && v.includes('*')));
}

function isEmptyArray(arr) {
  return Array.isArray(arr) && arr.length === 0;
}

export function checkAllowFrom(config) {
  const channels = get(config, 'channels', {});
  const issues = [];

  for (const chanKey of CHANNEL_KEYS) {
    const cfg = channels[chanKey];
    if (!cfg?.enabled) continue;

    const allowFrom = cfg.allowFrom ?? cfg.dmAllowFrom ?? null;
    const groupAllowFrom = cfg.groupAllowFrom ?? null;
    const dmPolicy = cfg.dmPolicy || '';
    const groupPolicy = cfg.groupPolicy || '';

    // Explicit wildcard
    if (isWildcard(allowFrom)) {
      issues.push({
        path: `channels.${chanKey}.allowFrom`,
        reason: `allowFrom: ["*"] — explicitly open to anyone`,
        severity: 'CRITICAL',
      });
    }

    // Empty array with non-restrictive dmPolicy
    if (isEmptyArray(allowFrom) && dmPolicy !== 'pairing' && dmPolicy !== 'disabled') {
      issues.push({
        path: `channels.${chanKey}.allowFrom`,
        reason: `allowFrom: [] (empty) with dmPolicy="${dmPolicy||'unset'}" — may default to open`,
        severity: 'HIGH',
      });
    }

    // groupAllowFrom empty + groupPolicy not disabled
    if (isEmptyArray(groupAllowFrom) && groupPolicy !== 'disabled') {
      issues.push({
        path: `channels.${chanKey}.groupAllowFrom`,
        reason: `groupAllowFrom: [] (empty) with groupPolicy="${groupPolicy||'unset'}" — group access unscoped`,
        severity: 'HIGH',
      });
    }

    // Check nested group entries
    const groups = cfg.groups || {};
    for (const [gid, gcfg] of Object.entries(groups)) {
      if (!gcfg || typeof gcfg !== 'object') continue;
      const gAllowFrom = gcfg.allowFrom ?? null;
      const gPolicy = gcfg.groupPolicy || '';

      if (isWildcard(gAllowFrom)) {
        issues.push({
          path: `channels.${chanKey}.groups.${gid}.allowFrom`,
          reason: `allowFrom: ["*"] — wildcard in group config`,
          severity: 'CRITICAL',
        });
      }
      if (isEmptyArray(gAllowFrom) && gPolicy !== 'disabled') {
        issues.push({
          path: `channels.${chanKey}.groups.${gid}.allowFrom`,
          reason: `allowFrom: [] (empty) with groupPolicy="${gPolicy||'unset'}"`,
          severity: 'MEDIUM',
        });
      }
    }
  }

  if (!issues.length) {
    return {
      id: 'channels.allowfrom',
      severity: 'HIGH',
      passed: true,
      passedMsg: 'All channel allowFrom settings are restricted',
    };
  }

  const criticals = issues.filter(i => i.severity === 'CRITICAL');
  const topSeverity = criticals.length ? 'CRITICAL' : 'HIGH';

  return {
    id: 'channels.allowfrom',
    severity: topSeverity,
    passed: false,
    title: `Dangerously permissive allowFrom settings (${issues.length} issue${issues.length > 1 ? 's' : ''})`,
    description: issues.map(i => `• ${i.path}: ${i.reason}`).join('\n') +
      `\nAny user who discovers your bot/channel can send commands to your agent.`,
    fix: issues.map(i => `openclaw config set ${i.path} '["your-user-id"]'`).join('\n'),
  };
}

export default [checkAllowFrom];
