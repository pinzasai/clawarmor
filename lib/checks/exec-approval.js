// T-EXEC-004 — Exec Approval Coverage
// Checks that exec commands require user approval.

import { get } from '../config.js';

export function checkExecApproval(config) {
  const ask = get(config, 'tools.exec.ask', null);
  const allowed = get(config, 'tools.exec.allowed', null);
  const hasAllowlist = Array.isArray(allowed) && allowed.length > 0;

  // ask === 'off' — no approvals at all
  if (ask === 'off') {
    return {
      id: 'exec.approval',
      severity: 'HIGH',
      passed: false,
      title: 'Exec approval disabled — all shell commands run without confirmation',
      description: `tools.exec.ask="off" means every shell command the agent triggers\nruns immediately with zero user approval. Any prompt injection or malicious\nskill can execute arbitrary commands on your system without you seeing them.\nAttack: attacker injects "run rm -rf ~/important" — it executes silently.`,
      fix: `openclaw config set tools.exec.ask always\n# or, to allow a specific set without prompts:\nopenctl config set tools.exec.ask on-miss\nopenctl config set tools.exec.allowed '["git","npm","node"]'`,
    };
  }

  // ask === 'on-miss' with no allowlist — unbounded
  if (ask === 'on-miss' && !hasAllowlist) {
    return {
      id: 'exec.approval',
      severity: 'MEDIUM',
      passed: false,
      title: 'Exec approval set to on-miss but no allowlist defined',
      description: `tools.exec.ask="on-miss" only prompts for commands not on the allowed list.\nWith no allowed list set, the effective behaviour depends on how openclaw handles\nan empty list — this is ambiguous and may allow all commands silently.\nAttack: attacker runs any command that happens to be implicitly allowed.`,
      fix: `Either require approval for everything:\n  openclaw config set tools.exec.ask always\nOr define an explicit allowlist:\n  openclaw config set tools.exec.allowed '["git","npm","node"]'`,
    };
  }

  // ask === 'always' — best practice
  if (ask === 'always') {
    return { id: 'exec.approval', severity: 'HIGH', passed: true,
      passedMsg: 'Exec approval set to always — all commands require confirmation' };
  }

  // ask === 'on-miss' with a non-empty allowlist — acceptable
  if (ask === 'on-miss' && hasAllowlist) {
    return { id: 'exec.approval', severity: 'HIGH', passed: true,
      passedMsg: `Exec approval: on-miss with ${allowed.length}-command allowlist` };
  }

  // ask is null/undefined — default behaviour is unknown; treat as warn
  if (ask == null) {
    return {
      id: 'exec.approval',
      severity: 'MEDIUM',
      passed: false,
      title: 'Exec approval not explicitly configured',
      description: `tools.exec.ask is not set. The default approval behaviour is unknown\nand may change across openclaw versions. Explicit configuration is safer.`,
      fix: `openclaw config set tools.exec.ask always`,
    };
  }

  // Unknown value — pass with info
  return { id: 'exec.approval', severity: 'HIGH', passed: true,
    passedMsg: `Exec approval: ask="${ask}"` };
}

export default [checkExecApproval];
