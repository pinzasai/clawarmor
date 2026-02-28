// File permission checks for sensitive OpenClaw files
import { existsSync } from 'fs';
import { getOctalPermissions, getAgentAccountsPath, getConfigPath } from '../config.js';

export function checkAgentAccountsPermissions() {
  const filePath = getAgentAccountsPath();

  if (!existsSync(filePath)) {
    return {
      id: 'fs.agentAccounts.permissions',
      severity: 'HIGH',
      passed: true,
      title: 'Agent accounts file permissions',
      passedMsg: 'agent-accounts.json not found (no credentials stored)',
    };
  }

  const perms = getOctalPermissions(filePath);

  if (perms !== '600') {
    return {
      id: 'fs.agentAccounts.permissions',
      severity: 'HIGH',
      passed: false,
      title: 'Credential file is world-readable',
      description: `~/.openclaw/agent-accounts.json has permissions ${perms}.\nAny user on this system can read your API keys and credentials.`,
      fix: `chmod 600 ~/.openclaw/agent-accounts.json`,
    };
  }

  return {
    id: 'fs.agentAccounts.permissions',
    severity: 'HIGH',
    passed: true,
    title: 'Agent accounts file permissions',
    passedMsg: 'agent-accounts.json is owner-only (600)',
  };
}

export function checkConfigFilePermissions() {
  const filePath = getConfigPath();
  const perms = getOctalPermissions(filePath);

  if (!perms) {
    return {
      id: 'fs.config.permissions',
      severity: 'HIGH',
      passed: true,
      title: 'Config file permissions',
      passedMsg: 'Config file not found (skipping)',
    };
  }

  if (perms !== '600') {
    return {
      id: 'fs.config.permissions',
      severity: 'HIGH',
      passed: false,
      title: 'Config file is world-readable',
      description: `~/.openclaw/openclaw.json has permissions ${perms}.\nThis file contains tokens and keys that any local user can read.`,
      fix: `chmod 600 ~/.openclaw/openclaw.json`,
    };
  }

  return {
    id: 'fs.config.permissions',
    severity: 'HIGH',
    passed: true,
    title: 'Config file permissions',
    passedMsg: 'openclaw.json is owner-only (600)',
  };
}

export default [checkAgentAccountsPermissions, checkConfigFilePermissions];
