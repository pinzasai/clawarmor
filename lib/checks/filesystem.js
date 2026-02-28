import { existsSync, statSync, readdirSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import { getOctalPermissions, getConfigPath, getAgentAccountsPath } from '../config.js';

const HOME = homedir();
const OC_DIR = join(HOME, '.openclaw');

function checkPerms(filePath, expected, label) {
  if (!existsSync(filePath)) return null;
  const p = getOctalPermissions(filePath);
  if (p !== expected) return { perms: p, path: filePath, label };
  return null;
}

export function checkOpenclawDirPerms() {
  if (!existsSync(OC_DIR)) return { id: 'fs.dir.perms', severity: 'HIGH', passed: true, passedMsg: '~/.openclaw/ not found' };
  const p = getOctalPermissions(OC_DIR);
  if (p !== '700') {
    return { id: 'fs.dir.perms', severity: 'HIGH', passed: false,
      title: '~/.openclaw/ directory is group/world readable',
      description: `~/.openclaw/ has permissions ${p}. Other users on this system can list\nyour config files, session transcripts, credentials, and installed skills.\nAttack: local user runs ls ~/.openclaw/credentials/ and reads your bot token.`,
      fix: `chmod 700 ~/.openclaw` };
  }
  return { id: 'fs.dir.perms', severity: 'HIGH', passed: true, passedMsg: '~/.openclaw/ is owner-only (700)' };
}

export function checkConfigFilePermissions() {
  const p = getOctalPermissions(getConfigPath());
  if (!p) return { id: 'fs.config.perms', severity: 'HIGH', passed: true, passedMsg: 'Config file not found' };
  if (p !== '600') {
    return { id: 'fs.config.perms', severity: 'HIGH', passed: false,
      title: 'openclaw.json is readable by other users',
      description: `~/.openclaw/openclaw.json has permissions ${p}. Contains bot tokens,\nAPI keys, and channel credentials readable by any local user.\nAttack: local user cat ~/.openclaw/openclaw.json → gets your Telegram bot token.`,
      fix: `chmod 600 ~/.openclaw/openclaw.json` };
  }
  return { id: 'fs.config.perms', severity: 'HIGH', passed: true, passedMsg: 'openclaw.json is owner-only (600)' };
}

export function checkAgentAccountsPermissions() {
  const fp = getAgentAccountsPath();
  if (!existsSync(fp)) return { id: 'fs.accounts.perms', severity: 'HIGH', passed: true, passedMsg: 'agent-accounts.json not found' };
  const p = getOctalPermissions(fp);
  if (p !== '600') {
    return { id: 'fs.accounts.perms', severity: 'HIGH', passed: false,
      title: 'agent-accounts.json is readable by other users',
      description: `Permissions ${p}. This file contains all API keys and passwords.\nAttack: one command gets every credential your agent holds.`,
      fix: `chmod 600 ~/.openclaw/agent-accounts.json` };
  }
  return { id: 'fs.accounts.perms', severity: 'HIGH', passed: true, passedMsg: 'agent-accounts.json is owner-only (600)' };
}

export function checkCredentialsDirPermissions() {
  const credDir = join(OC_DIR, 'credentials');
  if (!existsSync(credDir)) return { id: 'fs.creds.perms', severity: 'MEDIUM', passed: true, passedMsg: 'credentials/ not found' };
  const p = getOctalPermissions(credDir);
  if (p !== '700' && p !== '600') {
    return { id: 'fs.creds.perms', severity: 'MEDIUM', passed: false,
      title: 'credentials/ directory is not locked down',
      description: `~/.openclaw/credentials/ has permissions ${p}.\nContains channel auth tokens and pairing allowlists.`,
      fix: `chmod 700 ~/.openclaw/credentials\nchmod 600 ~/.openclaw/credentials/*.json 2>/dev/null || true` };
  }
  return { id: 'fs.creds.perms', severity: 'MEDIUM', passed: true, passedMsg: 'credentials/ directory is locked down' };
}

export function checkSessionTranscriptPermissions() {
  const agentsDir = join(OC_DIR, 'agents');
  if (!existsSync(agentsDir)) return { id: 'fs.sessions.perms', severity: 'LOW', passed: true, passedMsg: 'No agent sessions found' };
  // Check first session dir found
  try {
    const agents = readdirSync(agentsDir);
    for (const agent of agents) {
      const sessDir = join(agentsDir, agent, 'sessions');
      if (!existsSync(sessDir)) continue;
      const p = getOctalPermissions(sessDir);
      if (p && p !== '700' && p !== '600') {
        return { id: 'fs.sessions.perms', severity: 'LOW', passed: false,
          title: 'Session transcripts readable by other users',
          description: `~/.openclaw/agents/${agent}/sessions/ has permissions ${p}.\nTranscripts contain your full conversation history, tool outputs, and potentially secrets.`,
          fix: `chmod -R 700 ~/.openclaw/agents/` };
      }
    }
  } catch { /* skip */ }
  return { id: 'fs.sessions.perms', severity: 'LOW', passed: true, passedMsg: 'Session transcripts are private' };
}

export default [checkOpenclawDirPerms, checkConfigFilePermissions, checkAgentAccountsPermissions, checkCredentialsDirPermissions, checkSessionTranscriptPermissions];
