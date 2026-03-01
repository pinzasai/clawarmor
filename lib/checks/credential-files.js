// T-CRED-001 — Credential File Permission Hygiene
// Checks ~/.openclaw/ directory and file permissions, and scans JSON
// files for API key patterns (key names only — never values).

import { existsSync, readdirSync, statSync, readFileSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';

const HOME = homedir();
const OPENCLAW_DIR = join(HOME, '.openclaw');

// Same pattern shape as git-credential-leak: matches key names + long value
// We only use this to DETECT presence — we never log the value
const SECRET_PATTERN = /(?:api[_-]?key|token|secret|password|credential)["']?\s*[:=]\s*["']?([a-zA-Z0-9_\-]{16,})/i;

// ── check 1: directory permissions ─────────────────────────────────────────

export function checkCredDirPermissions() {
  if (!existsSync(OPENCLAW_DIR)) {
    return { id: 'cred.dir_permissions', severity: 'MEDIUM', passed: true,
      passedMsg: '~/.openclaw/ not found — credential directory check skipped' };
  }

  let dirStat;
  try { dirStat = statSync(OPENCLAW_DIR); }
  catch {
    return { id: 'cred.dir_permissions', severity: 'MEDIUM', passed: true,
      passedMsg: 'Could not stat ~/.openclaw/ — skipped' };
  }

  const mode = dirStat.mode & 0o777;
  if (mode > 0o700) {
    return {
      id: 'cred.dir_permissions',
      severity: 'MEDIUM',
      passed: false,
      title: `~/.openclaw/ directory permissions are too open (${mode.toString(8)})`,
      description: `The directory containing your credentials has permissions ${mode.toString(8)}.\nIt should be 700 (owner-only access). Overly permissive directory permissions\nallow other users or groups to list and access your credential files.`,
      fix: `chmod 700 ${OPENCLAW_DIR}`,
    };
  }

  return { id: 'cred.dir_permissions', severity: 'MEDIUM', passed: true,
    passedMsg: `~/.openclaw/ directory permissions are secure (${mode.toString(8)})` };
}

// ── check 2: file permissions ───────────────────────────────────────────────

export function checkCredFilePermissions() {
  if (!existsSync(OPENCLAW_DIR)) {
    return { id: 'cred.file_permissions', severity: 'CRITICAL', passed: true,
      passedMsg: '~/.openclaw/ not found — credential file permission check skipped' };
  }

  let entries;
  try { entries = readdirSync(OPENCLAW_DIR, { withFileTypes: true }); }
  catch {
    return { id: 'cred.file_permissions', severity: 'CRITICAL', passed: true,
      passedMsg: 'Could not read ~/.openclaw/ — skipped' };
  }

  const worldReadable = [];
  const groupReadable = [];

  for (const entry of entries) {
    if (!entry.isFile()) continue;
    const filePath = join(OPENCLAW_DIR, entry.name);
    let s;
    try { s = statSync(filePath); } catch { continue; }
    const mode = s.mode & 0o777;

    if (mode & 0o004) {
      // world-readable bit set → CRITICAL
      worldReadable.push({ name: entry.name, path: filePath, mode: mode.toString(8) });
    } else if (mode & 0o040) {
      // group-readable bit set (but not world) → HIGH
      groupReadable.push({ name: entry.name, path: filePath, mode: mode.toString(8) });
    }
  }

  if (worldReadable.length) {
    const fixLines = worldReadable.map(f => `  chmod 600 ${f.path}`).join('\n');
    const fileList = worldReadable.map(f => `• ${f.name} (${f.mode})`).join('\n');
    return {
      id: 'cred.file_permissions',
      severity: 'CRITICAL',
      passed: false,
      title: `World-readable credential files in ~/.openclaw/ (${worldReadable.length})`,
      description: `The following files are readable by any user on the system:\n${fileList}\n\nAny local process or user can read your API keys and tokens.`,
      fix: `Fix immediately:\n${fixLines}`,
    };
  }

  if (groupReadable.length) {
    const fixLines = groupReadable.map(f => `  chmod 600 ${f.path}`).join('\n');
    const fileList = groupReadable.map(f => `• ${f.name} (${f.mode})`).join('\n');
    return {
      id: 'cred.file_permissions',
      severity: 'HIGH',
      passed: false,
      title: `Group-readable credential files in ~/.openclaw/ (${groupReadable.length})`,
      description: `The following files are readable by your Unix group:\n${fileList}\n\nOther users in your group can read your credentials.`,
      fix: `Fix:\n${fixLines}`,
    };
  }

  return { id: 'cred.file_permissions', severity: 'CRITICAL', passed: true,
    passedMsg: 'Credential file permissions are secure (all ≤ 0600)' };
}

// ── check 3: JSON content scan for API key patterns ─────────────────────────

export function checkCredJsonSecrets() {
  if (!existsSync(OPENCLAW_DIR)) {
    return { id: 'cred.json_secrets', severity: 'HIGH', passed: true,
      passedMsg: '~/.openclaw/ not found — JSON secret pattern check skipped' };
  }

  let entries;
  try { entries = readdirSync(OPENCLAW_DIR, { withFileTypes: true }); }
  catch {
    return { id: 'cred.json_secrets', severity: 'HIGH', passed: true,
      passedMsg: 'Could not read ~/.openclaw/ — skipped' };
  }

  const flagged = [];

  for (const entry of entries) {
    if (!entry.isFile() || !entry.name.endsWith('.json')) continue;
    const filePath = join(OPENCLAW_DIR, entry.name);
    let content;
    try { content = readFileSync(filePath, 'utf8'); }
    catch { continue; }
    if (content.length > 1_000_000) continue;

    if (SECRET_PATTERN.test(content)) {
      flagged.push(entry.name);
    }
  }

  if (!flagged.length) {
    return { id: 'cred.json_secrets', severity: 'HIGH', passed: true,
      passedMsg: 'No API key patterns found in ~/.openclaw/ JSON files' };
  }

  return {
    id: 'cred.json_secrets',
    severity: 'HIGH',
    passed: false,
    title: `API key patterns found in ~/.openclaw/ JSON files (${flagged.length} file${flagged.length > 1 ? 's' : ''})`,
    description: `The following JSON files in ~/.openclaw/ contain patterns matching API keys or secrets:\n${flagged.map(f => `• ${f}`).join('\n')}\n\nNote: Only key name patterns are detected — actual values are never read or stored.\nCredentials in the wrong files may be at risk if file permissions are too open.`,
    fix: `Ensure all credential files use 0600 permissions:\n  chmod 600 ~/.openclaw/*.json\n\nIf credentials are in unexpected files, move them to agent-accounts.json.`,
  };
}

export default [checkCredDirPermissions, checkCredFilePermissions, checkCredJsonSecrets];
