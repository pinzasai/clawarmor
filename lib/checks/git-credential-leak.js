// T-EXFIL-003 — Workspace Git Credential Leak
// Scans the workspace git history and .env files for committed secrets.
// NEVER prints actual secret values — only reports key names and locations.

import { existsSync, readdirSync, readFileSync } from 'fs';
import { join, basename } from 'path';
import { homedir } from 'os';
import { execSync } from 'child_process';
import { get } from '../config.js';

const HOME = homedir();
const DEFAULT_WORKSPACE = join(HOME, 'clawd');

// Pattern: key/token/secret = "value_at_least_16_chars"
// NEVER logs the value; only the matched key name
const SECRET_PATTERN = /(?:api[_-]?key|token|secret|password|credential)["']?\s*[:=]\s*["']?([a-zA-Z0-9_\-]{16,})/i;
// Pattern to find the key name from the line (for reporting)
const KEY_NAME_PATTERN = /^[^=:]*?(api[_-]?key|token|secret|password|credential)/i;

const ENV_FILE_NAMES = ['.env', '.env.local', '.env.production', '.env.staging', '.env.development'];

function isGitRepo(dir) {
  return existsSync(join(dir, '.git'));
}

function scanEnvFiles(workspaceDir) {
  const findings = [];

  // Scan workspace root for .env files
  let files;
  try { files = readdirSync(workspaceDir); }
  catch { return findings; }

  for (const filename of files) {
    if (!ENV_FILE_NAMES.includes(filename)) continue;
    const filePath = join(workspaceDir, filename);
    let lines;
    try {
      lines = readFileSync(filePath, 'utf8').split('\n');
    } catch { continue; }

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (SECRET_PATTERN.test(line)) {
        const keyMatch = line.match(KEY_NAME_PATTERN);
        const keyName = keyMatch ? keyMatch[0].trim().replace(/["']/g, '') : 'unknown-key';
        findings.push(`${filename}:${i + 1} — key matching "${keyName.slice(0, 40)}"`);
      }
    }
  }

  return findings;
}

function scanGitLog(workspaceDir) {
  const findings = [];

  try {
    // Get last 50 commits' diffs — limit output to avoid huge repos
    const output = execSync(
      'git log -p --max-count=50 --no-color --unified=0',
      { cwd: workspaceDir, timeout: 15000, maxBuffer: 5 * 1024 * 1024, stdio: ['ignore', 'pipe', 'ignore'] }
    ).toString('utf8');

    const lines = output.split('\n');
    let currentCommit = '';
    let currentFile = '';

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      if (line.startsWith('commit ')) {
        currentCommit = line.slice(7, 15); // short hash
        continue;
      }
      if (line.startsWith('+++ b/')) {
        currentFile = line.slice(6);
        continue;
      }
      // Only check added lines (prefixed with +)
      if (!line.startsWith('+') || line.startsWith('+++')) continue;

      if (SECRET_PATTERN.test(line)) {
        const keyMatch = line.match(KEY_NAME_PATTERN);
        const keyName = keyMatch ? keyMatch[0].trim().replace(/["']/g, '') : 'unknown-key';
        const location = `commit ${currentCommit}, file ${currentFile || 'unknown'}, line pattern "${keyName.slice(0, 40)}"`;
        if (!findings.includes(location)) {
          findings.push(location);
        }
      }
    }
  } catch {
    // git not available, not a git repo, or timeout — skip silently
  }

  return findings;
}

export async function checkGitCredentialLeak(config) {
  // Resolve workspace directory from config or default
  const workspaceDir = get(config, 'workspace.dir', null) || DEFAULT_WORKSPACE;

  if (!existsSync(workspaceDir)) {
    return { id: 'exfil.git_credential_leak', severity: 'CRITICAL', passed: true,
      passedMsg: 'Workspace directory not found — git credential leak check skipped' };
  }

  const envFindings = scanEnvFiles(workspaceDir);

  let gitFindings = [];
  if (isGitRepo(workspaceDir)) {
    gitFindings = scanGitLog(workspaceDir);
  }

  const allFindings = [...envFindings, ...gitFindings];

  if (!allFindings.length) {
    return { id: 'exfil.git_credential_leak', severity: 'CRITICAL', passed: true,
      passedMsg: 'No credential patterns found in workspace .env files or git history' };
  }

  const list = allFindings.slice(0, 10).map(f => `• ${f}`).join('\n');
  const more = allFindings.length > 10 ? `\n  ...and ${allFindings.length - 10} more` : '';

  return {
    id: 'exfil.git_credential_leak',
    severity: 'CRITICAL',
    passed: false,
    title: `Credential patterns found in workspace (${allFindings.length} location${allFindings.length > 1 ? 's' : ''})`,
    description: `Secret-like patterns matching credential keys were found in your workspace.\nThis may mean API keys or tokens were committed to git or left in .env files.\n\n${list}${more}\n\nNote: Only key names are shown — no actual values are printed.`,
    fix: `For .env files: add them to .gitignore immediately:\n  echo '.env*' >> ${workspaceDir}/.gitignore\n\nFor committed secrets, scrub git history:\n  git filter-repo --path-glob '*.env' --invert-paths\n  # or: https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository\n\nRotate any exposed credentials immediately.`,
  };
}

export default [checkGitCredentialLeak];
