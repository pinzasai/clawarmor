// lib/stack/ironcurtain.js — IronCurtain integration
// IronCurtain: English constitution → LLM compiles to deterministic rules → runtime enforcement.
// We generate the Markdown constitution from audit findings. User runs compile-policy themselves.

import { existsSync, writeFileSync, mkdirSync, statSync, readdirSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import { spawnSync } from 'child_process';

const HOME = homedir();
const IRONCURTAIN_DIR = join(HOME, '.ironcurtain');
const CONSTITUTION_PATH = join(IRONCURTAIN_DIR, 'constitution-clawarmor.md');

/** Check if ironcurtain CLI is available (npm -g). */
export function checkInstalled() {
  try {
    const r = spawnSync('ironcurtain', ['--version'], { encoding: 'utf8', timeout: 5000 });
    return r.status === 0;
  } catch { return false; }
}

/**
 * Generate an IronCurtain constitution Markdown from audit findings.
 *
 * Key mappings (from research):
 *   exec.ask=off                      → Escalate: All exec tool calls require human approval
 *   elevated.allowFrom empty          → Forbidden: Elevated operations without allowFrom restrictions
 *   channels.groupPolicy=open         → Escalate: Messages to external groups require approval
 *   credential world-readable         → Forbidden: Reading lax-permission credential files
 *   skill supply chain                → Forbidden: Loading unverified/unpinned skills
 *
 * @param {Array} findings - array of { id, severity, title, detail }
 * @returns {string} Markdown constitution text
 */
export function generateConstitution(findings) {
  const now = new Date().toISOString().slice(0, 10);
  const lines = [
    `# ClawArmor-Generated Constitution`,
    `_Generated: ${now} by clawarmor stack deploy --ironcurtain_`,
    '',
  ];

  const allowed = [
    'Read and write files only within the project workspace directory',
    'Search the web for public information',
    'View git status and git log',
  ];
  const escalate = [];
  const forbidden = [
    'Accessing ~/.ssh, ~/.aws, ~/.openclaw, or other credential files outside the workspace',
    'Deleting files outside the project workspace directory',
  ];

  if (!findings || !findings.length) {
    // Conservative defaults when no audit data
    escalate.push('All exec tool calls (no audit data — applying conservative defaults)');
    escalate.push('Any network request to external URLs');
  } else {
    const added = new Set();
    for (const finding of findings) {
      const id = (finding.id || '').toLowerCase();
      const detail = (finding.detail || '').toLowerCase();
      const title = (finding.title || '').toLowerCase();
      const ref = `(audit: ${finding.id})`; // eslint-disable-line no-unused-vars

      // exec.ask=off → escalate exec
      if (
        !added.has('exec') &&
        (id.includes('exec') || title.includes('exec')) &&
        (id.includes('ask') || id.includes('approval') || detail.includes('ask') ||
         title.includes('approval') || title.includes('unrestricted') || detail.includes('unrestricted'))
      ) {
        added.add('exec');
        escalate.push(`All exec tool calls require human approval ${ref}`);
      }

      // elevated.allowFrom empty → forbidden elevated ops
      // Matches: elevated.*, tools.elevated.*, allowfrom.*
      if (
        !added.has('elevated') &&
        (id.includes('elevated') || id.includes('allowfrom') || title.includes('elevated'))
      ) {
        added.add('elevated');
        forbidden.push(`Elevated operations without explicit allowFrom restrictions ${ref}`);
      }

      // channels with no allowFrom / group policy open → escalate external messages
      // Matches: channel.groupPolicy, channel.allowFrom, channels.*
      if (
        !added.has('channel') &&
        (id.includes('channel') || title.includes('channel')) &&
        (id.includes('allow') || id.includes('group') || id.includes('policy') ||
         detail.includes('allowfrom') || detail.includes('open') ||
         title.includes('restriction') || title.includes('gate') || title.includes('group'))
      ) {
        added.add('channel');
        escalate.push(`Messages sent to external groups or channels require approval ${ref}`);
      }

      // gateway.host=0.0.0.0 → forbidden external gateway exposure
      if (
        !added.has('gateway') &&
        id.includes('gateway') && (id.includes('host') || detail.includes('0.0.0.0'))
      ) {
        added.add('gateway');
        forbidden.push(`Exposing the gateway to all network interfaces ${ref}`);
      }

      // credential files world-readable / secret exposure
      // Matches: cred.*, credential-file, cred.json_secrets, filesystem.perms
      if (
        !added.has('cred.perm') &&
        (id.includes('cred') || id.includes('credential') || id.includes('filesystem') ||
         id.includes('secret')) &&
        (id.includes('perm') || id.includes('secret') || id.includes('file') ||
         detail.includes('world') || detail.includes('readable') || detail.includes('permission') ||
         title.includes('permission') || title.includes('world') || title.includes('secret'))
      ) {
        added.add('cred.perm');
        forbidden.push(`Reading credential files with overly permissive file modes ${ref}`);
      }

      // skill supply chain
      if (
        !added.has('skill') &&
        id.includes('skill') &&
        (id.includes('pin') || id.includes('supply') || detail.includes('supply') ||
         detail.includes('unverified') || title.includes('pin') || title.includes('supply'))
      ) {
        added.add('skill');
        forbidden.push(`Loading unverified skills or skills without pinned versions ${ref}`);
      }
    }

    if (!escalate.length) {
      escalate.push('Any shell command execution');
      escalate.push('Any network request to external URLs not required by the task');
    }
  }

  lines.push('## Allowed');
  for (const item of allowed) lines.push(`- ${item}`);
  lines.push('');

  if (escalate.length) {
    lines.push('## Escalate (require human approval)');
    for (const item of escalate) lines.push(`- ${item}`);
    lines.push('');
  }

  lines.push('## Forbidden');
  for (const item of forbidden) lines.push(`- ${item}`);
  lines.push('');

  lines.push('---');
  lines.push('_To compile into deterministic rules:_');
  lines.push('```');
  lines.push('ironcurtain compile-policy ~/.ironcurtain/constitution-clawarmor.md');
  lines.push('```');
  lines.push('_To update after a new audit:_');
  lines.push('```');
  lines.push('clawarmor stack sync');
  lines.push('```');

  return lines.join('\n');
}

/**
 * Write constitution to ~/.ironcurtain/constitution-clawarmor.md.
 * @param {string} content
 * @returns {{ ok: boolean, err?: string, path: string }}
 */
export function writeConstitution(content) {
  try {
    if (!existsSync(IRONCURTAIN_DIR)) mkdirSync(IRONCURTAIN_DIR, { recursive: true });
    writeFileSync(CONSTITUTION_PATH, content, 'utf8');
    return { ok: true, path: CONSTITUTION_PATH };
  } catch (e) {
    return { ok: false, err: e.message?.split('\n')[0] || 'write failed', path: CONSTITUTION_PATH };
  }
}

/**
 * Check if ~/.ironcurtain/generated/ exists and has compiled output.
 * @returns {boolean}
 */
function checkCompiled() {
  const generatedDir = join(IRONCURTAIN_DIR, 'generated');
  if (!existsSync(generatedDir)) return false;
  try {
    const entries = readdirSync(generatedDir);
    return entries.length > 0;
  } catch { return false; }
}

/**
 * Get current status of IronCurtain integration.
 * @returns {{ installed: boolean, constitutionExists: boolean, constitutionPath: string, lastGenerated: string|null, compiled: boolean, enforcing: boolean }}
 */
export function getStatus() {
  const cliInstalled = checkInstalled();
  const constitutionExists = existsSync(CONSTITUTION_PATH);
  const compiled = checkCompiled();
  let lastGenerated = null;
  if (constitutionExists) {
    try { lastGenerated = statSync(CONSTITUTION_PATH).mtime.toISOString(); } catch { /* non-fatal */ }
  }
  // enforcing = cli installed + compiled output exists
  const enforcing = cliInstalled && compiled;
  return { installed: cliInstalled, cliInstalled, constitutionExists, constitutionPath: CONSTITUTION_PATH, lastGenerated, compiled, enforcing };
}
