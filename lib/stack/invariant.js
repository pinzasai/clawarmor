// lib/stack/invariant.js — Invariant Guardrails integration
// Invariant is a Python guardrailing library (invariantlabs-ai/invariant).
// Rules are plain Invariant DSL strings generated from audit findings.

import { existsSync, readFileSync, writeFileSync, mkdirSync, statSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import { execSync, spawnSync } from 'child_process';

const HOME = homedir();
const CLAWARMOR_DIR = join(HOME, '.clawarmor');
const RULES_PATH = join(CLAWARMOR_DIR, 'invariant-rules.inv');

/** Check if invariant-ai Python package is installed. */
export function checkInstalled() {
  try {
    const r = spawnSync('pip3', ['show', 'invariant-ai'], { encoding: 'utf8', timeout: 10000 });
    return r.status === 0 && !!(r.stdout && r.stdout.includes('Name:'));
  } catch { return false; }
}

/**
 * Install invariant-ai via pip3.
 * @returns {{ ok: boolean, err?: string }}
 */
export function install() {
  try {
    execSync('pip3 install invariant-ai', { stdio: 'pipe', timeout: 120000 });
    return { ok: true };
  } catch (e) {
    return { ok: false, err: e.message?.split('\n')[0] || 'pip3 install failed' };
  }
}

/**
 * Generate Invariant DSL rules from audit findings.
 *
 * Key mappings (from research):
 *   exec.security=full + exec.ask=off  → flag unrestricted exec tool calls
 *   channels with no allowFrom         → flag ungated message sends
 *   credential files world-readable    → block reads on sensitive paths
 *   skill supply chain findings        → block tool calls from unverified skill sources
 *   elevated.allowFrom empty           → flag escalated calls from non-allowlisted sources
 *
 * @param {Array} findings - array of { id, severity, title, detail }
 * @returns {string} Invariant policy (.inv) text
 */
export function generateRules(findings) {
  const now = new Date().toISOString().slice(0, 10);
  const lines = [
    `# ClawArmor-Generated Invariant Policy`,
    `# Generated: ${now} by clawarmor stack`,
    `# Source: clawarmor stack deploy --invariant`,
    '',
  ];

  if (!findings || !findings.length) {
    lines.push('# No findings from latest audit — no findings-specific rules generated.');
    lines.push('# Run: clawarmor audit, then: clawarmor stack sync');
    lines.push('');
    lines.push('# Generic fallback: prompt injection via web tool → send_message');
    lines.push('raise "Possible prompt injection via tool output" if:');
    lines.push('    (output: ToolOutput) -> (call2: ToolCall)');
    lines.push('    output is tool:get_website');
    lines.push('    prompt_injection(output.content, threshold=0.7)');
    lines.push('    call2 is tool:send_message');
    lines.push('');
    return lines.join('\n');
  }

  const generated = new Set();

  for (const finding of findings) {
    const id = (finding.id || '').toLowerCase();
    const detail = (finding.detail || '').toLowerCase();
    const title = (finding.title || '').toLowerCase();
    // label shown in rule comment — id is always present; title/severity optional
    const label = finding.title || finding.severity || finding.id;

    // exec.ask=off / exec unrestricted → flag bare exec tool calls
    // Matches: exec.approval, exec.ask, tools.exec.*
    if (
      !generated.has('exec.unrestricted') &&
      (id.includes('exec') || title.includes('exec')) &&
      (id.includes('ask') || id.includes('approval') || id.includes('exec') ||
       detail.includes('ask') || title.includes('approval') || title.includes('unrestricted') ||
       detail.includes('unrestricted'))
    ) {
      generated.add('exec.unrestricted');
      lines.push(`# Finding: ${finding.id} — ${label}`);
      lines.push(`raise "Unrestricted exec tool call detected (no approval gate)" if:`);
      lines.push(`    (call: ToolCall)`);
      lines.push(`    call is tool:exec`);
      lines.push('');
    }

    // channels with no allowFrom / open group policy → ungated message sends
    // Matches: channel.groupPolicy, channel.allowFrom, channels.*
    if (
      !generated.has('channel.ungated') &&
      (id.includes('channel') || title.includes('channel')) &&
      (id.includes('allow') || id.includes('group') || id.includes('policy') ||
       detail.includes('allowfrom') || title.includes('restriction') ||
       title.includes('gate') || title.includes('group') || detail.includes('open'))
    ) {
      generated.add('channel.ungated');
      lines.push(`# Finding: ${finding.id} — ${label}`);
      lines.push(`raise "Message sent via ungated channel (no allowFrom restriction)" if:`);
      lines.push(`    (call: ToolCall) -> (call2: ToolCall)`);
      lines.push(`    call is tool:read_file`);
      lines.push(`    call2 is tool:send_message({channel: ".*"})`);
      lines.push('');
    }

    // credential files / secret exposure → block reads on sensitive paths
    // Matches: cred.*, credential-file, cred.json_secrets, filesystem.perms
    if (
      !generated.has('cred.worldread') &&
      (id.includes('cred') || id.includes('credential') || id.includes('filesystem') ||
       id.includes('secret')) &&
      (id.includes('perm') || id.includes('secret') || id.includes('file') ||
       detail.includes('world') || detail.includes('readable') || detail.includes('permission') ||
       title.includes('world') || title.includes('permission') || title.includes('secret'))
    ) {
      generated.add('cred.worldread');
      lines.push(`# Finding: ${finding.id} — ${label}`);
      lines.push(`raise "File read on sensitive credential path" if:`);
      lines.push(`    (call: ToolCall)`);
      lines.push(`    call is tool:read_file`);
      lines.push(`    any(s in str(call.args.get("path", "")) for s in [".ssh", ".aws", "agent-accounts", ".openclaw"])`);
      lines.push('');
    }

    // skill supply chain — block tool calls from unverified sources
    // Matches: skill.pinning, skill.supplychain, skills.*
    if (
      !generated.has('skill.supplychain') &&
      id.includes('skill') &&
      (id.includes('pin') || id.includes('supply') || id.includes('md') ||
       detail.includes('supply') || detail.includes('unverified') ||
       title.includes('pin') || title.includes('supply'))
    ) {
      generated.add('skill.supplychain');
      lines.push(`# Finding: ${finding.id} — ${label}`);
      lines.push(`raise "Tool call from unverified skill source (no version pin)" if:`);
      lines.push(`    (call: ToolCall)`);
      lines.push(`    not call.metadata.get("skill_verified", False)`);
      lines.push('');
    }

    // elevated permissions with no allowFrom restriction
    // Matches: elevated.allowFrom, tools.elevated.*, allowFrom.*
    if (
      !generated.has('elevated.ungated') &&
      (id.includes('elevated') || id.includes('allowfrom') || title.includes('elevated'))
    ) {
      generated.add('elevated.ungated');
      lines.push(`# Finding: ${finding.id} — ${label}`);
      lines.push(`raise "Elevated tool call from ungated source" if:`);
      lines.push(`    (call: ToolCall)`);
      lines.push(`    call.metadata.get("elevated", False)`);
      lines.push(`    not call.metadata.get("allowFrom_restricted", False)`);
      lines.push('');
    }
  }

  if (!generated.size) {
    lines.push('# No specific rule mappings matched. Generic fallback:');
    lines.push('');
    lines.push('raise "Possible prompt injection via tool output" if:');
    lines.push('    (output: ToolOutput) -> (call2: ToolCall)');
    lines.push('    output is tool:get_website');
    lines.push('    prompt_injection(output.content, threshold=0.7)');
    lines.push('    call2 is tool:send_message');
    lines.push('');
  }

  return lines.join('\n');
}

/**
 * Write rules to ~/.clawarmor/invariant-rules.inv and validate syntax if invariant-ai is installed.
 * @param {string} rulesContent
 * @returns {{ ok: boolean, err?: string, rulesPath: string }}
 */
export function deploy(rulesContent) {
  try {
    if (!existsSync(CLAWARMOR_DIR)) mkdirSync(CLAWARMOR_DIR, { recursive: true });
    writeFileSync(RULES_PATH, rulesContent, 'utf8');

    // Validate syntax if invariant-ai is available (non-fatal if not)
    if (checkInstalled()) {
      const v = spawnSync('python3', [
        '-c',
        `from invariant.analyzer import LocalPolicy; LocalPolicy.from_file('${RULES_PATH}'); print('ok')`,
      ], { encoding: 'utf8', timeout: 30000 });
      if (v.status !== 0) {
        const msg = (v.stderr || '').split('\n')[0];
        return { ok: false, err: `Syntax validation failed: ${msg}`, rulesPath: RULES_PATH };
      }
    }
    return { ok: true, rulesPath: RULES_PATH };
  } catch (e) {
    return { ok: false, err: e.message?.split('\n')[0] || 'deploy failed', rulesPath: RULES_PATH };
  }
}

/**
 * Get current status of Invariant integration.
 * @returns {{ installed: boolean, rulesExist: boolean, rulesPath: string, ruleCount: number, lastDeployed: string|null, enforcing: boolean }}
 */
export function getStatus() {
  const installed = checkInstalled();
  const rulesExist = existsSync(RULES_PATH);
  let ruleCount = 0, lastDeployed = null;
  if (rulesExist) {
    try {
      const content = readFileSync(RULES_PATH, 'utf8');
      // Count non-comment rules (lines starting with 'raise')
      ruleCount = (content.match(/^raise /gm) || []).length;
      lastDeployed = statSync(RULES_PATH).mtime.toISOString();
    } catch { /* non-fatal */ }
  }
  // enforcing = pip installed + rules file exists + at least 1 non-comment rule
  const enforcing = installed && rulesExist && ruleCount > 0;
  return { installed, rulesExist, rulesPath: RULES_PATH, ruleCount, lastDeployed, enforcing };
}
