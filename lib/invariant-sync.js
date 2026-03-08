// lib/invariant-sync.js — clawarmor invariant sync command
// v3.3.0: Deep Invariant integration
//
// Severity tiers:
//   CRITICAL/HIGH   → raise "..." if: ...  (hard enforcement — blocks the trace)
//   MEDIUM          → warn "..." if: ...   (monitoring/alerting — logs but allows)
//   LOW/INFO        → # informational comment only
//
// Optional push to running Invariant instance via Python bridge.

import { existsSync, readFileSync, writeFileSync, mkdirSync, statSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import { execSync, spawnSync } from 'child_process';
import { paint } from './output/colors.js';
import { getStackStatus } from './stack/index.js';
import { checkInstalled as invariantInstalled, install as installInvariant } from './stack/invariant.js';

const HOME = homedir();
const CLAWARMOR_DIR = join(HOME, '.clawarmor');
const AUDIT_LOG = join(CLAWARMOR_DIR, 'audit.log');

// Output paths
const POLICY_DIR = join(CLAWARMOR_DIR, 'invariant-policies');
const POLICY_PATH = join(POLICY_DIR, 'clawarmor.inv');
const REPORT_PATH = join(POLICY_DIR, 'sync-report.json');

const SEP = paint.dim('─'.repeat(52));

function box(title) {
  const W = 52, pad = W - 2 - title.length, l = Math.floor(pad / 2), r = pad - l;
  return [
    paint.dim('╔' + '═'.repeat(W - 2) + '╗'),
    paint.dim('║') + ' '.repeat(l) + paint.bold(title) + ' '.repeat(r) + paint.dim('║'),
    paint.dim('╚' + '═'.repeat(W - 2) + '╝'),
  ].join('\n');
}

// ── Policy generation ─────────────────────────────────────────────────────────

/**
 * Map a single finding to one or more Invariant policy clauses.
 * Returns { clauses: string[], tier: 'enforce'|'monitor'|'info', mapped: boolean }
 */
function findingToPolicy(finding) {
  const id       = (finding.id       || '').toLowerCase();
  const severity = (finding.severity || '').toUpperCase();
  const title    = (finding.title    || '').toLowerCase();
  const detail   = (finding.detail   || '').toLowerCase();

  // Determine enforcement tier from severity
  const tier =
    severity === 'CRITICAL' || severity === 'HIGH' ? 'enforce' :
    severity === 'MEDIUM' ? 'monitor' : 'info';

  const directive = tier === 'enforce' ? 'raise' : tier === 'monitor' ? 'warn' : null;
  const clauses = [];

  // ── exec.ask=off / unrestricted exec ──────────────────────────────────────
  if (
    (id.includes('exec') || title.includes('exec')) &&
    (id.includes('ask') || id.includes('approval') || title.includes('approval') ||
     title.includes('unrestricted') || detail.includes('unrestricted') || detail.includes('ask'))
  ) {
    if (directive) {
      clauses.push(
        `# Finding ${finding.id} [${severity}]: ${finding.title || 'Unrestricted exec'}`,
        `${directive} "[ClawArmor] Unrestricted exec tool call — no approval gate (finding: ${finding.id})" if:`,
        `    (call: ToolCall)`,
        `    call is tool:exec`,
        ``
      );
    } else {
      clauses.push(
        `# [INFO] Finding ${finding.id}: ${finding.title || 'Exec approval'} — consider enabling exec.ask`,
        ``
      );
    }
    return { clauses, tier, mapped: true };
  }

  // ── Credential files world-readable / permission issues ───────────────────
  if (
    (id.includes('cred') || id.includes('credential') || id.includes('filesystem') ||
     id.includes('secret') || id.includes('permission') || id.includes('perm')) &&
    (id.includes('perm') || id.includes('secret') || id.includes('file') ||
     detail.includes('world') || detail.includes('readable') || detail.includes('permission') ||
     title.includes('world') || title.includes('permission') || title.includes('credential'))
  ) {
    const sensitivePatterns = ['.ssh', '.aws', 'agent-accounts', '.openclaw', 'secrets'];
    if (directive) {
      clauses.push(
        `# Finding ${finding.id} [${severity}]: ${finding.title || 'Credential file exposure'}`,
        `${directive} "[ClawArmor] Read on sensitive credential path (finding: ${finding.id})" if:`,
        `    (call: ToolCall)`,
        `    call is tool:read_file`,
        `    any(s in str(call.args.get("path", "")) for s in ${JSON.stringify(sensitivePatterns)})`,
        ``
      );
    } else {
      clauses.push(
        `# [INFO] Finding ${finding.id}: ${finding.title || 'Credential file'} — review file permissions`,
        ``
      );
    }
    return { clauses, tier, mapped: true };
  }

  // ── Open channel policy / ungated sends ───────────────────────────────────
  if (
    (id.includes('channel') || title.includes('channel') || id.includes('group') ||
     title.includes('group') || id.includes('policy')) &&
    (id.includes('allow') || id.includes('group') || id.includes('policy') ||
     detail.includes('allowfrom') || detail.includes('open') || title.includes('open') ||
     title.includes('restriction') || title.includes('ungated'))
  ) {
    if (directive) {
      clauses.push(
        `# Finding ${finding.id} [${severity}]: ${finding.title || 'Open channel policy'}`,
        `${directive} "[ClawArmor] Message sent via ungated channel — no allowFrom restriction (finding: ${finding.id})" if:`,
        `    (call: ToolCall) -> (call2: ToolCall)`,
        `    call is tool:read_file`,
        `    call2 is tool:send_message`,
        `    not call2.args.get("channel_restricted", False)`,
        ``
      );
    } else {
      clauses.push(
        `# [INFO] Finding ${finding.id}: ${finding.title || 'Channel policy'} — consider restricting with allowFrom`,
        ``
      );
    }
    return { clauses, tier, mapped: true };
  }

  // ── Elevated tool calls with no restriction ───────────────────────────────
  if (
    id.includes('elevated') || title.includes('elevated') ||
    (id.includes('allowfrom') && (id.includes('elevated') || title.includes('elevated')))
  ) {
    if (directive) {
      clauses.push(
        `# Finding ${finding.id} [${severity}]: ${finding.title || 'Elevated tool access'}`,
        `${directive} "[ClawArmor] Elevated tool call from unrestricted source (finding: ${finding.id})" if:`,
        `    (call: ToolCall)`,
        `    call.metadata.get("elevated", False)`,
        `    not call.metadata.get("allowFrom_restricted", False)`,
        ``
      );
    } else {
      clauses.push(
        `# [INFO] Finding ${finding.id}: ${finding.title || 'Elevated access'} — restrict with allowFrom`,
        ``
      );
    }
    return { clauses, tier, mapped: true };
  }

  // ── Skill supply chain / unpinned skills ──────────────────────────────────
  if (
    id.includes('skill') &&
    (id.includes('pin') || id.includes('supply') || id.includes('chain') ||
     title.includes('supply') || title.includes('unverified') || title.includes('pin'))
  ) {
    if (directive) {
      clauses.push(
        `# Finding ${finding.id} [${severity}]: ${finding.title || 'Skill supply chain'}`,
        `${directive} "[ClawArmor] Tool call from unverified/unpinned skill (finding: ${finding.id})" if:`,
        `    (call: ToolCall)`,
        `    not call.metadata.get("skill_verified", False)`,
        `    not call.metadata.get("skill_pinned", False)`,
        ``
      );
    } else {
      clauses.push(
        `# [INFO] Finding ${finding.id}: ${finding.title || 'Skill pinning'} — pin skill versions`,
        ``
      );
    }
    return { clauses, tier, mapped: true };
  }

  // ── API keys / secrets in config files ────────────────────────────────────
  if (
    (id.includes('api') || id.includes('token') || id.includes('key') || id.includes('secret')) &&
    (id.includes('config') || id.includes('json') || id.includes('leak') || id.includes('exposure') ||
     title.includes('api key') || title.includes('token') || detail.includes('api key'))
  ) {
    if (directive) {
      clauses.push(
        `# Finding ${finding.id} [${severity}]: ${finding.title || 'API key/secret exposure'}`,
        `${directive} "[ClawArmor] Possible exfil of secrets — read sensitive config then send_message (finding: ${finding.id})" if:`,
        `    (output: ToolOutput) -> (call2: ToolCall)`,
        `    output is tool:read_file`,
        `    any(k in str(output.content) for k in ["apiKey", "api_key", "token", "secret", "password"])`,
        `    call2 is tool:send_message`,
        ``
      );
    } else {
      clauses.push(
        `# [INFO] Finding ${finding.id}: ${finding.title || 'Secrets in config'} — move secrets to env vars`,
        ``
      );
    }
    return { clauses, tier, mapped: true };
  }

  // ── Gateway / auth issues ──────────────────────────────────────────────────
  if (
    id.includes('gateway') || id.includes('auth') ||
    title.includes('gateway') || title.includes('auth') || title.includes('unauthenticated')
  ) {
    if (directive) {
      clauses.push(
        `# Finding ${finding.id} [${severity}]: ${finding.title || 'Gateway auth'}`,
        `${directive} "[ClawArmor] Unauthenticated gateway connection attempt (finding: ${finding.id})" if:`,
        `    (call: ToolCall)`,
        `    call is tool:gateway_connect`,
        `    not call.args.get("authenticated", False)`,
        ``
      );
    } else {
      clauses.push(
        `# [INFO] Finding ${finding.id}: ${finding.title || 'Auth issue'} — review gateway authentication`,
        ``
      );
    }
    return { clauses, tier, mapped: true };
  }

  // ── Unmapped finding ───────────────────────────────────────────────────────
  return {
    clauses: [`# [UNMAPPED] Finding ${finding.id} [${severity}]: ${finding.title || id} — no specific Invariant rule\n`],
    tier,
    mapped: false,
  };
}

/**
 * Generate a full Invariant policy file from all findings.
 * Returns { policy: string, stats: { enforce, monitor, info, unmapped, total } }
 */
export function generateEnhancedPolicy(findings) {
  const now = new Date().toISOString().slice(0, 10);
  const ts  = new Date().toISOString();

  const header = [
    `# ClawArmor v3.3.0 — Invariant Runtime Policy`,
    `# Generated: ${ts}`,
    `# Source:    clawarmor invariant sync`,
    `# Format:    Invariant DSL (.inv) — https://github.com/invariantlabs-ai/invariant`,
    `#`,
    `# Tier mapping:`,
    `#   CRITICAL/HIGH findings → raise "..." (hard enforcement, blocks trace)`,
    `#   MEDIUM findings        → warn "..."  (monitoring/alerting, logged)`,
    `#   LOW/INFO findings      → # comment   (informational, no enforcement)`,
    ``,
  ];

  const stats = { enforce: 0, monitor: 0, info: 0, unmapped: 0, total: 0 };

  if (!findings || !findings.length) {
    return {
      policy: [
        ...header,
        `# No findings from latest audit.`,
        `# Run: clawarmor audit  then  clawarmor invariant sync`,
        ``,
        `# Generic baseline: prompt injection via web tool → send_message`,
        `raise "[ClawArmor] Possible prompt injection: web content → outbound message" if:`,
        `    (output: ToolOutput) -> (call: ToolCall)`,
        `    output is tool:get_website`,
        `    prompt_injection(output.content, threshold=0.7)`,
        `    call is tool:send_message`,
        ``,
      ].join('\n'),
      stats,
    };
  }

  // Sort findings: CRITICAL first, then HIGH, MEDIUM, LOW, INFO
  const ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  const sorted = [...findings].sort((a, b) => {
    const sa = ORDER[(a.severity || '').toUpperCase()] ?? 5;
    const sb = ORDER[(b.severity || '').toUpperCase()] ?? 5;
    return sa - sb;
  });

  const enforceSections = [`# ═══ ENFORCEMENT POLICIES (CRITICAL/HIGH) ═══════════════════════════════\n`];
  const monitorSections = [`# ═══ MONITORING POLICIES (MEDIUM) ══════════════════════════════════════\n`];
  const infoSections    = [`# ═══ INFORMATIONAL (LOW/INFO) ════════════════════════════════════════\n`];

  // Deduplicate by policy key to avoid duplicate rules
  const seenKeys = new Set();

  for (const finding of sorted) {
    const { clauses, tier, mapped } = findingToPolicy(finding);
    stats.total++;
    if (!mapped) stats.unmapped++;

    // Build a dedup key from the first raise/warn line
    const raiseLine = clauses.find(l => l.startsWith('raise') || l.startsWith('warn') || l.startsWith('#'));
    const key = raiseLine?.slice(0, 80) || finding.id;
    if (seenKeys.has(key)) continue;
    seenKeys.add(key);

    if (tier === 'enforce') {
      stats.enforce++;
      enforceSections.push(...clauses);
    } else if (tier === 'monitor') {
      stats.monitor++;
      monitorSections.push(...clauses);
    } else {
      stats.info++;
      infoSections.push(...clauses);
    }
  }

  // Always include prompt injection baseline
  enforceSections.push(
    `# Baseline: prompt injection via web content → outbound message`,
    `raise "[ClawArmor] Prompt injection risk: web content flowing to outbound call" if:`,
    `    (output: ToolOutput) -> (call: ToolCall)`,
    `    output is tool:get_website`,
    `    prompt_injection(output.content, threshold=0.7)`,
    `    call is tool:send_message`,
    ``,
  );

  const allSections = [
    ...header,
    ...enforceSections,
    ``,
    ...monitorSections,
    ``,
    ...infoSections,
  ];

  return { policy: allSections.join('\n'), stats };
}

// ── Invariant push (optional) ─────────────────────────────────────────────────

/**
 * Attempt to push the policy to a running Invariant instance via Python bridge.
 * Invariant exposes LocalPolicy.from_string() — we validate + optionally hot-reload.
 * @param {string} policyContent
 * @param {{ host?: string, port?: number }} opts
 * @returns {{ ok: boolean, method: string, err?: string }}
 */
function pushToInvariant(policyContent, opts = {}) {
  if (!invariantInstalled()) {
    return { ok: false, method: 'pip', err: 'invariant-ai not installed — run: pip3 install invariant-ai' };
  }

  // Write policy to temp file for Python to load
  const tmpPath = join(CLAWARMOR_DIR, '.inv-push-tmp.inv');
  try {
    writeFileSync(tmpPath, policyContent, 'utf8');
  } catch (e) {
    return { ok: false, method: 'push', err: `Could not write temp file: ${e.message}` };
  }

  // Validate syntax first
  const validateScript = `
from invariant.analyzer import LocalPolicy
try:
    p = LocalPolicy.from_file('${tmpPath}')
    print('VALID:' + str(len(p.rules)) + ' rules')
except Exception as e:
    print('ERROR:' + str(e))
`.trim();

  const validateResult = spawnSync('python3', ['-c', validateScript], {
    encoding: 'utf8',
    timeout: 30000,
  });

  if (validateResult.status !== 0 || (validateResult.stdout || '').startsWith('ERROR:')) {
    const msg = (validateResult.stdout || validateResult.stderr || '').split('\n')[0].replace('ERROR:', '');
    return { ok: false, method: 'validate', err: `Policy syntax error: ${msg.trim()}` };
  }

  const validatedInfo = (validateResult.stdout || '').trim().replace('VALID:', '');

  // Try to push to a running Invariant gateway instance (if available)
  const host = opts.host || '127.0.0.1';
  const port = opts.port || 8000;

  const pushScript = `
import urllib.request, json, sys

policy_path = '${tmpPath}'
host = '${host}'
port = ${port}
url = f'http://{host}:{port}/api/policy/reload'

try:
    with open(policy_path) as f:
        policy_content = f.read()

    payload = json.dumps({'policy': policy_content, 'source': 'clawarmor-v3.3.0'}).encode()
    req = urllib.request.Request(url, data=payload, headers={'Content-Type': 'application/json'})
    resp = urllib.request.urlopen(req, timeout=5)
    print('PUSHED:' + resp.read().decode()[:200])
except urllib.error.URLError as e:
    # Instance not running — not an error, just not enforcing live
    print('OFFLINE:' + str(e.reason))
except Exception as e:
    print('OFFLINE:' + str(e))
`.trim();

  const pushResult = spawnSync('python3', ['-c', pushScript], {
    encoding: 'utf8',
    timeout: 10000,
  });

  const pushOut = (pushResult.stdout || '').trim();
  if (pushOut.startsWith('PUSHED:')) {
    return { ok: true, method: 'live-reload', validatedInfo, pushOut: pushOut.replace('PUSHED:', '') };
  } else {
    // Not running live — still OK (rules file written, will be picked up on next start)
    return { ok: true, method: 'file-only', validatedInfo, note: 'Invariant not running — policy written to disk, enforces on next start' };
  }
}

// ── Main command ──────────────────────────────────────────────────────────────

/**
 * Run `clawarmor invariant sync`.
 * @param {string[]} args
 * @returns {Promise<number>} exit code
 */
export async function runInvariantSync(args = []) {
  const push   = args.includes('--push');
  const dryRun = args.includes('--dry-run');
  const json   = args.includes('--json');

  const hostIdx = args.indexOf('--host');
  const host = hostIdx !== -1 ? args[hostIdx + 1] : null;
  const portIdx = args.indexOf('--port');
  const port = portIdx !== -1 ? parseInt(args[portIdx + 1], 10) || 8000 : 8000;

  if (!json) {
    console.log('');
    console.log(box('ClawArmor  Invariant Sync  v3.3.0'));
    console.log('');
  }

  // Load audit data
  const { audit, profile } = await getStackStatus();
  if (!audit) {
    if (json) {
      console.log(JSON.stringify({ ok: false, error: 'No audit data — run clawarmor audit first' }));
    } else {
      console.log(`  ${paint.yellow('!')} No audit data found.`);
      console.log(`  ${paint.dim('Run clawarmor audit first, then clawarmor invariant sync.')}`);
      console.log('');
    }
    return 1;
  }

  const findings = audit.findings ?? [];

  if (!json) {
    console.log(`  ${paint.dim('Audit score')}   ${profile.score ?? 'n/a'}/100  ${paint.dim('(' + findings.length + ' findings)')}`);
    console.log(`  ${paint.dim('Risk profile')}  ${profile.label}`);
    console.log('');
    console.log(SEP);
    console.log('');
    console.log(`  ${paint.cyan('Generating severity-tiered Invariant policies...')}`);
    console.log('');
  }

  const { policy, stats } = generateEnhancedPolicy(findings);

  if (!json) {
    console.log(`  ${paint.bold('Policy summary:')}`);
    console.log(`    ${paint.red('✗ Enforce')}  ${stats.enforce} ${paint.dim('rules (CRITICAL/HIGH → hard block)')}`);
    console.log(`    ${paint.yellow('! Monitor')}  ${stats.monitor} ${paint.dim('rules (MEDIUM → alert/log)')}`);
    console.log(`    ${paint.dim('  Info')}      ${stats.info} ${paint.dim('comments (LOW/INFO → guidance only)')}`);
    if (stats.unmapped > 0) {
      console.log(`    ${paint.dim('  Unmapped')}  ${stats.unmapped} ${paint.dim('findings (no specific Invariant mapping)')}`);
    }
    console.log('');
  }

  if (dryRun) {
    if (!json) {
      console.log(SEP);
      console.log(`  ${paint.dim('--dry-run: policy preview (not written):')}`);
      console.log('');
      const lines = policy.split('\n');
      for (const line of lines.slice(0, 60)) {
        console.log(`  ${paint.dim(line)}`);
      }
      if (lines.length > 60) {
        console.log(`  ${paint.dim(`  ... (${lines.length - 60} more lines)`)}`);
      }
      console.log('');
      console.log(`  ${paint.dim('Run without --dry-run to write and activate.')}`);
      console.log('');
    } else {
      console.log(JSON.stringify({ ok: true, dryRun: true, stats, policy }, null, 2));
    }
    return 0;
  }

  // Write policy file
  try {
    if (!existsSync(POLICY_DIR)) mkdirSync(POLICY_DIR, { recursive: true });
    writeFileSync(POLICY_PATH, policy, 'utf8');
  } catch (e) {
    if (json) {
      console.log(JSON.stringify({ ok: false, error: e.message }));
    } else {
      console.log(`  ${paint.red('✗')} Failed to write policy: ${e.message}`);
    }
    return 1;
  }

  // Write JSON sync report
  const report = {
    syncedAt: new Date().toISOString(),
    auditScore: profile.score,
    findingsCount: findings.length,
    stats,
    policyPath: POLICY_PATH,
    pushed: false,
    pushMethod: null,
    pushError: null,
  };

  if (!json) {
    console.log(`  ${paint.green('✓')} Policy written: ${POLICY_PATH}`);
    console.log('');
    console.log(SEP);
  }

  // Optional push
  if (push) {
    if (!json) {
      process.stdout.write(`  ${paint.dim('Pushing to Invariant instance...')} `);
    }
    const pushResult = pushToInvariant(policy, { host, port });
    report.pushed = pushResult.ok;
    report.pushMethod = pushResult.method;
    if (!pushResult.ok) {
      report.pushError = pushResult.err;
    }

    if (!json) {
      if (pushResult.method === 'live-reload') {
        process.stdout.write(paint.green('✓\n'));
        console.log(`  ${paint.green('✓')} Live-reloaded: Invariant instance updated immediately`);
        if (pushResult.validatedInfo) {
          console.log(`  ${paint.dim('Validated: ' + pushResult.validatedInfo + ' rules')}`);
        }
      } else if (pushResult.method === 'file-only') {
        process.stdout.write(paint.yellow('○\n'));
        console.log(`  ${paint.yellow('○')} Invariant instance not running — policy on disk, enforces on next start`);
        if (pushResult.validatedInfo) {
          console.log(`  ${paint.dim('Validated: ' + pushResult.validatedInfo + ' rules')}`);
        }
        if (pushResult.note) {
          console.log(`  ${paint.dim(pushResult.note)}`);
        }
      } else {
        process.stdout.write(paint.red('✗\n'));
        console.log(`  ${paint.red('Error:')} ${pushResult.err}`);
      }
      console.log('');
    }
  } else {
    if (!json) {
      console.log('');
      console.log(`  ${paint.dim('Tip: use --push to validate syntax + push to running Invariant instance')}`);
      console.log(`  ${paint.dim('     pip3 install invariant-ai  (required for --push)')}`);
      console.log('');
    }
  }

  // Write report
  try {
    writeFileSync(REPORT_PATH, JSON.stringify(report, null, 2), 'utf8');
  } catch { /* non-fatal */ }

  if (!json) {
    console.log(SEP);
    console.log('');
    console.log(`  ${paint.green('✓')} Invariant sync complete.`);
    console.log('');
    console.log(`  ${paint.dim('Policy file:')}  ${POLICY_PATH}`);
    console.log(`  ${paint.dim('Sync report:')} ${REPORT_PATH}`);
    console.log('');

    const invInstalled = invariantInstalled();
    if (!invInstalled) {
      console.log(`  ${paint.yellow('!')} invariant-ai not installed.`);
      console.log(`  ${paint.dim('Install to validate + push policies: pip3 install invariant-ai')}`);
      console.log(`  ${paint.dim('Then re-run: clawarmor invariant sync --push')}`);
      console.log('');
    } else {
      console.log(`  ${paint.dim('To activate enforcement:')}`);
      console.log(`    ${paint.cyan('clawarmor invariant sync --push')}  ${paint.dim('# push to running Invariant instance')}`);
      console.log('');
    }
  } else {
    console.log(JSON.stringify({ ok: true, ...report, policy }, null, 2));
  }

  return 0;
}

// ── Status subcommand ─────────────────────────────────────────────────────────

export async function runInvariantStatus() {
  console.log('');
  console.log(box('ClawArmor  Invariant Sync  v3.3.0'));
  console.log('');

  const installed = invariantInstalled();
  const policyExists = existsSync(POLICY_PATH);
  const reportExists = existsSync(REPORT_PATH);

  console.log(`  ${paint.bold('invariant-ai')}  ${installed ? paint.green('✓ installed') : paint.yellow('○ not installed')}`);
  if (!installed) {
    console.log(`    ${paint.dim('Install: pip3 install invariant-ai')}`);
  }
  console.log('');

  if (policyExists) {
    try {
      const content = readFileSync(POLICY_PATH, 'utf8');
      const raiseCount = (content.match(/^raise /gm) || []).length;
      const warnCount  = (content.match(/^warn /gm)  || []).length;
      const mtime = statSync(POLICY_PATH).mtime.toISOString().slice(0, 19).replace('T', ' ');
      console.log(`  ${paint.green('✓')} ${paint.bold('Policy file')}   ${POLICY_PATH}`);
      console.log(`    ${paint.dim('Rules:')}    ${raiseCount} enforce + ${warnCount} monitor`);
      console.log(`    ${paint.dim('Updated:')}  ${mtime}`);
    } catch { /* non-fatal */ }
  } else {
    console.log(`  ${paint.yellow('○')} ${paint.bold('Policy file')}   not synced`);
    console.log(`    ${paint.dim('Run: clawarmor invariant sync')}`);
  }
  console.log('');

  if (reportExists) {
    try {
      const report = JSON.parse(readFileSync(REPORT_PATH, 'utf8'));
      console.log(SEP);
      console.log(`  ${paint.bold('Last sync')}`);
      console.log(`    ${paint.dim('Date:')}         ${report.syncedAt?.slice(0, 19).replace('T', ' ') ?? 'unknown'}`);
      console.log(`    ${paint.dim('Audit score:')}  ${report.auditScore ?? 'n/a'}/100`);
      console.log(`    ${paint.dim('Findings:')}     ${report.findingsCount ?? 0}`);
      if (report.stats) {
        console.log(`    ${paint.dim('Policies:')}     ${report.stats.enforce ?? 0} enforce, ${report.stats.monitor ?? 0} monitor, ${report.stats.info ?? 0} info`);
      }
      if (report.pushed) {
        console.log(`    ${paint.dim('Pushed:')}       ${paint.green('yes')} (${report.pushMethod})`);
      } else if (report.pushError) {
        console.log(`    ${paint.dim('Pushed:')}       ${paint.yellow('no')} — ${report.pushError}`);
      }
    } catch { /* non-fatal */ }
  }
  console.log('');
  return 0;
}
