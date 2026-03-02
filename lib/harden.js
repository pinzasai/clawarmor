// clawarmor harden — Interactive security hardening wizard.
// Modes:
//   default:    show each fix, prompt y/N before applying
//   --dry-run:  show what WOULD be fixed, no writes
//   --auto:     apply all safe + caution fixes without confirmation (skips breaking)
//   --auto --force: apply ALL fixes including breaking ones

import { existsSync, readdirSync, statSync, readFileSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import { execSync, spawnSync } from 'child_process';
import { createInterface } from 'readline';
import { paint } from './output/colors.js';
import { scoreToGrade, scoreColor, gradeColor } from './output/progress.js';
import { loadConfig, get } from './config.js';
import { saveSnapshot } from './snapshot.js';
import { enableMonitor, disableMonitor, getMonitorStatus, printMonitorReport } from './monitor.js';
import { getProfile, isExpectedFinding, getOverriddenSeverity } from './profiles.js';

const HOME = homedir();
const OC_DIR = join(HOME, '.openclaw');
const CLAWARMOR_DIR = join(HOME, '.clawarmor');
const HISTORY_FILE = join(CLAWARMOR_DIR, 'history.json');
const CLI_PATH = new URL('../cli.js', import.meta.url).pathname;
const SEP = paint.dim('─'.repeat(52));

// ── Impact levels ─────────────────────────────────────────────────────────────
// SAFE:     No functionality impact. Pure security improvement.
// CAUTION:  May change agent behavior. User should be aware.
// BREAKING: Will disable or restrict features currently in use.

const IMPACT = {
  SAFE: 'safe',
  CAUTION: 'caution',
  BREAKING: 'breaking',
};

const IMPACT_BADGE = {
  [IMPACT.SAFE]:     (s) => paint.green(`🟢 Safe`),
  [IMPACT.CAUTION]:  (s) => paint.yellow(`🟡 Caution`),
  [IMPACT.BREAKING]: (s) => paint.red(`🔴 Breaking`),
};

const IMPACT_LABEL = {
  [IMPACT.SAFE]:     'No functionality impact',
  [IMPACT.CAUTION]:  'May change agent behavior',
  [IMPACT.BREAKING]: 'Will disable or restrict features you\'re actively using',
};

function box(title) {
  const W = 52, pad = W - 2 - title.length, l = Math.floor(pad / 2), r = pad - l;
  return [
    paint.dim('╔' + '═'.repeat(W - 2) + '╗'),
    paint.dim('║') + ' '.repeat(l) + paint.bold(title) + ' '.repeat(r) + paint.dim('║'),
    paint.dim('╚' + '═'.repeat(W - 2) + '╝'),
  ].join('\n');
}

// ── Fix discovery ────────────────────────────────────────────────────────────

function findWorldReadableCredFiles() {
  if (!existsSync(OC_DIR)) return [];
  const bad = [];
  try {
    const entries = readdirSync(OC_DIR, { withFileTypes: true });
    for (const entry of entries) {
      if (!entry.isFile()) continue;
      const filePath = join(OC_DIR, entry.name);
      let s;
      try { s = statSync(filePath); } catch { continue; }
      const mode = s.mode & 0o777;
      if (mode & 0o004 || mode & 0o040) {
        bad.push({ path: filePath, name: entry.name, mode: mode.toString(8) });
      }
    }
  } catch { /* non-fatal */ }
  return bad;
}

function buildFixes(config) {
  const fixes = [];

  // Fix 1: world/group-readable credential files — chmod 600
  const badFiles = findWorldReadableCredFiles();
  for (const f of badFiles) {
    // Classify: credential files (tokens, keys) are safe to lock down.
    // Config files that other tools might read need caution.
    const isSensitive = /\.(env|json|key|pem|token|secret)$/i.test(f.name) ||
                        f.name === 'agent-accounts.json' ||
                        f.name === 'openclaw.json';
    const isScript = /\.(py|sh|js|ts)$/i.test(f.name);

    fixes.push({
      id: `cred.perms.${f.name}`,
      problem: `${f.name} is readable by other users (permissions: ${f.mode})`,
      action: `chmod 600 ${f.path}`,
      description: `Set permissions to 600 (owner-only) on ${f.path}`,
      type: 'shell',
      impact: IMPACT.SAFE,
      impactDetail: isScript
        ? 'Only restricts other system users. Scripts will still run as you.'
        : 'Only restricts other system users from reading this file. Your agent is unaffected.',
      manualNote: null,
    });
  }

  // Fix 2: gateway.host = 0.0.0.0 → 127.0.0.1
  const gwHost = get(config, 'gateway.host', null);
  if (gwHost === '0.0.0.0') {
    fixes.push({
      id: 'gateway.host.open',
      problem: 'gateway.host is set to 0.0.0.0 — listens on all network interfaces',
      action: 'openclaw config set gateway.host 127.0.0.1',
      description: 'Change gateway.host to 127.0.0.1 (loopback only)',
      type: 'openclaw',
      impact: IMPACT.BREAKING,
      impactDetail: 'Remote connections to the gateway will stop working.\n' +
        '     If you access OpenClaw from other devices on your network (e.g. phone,\n' +
        '     tablet, or another computer), those connections will be blocked.\n' +
        '     Only localhost access will work after this change.',
      manualNote: 'Restart gateway after applying: openclaw gateway restart',
    });
  }

  // Fix 3: exec.ask = off → always
  const execAsk = get(config, 'exec.ask', null) ?? get(config, 'tools.exec.ask', null);
  if (execAsk === 'off' || execAsk === false) {
    fixes.push({
      id: 'exec.ask.off',
      problem: 'exec.ask is off — shell commands run without user confirmation',
      action: 'openclaw config set tools.exec.ask on-miss',
      description: 'Enable exec approval for unrecognized commands',
      type: 'openclaw',
      impact: IMPACT.BREAKING,
      impactDetail: 'Your agent will need approval for shell commands not in the allowlist.\n' +
        '     Autonomous workflows (cron jobs, background tasks, sub-agents) that run\n' +
        '     shell commands may pause waiting for approval.\n' +
        '     You\'ll need to approve commands via the web UI or CLI.',
      manualNote: 'Restart gateway after applying: openclaw gateway restart',
    });
  }

  return fixes;
}

// ── Apply a single fix ────────────────────────────────────────────────────────

function applyFix(fix) {
  try {
    execSync(fix.action, { stdio: 'ignore', shell: true });
    return { ok: true };
  } catch (e) {
    return { ok: false, err: e.message.split('\n')[0] };
  }
}

// ── Re-run audit (JSON) for before/after score ────────────────────────────────

function runAuditJson() {
  try {
    const result = spawnSync(process.execPath, [CLI_PATH, 'audit', '--json'], {
      encoding: 'utf8',
      timeout: 30000,
      maxBuffer: 1024 * 1024,
    });
    if (result.stdout) {
      const jsonStart = result.stdout.indexOf('{');
      if (jsonStart !== -1) return JSON.parse(result.stdout.slice(jsonStart));
    }
  } catch { /* non-fatal */ }
  return null;
}

// ── Interactive y/N prompt ────────────────────────────────────────────────────

async function askYN(question) {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  return new Promise(resolve => {
    rl.question(question, answer => {
      rl.close();
      const a = answer.trim().toLowerCase();
      resolve(a === 'y' || a === 'yes');
    });
  });
}

// ── Load last history entry for before score ─────────────────────────────────

function loadLastHistoryEntry() {
  try {
    if (!existsSync(HISTORY_FILE)) return null;
    const h = JSON.parse(readFileSync(HISTORY_FILE, 'utf8'));
    if (!Array.isArray(h) || !h.length) return null;
    return h[h.length - 1];
  } catch { return null; }
}

// ── Manual follow-up items (things that require human action) ─────────────────

function getManualItems() {
  return [
    'Rotate tokens older than 90 days (run: clawarmor log --tokens)',
    'Review and rotate any compromised or exposed credentials',
    'Enable agent sandbox isolation if Docker Desktop is available',
  ];
}

// ── Collect current file permissions for shell chmod fixes ────────────────────

function collectFilePermissions(fixes) {
  const perms = {};
  for (const fix of fixes) {
    if (fix.type !== 'shell') continue;
    const m = fix.action.match(/^chmod\s+\d+\s+(.+)$/);
    if (!m) continue;
    const p = m[1].trim();
    try {
      const mode = statSync(p).mode & 0o777;
      perms[p] = mode.toString(8).padStart(3, '0');
    } catch { /* file may not exist */ }
  }
  return perms;
}

// ── Print impact summary ──────────────────────────────────────────────────────

function printImpactSummary(fixes) {
  const counts = { [IMPACT.SAFE]: 0, [IMPACT.CAUTION]: 0, [IMPACT.BREAKING]: 0 };
  for (const fix of fixes) counts[fix.impact]++;
  
  const parts = [];
  if (counts[IMPACT.SAFE]) parts.push(paint.green(`${counts[IMPACT.SAFE]} safe`));
  if (counts[IMPACT.CAUTION]) parts.push(paint.yellow(`${counts[IMPACT.CAUTION]} caution`));
  if (counts[IMPACT.BREAKING]) parts.push(paint.red(`${counts[IMPACT.BREAKING]} breaking`));
  
  return parts.join(paint.dim(' · '));
}

// ── Main export ───────────────────────────────────────────────────────────────

export async function runHarden(flags = {}) {
  // ── Monitor advisory flags (early return, no box) ──────────────────────────
  if (flags.monitorOff) {
    const ok = disableMonitor();
    console.log('');
    console.log(ok
      ? `  ${paint.green('✓')} Monitor mode disabled.`
      : `  ${paint.red('✗')} Failed to disable monitor mode.`);
    console.log('');
    return ok ? 0 : 1;
  }

  if (flags.monitorReport) {
    const status = getMonitorStatus();
    printMonitorReport(status);
    return 0;
  }

  // Load active profile (from flag or saved file)
  let profileName = flags.profile || null;
  if (!profileName) {
    try {
      const { readFileSync: rfs, existsSync: efs } = await import('fs');
      const { join: pjoin } = await import('path');
      const { homedir: phome } = await import('os');
      const pFile = pjoin(phome(), '.clawarmor', 'profile.json');
      if (efs(pFile)) profileName = JSON.parse(rfs(pFile, 'utf8')).name || null;
    } catch { /* non-fatal */ }
  }
  const profile = profileName ? getProfile(profileName) : null;

  console.log(''); console.log(box('ClawArmor Harden  v2.1')); console.log('');

  if (profile) {
    console.log(`  ${paint.dim('Profile:')} ${paint.cyan(profile.name)} ${paint.dim('—')} ${profile.description}`);
    console.log('');
  }

  const { config, configPath } = loadConfig();
  const allFixes = buildFixes(config);

  // When profile is set, skip or adjust fixes for expected capabilities
  const fixes = allFixes.map(fix => {
    if (!profile) return fix;
    const overrideSev = getOverriddenSeverity(profile.name, fix.id);
    const expected = isExpectedFinding(profile.name, fix.id);
    if (expected) {
      // Mark as expected — skip entirely from harden output
      return { ...fix, _skipForProfile: true };
    }
    if (overrideSev) {
      // Upgrade to higher severity if unexpected for this profile
      const currentWeight = { SAFE: 1, CAUTION: 2, BREAKING: 3 };
      const upgradeMap = { HIGH: IMPACT.BREAKING, MEDIUM: IMPACT.CAUTION, INFO: IMPACT.SAFE };
      const newImpact = upgradeMap[overrideSev] || fix.impact;
      return { ...fix, impact: newImpact, _profileOverride: overrideSev };
    }
    return fix;
  }).filter(fix => !fix._skipForProfile);

  // ── Monitor enable (advisory only, no apply) ───────────────────────────────
  if (flags.monitor) {
    const fixIds = fixes.map(f => f.id);
    const ok = enableMonitor(fixIds);
    if (ok) {
      console.log(`  ${paint.green('✓')} Monitor mode enabled.`);
      console.log(`  ${paint.dim('Observing:')} ${fixIds.length ? fixIds.join(', ') : 'no current fixes found'}`);
      console.log(`  ${paint.dim('Run')} ${paint.cyan('clawarmor harden --monitor-report')} ${paint.dim('to see what would have changed.')}`);
      console.log(`  ${paint.dim('Run')} ${paint.cyan('clawarmor harden --monitor-off')} ${paint.dim('to disable.')}`);
    } else {
      console.log(`  ${paint.red('✗')} Failed to enable monitor mode.`);
    }
    console.log('');
    return ok ? 0 : 1;
  }

  // Snapshot before score
  const before = loadLastHistoryEntry();
  const beforeScore = before?.score ?? null;
  const beforeGrade = before?.grade ?? null;

  // Count by impact
  const safeFixes = fixes.filter(f => f.impact === IMPACT.SAFE);
  const cautionFixes = fixes.filter(f => f.impact === IMPACT.CAUTION);
  const breakingFixes = fixes.filter(f => f.impact === IMPACT.BREAKING);

  // ── DRY RUN ────────────────────────────────────────────────────────────────
  if (flags.dryRun) {
    console.log(`  ${paint.cyan('Dry run — showing what would be fixed (no changes applied):')}`);
    console.log('');

    if (!fixes.length) {
      console.log(`  ${paint.green('✓')} No auto-fixable issues found.`);
      console.log(`  ${paint.dim('Run')} ${paint.cyan('clawarmor audit')} ${paint.dim('to see all findings.')}`);
      console.log('');
      return 0;
    }

    for (const fix of fixes) {
      const badge = IMPACT_BADGE[fix.impact]();
      console.log(`  ${paint.yellow('!')}  ${paint.bold(fix.problem)}`);
      console.log(`     ${paint.dim('Fix:')} ${fix.description}`);
      console.log(`     ${paint.dim('Cmd:')} ${fix.action}`);
      console.log(`     ${badge}${paint.dim(':')} ${fix.impactDetail}`);
      if (fix.manualNote) console.log(`     ${paint.dim('Note:')} ${fix.manualNote}`);
      console.log('');
    }

    console.log(SEP);
    console.log(`  ${fixes.length} fix${fixes.length !== 1 ? 'es' : ''} available: ${printImpactSummary(fixes)}`);
    console.log('');
    console.log(`  ${paint.dim('Run')} ${paint.cyan('clawarmor harden')} ${paint.dim('to apply interactively.')}`);
    console.log(`  ${paint.dim('Run')} ${paint.cyan('clawarmor harden --auto')} ${paint.dim('to apply safe + caution fixes.')}`);
    if (breakingFixes.length) {
      console.log(`  ${paint.dim('Run')} ${paint.cyan('clawarmor harden --auto --force')} ${paint.dim('to apply ALL fixes (including breaking).')}`);
    }
    console.log('');

    const manualItems = getManualItems();
    console.log(SEP);
    console.log(`  ${paint.bold('Manual follow-up required:')}`);
    for (const item of manualItems) {
      console.log(`    ${paint.dim('•')} ${item}`);
    }
    console.log('');
    return 0;
  }

  // ── AUTO or INTERACTIVE ────────────────────────────────────────────────────

  if (!fixes.length) {
    console.log(`  ${paint.green('✓')} No auto-fixable issues found. Your config looks good.`);
    console.log(`  ${paint.dim('Run')} ${paint.cyan('clawarmor audit')} ${paint.dim('for the full picture.')}`);
    console.log('');

    const manualItems = getManualItems();
    console.log(SEP);
    console.log(`  ${paint.bold('Manual follow-up required:')}`);
    for (const item of manualItems) {
      console.log(`    ${paint.dim('•')} ${item}`);
    }
    console.log('');
    return 0;
  }

  if (flags.auto) {
    // --auto mode: apply safe + caution, SKIP breaking unless --force
    const autoLabel = flags.force
      ? paint.cyan('Auto mode (--force) — applying ALL fixes including breaking')
      : paint.cyan('Auto mode — applying safe + caution fixes (skipping breaking)');
    console.log(`  ${autoLabel}`);
    console.log(`  ${paint.dim('Fixes found:')} ${printImpactSummary(fixes)}`);
  } else {
    console.log(`  ${paint.cyan('Interactive mode — review and apply fixes one by one')}`);
    console.log(`  ${paint.dim('Fixes found:')} ${printImpactSummary(fixes)}`);
  }
  console.log('');

  // ── Snapshot before applying any fix ──────────────────────────────────────
  const trigger = flags.auto
    ? (flags.force ? 'harden --auto --force' : 'harden --auto')
    : 'harden --interactive';
  const configContent = (() => { try { return readFileSync(configPath, 'utf8'); } catch { return null; } })();
  saveSnapshot({ trigger, configPath, configContent, filePermissions: collectFilePermissions(fixes), appliedFixes: fixes.map(f => f.id) });

  let applied = 0, skipped = 0, failed = 0, skippedBreaking = 0;
  const restartNotes = [];

  for (const fix of fixes) {
    const badge = IMPACT_BADGE[fix.impact]();

    console.log(SEP);
    console.log(`  ${badge}`);
    console.log(`  ${paint.bold('Problem:')}  ${fix.problem}`);
    console.log(`  ${paint.dim('Fix:')}      ${fix.description}`);
    console.log(`  ${paint.dim('Impact:')}   ${fix.impactDetail}`);
    console.log(`  ${paint.dim('Command:')} ${paint.dim(fix.action)}`);
    console.log('');

    let doApply;

    if (flags.auto) {
      // In auto mode: apply safe + caution, skip breaking unless --force
      if (fix.impact === IMPACT.BREAKING && !flags.force) {
        console.log(`  ${paint.red('⊘ Skipped')} ${paint.dim('(breaking — use --auto --force to include)')}`);
        skippedBreaking++;
        skipped++;
        console.log('');
        continue;
      }
      doApply = true;
    } else {
      // Interactive mode: always ask, but warn about breaking
      if (fix.impact === IMPACT.BREAKING) {
        console.log(`  ${paint.red('⚠  This fix will change how your agent works.')}`);
        console.log(`  ${paint.red('   Read the impact above carefully before applying.')}`);
        console.log('');
      }
      doApply = await askYN(`  Apply this fix? [y/N] `);
    }

    if (!doApply) {
      console.log(`  ${paint.dim('✗ Skipped')}`);
      skipped++;
      console.log('');
      continue;
    }

    const result = applyFix(fix);
    if (result.ok) {
      console.log(`  ${paint.green('✓ Fixed')}`);
      applied++;
      if (fix.manualNote) restartNotes.push(fix.manualNote);
    } else {
      console.log(`  ${paint.red('✗ Failed:')} ${result.err}`);
      failed++;
    }
    console.log('');
  }

  console.log(SEP);
  console.log('');
  console.log(`  Applied: ${paint.green(String(applied))}  Skipped: ${paint.dim(String(skipped))}  Failed: ${failed > 0 ? paint.red(String(failed)) : paint.dim('0')}`);

  if (skippedBreaking > 0) {
    console.log(`  ${paint.dim(`(${skippedBreaking} breaking fix${skippedBreaking !== 1 ? 'es' : ''} skipped — use --auto --force to include)`)}`);
  }

  // Restart notes
  if (restartNotes.length) {
    console.log('');
    for (const note of [...new Set(restartNotes)]) {
      console.log(`  ${paint.yellow('!')} ${note}`);
    }
  }

  // Manual follow-up
  console.log('');
  console.log(SEP);
  console.log(`  ${paint.bold('Manual follow-up required:')}`);
  const manualItems = getManualItems();
  for (const item of manualItems) {
    console.log(`    ${paint.dim('•')} ${item}`);
  }

  // Before/after score comparison (only if we applied something)
  if (applied > 0) {
    console.log('');
    console.log(SEP);
    console.log(`  ${paint.dim('Re-running audit to measure impact...')}`);
    const after = runAuditJson();
    const afterScore = after?.score ?? null;
    const afterGrade = after?.grade ?? null;

    if (afterScore !== null) {
      console.log('');
      if (beforeScore !== null) {
        const delta = afterScore - beforeScore;
        const deltaStr = delta > 0 ? paint.green(`+${delta}`) : delta < 0 ? paint.red(String(delta)) : paint.dim('±0');
        console.log(`  Before: ${scoreColor(beforeScore)(beforeScore + '/100')}  ${paint.dim('Grade:')} ${gradeColor(beforeGrade || scoreToGrade(beforeScore))}`);
        console.log(`  After:  ${scoreColor(afterScore)(afterScore + '/100')}  ${paint.dim('Grade:')} ${gradeColor(afterGrade || scoreToGrade(afterScore))}  ${deltaStr}`);
      } else {
        console.log(`  Score: ${scoreColor(afterScore)(afterScore + '/100')}  ${paint.dim('Grade:')} ${gradeColor(afterGrade || scoreToGrade(afterScore))}`);
      }
    }
  }

  console.log('');
  return failed > 0 ? 1 : 0;
}
