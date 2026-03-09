// ClawArmor v3.6.0 — report --compare command
// Diffs two ClawArmor report JSON files to show security drift over time.

import { readFileSync, existsSync } from 'fs';
import { paint, severityColor } from './output/colors.js';

const SEP = paint.dim('─'.repeat(60));
const SEP_SHORT = paint.dim('─'.repeat(40));

function box(title) {
  const W = 60, pad = W - 2 - title.length;
  const l = Math.floor(pad / 2), r = pad - l;
  return [
    paint.dim('╔' + '═'.repeat(W - 2) + '╗'),
    paint.dim('║') + ' '.repeat(l) + paint.bold(title) + ' '.repeat(r) + paint.dim('║'),
    paint.dim('╚' + '═'.repeat(W - 2) + '╝'),
  ].join('\n');
}

function formatTimestamp(ts) {
  if (!ts) return 'unknown';
  try {
    return new Date(ts).toLocaleString('en-US', {
      year: 'numeric', month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit', hour12: false,
    });
  } catch {
    return ts;
  }
}

function getScore(report) {
  // scan reports have top-level score, harden reports don't
  if (typeof report.score === 'number') return report.score;
  const summary = report.summary || {};
  if (typeof summary.score === 'number') return summary.score;
  return null;
}

function getReportType(report) {
  // Detect report type from command field or structure
  if (report.command) return report.command;
  if (Array.isArray(report.checks)) return 'scan';
  if (Array.isArray(report.items)) return 'harden';
  return 'unknown';
}

/**
 * Normalize checks from any report format into a common shape:
 * { id, name, status, severity, detail }
 *
 * Scan reports: checks[] with { name, status, severity, detail }
 * Harden reports: items[] with { check, status, action }
 */
function normalizeChecks(report) {
  const checks = [];

  // Scan report format
  if (Array.isArray(report.checks)) {
    for (const c of report.checks) {
      const id = c.id || c.name;
      checks.push({
        id,
        name: c.name || id,
        status: c.status,   // 'pass' | 'warn' | 'block' | 'info'
        severity: c.severity || 'NONE',
        detail: c.detail || '',
      });
    }
  }

  // Harden report format
  if (Array.isArray(report.items)) {
    for (const item of report.items) {
      const id = item.check || item.id;
      checks.push({
        id,
        name: item.check || id,
        status: item.status,  // 'hardened' | 'already_good' | 'skipped' | 'failed'
        severity: item.severity || 'NONE',
        detail: item.action || item.detail || '',
      });
    }
  }

  return checks;
}

function isPass(status) {
  return status === 'pass' || status === 'already_good';
}

function isFail(status) {
  return status === 'block' || status === 'fail' || status === 'failed';
}

function isWarn(status) {
  return status === 'warn' || status === 'skipped';
}

function statusLabel(status) {
  if (isPass(status)) return paint.green(status.toUpperCase());
  if (isFail(status)) return paint.red(status.toUpperCase());
  if (isWarn(status)) return paint.yellow(status.toUpperCase());
  return paint.dim(status.toUpperCase());
}

/**
 * Core diff logic — exported for unit testing.
 *
 * Returns:
 * {
 *   regressions:  [{ id, name, oldStatus, newStatus, severity, detail }]
 *   improvements: [{ id, name, oldStatus, newStatus, severity, detail }]
 *   newIssues:    [{ id, name, status, severity, detail }]
 *   resolved:     [{ id, name, status, severity, detail }]
 *   unchanged:    number
 *   scoreOld:     number|null
 *   scoreNew:     number|null
 * }
 */
export function diffReports(report1, report2) {
  const checks1 = normalizeChecks(report1);
  const checks2 = normalizeChecks(report2);

  const map1 = new Map(checks1.map(c => [c.id, c]));
  const map2 = new Map(checks2.map(c => [c.id, c]));

  const regressions = [];
  const improvements = [];
  const newIssues = [];
  const resolved = [];
  let unchanged = 0;

  // Check all IDs from file2
  for (const [id, c2] of map2) {
    if (!map1.has(id)) {
      // New check in file2
      if (!isPass(c2.status)) {
        newIssues.push(c2);
      }
      continue;
    }

    const c1 = map1.get(id);
    if (isPass(c1.status) && !isPass(c2.status)) {
      // Was passing, now failing/warning → regression
      regressions.push({
        id,
        name: c2.name,
        oldStatus: c1.status,
        newStatus: c2.status,
        severity: c2.severity,
        detail: c2.detail,
      });
    } else if (!isPass(c1.status) && isPass(c2.status)) {
      // Was failing/warning, now passing → improvement
      improvements.push({
        id,
        name: c2.name,
        oldStatus: c1.status,
        newStatus: c2.status,
        severity: c1.severity,
        detail: c2.detail,
      });
    } else {
      unchanged++;
    }
  }

  // Checks only in file1 (resolved / no longer present)
  for (const [id, c1] of map1) {
    if (!map2.has(id) && !isPass(c1.status)) {
      resolved.push(c1);
    } else if (!map2.has(id) && isPass(c1.status)) {
      // Was passing, no longer checked — just ignore (counts as unchanged context)
      unchanged++;
    }
  }

  return {
    regressions,
    improvements,
    newIssues,
    resolved,
    unchanged,
    scoreOld: getScore(report1),
    scoreNew: getScore(report2),
  };
}

export async function runReportCompare(file1, file2) {
  // ── Validate inputs ──────────────────────────────────────────────────────────
  if (!file1 || !file2) {
    console.error('');
    console.error(`  ${paint.red('✗')} Usage: clawarmor report --compare <file1> <file2>`);
    console.error(`  ${paint.dim('Example: clawarmor report --compare old-report.json new-report.json')}`);
    console.error('');
    return 1;
  }

  if (!existsSync(file1)) {
    console.error('');
    console.error(`  ${paint.red('✗')} File not found: ${file1}`);
    console.error('');
    return 1;
  }

  if (!existsSync(file2)) {
    console.error('');
    console.error(`  ${paint.red('✗')} File not found: ${file2}`);
    console.error('');
    return 1;
  }

  let report1, report2;
  try {
    report1 = JSON.parse(readFileSync(file1, 'utf8'));
  } catch (e) {
    console.error('');
    console.error(`  ${paint.red('✗')} Could not parse ${file1}: ${e.message}`);
    console.error('');
    return 1;
  }

  try {
    report2 = JSON.parse(readFileSync(file2, 'utf8'));
  } catch (e) {
    console.error('');
    console.error(`  ${paint.red('✗')} Could not parse ${file2}: ${e.message}`);
    console.error('');
    return 1;
  }

  // ── Header ───────────────────────────────────────────────────────────────────
  console.log('');
  console.log(box('ClawArmor — Security Drift Report'));
  console.log('');

  const type1 = getReportType(report1);
  const type2 = getReportType(report2);

  if (type1 !== type2) {
    console.log(`  ${paint.yellow('⚠')}  Report types differ: ${paint.bold(type1)} vs ${paint.bold(type2)}`);
    console.log(`     ${paint.dim('Comparison may be incomplete — check IDs may not align.')}`);
    console.log('');
  }

  console.log(`  ${paint.dim('Baseline:')}  ${formatTimestamp(report1.timestamp)}  ${paint.dim('(' + file1 + ')')}`);
  console.log(`  ${paint.dim('Current:')}   ${formatTimestamp(report2.timestamp)}  ${paint.dim('(' + file2 + ')')}`);
  console.log('');

  // ── Score delta ───────────────────────────────────────────────────────────────
  const diff = diffReports(report1, report2);

  if (diff.scoreOld !== null && diff.scoreNew !== null) {
    const delta = diff.scoreNew - diff.scoreOld;
    const deltaStr = delta > 0 ? paint.green(`+${delta}`) : delta < 0 ? paint.red(`${delta}`) : paint.dim('±0');
    const oldColor = diff.scoreOld >= 80 ? paint.green : diff.scoreOld >= 60 ? paint.yellow : paint.red;
    const newColor = diff.scoreNew >= 80 ? paint.green : diff.scoreNew >= 60 ? paint.yellow : paint.red;
    console.log(`  ${paint.bold('Score:')} ${oldColor(String(diff.scoreOld))} → ${newColor(String(diff.scoreNew))} (${deltaStr})`);
    console.log('');
  } else if (diff.scoreOld !== null || diff.scoreNew !== null) {
    const s = diff.scoreOld ?? diff.scoreNew;
    console.log(`  ${paint.bold('Score:')} ${paint.dim('N/A')} → ${s} ${paint.dim('(only one report has a score)')}`);
    console.log('');
  }

  // ── Regressions ──────────────────────────────────────────────────────────────
  console.log(SEP);
  if (diff.regressions.length === 0) {
    console.log(`  ${paint.green('✓')} ${paint.bold('No regressions')} — nothing got worse`);
  } else {
    console.log(`  ${paint.red('✗')} ${paint.bold(`Regressions (${diff.regressions.length})`)} — ${paint.red('things that got worse')}`);
    console.log(SEP);
    for (const r of diff.regressions) {
      const sevCol = severityColor[r.severity] || paint.dim;
      console.log(`  ${paint.red('↓')} ${paint.bold(r.name)}`);
      console.log(`     ${paint.dim('Was:')} ${statusLabel(r.oldStatus)}  ${paint.dim('→')}  ${paint.dim('Now:')} ${statusLabel(r.newStatus)}  ${sevCol('[' + r.severity + ']')}`);
      if (r.detail) console.log(`     ${paint.dim(r.detail)}`);
    }
  }
  console.log('');

  // ── Improvements ─────────────────────────────────────────────────────────────
  console.log(SEP);
  if (diff.improvements.length === 0) {
    console.log(`  ${paint.dim('─')} No improvements`);
  } else {
    console.log(`  ${paint.green('✓')} ${paint.bold(`Improvements (${diff.improvements.length})`)} — ${paint.green('things that got better')}`);
    console.log(SEP);
    for (const r of diff.improvements) {
      const sevCol = severityColor[r.severity] || paint.dim;
      console.log(`  ${paint.green('↑')} ${paint.bold(r.name)}`);
      console.log(`     ${paint.dim('Was:')} ${statusLabel(r.oldStatus)}  ${paint.dim('→')}  ${paint.dim('Now:')} ${statusLabel(r.newStatus)}  ${sevCol('[' + r.severity + ']')}`);
      if (r.detail) console.log(`     ${paint.dim(r.detail)}`);
    }
  }
  console.log('');

  // ── New Issues ────────────────────────────────────────────────────────────────
  console.log(SEP);
  if (diff.newIssues.length === 0) {
    console.log(`  ${paint.dim('─')} No new issues`);
  } else {
    console.log(`  ${paint.yellow('!')} ${paint.bold(`New Issues (${diff.newIssues.length})`)} — ${paint.yellow('checks not in baseline report')}`);
    console.log(SEP);
    for (const r of diff.newIssues) {
      const sevCol = severityColor[r.severity] || paint.dim;
      console.log(`  ${paint.yellow('+')} ${paint.bold(r.name)}  ${sevCol('[' + r.severity + ']')}`);
      if (r.detail) console.log(`     ${paint.dim(r.detail)}`);
    }
  }
  console.log('');

  // ── Resolved ─────────────────────────────────────────────────────────────────
  console.log(SEP);
  if (diff.resolved.length === 0) {
    console.log(`  ${paint.dim('─')} Nothing resolved`);
  } else {
    console.log(`  ${paint.green('✓')} ${paint.bold(`Resolved (${diff.resolved.length})`)} — ${paint.green('issues no longer present')}`);
    console.log(SEP);
    for (const r of diff.resolved) {
      console.log(`  ${paint.green('✓')} ${paint.bold(r.name)}  ${paint.dim('[' + r.severity + ']')}`);
      if (r.detail) console.log(`     ${paint.dim(r.detail)}`);
    }
  }
  console.log('');

  // ── Summary ───────────────────────────────────────────────────────────────────
  console.log(SEP);
  console.log(`  ${paint.bold('Summary')}`);
  console.log(SEP);
  console.log(`  ${paint.red('Regressions:')}   ${diff.regressions.length}`);
  console.log(`  ${paint.green('Improvements:')}  ${diff.improvements.length}`);
  console.log(`  ${paint.yellow('New Issues:')}    ${diff.newIssues.length}`);
  console.log(`  ${paint.green('Resolved:')}      ${diff.resolved.length}`);
  console.log(`  ${paint.dim('Unchanged:')}     ${diff.unchanged}`);
  console.log('');

  if (diff.regressions.length > 0) {
    console.log(`  ${paint.red('⚠')}  ${paint.bold(diff.regressions.length + ' regression(s) detected.')}  Exit code: 1`);
    console.log('');
    return 1;
  }

  console.log(`  ${paint.green('✓')} ${paint.bold('No regressions.')}  Exit code: 0`);
  console.log('');
  return 0;
}
