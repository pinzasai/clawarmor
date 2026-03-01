// ClawArmor v2.0 — Audit Log Viewer
// Reads ~/.clawarmor/audit.log (JSONL) and displays events in human-readable form.
// Flags: --since <Nd|Nh>  --json  --tokens

import { existsSync, readFileSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import { paint, severityColor } from './output/colors.js';

const LOG_FILE = join(homedir(), '.clawarmor', 'audit.log');
const SEP = paint.dim('─'.repeat(52));

function parseEntries() {
  if (!existsSync(LOG_FILE)) return null;
  const raw = readFileSync(LOG_FILE, 'utf8');
  return raw
    .split('\n')
    .filter(Boolean)
    .map(line => { try { return JSON.parse(line); } catch { return null; } })
    .filter(Boolean);
}

function parseSince(sinceArg) {
  if (!sinceArg) return null;
  const m = sinceArg.match(/^(\d+)(d|h)$/);
  if (!m) return null;
  const n = parseInt(m[1], 10);
  const ms = m[2] === 'd' ? n * 86_400_000 : n * 3_600_000;
  return new Date(Date.now() - ms);
}

function cmdColor(cmd) {
  switch (cmd) {
    case 'audit':   return paint.cyan(cmd.padEnd(7));
    case 'scan':    return paint.cyan(cmd.padEnd(7));
    case 'prescan': return paint.cyan(cmd.padEnd(7));
    case 'watch':   return paint.dim(cmd.padEnd(7));
    default:        return paint.dim((cmd || '?').padEnd(7));
  }
}

function formatScore(score, delta) {
  if (score == null) return '';
  const s = `${score}/100`;
  if (delta == null) return paint.bold(s);
  const dStr = delta >= 0 ? `+${delta}` : `${delta}`;
  const dColor = delta >= 0 ? paint.green : paint.red;
  return `${paint.bold(s)} ${dColor(dStr)}`;
}

function formatFindings(findings) {
  if (!Array.isArray(findings) || !findings.length) return paint.green('clean');
  const bySev = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const f of findings) bySev[f.severity] = (bySev[f.severity] || 0) + 1;
  const parts = [];
  if (bySev.CRITICAL) parts.push(paint.red(`${bySev.CRITICAL}C`));
  if (bySev.HIGH)     parts.push(paint.yellow(`${bySev.HIGH}H`));
  if (bySev.MEDIUM)   parts.push(paint.cyan(`${bySev.MEDIUM}M`));
  if (bySev.LOW || bySev.INFO)
    parts.push(paint.dim(`${(bySev.LOW || 0) + (bySev.INFO || 0)}L`));
  return parts.join(' ') || paint.green('clean');
}

function formatEntry(e) {
  const ts = new Date(e.ts).toLocaleString('en-US', { dateStyle: 'medium', timeStyle: 'short' });
  const cmd = cmdColor(e.cmd);
  const trigger = paint.dim(`[${e.trigger || 'manual'}]`);
  const scoreStr = formatScore(e.score, e.delta);
  const findingsStr = formatFindings(e.findings);
  const blocked = e.blocked === true ? `  ${paint.red('BLOCKED')}` : '';
  const skill = e.skill ? `  ${paint.cyan(e.skill)}` : '';

  const parts = [paint.dim(ts), cmd, trigger];
  if (scoreStr) parts.push(scoreStr);
  parts.push(findingsStr);

  return `  ${parts.join('  ')}${skill}${blocked}`;
}

export async function runLog(flags = {}) {
  const entries = parseEntries();

  if (!entries) {
    console.log('');
    console.log(`  No audit log yet. Run ${paint.cyan('clawarmor audit')} to start.`);
    console.log('');
    return 0;
  }

  let filtered = entries;

  // --since filter
  const since = parseSince(flags.since);
  if (since) {
    filtered = filtered.filter(e => new Date(e.ts) >= since);
  }

  // --tokens filter
  if (flags.tokens) {
    filtered = filtered.filter(e =>
      Array.isArray(e.findings) &&
      e.findings.some(f => (f.id || '').includes('token') || (f.id || '').includes('access'))
    );
  }

  // --json: raw JSONL output
  if (flags.json) {
    for (const e of filtered) console.log(JSON.stringify(e));
    return 0;
  }

  // Default: last 10 events
  const recent = filtered.slice(-10);

  console.log('');
  if (!recent.length) {
    console.log(`  No log entries match the given filters.`);
    console.log(`  ${paint.dim('Total entries in log:')} ${entries.length}`);
    console.log('');
    return 0;
  }

  console.log(SEP);
  const label = flags.since ? ` — since ${flags.since}` : ` — last ${recent.length}`;
  console.log(`  ${paint.bold('ClawArmor Audit Log')}${paint.dim(label)}`);
  console.log(SEP);
  console.log('');

  for (const e of recent) {
    console.log(formatEntry(e));
  }

  if (filtered.length > 10) {
    console.log('');
    console.log(`  ${paint.dim(`(showing 10 of ${filtered.length} entries — use --since to filter)`)}`);
  }

  console.log('');
  return 0;
}
