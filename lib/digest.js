// clawarmor digest — Weekly security digest + cron job installer.
// Reads ~/.clawarmor/audit.log for past 7 days and outputs a formatted summary.

import { existsSync, readFileSync, mkdirSync, writeFileSync, renameSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import { paint } from './output/colors.js';
import { scoreToGrade } from './output/progress.js';

const HOME = homedir();
const OC_DIR = join(HOME, '.openclaw');
const CLAWARMOR_DIR = join(HOME, '.clawarmor');
const AUDIT_LOG = join(CLAWARMOR_DIR, 'audit.log');
const HISTORY_FILE = join(CLAWARMOR_DIR, 'history.json');
const CRON_DIR = join(OC_DIR, 'cron');
const CRON_JOBS_FILE = join(CRON_DIR, 'jobs.json');

// ── Cron installer ────────────────────────────────────────────────────────────

export function installDigestCron() {
  try {
    mkdirSync(CRON_DIR, { recursive: true });

    let jobs = [];
    if (existsSync(CRON_JOBS_FILE)) {
      try { jobs = JSON.parse(readFileSync(CRON_JOBS_FILE, 'utf8')); }
      catch { jobs = []; }
      if (!Array.isArray(jobs)) jobs = [];
    }

    // Remove existing entry with same ID to avoid duplicates
    jobs = jobs.filter(j => j.id !== 'clawarmor-weekly-digest');

    jobs.push({
      id: 'clawarmor-weekly-digest',
      schedule: '0 9 * * 0',
      task: 'clawarmor digest',
      announce: true,
      deliver: 'main',
      description: 'ClawArmor weekly security digest — every Sunday at 9am',
    });

    const tmp = CRON_JOBS_FILE + '.tmp';
    writeFileSync(tmp, JSON.stringify(jobs, null, 2), 'utf8');
    renameSync(tmp, CRON_JOBS_FILE);
    return true;
  } catch { return false; }
}

// ── Log parsing ───────────────────────────────────────────────────────────────

function parseLog() {
  if (!existsSync(AUDIT_LOG)) return [];
  try {
    return readFileSync(AUDIT_LOG, 'utf8')
      .split('\n')
      .filter(Boolean)
      .map(l => { try { return JSON.parse(l); } catch { return null; } })
      .filter(Boolean);
  } catch { return []; }
}

function readHistory() {
  try {
    if (!existsSync(HISTORY_FILE)) return [];
    return JSON.parse(readFileSync(HISTORY_FILE, 'utf8')) || [];
  } catch { return []; }
}

function formatDateRange(from, to) {
  const opts = { month: 'short', day: 'numeric' };
  const f = from.toLocaleDateString('en-US', opts);
  const t = to.toLocaleDateString('en-US', opts);
  const year = to.getFullYear();
  return `${f} – ${t}, ${year}`;
}

function nextSunday() {
  const now = new Date();
  const day = now.getDay();
  const daysUntil = day === 0 ? 7 : 7 - day;
  const next = new Date(now);
  next.setDate(now.getDate() + daysUntil);
  next.setHours(9, 0, 0, 0);
  return next.toLocaleDateString('en-US', { weekday: 'long', month: 'long', day: 'numeric' });
}

// ── Main export ───────────────────────────────────────────────────────────────

export async function runDigest() {
  const now = new Date();
  const weekAgo = new Date(now.getTime() - 7 * 86_400_000);

  const allEntries = parseLog();
  const weekEntries = allEntries.filter(e => new Date(e.ts) >= weekAgo);

  const history = readHistory();
  const weekAgoHistory = [...history].reverse().find(h => new Date(h.timestamp) < weekAgo);

  // Current score from latest history entry
  const latestHistory = history[history.length - 1];
  const currentScore = latestHistory?.score ?? null;
  const currentGrade = latestHistory?.grade ?? (currentScore != null ? scoreToGrade(currentScore) : null);
  const prevScore = weekAgoHistory?.score ?? null;
  const scoreDelta = (currentScore != null && prevScore != null) ? currentScore - prevScore : null;

  // Stats from this week's log entries
  const auditsRun = weekEntries.filter(e => e.cmd === 'audit').length;
  const skillsScanned = weekEntries.filter(e => e.cmd === 'scan' || e.cmd === 'prescan').length;
  const incidents = weekEntries.filter(e =>
    Array.isArray(e.findings) && e.findings.some(f => f.severity === 'CRITICAL')
  ).length;
  const configChanges = weekEntries.filter(e => e.trigger === 'watch').length;

  // Collect still-open findings from latest audit history entry
  const openFindings = latestHistory?.failedIds ?? [];

  // ── Output ─────────────────────────────────────────────────────────────────
  const dateRange = formatDateRange(weekAgo, now);
  const arrowStr = scoreDelta != null
    ? (scoreDelta > 0 ? `↑+${scoreDelta}` : scoreDelta < 0 ? `↓${scoreDelta}` : '→±0')
    : '';

  console.log('');
  console.log(`  🛡 ClawArmor Weekly — ${dateRange}`);
  console.log('');

  if (currentScore != null) {
    const scoreStr = `${currentScore}/100 ${currentGrade}`;
    const deltaStr = arrowStr ? ` ${arrowStr} vs last week` : '';
    console.log(`  Security posture: ${scoreStr}${deltaStr}`);
  } else {
    console.log(`  Security posture: no data — run: clawarmor audit`);
  }

  console.log(`  Skills installed: ${skillsScanned} scanned this week`);
  console.log(`  Config changes:   ${configChanges}`);
  console.log(`  Audits run:       ${auditsRun}`);
  console.log(`  Incidents:        ${incidents}`);

  if (openFindings.length) {
    console.log('');
    console.log(`  Recommendations:`);
    for (const id of openFindings.slice(0, 5)) {
      console.log(`    • ${id}`);
    }
    if (openFindings.length > 5) {
      console.log(`    • … and ${openFindings.length - 5} more (run: clawarmor audit)`);
    }
  }

  console.log('');
  console.log(`  Next digest: ${nextSunday()}`);
  console.log('');

  return 0;
}
