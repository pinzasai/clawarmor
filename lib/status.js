// clawarmor status — One-screen security posture dashboard.
// Shows: score+grade+trend, last audit, watcher, intercept, log, skills, config, credentials, next digest.

import { existsSync, readFileSync, readdirSync, statSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import { paint } from './output/colors.js';
import { scoreToGrade, scoreColor, gradeColor } from './output/progress.js';
import { watchDaemonStatus } from './watch.js';
import { getMonitorStatus } from './monitor.js';

const HOME = homedir();
const OC_DIR = join(HOME, '.openclaw');
const CLAWARMOR_DIR = join(HOME, '.clawarmor');
const LAST_SCORE_FILE = join(CLAWARMOR_DIR, 'last-score.json');
const HISTORY_FILE = join(CLAWARMOR_DIR, 'history.json');
const AUDIT_LOG = join(CLAWARMOR_DIR, 'audit.log');
const ZSHRC = join(HOME, '.zshrc');
const BASHRC = join(HOME, '.bashrc');
const FISH_FUNCTION_FILE = join(HOME, '.config', 'fish', 'functions', 'openclaw.fish');
const SHELL_MARKER = '# ClawArmor intercept — added by: clawarmor protect --install';
const CRON_JOBS_FILE = join(OC_DIR, 'cron', 'jobs.json');
const HOOKS_DIR = join(OC_DIR, 'hooks', 'clawarmor-guard');
const VERSION = '2.2.0';

const SEP = paint.dim('─'.repeat(52));

// ── Helpers ─────────────────────────────────────────────────────────────────

function readJson(file) {
  try {
    if (!existsSync(file)) return null;
    return JSON.parse(readFileSync(file, 'utf8'));
  } catch { return null; }
}

function timeAgo(isoString) {
  if (!isoString) return 'never';
  const ms = Date.now() - new Date(isoString).getTime();
  const secs = Math.floor(ms / 1000);
  if (secs < 60) return `${secs}s ago`;
  const mins = Math.floor(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function trendArrow(delta) {
  if (delta == null) return paint.dim('—');
  if (delta > 0) return paint.green(`↑+${delta}`);
  if (delta < 0) return paint.red(`↓${delta}`);
  return paint.dim('→±0');
}

function intercept() {
  const inZsh = existsSync(ZSHRC) && readFileSync(ZSHRC, 'utf8').includes(SHELL_MARKER);
  const inBash = existsSync(BASHRC) && readFileSync(BASHRC, 'utf8').includes(SHELL_MARKER);
  const inFish = existsSync(FISH_FUNCTION_FILE) && readFileSync(FISH_FUNCTION_FILE, 'utf8').includes(SHELL_MARKER);
  if (inZsh || inBash || inFish) {
    const where = [inZsh && '~/.zshrc', inBash && '~/.bashrc', inFish && '~/.config/fish'].filter(Boolean).join(', ');
    return { active: true, where };
  }
  return { active: false, where: null };
}

function hookFilesExist() {
  return existsSync(join(HOOKS_DIR, 'HOOK.md')) &&
         existsSync(join(HOOKS_DIR, 'handler.js'));
}

function parseAuditLog() {
  if (!existsSync(AUDIT_LOG)) return { count: 0, lastEntry: null };
  try {
    const lines = readFileSync(AUDIT_LOG, 'utf8')
      .split('\n')
      .filter(Boolean)
      .map(l => { try { return JSON.parse(l); } catch { return null; } })
      .filter(Boolean);
    return { count: lines.length, lastEntry: lines[lines.length - 1] || null };
  } catch { return { count: 0, lastEntry: null }; }
}

function countInstalledSkills() {
  const dirs = [];
  const userSkillsDir = join(OC_DIR, 'skills');
  if (existsSync(userSkillsDir)) {
    try {
      dirs.push(...readdirSync(userSkillsDir, { withFileTypes: true })
        .filter(e => e.isDirectory())
        .map(e => join(userSkillsDir, e.name)));
    } catch { /* skip */ }
  }
  return dirs.length;
}

function credentialSummary() {
  const credFile = join(OC_DIR, 'agent-accounts.json');
  if (!existsSync(credFile)) return { count: 0, oldestDays: null };
  try {
    const data = JSON.parse(readFileSync(credFile, 'utf8'));
    let tokens = [];
    if (Array.isArray(data)) tokens = data;
    else if (data.accounts) tokens = Object.values(data.accounts);
    else if (typeof data === 'object') tokens = Object.values(data);

    const count = tokens.length;

    let oldest = null;
    for (const tok of tokens) {
      if (tok && typeof tok === 'object') {
        const dateStr = tok.createdAt || tok.created_at || tok.timestamp || null;
        if (dateStr) {
          const d = new Date(dateStr);
          if (!isNaN(d) && (!oldest || d < oldest)) oldest = d;
        }
      }
    }
    const oldestDays = oldest ? Math.floor((Date.now() - oldest.getTime()) / 86_400_000) : null;
    return { count, oldestDays };
  } catch { return { count: 0, oldestDays: null }; }
}

function configBaselineStatus() {
  const baselineFile = join(CLAWARMOR_DIR, 'config-baseline.json');
  if (!existsSync(baselineFile)) return { status: 'unknown' };
  try {
    const baseline = JSON.parse(readFileSync(baselineFile, 'utf8'));
    return { status: 'baseline', at: baseline.at || null };
  } catch { return { status: 'unknown' }; }
}

function nextDigestDate() {
  const now = new Date();
  const dayOfWeek = now.getDay();
  const daysUntilSunday = dayOfWeek === 0 ? 7 : 7 - dayOfWeek;
  const next = new Date(now);
  next.setDate(now.getDate() + daysUntilSunday);
  next.setHours(9, 0, 0, 0);
  const daysUntil = Math.ceil((next - now) / 86_400_000);
  return {
    label: next.toLocaleDateString('en-US', { weekday: 'long', month: 'short', day: 'numeric' }),
    daysUntil,
  };
}

function digestInstalled() {
  const jobs = readJson(CRON_JOBS_FILE);
  if (!Array.isArray(jobs)) return false;
  return jobs.some(j => j.id === 'clawarmor-weekly-digest');
}

// ── Grade color (A+/A=green, B=yellow, C=orange/yellow, D/F=red) ─────────────

function gradeStatusColor(grade) {
  if (grade === 'A+' || grade === 'A') return paint.green;
  if (grade === 'B') return paint.yellow;
  if (grade === 'C') return paint.yellow; // no orange in ANSI; yellow is closest
  return paint.red; // D, F
}

// ── Main export ───────────────────────────────────────────────────────────────

export async function runStatus() {
  console.log('');
  console.log(`  ${paint.bold('ClawArmor')} ${paint.dim('v' + VERSION)} ${paint.dim('—')} ${paint.bold('Security Status')}`);
  console.log('');

  // ── Posture ──────────────────────────────────────────────────────────────
  const lastScore = readJson(LAST_SCORE_FILE);
  const history = readJson(HISTORY_FILE) || [];
  const latestHistoryForPosture = history.length ? history[history.length - 1] : null;

  let score = lastScore?.score ?? latestHistoryForPosture?.score ?? null;
  let grade = lastScore?.grade ?? latestHistoryForPosture?.grade ?? null;
  let scoreTs = lastScore?.timestamp ?? latestHistoryForPosture?.timestamp ?? null;

  let weekDelta = null;
  if (history.length >= 2) {
    const weekAgo = Date.now() - 7 * 86_400_000;
    const weekEntry = [...history].reverse().find(h => new Date(h.timestamp).getTime() < weekAgo);
    if (weekEntry && score != null) {
      weekDelta = score - weekEntry.score;
    }
  }

  if (score != null) {
    const grade2 = grade || scoreToGrade(score);
    const colorFn = scoreColor(score);
    const gradeFn = gradeStatusColor(grade2);
    const arrow = trendArrow(weekDelta);
    const weekNote = weekDelta != null ? paint.dim(' vs last week') : '';
    console.log(`  ${paint.dim('Posture')}       ${gradeFn(grade2)} ${colorFn(score + '/100')}   ${arrow}${weekNote}`);
  } else {
    console.log(`  ${paint.dim('Posture')}       ${paint.dim('No audit data — run: clawarmor audit')}`);
  }

  // ── Last audit ────────────────────────────────────────────────────────────
  const { count: logCount, lastEntry } = parseAuditLog();
  const lastAuditTs = lastEntry?.ts ?? scoreTs ?? null;
  const trigger = lastEntry?.trigger ?? 'manual';
  const auditAgo = lastAuditTs ? timeAgo(lastAuditTs) : 'never';
  console.log(`  ${paint.dim('Last audit')}    ${paint.bold(auditAgo)}  ${paint.dim('(' + trigger + ')')}`);

  // ── Watcher ───────────────────────────────────────────────────────────────
  const daemon = watchDaemonStatus();
  let watchStr;
  if (daemon.running) {
    watchStr = `${paint.green('●')} ${paint.bold('running')} ${paint.dim('(PID ' + daemon.pid + ')')}`;
  } else {
    watchStr = `${paint.red('○')} ${paint.red('stopped')}  ${paint.dim('→ run: clawarmor watch --daemon')}`;
  }
  console.log(`  ${paint.dim('Watcher')}       ${watchStr}`);

  // ── Monitor mode ──────────────────────────────────────────────────────────
  const monitorStatus = getMonitorStatus();
  if (monitorStatus.enabled) {
    const startedAgo = timeAgo(monitorStatus.startedAt);
    const fixCount = monitorStatus.fixes?.length || 0;
    console.log(`  ${paint.dim('Monitor')}       ${paint.yellow('●')} ${paint.bold('active')} ${paint.dim('(started ' + startedAgo + ', ' + fixCount + ' fix' + (fixCount !== 1 ? 'es' : '') + ')')}  ${paint.dim('→ clawarmor harden --monitor-report')}`);
  }

  // ── Shell intercept ───────────────────────────────────────────────────────
  const icp = intercept();
  const icpStr = icp.active
    ? `${paint.green('✓')} ${paint.bold('active')} ${paint.dim('(' + icp.where + ')')}`
    : `${paint.red('✗')} ${paint.dim('not installed')}`;
  console.log(`  ${paint.dim('Intercept')}     ${icpStr}`);

  // ── Audit log ─────────────────────────────────────────────────────────────
  console.log(`  ${paint.dim('Audit log')}     ${paint.bold(String(logCount))} ${paint.dim('events')}  ${paint.dim('(clawarmor log to view)')}`);

  console.log('');
  console.log(SEP);

  // ── Skills ────────────────────────────────────────────────────────────────
  const skillCount = countInstalledSkills();
  console.log(`  ${paint.dim('Skills')}        ${paint.bold(String(skillCount))} ${paint.dim('installed')}  ${paint.dim('(clawarmor scan to check)')}`);

  // ── Config baseline ───────────────────────────────────────────────────────
  const baseline = configBaselineStatus();
  const configStr = baseline.status === 'baseline'
    ? `${paint.green('Baseline match')} ${paint.green('✓')}`
    : paint.dim('No baseline yet — run: clawarmor audit');
  console.log(`  ${paint.dim('Config')}        ${configStr}`);

  // ── Credentials ───────────────────────────────────────────────────────────
  const creds = credentialSummary();
  let credStr = creds.count > 0
    ? `${paint.bold(String(creds.count))} ${paint.dim('tokens')}`
    : paint.dim('none found');
  if (creds.oldestDays != null) {
    const ageMark = creds.oldestDays > 90 ? paint.yellow('!') : paint.green('✓');
    credStr += `${paint.dim(', oldest:')} ${creds.oldestDays}d ${ageMark}`;
  }
  console.log(`  ${paint.dim('Credentials')}   ${credStr}`);

  console.log('');
  console.log(SEP);

  // ── Next digest ───────────────────────────────────────────────────────────
  const digestOk = digestInstalled();
  const nextDigest = nextDigestDate();
  if (digestOk) {
    console.log(`  ${paint.dim('Next digest')}   ${paint.bold(nextDigest.label)} ${paint.dim('(' + nextDigest.daysUntil + ' days)')}`);
  } else {
    console.log(`  ${paint.dim('Next digest')}   ${paint.dim('not scheduled')}  ${paint.dim('(run: clawarmor protect --install)')}`);
  }

  // ── Full protection footer ────────────────────────────────────────────────
  const hookOk = hookFilesExist();
  const fullProtection = hookOk && daemon.running && icp.active;
  console.log('');
  if (fullProtection) {
    console.log(`  Full protection: ${paint.green('[✓ YES]')}`);
  } else {
    console.log(`  Full protection: ${paint.red('[✗ NO')} ${paint.dim('— run clawarmor protect --install]')}`);
  }
  console.log('');
  return 0;
}
