// clawarmor monitor — Monitor mode state management and reporting.
// Monitor state stored in ~/.clawarmor/monitor.json:
//   { enabled: true, startedAt: ISO, fixes: [fix ids being monitored] }
// Advisory only — no config changes are applied.

import { existsSync, mkdirSync, readFileSync, writeFileSync, unlinkSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import { paint } from './output/colors.js';

const HOME = homedir();
const CLAWARMOR_DIR = join(HOME, '.clawarmor');
const MONITOR_FILE = join(CLAWARMOR_DIR, 'monitor.json');
const AUDIT_LOG = join(CLAWARMOR_DIR, 'audit.log');

const SEP = paint.dim('─'.repeat(52));

/**
 * Get current monitor mode status.
 * @returns {{ enabled: boolean, startedAt?: string, fixes?: string[] }}
 */
export function getMonitorStatus() {
  if (!existsSync(MONITOR_FILE)) return { enabled: false };
  try { return JSON.parse(readFileSync(MONITOR_FILE, 'utf8')); } catch { return { enabled: false }; }
}

/**
 * Enable monitor mode, recording the fix ids to observe.
 * @param {string[]} fixIds
 * @returns {boolean} success
 */
export function enableMonitor(fixIds = []) {
  try {
    if (!existsSync(CLAWARMOR_DIR)) mkdirSync(CLAWARMOR_DIR, { recursive: true });
    const data = { enabled: true, startedAt: new Date().toISOString(), fixes: fixIds };
    writeFileSync(MONITOR_FILE, JSON.stringify(data, null, 2), 'utf8');
    return true;
  } catch { return false; }
}

/**
 * Disable monitor mode by removing the state file.
 * @returns {boolean} success
 */
export function disableMonitor() {
  try {
    if (existsSync(MONITOR_FILE)) unlinkSync(MONITOR_FILE);
    return true;
  } catch { return false; }
}

/** @returns {Array<Object>} parsed audit log entries since given ISO timestamp */
function readAuditsSince(sinceIso) {
  if (!existsSync(AUDIT_LOG)) return [];
  try {
    const since = new Date(sinceIso).getTime();
    return readFileSync(AUDIT_LOG, 'utf8')
      .split('\n').filter(Boolean)
      .map(l => { try { return JSON.parse(l); } catch { return null; } })
      .filter(l => l && new Date(l.ts).getTime() >= since);
  } catch { return []; }
}

/**
 * Print a monitor mode report showing audit activity since monitoring started.
 * @param {{ enabled: boolean, startedAt?: string, fixes?: string[] }} status
 */
export function printMonitorReport(status) {
  console.log('');
  console.log(`  ${paint.bold('Monitor Mode Report')}`);
  console.log('');

  if (!status.enabled || !status.startedAt) {
    console.log(`  ${paint.dim('Monitor mode is not active.')}`);
    console.log(`  ${paint.dim('Enable with:')} ${paint.cyan('clawarmor harden --monitor')}`);
    console.log('');
    return;
  }

  const monitoredFixes = status.fixes || [];
  const audits = readAuditsSince(status.startedAt);

  console.log(`  ${paint.dim('Started:')}      ${new Date(status.startedAt).toLocaleString()}`);
  console.log(`  ${paint.dim('Monitoring:')}   ${monitoredFixes.length ? monitoredFixes.join(', ') : 'all available fixes'}`);
  console.log(`  ${paint.dim('Audits run:')}   ${audits.length}`);
  console.log('');

  if (!audits.length) {
    console.log(`  ${paint.dim('No audits found since monitoring started.')}`);
    console.log(`  ${paint.dim('Run')} ${paint.cyan('clawarmor audit')} ${paint.dim('to generate data.')}`);
    console.log('');
    return;
  }

  console.log(SEP);
  console.log('');

  const scores = audits.map(a => a.score).filter(s => typeof s === 'number');
  if (scores.length >= 2) {
    const delta = scores[scores.length - 1] - scores[0];
    const deltaStr = delta > 0 ? paint.green(`+${delta}`) : delta < 0 ? paint.red(String(delta)) : paint.dim('±0');
    console.log(`  ${paint.dim('Score change:')} ${scores[0]} → ${scores[scores.length - 1]} (${deltaStr})`);
  } else if (scores.length === 1) {
    console.log(`  ${paint.dim('Score observed:')} ${scores[0]}`);
  }

  let criticalCount = 0, highCount = 0;
  for (const a of audits) {
    if (Array.isArray(a.findings)) {
      for (const f of a.findings) {
        if (f.severity === 'CRITICAL') criticalCount++;
        else if (f.severity === 'HIGH') highCount++;
      }
    }
  }
  if (criticalCount > 0 || highCount > 0) {
    console.log(`  ${paint.dim('Findings:')}     ${paint.red(String(criticalCount) + ' critical')} ${paint.dim('·')} ${paint.yellow(String(highCount) + ' high')}`);
  }

  console.log('');

  const lastScore = scores.length ? scores[scores.length - 1] : null;
  if (lastScore !== null && lastScore < 75) {
    console.log(`  ${paint.yellow('!')} ${paint.bold('Recommendation:')} Score is below 75. Consider applying fixes:`);
    console.log(`     ${paint.dim('Run:')} ${paint.cyan('clawarmor harden')}`);
  } else {
    console.log(`  ${paint.green('✓')} Monitoring period looks stable.`);
    console.log(`  ${paint.dim('When ready, apply fixes with:')} ${paint.cyan('clawarmor harden')}`);
  }
  console.log('');
}
