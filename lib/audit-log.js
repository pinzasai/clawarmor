// ClawArmor v2.0 — Security Audit Log
// Appends one JSONL line per event to ~/.clawarmor/audit.log
// Schema: { ts, cmd, trigger, score, delta, findings, blocked, skill }

import { mkdirSync, appendFileSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';

const LOG_DIR = join(homedir(), '.clawarmor');
const LOG_FILE = join(LOG_DIR, 'audit.log');

/**
 * Append one audit event to ~/.clawarmor/audit.log (JSONL format).
 * @param {object} entry
 * @param {string}        entry.cmd       - 'audit' | 'scan' | 'prescan' | 'watch'
 * @param {string}        entry.trigger   - 'manual' | 'gateway:startup' | 'watch' | 'prescan'
 * @param {number|null}   entry.score     - numeric score (audit only)
 * @param {number|null}   entry.delta     - score change from previous run
 * @param {Array}         entry.findings  - [{ id, severity }]
 * @param {boolean|null}  entry.blocked   - prescan blocked install
 * @param {string|null}   entry.skill     - skill name (prescan / scan per-skill)
 */
export function append(entry) {
  try {
    mkdirSync(LOG_DIR, { recursive: true });
    const line = JSON.stringify({
      ts: new Date().toISOString(),
      cmd: entry.cmd ?? null,
      trigger: entry.trigger ?? 'manual',
      score: entry.score ?? null,
      delta: entry.delta ?? null,
      findings: Array.isArray(entry.findings) ? entry.findings : [],
      blocked: entry.blocked ?? null,
      skill: entry.skill ?? null,
    }) + '\n';
    appendFileSync(LOG_FILE, line, 'utf8');
  } catch { /* non-fatal — never crash the main command */ }
}
