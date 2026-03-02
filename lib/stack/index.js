// lib/stack/index.js — Stack orchestrator
// Reads latest audit result from ~/.clawarmor/audit.log (JSONL),
// maps score + findings to a risk profile, and determines deployment plan.

import { existsSync, readFileSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';

const HOME = homedir();
const AUDIT_LOG = join(HOME, '.clawarmor', 'audit.log');

/**
 * Read the latest scored audit entry from ~/.clawarmor/audit.log (JSONL).
 * Prefers entries where score !== null (cmd==='audit'), skips scan entries.
 * Falls back to last-score.json combined with history.json if no scored entry found.
 */
function readLatestAudit() {
  if (existsSync(AUDIT_LOG)) {
    try {
      const lines = readFileSync(AUDIT_LOG, 'utf8').split('\n').filter(Boolean);
      for (let i = lines.length - 1; i >= 0; i--) {
        try {
          const entry = JSON.parse(lines[i]);
          if (entry && entry.score != null) return entry;
        } catch { /* skip bad lines */ }
      }
    } catch { /* non-fatal */ }
  }
  // Fallback: last-score.json (minimal — no findings detail)
  const lastScoreFile = join(HOME, '.clawarmor', 'last-score.json');
  if (existsSync(lastScoreFile)) {
    try {
      const s = JSON.parse(readFileSync(lastScoreFile, 'utf8'));
      if (s && s.score != null) return { score: s.score, grade: s.grade, findings: [] };
    } catch { /* non-fatal */ }
  }
  return null;
}

/**
 * Map audit score + findings to a risk profile.
 * @param {Object|null} audit
 * @returns {{ level: string, label: string, score: number|null, findings: Array }}
 */
export function getRiskProfile(audit) {
  if (!audit) return { level: 'unknown', label: 'No audit data', score: null, findings: [] };
  const score = audit.score ?? null;
  const findings = audit.findings ?? [];
  let level, label;
  if (score == null)    { level = 'unknown';  label = 'Unknown risk'; }
  else if (score < 50)  { level = 'critical'; label = 'Critical / High risk'; }
  else if (score < 75)  { level = 'medium';   label = 'Medium risk'; }
  else                  { level = 'low';       label = 'Low risk'; }
  return { level, label, score, findings };
}

/**
 * Read latest audit + derive risk profile.
 * @returns {Promise<{ audit: Object|null, profile: Object }>}
 */
export async function getStackStatus() {
  const audit = readLatestAudit();
  const profile = getRiskProfile(audit);
  return { audit, profile };
}

/**
 * Get recommended deployment plan based on risk profile.
 * @param {Object} profile - from getRiskProfile()
 * @returns {{ invariant: boolean, ironcurtain: boolean, reason: string }}
 */
export function getPlan(profile) {
  const { level } = profile;
  if (level === 'critical') return {
    invariant: true, ironcurtain: true,
    reason: 'Critical risk: deploy Invariant flow guardrails + generate IronCurtain constitution',
  };
  if (level === 'medium') return {
    invariant: true, ironcurtain: true,
    reason: 'Medium risk: deploy Invariant flow guardrails + generate IronCurtain constitution',
  };
  if (level === 'low') return {
    invariant: false, ironcurtain: true,
    reason: 'Low risk: generate IronCurtain constitution as reference hardening',
  };
  // unknown — no audit yet
  return {
    invariant: true, ironcurtain: true,
    reason: 'No audit data: run clawarmor audit first for precise recommendations',
  };
}
