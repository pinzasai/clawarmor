// ClawArmor baseline storage — save, list, and diff audit baselines.
// Baselines are stored in ~/.openclaw/workspace/memory/clawarmor-baselines/

import { writeFileSync, mkdirSync, existsSync, readFileSync, readdirSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';

const BASELINE_DIR = join(homedir(), '.openclaw', 'workspace', 'memory', 'clawarmor-baselines');

function ensureDir() {
  mkdirSync(BASELINE_DIR, { recursive: true });
}

function baselinePath(label) {
  return join(BASELINE_DIR, `${label}.json`);
}

/**
 * Save a baseline snapshot.
 * @param {{ label: string, score: number, findings: any[], profile?: string }} data
 */
export function saveBaseline({ label, score, findings, profile }) {
  ensureDir();
  const entry = {
    label,
    savedAt: new Date().toISOString(),
    score,
    findings: findings || [],
    profile: profile || null,
  };
  writeFileSync(baselinePath(label), JSON.stringify(entry, null, 2), 'utf8');
  return baselinePath(label);
}

/**
 * List all saved baselines, sorted by savedAt ascending.
 * @returns {Array<{ label, savedAt, score, profile, path }>}
 */
export function listBaselines() {
  if (!existsSync(BASELINE_DIR)) return [];
  try {
    const files = readdirSync(BASELINE_DIR).filter(f => f.endsWith('.json'));
    const baselines = [];
    for (const f of files) {
      try {
        const raw = JSON.parse(readFileSync(join(BASELINE_DIR, f), 'utf8'));
        baselines.push({
          label: raw.label || f.replace('.json', ''),
          savedAt: raw.savedAt || null,
          score: raw.score ?? null,
          profile: raw.profile || null,
          path: join(BASELINE_DIR, f),
        });
      } catch { /* skip malformed */ }
    }
    baselines.sort((a, b) => (a.savedAt || '').localeCompare(b.savedAt || ''));
    return baselines;
  } catch { return []; }
}

/**
 * Load a baseline by label.
 * @param {string} label
 * @returns {object|null}
 */
export function loadBaseline(label) {
  const p = baselinePath(label);
  if (!existsSync(p)) return null;
  try { return JSON.parse(readFileSync(p, 'utf8')); }
  catch { return null; }
}

/**
 * Diff two baselines.
 * Returns { scoreDelta, newFindings, resolvedFindings, fromLabel, toLabel, fromScore, toScore }
 */
export function diffBaselines(fromLabel, toLabel) {
  const from = loadBaseline(fromLabel);
  const to = loadBaseline(toLabel);

  if (!from) throw new Error(`Baseline not found: ${fromLabel}`);
  if (!to) throw new Error(`Baseline not found: ${toLabel}`);

  const fromScore = from.score ?? 0;
  const toScore = to.score ?? 0;
  const scoreDelta = toScore - fromScore;

  // Key findings by patternId+skill for comparison
  const key = f => `${f.skill || ''}:${f.patternId || f.id || ''}:${f.severity || ''}`;

  const fromKeys = new Set((from.findings || []).map(key));
  const toKeys = new Set((to.findings || []).map(key));

  const newFindings = (to.findings || []).filter(f => !fromKeys.has(key(f)));
  const resolvedFindings = (from.findings || []).filter(f => !toKeys.has(key(f)));

  return {
    fromLabel,
    toLabel,
    fromScore,
    toScore,
    scoreDelta,
    newFindings,
    resolvedFindings,
  };
}
