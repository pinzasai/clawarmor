// integrity.js — Config integrity hashing (P2-3)
// On first clean audit: hashes the config and saves the baseline.
// On subsequent runs: detects changes and surfaces them.
// Zero external deps — uses Node.js built-in crypto.

import { createHash } from 'crypto';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';

const INTEGRITY_FILE = join(homedir(), '.clawarmor', 'integrity.json');

function hashFile(filePath) {
  try {
    const content = readFileSync(filePath, 'utf8');
    return {
      hash: createHash('sha256').update(content).digest('hex').slice(0, 16),
      size: content.length,
      lines: content.split('\n').length,
    };
  } catch {
    return null;
  }
}

function loadIntegrity() {
  if (!existsSync(INTEGRITY_FILE)) return null;
  try { return JSON.parse(readFileSync(INTEGRITY_FILE, 'utf8')); }
  catch { return null; }
}

function saveIntegrity(data) {
  try {
    mkdirSync(join(homedir(), '.clawarmor'), { recursive: true });
    writeFileSync(INTEGRITY_FILE, JSON.stringify(data, null, 2), 'utf8');
  } catch { /* non-fatal */ }
}

/**
 * Check config integrity. Call this after a successful (score > 0) audit.
 * Returns { status, changes } where status is 'baseline'|'ok'|'changed'.
 */
export function checkIntegrity(configPath, score) {
  const current = hashFile(configPath);
  if (!current) return { status: 'unreadable', changes: [] };

  const stored = loadIntegrity();

  if (!stored) {
    // First run — establish baseline (only if clean or near-clean)
    if (score >= 80) {
      saveIntegrity({
        configPath,
        hash: current.hash,
        size: current.size,
        lines: current.lines,
        baselineAt: new Date().toISOString(),
        baselineScore: score,
      });
      return { status: 'baseline', changes: [] };
    }
    return { status: 'no-baseline', changes: [] };
  }

  // Check for changes
  if (stored.hash === current.hash) {
    return { status: 'ok', changes: [] };
  }

  const changes = [];
  if (stored.size !== current.size) {
    const delta = current.size - stored.size;
    changes.push(`Size: ${stored.size} → ${current.size} bytes (${delta > 0 ? '+' : ''}${delta})`);
  }
  if (stored.lines !== current.lines) {
    const delta = current.lines - stored.lines;
    changes.push(`Lines: ${stored.lines} → ${current.lines} (${delta > 0 ? '+' : ''}${delta})`);
  }
  changes.push(`Hash: ${stored.hash} → ${current.hash}`);

  return {
    status: 'changed',
    changes,
    baselineAt: stored.baselineAt,
    baselineScore: stored.baselineScore,
  };
}

/** Update baseline after a clean audit (call when user explicitly passes --accept-changes). */
export function updateBaseline(configPath, score) {
  const current = hashFile(configPath);
  if (!current) return false;
  saveIntegrity({
    configPath,
    hash: current.hash,
    size: current.size,
    lines: current.lines,
    baselineAt: new Date().toISOString(),
    baselineScore: score,
  });
  return true;
}
