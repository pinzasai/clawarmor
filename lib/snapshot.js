// clawarmor snapshot — Config snapshot save/load/list/restore.
// Snapshots are saved to ~/.clawarmor/snapshots/<timestamp>.json.
// Max 20 snapshots are kept; oldest are pruned on new save.

import { existsSync, mkdirSync, readFileSync, writeFileSync, readdirSync, unlinkSync, chmodSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';

const HOME = homedir();
const SNAPSHOTS_DIR = join(HOME, '.clawarmor', 'snapshots');
const MAX_SNAPSHOTS = 20;

/** @returns {string[]} snapshot filenames sorted oldest-first */
function listSnapshotFiles() {
  if (!existsSync(SNAPSHOTS_DIR)) return [];
  try {
    return readdirSync(SNAPSHOTS_DIR).filter(f => f.endsWith('.json')).sort();
  } catch { return []; }
}

/** Prune to MAX_SNAPSHOTS, removing oldest entries. */
function pruneSnapshots() {
  const files = listSnapshotFiles();
  if (files.length <= MAX_SNAPSHOTS) return;
  for (const f of files.slice(0, files.length - MAX_SNAPSHOTS)) {
    try { unlinkSync(join(SNAPSHOTS_DIR, f)); } catch { /* non-fatal */ }
  }
}

/**
 * Save a snapshot before applying fixes.
 * @param {{ trigger: string, configPath: string, configContent: string|null, filePermissions: Object, appliedFixes: string[] }} opts
 * @returns {string|null} snapshot id or null on failure
 */
export function saveSnapshot({ trigger, configPath, configContent, filePermissions = {}, appliedFixes = [] }) {
  try {
    if (!existsSync(SNAPSHOTS_DIR)) mkdirSync(SNAPSHOTS_DIR, { recursive: true });
    const timestamp = new Date().toISOString();
    const id = timestamp.replace(/[:.]/g, '-');
    const snapshot = { timestamp, trigger, configPath, configContent, filePermissions, appliedFixes };
    writeFileSync(join(SNAPSHOTS_DIR, `${id}.json`), JSON.stringify(snapshot, null, 2), 'utf8');
    pruneSnapshots();
    return id;
  } catch { return null; }
}

/**
 * List all snapshots, newest first.
 * @returns {Array<{ id: string, timestamp: string, trigger: string, appliedFixes: string[], configPath: string }>}
 */
export function listSnapshots() {
  return listSnapshotFiles().reverse().map(f => {
    try {
      const data = JSON.parse(readFileSync(join(SNAPSHOTS_DIR, f), 'utf8'));
      return {
        id: f.replace('.json', ''),
        timestamp: data.timestamp,
        trigger: data.trigger || 'unknown',
        appliedFixes: data.appliedFixes || [],
        configPath: data.configPath || null,
      };
    } catch { return null; }
  }).filter(Boolean);
}

/**
 * Load a specific snapshot by id.
 * @param {string} id
 * @returns {Object|null}
 */
export function loadSnapshot(id) {
  const filePath = join(SNAPSHOTS_DIR, `${id}.json`);
  if (!existsSync(filePath)) return null;
  try { return JSON.parse(readFileSync(filePath, 'utf8')); } catch { return null; }
}

/**
 * Load the most recent snapshot.
 * @returns {Object|null}
 */
export function loadLatestSnapshot() {
  const files = listSnapshotFiles();
  if (!files.length) return null;
  try { return JSON.parse(readFileSync(join(SNAPSHOTS_DIR, files[files.length - 1]), 'utf8')); } catch { return null; }
}

/**
 * Restore a snapshot: writes config content and restores file permissions.
 * @param {Object} snapshot
 * @returns {{ ok: boolean, err?: string }}
 */
export function restoreSnapshot(snapshot) {
  try {
    if (snapshot.configPath && snapshot.configContent != null) {
      writeFileSync(snapshot.configPath, snapshot.configContent, 'utf8');
    }
    for (const [filePath, octalStr] of Object.entries(snapshot.filePermissions || {})) {
      try {
        if (existsSync(filePath)) chmodSync(filePath, parseInt(octalStr, 8));
      } catch { /* non-fatal per-file */ }
    }
    return { ok: true };
  } catch (e) { return { ok: false, err: e.message }; }
}
