// T-PERSIST-002 — Skill Version Pinning
// Checks that installed skills have explicit version pins to prevent
// update poisoning attacks.

import { existsSync, readdirSync, readFileSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import { get } from '../config.js';

const HOME = homedir();
const OC_DIR = join(HOME, '.openclaw');
const SKILLS_DIR = join(OC_DIR, 'skills');

// A version pin looks like @1.2.3 or @1.2.3-beta.1 (semver)
const SEMVER_PIN = /^[\^~]?\d+\.\d+\.\d+/;
// "latest", "next", "*", ranges like ">=1.0.0" are NOT pins
const FLOATING = /^(latest|next|beta|alpha|\*|>=|>|<|~\d|^\d)/;

function isPinned(version) {
  if (!version || typeof version !== 'string') return false;
  if (FLOATING.test(version)) return false;
  return SEMVER_PIN.test(version);
}

function collectUnpinnedFromConfig(config) {
  const unpinned = [];

  // Check skills.managed (array or object of { name, version })
  const managed = get(config, 'skills.managed', null);
  if (Array.isArray(managed)) {
    for (const entry of managed) {
      if (typeof entry === 'string') {
        // "skill-name" with no version
        unpinned.push({ name: entry, source: 'skills.managed', version: null });
      } else if (entry && typeof entry === 'object') {
        const name = entry.name || entry.id || JSON.stringify(entry);
        if (!isPinned(entry.version)) {
          unpinned.push({ name, source: 'skills.managed', version: entry.version || null });
        }
      }
    }
  } else if (managed && typeof managed === 'object') {
    for (const [name, value] of Object.entries(managed)) {
      const version = typeof value === 'string' ? value : value?.version;
      if (!isPinned(version)) {
        unpinned.push({ name, source: 'skills.managed', version: version || null });
      }
    }
  }

  // Check skills.installed
  const installed = get(config, 'skills.installed', null);
  if (Array.isArray(installed)) {
    for (const entry of installed) {
      if (typeof entry === 'string') {
        // May be "name@version" or just "name"
        const atIdx = entry.lastIndexOf('@');
        if (atIdx > 0) {
          const version = entry.slice(atIdx + 1);
          const name = entry.slice(0, atIdx);
          if (!isPinned(version)) unpinned.push({ name, source: 'skills.installed', version });
        } else {
          unpinned.push({ name: entry, source: 'skills.installed', version: null });
        }
      } else if (entry && typeof entry === 'object') {
        const name = entry.name || entry.id || JSON.stringify(entry);
        if (!isPinned(entry.version)) {
          unpinned.push({ name, source: 'skills.installed', version: entry.version || null });
        }
      }
    }
  }

  return unpinned;
}

function collectUnpinnedFromDisk() {
  const unpinned = [];
  if (!existsSync(SKILLS_DIR)) return unpinned;

  let entries;
  try { entries = readdirSync(SKILLS_DIR, { withFileTypes: true }); }
  catch { return unpinned; }

  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    const skillDir = join(SKILLS_DIR, entry.name);

    // Look for a package.json to find version
    const pkgPath = join(skillDir, 'package.json');
    if (existsSync(pkgPath)) {
      try {
        const pkg = JSON.parse(readFileSync(pkgPath, 'utf8'));
        // If installed from a range or "latest", flag it
        // We check _resolved or _requested for npm install metadata
        const requested = pkg._requested?.rawSpec || pkg._spec;
        if (requested && !isPinned(requested)) {
          unpinned.push({ name: entry.name, source: 'skills/', version: requested });
          continue;
        }
        // If no version at all in package.json
        if (!pkg.version) {
          unpinned.push({ name: entry.name, source: 'skills/', version: null });
        }
        // If version looks like a range (shouldn't happen for installed, but defensive)
      } catch { /* skip */ }
    } else {
      // Directory exists but no package.json — unpinned / manual install
      const skillMd = join(skillDir, 'SKILL.md');
      if (existsSync(skillMd)) {
        // Check frontmatter for version
        try {
          const md = readFileSync(skillMd, 'utf8');
          const versionMatch = md.match(/^version:\s*(.+)$/m);
          const version = versionMatch ? versionMatch[1].trim() : null;
          if (!isPinned(version)) {
            unpinned.push({ name: entry.name, source: 'skills/', version });
          }
        } catch {
          unpinned.push({ name: entry.name, source: 'skills/', version: null });
        }
      }
    }
  }

  return unpinned;
}

export function checkSkillPinning(config) {
  const fromConfig = collectUnpinnedFromConfig(config);
  const fromDisk = collectUnpinnedFromDisk();

  // Merge, dedup by name
  const seen = new Set(fromConfig.map(s => s.name));
  const all = [...fromConfig];
  for (const s of fromDisk) {
    if (!seen.has(s.name)) { all.push(s); seen.add(s.name); }
  }

  if (!all.length) {
    return { id: 'persist.skill_pinning', severity: 'MEDIUM', passed: true,
      passedMsg: 'All installed skills have explicit version pins' };
  }

  const list = all.map(({ name, version }) =>
    `• ${name}${version ? ` (version: "${version}" — not pinned)` : ' (no version specified)'}`
  ).join('\n');

  return {
    id: 'persist.skill_pinning',
    severity: 'MEDIUM',
    passed: false,
    title: `${all.length} skill${all.length > 1 ? 's' : ''} installed without a version pin`,
    description: `Skills without a pinned version can silently update to a malicious release.\nAttack (T-PERSIST-002): attacker publishes a new "latest" version of a skill\nyou use — your next gateway start runs the malicious code automatically.\n\n${list}`,
    fix: `Pin skills to a specific version when installing:\n  openclaw clawhub install <skill>@<version>\n\nExample:\n  openclaw clawhub install weather@1.4.2`,
  };
}

export default [checkSkillPinning];
