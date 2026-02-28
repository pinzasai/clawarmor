import { existsSync, readdirSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';

const HOME = homedir();

const SKILL_SEARCH_PATHS = [
  join(HOME, '.openclaw', 'skills'),
  join(HOME, '.openclaw', 'workspace', 'skills'),
  join(HOME, '.openclaw', 'agents', 'main', 'skills'),
  join(HOME, '.npm-global', 'lib', 'node_modules', 'openclaw', 'skills'),
  '/opt/homebrew/lib/node_modules/openclaw/skills',
  '/usr/local/lib/node_modules/openclaw/skills',
];

function getAllFiles(dirPath, files = []) {
  try {
    const entries = readdirSync(dirPath, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.name.startsWith('.') || entry.name === 'node_modules' || entry.name === '__pycache__') continue;
      const fullPath = join(dirPath, entry.name);
      if (entry.isDirectory()) getAllFiles(fullPath, files);
      else if (entry.isFile()) files.push(fullPath);
    }
  } catch { /* permission denied — skip */ }
  return files;
}

export function findInstalledSkills() {
  const skills = [];
  const seenNames = new Set(); // deduplicate by skill name (same skill in multiple installs)

  for (const searchPath of SKILL_SEARCH_PATHS) {
    if (!existsSync(searchPath)) continue;
    try {
      const entries = readdirSync(searchPath, { withFileTypes: true });
      for (const entry of entries) {
        if (!entry.isDirectory()) continue;
        if (seenNames.has(entry.name)) continue; // skip duplicate skill names
        seenNames.add(entry.name);
        const skillPath = join(searchPath, entry.name);
        skills.push({
          name: entry.name,
          path: skillPath,
          files: getAllFiles(skillPath),
          isBuiltIn: searchPath.includes('node_modules/openclaw'),
        });
      }
    } catch { continue; }
  }

  return skills;
}
