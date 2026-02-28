import { existsSync, readdirSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';

const HOME = homedir();
const BUILTIN_PATHS = new Set([
  join(HOME, '.npm-global', 'lib', 'node_modules', 'openclaw', 'skills'),
  '/opt/homebrew/lib/node_modules/openclaw/skills',
  '/usr/local/lib/node_modules/openclaw/skills',
]);
const USER_PATHS = [
  join(HOME, '.openclaw', 'skills'),
  join(HOME, '.openclaw', 'workspace', 'skills'),
];

function getAllFiles(dir, files = []) {
  try {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      if (e.name.startsWith('.') || e.name === 'node_modules' || e.name === '__pycache__') continue;
      const fp = join(dir, e.name);
      if (e.isDirectory()) getAllFiles(fp, files);
      else files.push(fp);
    }
  } catch { /* permission denied */ }
  return files;
}

export function findInstalledSkills() {
  const skills = [];
  const seenNames = new Set();

  // User-installed skills first (higher priority, higher severity)
  for (const searchPath of USER_PATHS) {
    if (!existsSync(searchPath)) continue;
    for (const e of readdirSync(searchPath, { withFileTypes: true })) {
      if (!e.isDirectory() || seenNames.has(e.name)) continue;
      seenNames.add(e.name);
      const skillPath = join(searchPath, e.name);
      skills.push({ name: e.name, path: skillPath, files: getAllFiles(skillPath), isBuiltin: false });
    }
  }

  // Built-in skills (lower severity findings)
  for (const searchPath of BUILTIN_PATHS) {
    if (!existsSync(searchPath)) continue;
    try {
      for (const e of readdirSync(searchPath, { withFileTypes: true })) {
        if (!e.isDirectory() || seenNames.has(e.name)) continue;
        seenNames.add(e.name);
        const skillPath = join(searchPath, e.name);
        skills.push({ name: e.name, path: skillPath, files: getAllFiles(skillPath), isBuiltin: true });
      }
    } catch { continue; }
    break; // Only scan one built-in path (first found = deduped)
  }

  return skills;
}
