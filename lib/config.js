import { readFileSync, statSync, existsSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';

const HOME = homedir();
const OC_DIR = join(HOME, '.openclaw');

export function getConfigPath() { return join(OC_DIR, 'openclaw.json'); }
export function getAgentAccountsPath() { return join(OC_DIR, 'agent-accounts.json'); }

export function getOctalPermissions(filePath) {
  if (!existsSync(filePath)) return null;
  try { return (statSync(filePath).mode & 0o777).toString(8).padStart(3, '0'); }
  catch { return null; }
}

export function get(obj, path, def = undefined) {
  if (!obj || typeof obj !== 'object') return def;
  const parts = path.split('.');
  let cur = obj;
  for (const p of parts) {
    if (cur == null || typeof cur !== 'object') return def;
    cur = cur[p];
  }
  return cur === undefined ? def : cur;
}

export function loadConfig(overridePath = null) {
  const configPath = overridePath || getConfigPath();
  if (!existsSync(configPath)) {
    return { config: {}, configPath, error: `Config not found at ${configPath}\nRun: openclaw doctor` };
  }
  try {
    const raw = readFileSync(configPath, 'utf8');
    // Strip JS-style comments and trailing commas (openclaw.json may use JSON5)
    let clean = raw
      .replace(/\/\/[^\n]*/g, '')           // single-line comments
      .replace(/\/\*[\s\S]*?\*\//g, '')     // block comments
      .replace(/,(\s*[}\]])/g, '$1');       // trailing commas
    // Try cleaned first, fall back to raw
    let config;
    try { config = JSON.parse(clean); }
    catch { config = JSON.parse(raw); }     // raw is valid JSON — use it
    return { config, configPath, error: null };
  } catch (err) {
    return { config: {}, configPath, error: `Failed to parse openclaw.json: ${err.message}` };
  }
}
