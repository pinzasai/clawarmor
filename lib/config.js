// Reads ~/.openclaw/openclaw.json and resolves related paths
import { readFileSync, statSync, existsSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';

const OPENCLAW_DIR = join(homedir(), '.openclaw');

export function getOpenclawDir() {
  return OPENCLAW_DIR;
}

export function getConfigPath() {
  return join(OPENCLAW_DIR, 'openclaw.json');
}

export function getAgentAccountsPath() {
  return join(OPENCLAW_DIR, 'agent-accounts.json');
}

export function loadConfig() {
  const configPath = getConfigPath();

  if (!existsSync(configPath)) {
    return { error: `Config file not found: ${configPath}\n\nIs OpenClaw installed? Expected: ${configPath}` };
  }

  let raw;
  try {
    raw = readFileSync(configPath, 'utf8');
  } catch (err) {
    return { error: `Cannot read config file: ${err.message}` };
  }

  let config;
  try {
    config = JSON.parse(raw);
  } catch (err) {
    return { error: `Config file is not valid JSON: ${err.message}` };
  }

  return { config, configPath };
}

export function getFileStat(filePath) {
  try {
    return statSync(filePath);
  } catch {
    return null;
  }
}

// Returns octal permission string e.g. "600", "644"
export function getOctalPermissions(filePath) {
  const stat = getFileStat(filePath);
  if (!stat) return null;
  return (stat.mode & 0o777).toString(8).padStart(3, '0');
}

// Deep-get a value from nested config object by dot-path
// e.g. get(config, 'gateway.auth.mode')
export function get(obj, path, defaultValue = undefined) {
  const parts = path.split('.');
  let cur = obj;
  for (const p of parts) {
    if (cur == null || typeof cur !== 'object') return defaultValue;
    cur = cur[p];
  }
  return cur === undefined ? defaultValue : cur;
}
