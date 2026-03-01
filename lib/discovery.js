// ClawArmor — Discovers the actual running OpenClaw instance
// Uses only Node.js built-ins: child_process, fs, os
// Runs fast (<500ms) via execSync with timeout

import { execSync } from 'child_process';
import { existsSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';

const DEFAULT_CONFIG_PATH = join(homedir(), '.openclaw', 'openclaw.json');
const DEFAULT_PORT = 18789;

function runPs() {
  try {
    const out = execSync('ps aux', { timeout: 400, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
    return out;
  } catch {
    return '';
  }
}

function parseInstances(psOutput) {
  const instances = [];
  for (const line of psOutput.split('\n')) {
    // Match node processes running openclaw gateway
    if (!/node\b/.test(line)) continue;
    if (!/openclaw/.test(line)) continue;
    if (!/gateway/.test(line)) continue;

    // Extract PID (second field in ps aux)
    const fields = line.trim().split(/\s+/);
    const pid = parseInt(fields[1], 10);

    // Extract --config flag value
    const configMatch = line.match(/--config\s+([^\s]+)/);
    const configPath = configMatch ? configMatch[1] : DEFAULT_CONFIG_PATH;

    // Extract --port flag value
    const portMatch = line.match(/--port\s+(\d+)/);
    const port = portMatch ? parseInt(portMatch[1], 10) : DEFAULT_PORT;

    instances.push({ pid, configPath, port });
  }
  return instances;
}

/**
 * Discovers the running OpenClaw instance.
 *
 * Returns:
 *   { configPath, port, pid, multiple: false, instances: [] }
 *   or
 *   { configPath, port, pid, multiple: true, instances: [{ pid, configPath, port }, ...] }
 *
 * Falls back gracefully: if ps fails or no process found, returns defaults.
 */
export async function discoverRunningInstance() {
  const psOutput = runPs();
  const instances = parseInstances(psOutput);

  if (instances.length === 0) {
    // No process found — return defaults (probe will check if port responds)
    return {
      configPath: existsSync(DEFAULT_CONFIG_PATH) ? DEFAULT_CONFIG_PATH : null,
      port: DEFAULT_PORT,
      pid: null,
      multiple: false,
      instances: [],
    };
  }

  if (instances.length === 1) {
    const inst = instances[0];
    return {
      configPath: inst.configPath,
      port: inst.port,
      pid: inst.pid,
      multiple: false,
      instances,
    };
  }

  // Multiple instances: prefer the one on default port, else first
  const preferred = instances.find(i => i.port === DEFAULT_PORT) || instances[0];
  return {
    configPath: preferred.configPath,
    port: preferred.port,
    pid: preferred.pid,
    multiple: true,
    instances,
  };
}
