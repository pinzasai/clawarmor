// Version currency check — fetches latest from npm registry
import { get } from '../config.js';

// Convert date-based version (2026.2.24) to comparable number
function versionToNum(v) {
  if (!v || typeof v !== 'string') return 0;
  // Handle both semver (1.2.3) and date-based (2026.2.24)
  const parts = v.replace(/^v/, '').split('.').map(Number);
  if (parts.length === 3) {
    return parts[0] * 10000 + parts[1] * 100 + parts[2];
  }
  return 0;
}

function isNewer(latest, installed) {
  return versionToNum(latest) > versionToNum(installed);
}

export async function checkVersion(config) {
  const installedVersion = get(config, 'meta.lastTouchedVersion', null);

  if (!installedVersion) {
    return {
      id: 'version.current',
      severity: 'MEDIUM',
      passed: true,
      title: 'OpenClaw version',
      passedMsg: 'Cannot determine installed version (skipping check)',
    };
  }

  let latestVersion = null;
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3000);

    const res = await fetch('https://registry.npmjs.org/openclaw/latest', {
      signal: controller.signal,
      headers: { 'Accept': 'application/json' },
    });
    clearTimeout(timeout);

    if (res.ok) {
      const data = await res.json();
      latestVersion = data.version || null;
    }
  } catch {
    // Network unavailable — skip gracefully
    return {
      id: 'version.current',
      severity: 'MEDIUM',
      passed: true,
      title: 'OpenClaw version',
      passedMsg: `Version ${installedVersion} (network unavailable, skipping latest check)`,
    };
  }

  if (!latestVersion) {
    return {
      id: 'version.current',
      severity: 'MEDIUM',
      passed: true,
      title: 'OpenClaw version',
      passedMsg: `Version ${installedVersion} (latest version unavailable)`,
    };
  }

  if (isNewer(latestVersion, installedVersion)) {
    return {
      id: 'version.current',
      severity: 'MEDIUM',
      passed: false,
      title: 'Running outdated OpenClaw version',
      description: `Installed: ${installedVersion}  →  Latest: ${latestVersion}\nOutdated versions may have known security vulnerabilities.`,
      fix: `npm install -g openclaw@latest\nOr use your system package manager to update OpenClaw.`,
    };
  }

  return {
    id: 'version.current',
    severity: 'MEDIUM',
    passed: true,
    title: 'OpenClaw version',
    passedMsg: `Version ${installedVersion} is current`,
  };
}

export default [checkVersion];
