import { execSync } from 'child_process';

export async function checkVersion() {
  let installed = null;
  let latest = null;

  // Read from binary, not config (v0.1 false positive fix)
  const candidates = [
    process.env.HOME + '/.npm-global/bin/openclaw',
    '/opt/homebrew/bin/openclaw',
    '/usr/local/bin/openclaw',
    'openclaw',
  ];
  for (const bin of candidates) {
    try {
      const out = execSync(`${bin} --version 2>/dev/null`, { timeout: 3000, encoding: 'utf8' }).trim();
      if (out && /^\d{4}\./.test(out)) { installed = out; break; }
    } catch { continue; }
  }

  if (!installed) {
    return { id: 'version.check', severity: 'LOW', passed: true,
      passedMsg: 'Could not detect OpenClaw version (binary not in PATH)' };
  }

  // Fetch latest from npm registry
  try {
    const res = await fetch('https://registry.npmjs.org/openclaw/latest', {
      signal: AbortSignal.timeout(4000),
      headers: { 'User-Agent': 'clawarmor-audit/0.5.0' },
    });
    if (res.ok) {
      const data = await res.json();
      latest = data.version;
    }
  } catch { /* no network — skip */ }

  if (!latest) {
    return { id: 'version.check', severity: 'LOW', passed: true,
      passedMsg: `OpenClaw ${installed} (could not check latest — offline?)` };
  }

  if (installed === latest) {
    return { id: 'version.check', severity: 'MEDIUM', passed: true,
      passedMsg: `OpenClaw ${installed} (up to date)` };
  }

  // Compare: installed < latest?
  const toNum = v => v.replace(/\./g, '').padStart(10, '0');
  if (toNum(installed) < toNum(latest)) {
    return { id: 'version.check', severity: 'MEDIUM', passed: false,
      title: 'OpenClaw is out of date',
      description: `Installed: ${installed} → Latest: ${latest}\nOutdated versions may have known security vulnerabilities.\nAttack: known CVEs against your version are publicly documented.`,
      fix: `npm install -g openclaw@latest && openclaw gateway restart` };
  }

  return { id: 'version.check', severity: 'MEDIUM', passed: true,
    passedMsg: `OpenClaw ${installed} (up to date)` };
}

export default [checkVersion];
