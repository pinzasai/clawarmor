// clawarmor watch — Real-time file watcher for OpenClaw config and skills.
// Uses Node.js built-in fs.watch only. Zero new dependencies.

import { watch, existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync, unlinkSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import { spawnSync, fork } from 'child_process';

const HOME = homedir();
const OC_DIR = join(HOME, '.openclaw');
const CLAWARMOR_DIR = join(HOME, '.clawarmor');
const PID_FILE = join(CLAWARMOR_DIR, 'watch.pid');
const LAST_SCORE_FILE = join(CLAWARMOR_DIR, 'last-score.json');
const CONFIG_FILE = join(OC_DIR, 'openclaw.json');
const SKILLS_DIR = join(OC_DIR, 'skills');
const CLI_PATH = new URL('../cli.js', import.meta.url).pathname;

// Dynamically detect npm global skills dir
function detectNpmSkillsDir() {
  try {
    const result = spawnSync('npm', ['root', '-g'], { encoding: 'utf8', timeout: 5000 });
    if (result.status === 0 && result.stdout) {
      const npmRoot = result.stdout.trim();
      const candidate = join(npmRoot, 'openclaw', 'skills');
      if (existsSync(candidate)) return candidate;
    }
  } catch { /* skip */ }
  return null;
}

function readLastScore() {
  try {
    if (existsSync(LAST_SCORE_FILE)) {
      return JSON.parse(readFileSync(LAST_SCORE_FILE, 'utf8'));
    }
  } catch { /* ignore */ }
  return null;
}

function writeLastScore(data) {
  try {
    mkdirSync(CLAWARMOR_DIR, { recursive: true });
    writeFileSync(LAST_SCORE_FILE, JSON.stringify(data, null, 2), 'utf8');
  } catch { /* non-fatal */ }
}

function runAuditJson() {
  try {
    const result = spawnSync(process.execPath, [CLI_PATH, 'audit', '--json'], {
      encoding: 'utf8',
      timeout: 30000,
      maxBuffer: 1024 * 1024,
    });
    if (result.stdout) {
      // Find the JSON blob in output (audit --json may mix some text before JSON)
      const jsonStart = result.stdout.indexOf('{');
      if (jsonStart !== -1) {
        return JSON.parse(result.stdout.slice(jsonStart));
      }
    }
  } catch { /* non-fatal */ }
  return null;
}

function timestamp() {
  return new Date().toLocaleTimeString('en-US', { hour12: false });
}

function onConfigChange() {
  console.log(`[${timestamp()}] Config changed — re-running audit...`);

  const auditResult = runAuditJson();
  if (!auditResult) {
    console.log(`[${timestamp()}] Could not parse audit output.`);
    return;
  }

  const newScore = auditResult.score ?? null;
  const lastState = readLastScore();

  if (newScore !== null) {
    const lastScore = lastState?.score ?? null;
    if (lastScore !== null && newScore < lastScore) {
      const drop = lastScore - newScore;
      console.log(`[${timestamp()}] ALERT: Security score dropped ${drop} points (${lastScore} → ${newScore})`);
      const newCriticals = (auditResult.failed || []).filter(f => f.severity === 'CRITICAL');
      if (newCriticals.length) {
        console.log(`[${timestamp()}] CRITICAL findings: ${newCriticals.map(f => f.id || f.title).join(', ')}`);
      }
    } else if (lastScore !== null && newScore > lastScore) {
      console.log(`[${timestamp()}] Score improved: ${lastScore} → ${newScore}`);
    } else {
      console.log(`[${timestamp()}] Score unchanged: ${newScore}/100`);
    }
    writeLastScore({ score: newScore, grade: auditResult.grade, timestamp: new Date().toISOString() });
  }
}

function onNewSkill(skillName) {
  console.log(`[${timestamp()}] New skill detected: ${skillName}`);
  console.log(`[${timestamp()}] Run: clawarmor scan   to check for malicious patterns`);
}

export async function runWatch(flags = {}) {
  if (flags.daemon) {
    return startDaemon();
  }

  // Ensure ~/.clawarmor/ exists
  mkdirSync(CLAWARMOR_DIR, { recursive: true });

  const watchTargets = [];

  if (existsSync(CONFIG_FILE)) {
    watchTargets.push({ path: CONFIG_FILE, label: 'openclaw.json', type: 'config' });
  }

  if (!existsSync(OC_DIR)) {
    console.log(`  [watch] ~/.openclaw/ not found — waiting for it to appear is not supported.`);
    console.log(`  [watch] Run: openclaw doctor  to set up OpenClaw first.`);
    return 1;
  }

  // Watch skills dir (may not exist yet)
  if (existsSync(SKILLS_DIR)) {
    watchTargets.push({ path: SKILLS_DIR, label: 'skills/', type: 'skills' });
  }

  const npmSkillsDir = detectNpmSkillsDir();
  if (npmSkillsDir) {
    watchTargets.push({ path: npmSkillsDir, label: 'npm skills/', type: 'skills' });
  }

  if (!watchTargets.length) {
    console.log(`  [watch] Nothing to watch — no config or skills directories found.`);
    return 1;
  }

  console.log(`  ClawArmor Watch — monitoring ${watchTargets.length} path(s)`);
  for (const t of watchTargets) console.log(`    ${t.label}  (${t.path})`);
  console.log(`  Press Ctrl+C to stop.\n`);

  const debounceMap = new Map();
  const DEBOUNCE_MS = 500;

  // Track skill dirs seen
  const seenSkills = new Set();
  try {
    if (existsSync(SKILLS_DIR)) {
      readdirSync(SKILLS_DIR).forEach(d => seenSkills.add(d));
    }
  } catch { /* ignore */ }

  for (const target of watchTargets) {
    try {
      watch(target.path, { recursive: target.type === 'skills' }, (eventType, filename) => {
        const key = `${target.path}::${filename}`;
        if (debounceMap.has(key)) clearTimeout(debounceMap.get(key));

        debounceMap.set(key, setTimeout(() => {
          debounceMap.delete(key);

          if (target.type === 'config') {
            onConfigChange();
          } else if (target.type === 'skills' && filename) {
            // Check if this is a new top-level skill directory
            const topDir = filename.split('/')[0];
            if (topDir && !seenSkills.has(topDir)) {
              seenSkills.add(topDir);
              onNewSkill(topDir);
            }
          }
        }, DEBOUNCE_MS));
      });
    } catch (e) {
      console.log(`  [watch] Could not watch ${target.label}: ${e.message}`);
    }
  }

  // Keep alive
  return new Promise(() => {});
}

function startDaemon() {
  mkdirSync(CLAWARMOR_DIR, { recursive: true });

  const child = fork(CLI_PATH, ['watch'], {
    detached: true,
    stdio: 'ignore',
    env: { ...process.env, CLAWARMOR_DAEMON: '1' },
  });

  child.unref();

  try {
    writeFileSync(PID_FILE, String(child.pid), 'utf8');
  } catch { /* non-fatal */ }

  console.log(`  ClawArmor Watch daemon started (PID ${child.pid})`);
  console.log(`  PID written to: ${PID_FILE}`);
  console.log(`  Stop with: kill $(cat ${PID_FILE})`);
  return 0;
}

export function stopDaemon() {
  if (!existsSync(PID_FILE)) {
    console.log('  No watch daemon PID file found.');
    return false;
  }
  try {
    const pid = parseInt(readFileSync(PID_FILE, 'utf8').trim(), 10);
    if (isNaN(pid)) { console.log('  Invalid PID in watch.pid'); return false; }
    process.kill(pid, 'SIGTERM');
    // Remove PID file
    try { unlinkSync(PID_FILE); } catch { /* ignore */ }
    console.log(`  Watch daemon (PID ${pid}) stopped.`);
    return true;
  } catch (e) {
    console.log(`  Could not stop watch daemon: ${e.message}`);
    return false;
  }
}

export function watchDaemonStatus() {
  if (!existsSync(PID_FILE)) return { running: false, pid: null };
  try {
    const pid = parseInt(readFileSync(PID_FILE, 'utf8').trim(), 10);
    if (isNaN(pid)) return { running: false, pid: null };
    // Check if the process is alive
    process.kill(pid, 0); // throws if not running
    return { running: true, pid };
  } catch {
    return { running: false, pid: null };
  }
}
