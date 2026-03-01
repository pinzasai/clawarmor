// clawarmor protect — Install/uninstall/status the full ClawArmor guard system.
// --install:   writes hook files, adds shell intercept, starts watch daemon
// --uninstall: reverses all of the above cleanly
// --status:    shows current state without modifying anything

import {
  existsSync, mkdirSync, readFileSync, writeFileSync, unlinkSync, readdirSync, rmSync,
} from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import { spawnSync } from 'child_process';
import { watchDaemonStatus } from './watch.js';

const HOME = homedir();
const OC_DIR = join(HOME, '.openclaw');
const CLAWARMOR_DIR = join(HOME, '.clawarmor');
const HOOKS_DIR = join(OC_DIR, 'hooks');
const GUARD_HOOK_DIR = join(HOOKS_DIR, 'clawarmor-guard');
const CLI_PATH = new URL('../cli.js', import.meta.url).pathname;

const SHELL_FUNCTION = `
# ClawArmor intercept — added by: clawarmor protect --install
# Wraps 'openclaw clawhub install' to scan skills before activation.
openclaw() {
  if [ "$1" = "clawhub" ] && [ "$2" = "install" ] && [ -n "$3" ]; then
    echo "ClawArmor: scanning $3 before install..."
    clawarmor prescan "$3" || { echo "Blocked by ClawArmor. Use --force to override."; return 1; }
  fi
  command openclaw "$@"
}
# End ClawArmor intercept
`;

const SHELL_MARKER_START = '# ClawArmor intercept — added by: clawarmor protect --install';
const SHELL_MARKER_END = '# End ClawArmor intercept';

const HOOK_MD = `---
name: clawarmor-guard
description: Runs a silent security audit on gateway startup and alerts on regressions
events:
  - gateway:startup
requires:
  bins:
    - clawarmor
---

# clawarmor-guard

Fires on every gateway startup. Runs \`clawarmor audit --json\` in the background,
compares the score to the last known baseline, and alerts the agent if the score
drops by 5 or more points, or if a new CRITICAL finding appears.

Install with: \`clawarmor protect --install\`
`;

const HANDLER_JS = `// clawarmor-guard hook handler
// Fires on gateway:startup. Silent unless score drops or CRITICAL finding appears.
// No external dependencies.

import { spawnSync } from 'child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';

const HOME = homedir();
const CLAWARMOR_DIR = join(HOME, '.clawarmor');
const LAST_SCORE_FILE = join(CLAWARMOR_DIR, 'last-score.json');

function readLastScore() {
  try {
    if (existsSync(LAST_SCORE_FILE)) return JSON.parse(readFileSync(LAST_SCORE_FILE, 'utf8'));
  } catch {}
  return null;
}

function writeLastScore(data) {
  try {
    mkdirSync(CLAWARMOR_DIR, { recursive: true });
    writeFileSync(LAST_SCORE_FILE, JSON.stringify(data, null, 2), 'utf8');
  } catch {}
}

function runAuditJson() {
  try {
    const result = spawnSync('clawarmor', ['audit', '--json'], {
      encoding: 'utf8',
      timeout: 30000,
      maxBuffer: 1024 * 1024,
    });
    if (result.stdout) {
      const jsonStart = result.stdout.indexOf('{');
      if (jsonStart !== -1) return JSON.parse(result.stdout.slice(jsonStart));
    }
  } catch {}
  return null;
}

// Main hook entry point — called by openclaw on gateway:startup
export default async function handler(event) {
  let auditResult;
  try {
    auditResult = runAuditJson();
  } catch (e) {
    // If clawarmor itself fails, don't block startup
    return;
  }

  if (!auditResult) return;

  const newScore = auditResult.score ?? null;
  const lastState = readLastScore();
  const lastScore = lastState?.score ?? null;
  const isFirstRun = lastScore === null;

  if (newScore !== null) {
    if (isFirstRun) {
      writeLastScore({ score: newScore, grade: auditResult.grade, timestamp: new Date().toISOString() });
      // First run — establish baseline silently
      return;
    }

    const drop = lastScore - newScore;
    const newCriticals = (auditResult.failed || []).filter(f => f.severity === 'CRITICAL');
    const hadCriticals = (lastState?.criticals || 0);
    const newCriticalCount = newCriticals.length;

    writeLastScore({
      score: newScore,
      grade: auditResult.grade,
      criticals: newCriticalCount,
      timestamp: new Date().toISOString(),
    });

    if (newCriticalCount > hadCriticals) {
      // New CRITICAL finding — alert immediately
      const names = newCriticals.map(f => f.id || f.title).join(', ');
      console.error(\`[ClawArmor] CRITICAL security finding: \${names}\`);
      console.error(\`[ClawArmor] Run: clawarmor audit   for details and fix commands.\`);
      return;
    }

    if (drop >= 5) {
      console.error(\`[ClawArmor] Security score dropped \${drop} points (\${lastScore} → \${newScore})\`);
      console.error(\`[ClawArmor] Run: clawarmor audit   to see what changed.\`);
    }
    // Score improved or unchanged — no output (don't interrupt users with good news)
  }
}
`;

// ── Install ──────────────────────────────────────────────────────────────────

function writeHookFiles() {
  mkdirSync(GUARD_HOOK_DIR, { recursive: true });
  writeFileSync(join(GUARD_HOOK_DIR, 'HOOK.md'), HOOK_MD, 'utf8');
  writeFileSync(join(GUARD_HOOK_DIR, 'handler.js'), HANDLER_JS, 'utf8');
}

function removeHookFiles() {
  if (!existsSync(GUARD_HOOK_DIR)) return false;
  try {
    rmSync(GUARD_HOOK_DIR, { recursive: true, force: true });
    return true;
  } catch { return false; }
}

function hookFilesExist() {
  return existsSync(join(GUARD_HOOK_DIR, 'HOOK.md')) &&
         existsSync(join(GUARD_HOOK_DIR, 'handler.js'));
}

// ── Shell function ────────────────────────────────────────────────────────────

function shellFunctionPresent(rcPath) {
  if (!existsSync(rcPath)) return false;
  try {
    return readFileSync(rcPath, 'utf8').includes(SHELL_MARKER_START);
  } catch { return false; }
}

function injectShellFunction(rcPath) {
  if (!existsSync(rcPath)) return false;
  if (shellFunctionPresent(rcPath)) return true; // already there
  try {
    const existing = readFileSync(rcPath, 'utf8');
    writeFileSync(rcPath, existing + '\n' + SHELL_FUNCTION, 'utf8');
    return true;
  } catch { return false; }
}

function removeShellFunction(rcPath) {
  if (!existsSync(rcPath)) return false;
  try {
    const content = readFileSync(rcPath, 'utf8');
    const start = content.indexOf(SHELL_MARKER_START);
    const end = content.indexOf(SHELL_MARKER_END);
    if (start === -1) return false;
    const after = end !== -1 ? end + SHELL_MARKER_END.length : start;
    const newContent = content.slice(0, start).trimEnd() + '\n' + content.slice(after + 1);
    writeFileSync(rcPath, newContent, 'utf8');
    return true;
  } catch { return false; }
}

function startWatchDaemon() {
  const result = spawnSync(process.execPath, [CLI_PATH, 'watch', '--daemon'], {
    encoding: 'utf8',
    timeout: 10000,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  return result.status === 0;
}

// ── Public API ────────────────────────────────────────────────────────────────

export async function runProtect(flags = {}) {
  const zshrc = join(HOME, '.zshrc');
  const bashrc = join(HOME, '.bashrc');

  if (flags.install) {
    console.log('\n  ClawArmor Protect — installing...\n');

    // 1. Hook files
    writeHookFiles();
    console.log(`  ✓ Gateway hook installed (clawarmor-guard)`);

    // 2. Start watch daemon
    const daemonStarted = startWatchDaemon();
    let daemonPid = null;
    if (daemonStarted) {
      // Read the PID that was written by the daemon
      try {
        const pidFile = join(CLAWARMOR_DIR, 'watch.pid');
        if (existsSync(pidFile)) daemonPid = readFileSync(pidFile, 'utf8').trim();
      } catch { /* non-fatal */ }
      const pidStr = daemonPid ? ` (PID ${daemonPid})` : '';
      console.log(`  ✓ Watch daemon started${pidStr}`);
    } else {
      console.log(`  !  Watch daemon could not be started automatically`);
      console.log(`     Run manually: clawarmor watch --daemon`);
    }

    // 3. Shell intercept
    let shellInstalled = false;
    let shellPath = null;
    if (injectShellFunction(zshrc)) {
      shellPath = '~/.zshrc';
      shellInstalled = true;
    }
    if (injectShellFunction(bashrc)) {
      shellPath = shellPath ? shellPath + ', ~/.bashrc' : '~/.bashrc';
      shellInstalled = true;
    }
    if (shellInstalled) {
      console.log(`  ✓ Shell intercept added (${shellPath})`);
    } else {
      console.log(`  !  No ~/.zshrc or ~/.bashrc found — shell intercept skipped`);
    }

    // 4. Weekly digest cron
    const { installDigestCron } = await import('./digest.js');
    const cronOk = installDigestCron();
    if (cronOk) {
      console.log(`  ✓ Weekly digest scheduled (Sundays 9am)`);
    } else {
      console.log(`  !  Could not write digest cron job`);
    }

    console.log('\n  ClawArmor Protect is now active.\n');
    console.log(`  The guard hook fires on every gateway startup.`);
    console.log(`  The watcher monitors config and skill changes in real time.`);
    if (shellInstalled) {
      console.log(`  Restart your shell (or: source ~/.zshrc) for the intercept to take effect.`);
    }
    console.log('');
    return 0;
  }

  if (flags.uninstall) {
    console.log('\n  ClawArmor Protect — uninstalling...\n');

    // 1. Hook files
    if (removeHookFiles()) {
      console.log(`  ✓  Hook files removed`);
    } else {
      console.log(`  -  Hook files were not present`);
    }

    // 2. Shell function
    let shellRemoved = false;
    if (removeShellFunction(zshrc)) {
      console.log(`  ✓  Shell intercept removed from ~/.zshrc`);
      shellRemoved = true;
    }
    if (removeShellFunction(bashrc)) {
      console.log(`  ✓  Shell intercept removed from ~/.bashrc`);
      shellRemoved = true;
    }
    if (!shellRemoved) {
      console.log(`  -  No shell intercept found to remove`);
    }

    // 3. Stop watch daemon
    const { stopDaemon } = await import('./watch.js');
    stopDaemon();

    console.log('\n  ClawArmor Protect has been uninstalled.\n');
    return 0;
  }

  if (flags.status) {
    console.log('\n  ClawArmor Protect — Status\n');

    // Hook files
    const hookOk = hookFilesExist();
    console.log(`  Hook (gateway:startup)   ${hookOk ? '✓ installed' : '✗ not installed'}`);

    // Watch daemon
    const daemon = watchDaemonStatus();
    console.log(`  Watch daemon             ${daemon.running ? `● running  (PID ${daemon.pid})` : '○ not running'}`);

    // Shell function
    const inZsh = shellFunctionPresent(zshrc);
    const inBash = shellFunctionPresent(bashrc);
    if (inZsh || inBash) {
      const where = [inZsh && '~/.zshrc', inBash && '~/.bashrc'].filter(Boolean).join(', ');
      console.log(`  Shell intercept          ✓ active  (${where})`);
    } else {
      console.log(`  Shell intercept          ✗ not installed`);
    }

    const allActive = hookOk && daemon.running && (inZsh || inBash);
    console.log('');
    if (allActive) {
      console.log(`  Full protection active.`);
    } else {
      console.log(`  Protection incomplete. Run: clawarmor protect --install`);
    }
    console.log('');
    return 0;
  }

  // No flag — show usage
  console.log('');
  console.log(`  Usage: clawarmor protect [--install | --uninstall | --status]`);
  console.log('');
  console.log(`    --install    Install the guard hook, shell intercept, and watch daemon`);
  console.log(`    --uninstall  Remove all ClawArmor protect components`);
  console.log(`    --status     Show current protection state`);
  console.log('');
  return 0;
}
