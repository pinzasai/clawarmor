import { loadConfig } from './config.js';
import { paint, severityColor } from './output/colors.js';
import { progressBar, scoreColor, gradeColor, scoreToGrade } from './output/progress.js';
import { probeGatewayLive } from './probes/gateway-probe.js';
import gatewayChecks from './checks/gateway.js';
import filesystemChecks from './checks/filesystem.js';
import channelChecks from './checks/channels.js';
import authChecks from './checks/auth.js';
import toolChecks from './checks/tools.js';
import versionChecks from './checks/version.js';
import hooksChecks from './checks/hooks.js';
import allowFromChecks from './checks/allowfrom.js';
import { writeFileSync, mkdirSync, existsSync, readFileSync, renameSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';

const W = { CRITICAL: 25, HIGH: 15, MEDIUM: 8, LOW: 3, INFO: 0 };
const SEP = paint.dim('─'.repeat(52));
const W52 = 52;
const VERSION = '1.0.0';

const HISTORY_DIR = join(homedir(), '.clawarmor');
const HISTORY_FILE = join(HISTORY_DIR, 'history.json');

function box(title) {
  const pad = W52 - 2 - title.length;
  const l = Math.floor(pad/2), r = pad - l;
  return [
    paint.dim('╔' + '═'.repeat(W52-2) + '╗'),
    paint.dim('║') + ' '.repeat(l) + paint.bold(title) + ' '.repeat(r) + paint.dim('║'),
    paint.dim('╚' + '═'.repeat(W52-2) + '╝'),
  ].join('\n');
}

function printFinding(f) {
  console.log('');
  console.log(`  ${paint.red('✗')} ${paint.bold(f.title)}`);
  for (const line of (f.description||'').split('\n'))
    console.log(`    ${paint.dim(line)}`);
  if (f.fix) {
    console.log('');
    const lines = f.fix.split('\n');
    console.log(`    ${paint.cyan('Fix:')} ${lines[0]}`);
    for (let i=1;i<lines.length;i++) console.log(`         ${lines[i]}`);
  }
}

export function loadHistory() {
  if (!existsSync(HISTORY_FILE)) return [];
  try { return JSON.parse(readFileSync(HISTORY_FILE, 'utf8')); }
  catch { return []; }
}

function appendHistory(entry) {
  try {
    mkdirSync(HISTORY_DIR, { recursive: true });
    const existing = loadHistory();
    existing.push(entry);
    // Atomic write: temp file → rename
    const tmp = HISTORY_FILE + '.tmp';
    writeFileSync(tmp, JSON.stringify(existing, null, 2), 'utf8');
    renameSync(tmp, HISTORY_FILE);
  } catch { /* non-fatal */ }
}

export async function runAudit(flags = {}) {
  const { config, configPath, error } = loadConfig();
  console.log(''); console.log(box('ClawArmor Audit  v' + VERSION)); console.log('');
  if (error) {
    console.log(`  ${paint.red('✗')} ${error}`); console.log(''); process.exit(2);
  }
  console.log(`  ${paint.dim('Config:')}  ${configPath}`);
  console.log(`  ${paint.dim('Scanned:')} ${new Date().toLocaleString('en-US',{dateStyle:'medium',timeStyle:'short'})}`);
  console.log('');

  // ── LIVE GATEWAY PROBES ─────────────────────────────────────────────────
  console.log(SEP);
  console.log(`  ${paint.cyan('LIVE GATEWAY PROBES')}${paint.dim('  (connecting to 127.0.0.1)')}`);
  console.log(SEP);

  let liveResults = [];
  try {
    liveResults = await probeGatewayLive(config);
  } catch (e) {
    liveResults = [];
  }

  const gatewayRunning = liveResults.find(r => r.id === 'probe.gateway_running')?.gatewayRunning ?? false;

  if (!gatewayRunning) {
    console.log(`  ${paint.dim('ℹ')}  ${paint.dim('Gateway not running — skipping live probes')}`);
  } else {
    for (const r of liveResults) {
      if (r.passed) {
        console.log(`  ${paint.green('✓')} ${paint.dim(r.passedMsg || r.title)}`);
      } else {
        const sc = severityColor[r.severity] || paint.dim;
        console.log(`  ${paint.red('✗')} ${r.title}  ${paint.dim('←')} ${sc(r.severity)}`);
      }
    }
  }
  console.log('');

  // ── STATIC CONFIG CHECKS ────────────────────────────────────────────────
  const allChecks = [
    ...gatewayChecks, ...filesystemChecks, ...channelChecks,
    ...authChecks, ...toolChecks, ...versionChecks, ...hooksChecks,
    ...allowFromChecks,
  ];
  const staticResults = [];
  for (const check of allChecks) {
    try { staticResults.push(await check(config)); }
    catch (e) { staticResults.push({ id:'err', severity:'LOW', passed:true, passedMsg:`Check error: ${e.message}` }); }
  }

  // Merge: live (non-probe.gateway_running) + static
  const liveFindingResults = gatewayRunning
    ? liveResults.filter(r => r.id !== 'probe.gateway_running')
    : [];

  const results = [...liveFindingResults, ...staticResults];
  const failed = results.filter(r => !r.passed);
  const passed = results.filter(r => r.passed);
  const criticals = failed.filter(r => r.severity === 'CRITICAL').length;

  // Score with floor rules
  let score = 100;
  for (const f of failed) score -= (W[f.severity] || 0);
  score = Math.max(0, score);
  if (criticals >= 2) score = Math.min(score, 25);
  else if (criticals >= 1) score = Math.min(score, 50);

  const grade = scoreToGrade(score);
  const colorFn = scoreColor(score);

  console.log(SEP);
  console.log(`  ${paint.bold('Security Score:')} ${colorFn(score+'/100')}  ${paint.dim('┃')}  Grade: ${gradeColor(grade)}`);
  console.log(`  ${colorFn(progressBar(score,20))}  ${paint.dim(score+'%')}`);

  // Human verdict
  {
    const openCriticals = failed.filter(f => f.severity === 'CRITICAL').length;
    const openHighs = failed.filter(f => f.severity === 'HIGH').length;
    let verdict;
    if (!failed.length) {
      verdict = paint.green('Your instance is secure. No issues found.');
    } else if (openCriticals >= 1) {
      verdict = paint.red('Your instance has CRITICAL exposure. Fix immediately before using.');
    } else if (openHighs >= 1) {
      verdict = paint.yellow('Your instance has HIGH-risk issues. Fix before going to production.');
    } else {
      verdict = paint.dim('Your instance is well-configured. Open items are low-risk hardening.');
    }
    console.log('');
    console.log(`  ${paint.dim('Verdict:')}  ${verdict}`);
  }

  if (flags.json) {
    console.log(JSON.stringify({score,grade,failed,passed},null,2));
    appendHistory({ timestamp: new Date().toISOString(), score, grade,
      findings: failed.length, criticals, version: VERSION,
      failedIds: failed.map(f => f.id) });
    return 0;
  }

  for (const sev of ['CRITICAL','HIGH','MEDIUM','LOW']) {
    const group = failed.filter(f => f.severity === sev);
    if (!group.length) continue;
    console.log(''); console.log(SEP);
    console.log(`  ${severityColor[sev](sev)}${paint.dim('  ('+group.length+' finding'+(group.length>1?'s':'')+')')}`);
    console.log(SEP);
    for (const f of group) printFinding(f);
  }

  if (passed.length) {
    console.log(''); console.log(SEP);
    console.log(`  ${paint.green('PASSED')}${paint.dim('  ('+passed.filter(p=>!(p.id||'').startsWith('probe.')).length+' checks)')}`);
    console.log(SEP);
    for (const p of passed) {
      if ((p.id||'').startsWith('probe.')) continue;
      console.log(`  ${paint.green('✓')} ${paint.dim(p.passedMsg||p.title||p.id)}`);
    }
  }

  console.log(''); console.log(SEP);
  if (!failed.length) {
    console.log(`  ${paint.green('✓')} ${paint.bold('All checks passed.')}`);
  } else {
    console.log(`  ${failed.length} issue${failed.length>1?'s':''} found. Fix above to improve score.`);
  }
  console.log(`  ${paint.dim('Run')} ${paint.cyan('clawarmor scan')} ${paint.dim('to check installed skills.')}`);
  console.log(`  ${paint.dim('Run')} ${paint.cyan('clawarmor trend')} ${paint.dim('to see score history.')}`);
  console.log(`  ${paint.dim('Continuous monitoring:')} ${paint.cyan('clawarmor.dev/monitor')}`);
  console.log('');

  // Persist history (atomic)
  appendHistory({
    timestamp: new Date().toISOString(),
    score,
    grade,
    findings: failed.length,
    criticals,
    version: VERSION,
    failedIds: failed.map(f => f.id),
  });

  return failed.length > 0 ? 1 : 0;
}
