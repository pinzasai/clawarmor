import { loadConfig } from './config.js';
import { paint, severityColor } from './output/colors.js';
import { getProfile, isExpectedFinding } from './profiles.js';
import { progressBar, scoreColor, gradeColor, scoreToGrade } from './output/progress.js';
import { probeGatewayLive } from './probes/gateway-probe.js';
import { discoverRunningInstance } from './discovery.js';
import gatewayChecks from './checks/gateway.js';
import filesystemChecks from './checks/filesystem.js';
import channelChecks from './checks/channels.js';
import authChecks from './checks/auth.js';
import toolChecks from './checks/tools.js';
import versionChecks from './checks/version.js';
import hooksChecks from './checks/hooks.js';
import allowFromChecks from './checks/allowfrom.js';
import tokenAgeChecks from './checks/token-age.js';
import execApprovalChecks from './checks/exec-approval.js';
import skillPinningChecks from './checks/skill-pinning.js';
import gitCredentialLeakChecks from './checks/git-credential-leak.js';
import { writeFileSync, mkdirSync, existsSync, readFileSync, renameSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import { checkIntegrity, updateBaseline } from './integrity.js';
import { append as auditLogAppend } from './audit-log.js';
import credentialFilesChecks from './checks/credential-files.js';

const W = { CRITICAL: 25, HIGH: 15, MEDIUM: 8, LOW: 3, INFO: 0 };
const SEP = paint.dim('─'.repeat(52));
const W52 = 52;
const VERSION = '2.0.0-alpha.1';

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
  const GATEWAY_PORT_DEFAULT = 18789;

  // Load active profile (from flag or saved file)
  let profileName = flags.profile || null;
  if (!profileName) {
    try {
      const { readFileSync: rfs, existsSync: efs } = await import('fs');
      const { join: pjoin } = await import('path');
      const { homedir: phome } = await import('os');
      const pFile = pjoin(phome(), '.clawarmor', 'profile.json');
      if (efs(pFile)) profileName = JSON.parse(rfs(pFile, 'utf8')).name || null;
    } catch { /* non-fatal */ }
  }
  const activeProfile = profileName ? getProfile(profileName) : null;

  // ── DISCOVERY: find what's actually running ──────────────────────────────
  let discovery = null;
  // Only auto-discover when no --url override was given
  if (!flags.targetHost) {
    try { discovery = await discoverRunningInstance(); }
    catch { discovery = null; }
  }

  // Resolve target host/port
  const targetHost = flags.targetHost || '127.0.0.1';
  let targetPort = flags.targetPort || null;

  // Load config — prefer CLI override, then discovered path, then default
  const configOverridePath = flags.configPath || (discovery?.configPath !== undefined ? discovery.configPath : null);
  const { config, configPath, error } = loadConfig(configOverridePath);

  if (!targetPort) {
    targetPort = config?.gateway?.port || GATEWAY_PORT_DEFAULT;
  }

  console.log(''); console.log(box('ClawArmor Audit  v' + VERSION)); console.log('');

  if (activeProfile) {
    console.log(`  ${paint.dim('Profile:')} ${paint.cyan(activeProfile.name)} ${paint.dim('—')} ${activeProfile.description}`);
    console.log('');
  }

  if (error) {
    console.log(`  ${paint.red('✗')} ${error}`); console.log(''); process.exit(2);
  }

  // Discovery warnings
  if (discovery?.multiple) {
    const chosen = targetPort;
    console.log(`  ${paint.yellow('!')} Found ${discovery.instances.length} running OpenClaw instances. Auditing the one on port ${chosen}. Use --url to specify a different one.`);
    console.log('');
  }

  const isRemote = targetHost !== '127.0.0.1' && targetHost !== 'localhost' && targetHost !== '::1';
  const probeTarget = `${targetHost}:${targetPort}`;

  // Show config path info
  if (isRemote || (discovery?.configPath && discovery.configPath !== configPath)) {
    console.log(`  ${paint.dim('Config:')}  ${configPath}  ${paint.dim('(local)')}`);
    console.log(`  ${paint.dim('Probes:')}  ${probeTarget}`);
  } else {
    console.log(`  ${paint.dim('Config:')}  ${configPath}`);
  }
  console.log(`  ${paint.dim('Scanned:')} ${new Date().toLocaleString('en-US',{dateStyle:'medium',timeStyle:'short'})}`);
  console.log('');

  // ── LIVE GATEWAY PROBES ─────────────────────────────────────────────────
  console.log(SEP);
  const probeLabel = isRemote
    ? `  ${paint.cyan('LIVE GATEWAY PROBES')}${paint.dim('  (connecting to ' + probeTarget + ')')}`
    : `  ${paint.cyan('LIVE GATEWAY PROBES')}${paint.dim('  (connecting to ' + probeTarget + ')')}`;
  console.log(probeLabel);
  console.log(SEP);

  let liveResults = [];
  try {
    liveResults = await probeGatewayLive(config, { host: targetHost, port: targetPort });
  } catch (e) {
    liveResults = [];
  }

  const probeRunningResult = liveResults.find(r => r.id === 'probe.gateway_running');
  const gatewayRunning = probeRunningResult?.gatewayRunning ?? false;

  if (!gatewayRunning) {
    if (isRemote) {
      console.log(`  ${paint.red('✗')}  Gateway not reachable at ${probeTarget}`);
      console.log(`     ${paint.dim('Check that the host is reachable and the port is correct.')}`);
    } else {
      console.log(`  ${paint.dim('ℹ')}  ${paint.dim('Gateway not running — skipping live probes')}`);
    }
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
    ...tokenAgeChecks, ...execApprovalChecks, ...skillPinningChecks,
    ...gitCredentialLeakChecks,
    ...credentialFilesChecks,
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

  // Annotate expected findings for active profile
  const annotatedFailed = failed.map(f => {
    if (activeProfile && isExpectedFinding(activeProfile.name, f.id)) {
      return { ...f, _profileExpected: true };
    }
    return f;
  });

  // Score: expected findings don't count against the score
  const scoringFailed = activeProfile
    ? annotatedFailed.filter(f => !f._profileExpected)
    : annotatedFailed;

  const criticals = scoringFailed.filter(r => r.severity === 'CRITICAL').length;

  // Score with floor rules
  let score = 100;
  for (const f of scoringFailed) score -= (W[f.severity] || 0);
  score = Math.max(0, score);
  if (criticals >= 2) score = Math.min(score, 25);
  else if (criticals >= 1) score = Math.min(score, 50);

  const grade = scoreToGrade(score);
  const colorFn = scoreColor(score);

  console.log(SEP);
  console.log(`  ${paint.bold('Security Score:')} ${colorFn(score+'/100')}  ${paint.dim('┃')}  Grade: ${gradeColor(grade)}`);
  console.log(`  ${colorFn(progressBar(score,20))}  ${paint.dim(score+'%')}`);

  // Human verdict (uses scoringFailed for accurate verdict)
  {
    const openCriticals = scoringFailed.filter(f => f.severity === 'CRITICAL').length;
    const openHighs = scoringFailed.filter(f => f.severity === 'HIGH').length;
    let verdict;
    if (!scoringFailed.length) {
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
    console.log(JSON.stringify({score,grade,failed: annotatedFailed,passed},null,2));
    const histJ = loadHistory();
    const prevScoreJ = histJ.length ? histJ[histJ.length - 1].score : null;
    const deltaJ = prevScoreJ != null ? score - prevScoreJ : null;
    auditLogAppend({
      cmd: 'audit',
      trigger: 'manual',
      score,
      delta: deltaJ,
      findings: annotatedFailed.map(f => ({ id: f.id, severity: f.severity })),
      blocked: null,
      skill: null,
    });
    appendHistory({ timestamp: new Date().toISOString(), score, grade,
      findings: annotatedFailed.length, criticals, version: VERSION,
      failedIds: annotatedFailed.map(f => f.id) });
    return 0;
  }

  for (const sev of ['CRITICAL','HIGH','MEDIUM','LOW']) {
    const group = annotatedFailed.filter(f => f.severity === sev);
    if (!group.length) continue;
    console.log(''); console.log(SEP);
    console.log(`  ${severityColor[sev](sev)}${paint.dim('  ('+group.length+' finding'+(group.length>1?'s':'')+')')}`);
    console.log(SEP);
    for (const f of group) {
      if (f._profileExpected) {
        console.log('');
        console.log(`  ${paint.dim('○')} ${paint.dim('[profile: expected]')} ${paint.dim(f.title)}`);
      } else {
        printFinding(f);
      }
    }
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
  if (!scoringFailed.length) {
    console.log(`  ${paint.green('✓')} ${paint.bold('All checks passed.')}`);
  } else {
    const expectedCount = annotatedFailed.length - scoringFailed.length;
    const suffix = expectedCount > 0 ? ` ${paint.dim(`(${expectedCount} expected for profile)`)}` : '';
    console.log(`  ${scoringFailed.length} issue${scoringFailed.length>1?'s':''} found. Fix above to improve score.${suffix}`);
  }
  console.log(`  ${paint.dim('Run')} ${paint.cyan('clawarmor scan')} ${paint.dim('to check installed skills.')}`);
  console.log(`  ${paint.dim('Run')} ${paint.cyan('clawarmor trend')} ${paint.dim('to see score history.')}`);
  console.log(`  ${paint.dim('Continuous monitoring:')} ${paint.cyan('github.com/pinzasai/clawarmor')}`);
  console.log('');

  // ── CONFIG INTEGRITY CHECK ─────────────────────────────────────────────
  if (!isRemote && configPath) {
    const integ = checkIntegrity(configPath, score);
    if (integ.status === 'baseline') {
      console.log(`  ${paint.dim('ℹ')}  ${paint.dim('Config baseline established — future changes will be flagged.')}`);
    } else if (integ.status === 'changed') {
      console.log('');
      console.log(`  ${paint.yellow('!')}  ${paint.bold('Config changed since last clean audit')}`);
      for (const c of integ.changes) console.log(`     ${paint.dim(c)}`);
      console.log(`     ${paint.dim('Baseline set: ' + integ.baselineAt?.slice(0,10))}`);
      console.log(`     ${paint.dim('Run clawarmor audit --accept-changes to update baseline')}`);
    }
  }
  if (flags.acceptChanges && configPath) {
    updateBaseline(configPath, score);
    console.log(`  ${paint.green('✓')}  Config baseline updated.`);
  }

    // Audit log (JSONL) — compute delta from history before writing
  const hist = loadHistory();
  const prevScore = hist.length ? hist[hist.length - 1].score : null;
  const delta = prevScore != null ? score - prevScore : null;
  auditLogAppend({
    cmd: 'audit',
    trigger: 'manual',
    score,
    delta,
    findings: annotatedFailed.map(f => ({ id: f.id, severity: f.severity })),
    blocked: null,
    skill: null,
  });

  // Persist history (atomic)
  appendHistory({
    timestamp: new Date().toISOString(),
    score,
    grade,
    findings: annotatedFailed.length,
    criticals,
    version: VERSION,
    failedIds: annotatedFailed.map(f => f.id),
  });

  return failed.length > 0 ? 1 : 0;
}
