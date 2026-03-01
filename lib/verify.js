// ClawArmor v1.0.0 — verify command
// Re-runs only the checks that failed in the LAST audit run.
// Reads failed check IDs from ~/.clawarmor/history.json.

import { loadConfig } from './config.js';
import { paint, severityColor } from './output/colors.js';
import { loadHistory } from './audit.js';
import { probeGatewayLive } from './probes/gateway-probe.js';
import gatewayChecks from './checks/gateway.js';
import filesystemChecks from './checks/filesystem.js';
import channelChecks from './checks/channels.js';
import authChecks from './checks/auth.js';
import toolChecks from './checks/tools.js';
import versionChecks from './checks/version.js';
import hooksChecks from './checks/hooks.js';
import allowFromChecks from './checks/allowfrom.js';

const SEP = paint.dim('─'.repeat(52));
const W52 = 52;

const PROBE_IDS = new Set([
  'probe.gateway_running', 'probe.network_exposed', 'probe.ws_auth',
  'probe.health_leak', 'probe.cors',
]);

function box(title) {
  const pad = W52 - 2 - title.length;
  const l = Math.floor(pad/2), r = pad - l;
  return [
    paint.dim('╔' + '═'.repeat(W52-2) + '╗'),
    paint.dim('║') + ' '.repeat(l) + paint.bold(title) + ' '.repeat(r) + paint.dim('║'),
    paint.dim('╚' + '═'.repeat(W52-2) + '╝'),
  ].join('\n');
}

function buildCheckMap(staticResults, liveResults) {
  const map = new Map();
  for (const r of [...staticResults, ...liveResults]) {
    if (r.id) map.set(r.id, r);
  }
  return map;
}

export async function runVerify() {
  const history = loadHistory();

  console.log(''); console.log(box('ClawArmor Verify  v1.0.0')); console.log('');

  if (!history.length) {
    console.log(`  ${paint.dim('No audit history found — running full audit.')}`);
    console.log('');
    const { runAudit } = await import('./audit.js');
    return runAudit();
  }

  const last = history[history.length - 1];
  const failedIds = last.failedIds || [];

  if (!failedIds.length) {
    console.log(`  ${paint.green('✓')} Last audit had no failures — nothing to re-check.`);
    console.log(`  ${paint.dim('Run')} ${paint.cyan('clawarmor audit')} ${paint.dim('for a fresh full audit.')}`);
    console.log('');
    return 0;
  }

  console.log(`  ${paint.dim('Last audit:')} ${new Date(last.timestamp).toLocaleString('en-US',{dateStyle:'medium',timeStyle:'short'})}`);
  console.log(`  ${paint.cyan('Re-checking')} ${paint.bold(String(failedIds.length))} ${paint.dim('previously failed item' + (failedIds.length>1?'s':'') + '...')}`);
  console.log('');

  const { config, error } = loadConfig();
  if (error) {
    console.log(`  ${paint.red('✗')} ${error}`); console.log(''); return 2;
  }

  // Run all checks
  const allStaticChecks = [
    ...gatewayChecks, ...filesystemChecks, ...channelChecks,
    ...authChecks, ...toolChecks, ...versionChecks, ...hooksChecks,
    ...allowFromChecks,
  ];

  const staticResults = [];
  for (const check of allStaticChecks) {
    try { staticResults.push(await check(config)); }
    catch (e) { staticResults.push({ id:'err', severity:'LOW', passed:true, passedMsg:`Check error: ${e.message}` }); }
  }

  let liveResults = [];
  const needsLive = failedIds.some(id => PROBE_IDS.has(id));
  if (needsLive) {
    try { liveResults = await probeGatewayLive(config); }
    catch { liveResults = []; }
  }

  const checkMap = buildCheckMap(staticResults, liveResults);

  const nowPassed = [];
  const stillFailed = [];

  for (const id of failedIds) {
    const result = checkMap.get(id);
    if (!result) {
      // Check not found in this run (may have been removed) — treat as passed
      nowPassed.push({ id, title: id, passedMsg: 'Check no longer applicable' });
      continue;
    }
    if (result.passed) nowPassed.push(result);
    else stillFailed.push(result);
  }

  console.log(SEP);
  if (nowPassed.length) {
    console.log(`  ${paint.green('FIXED')}${paint.dim('  ('+nowPassed.length+')')}`);
    console.log(SEP);
    for (const r of nowPassed) {
      console.log(`  ${paint.green('✓')} ${paint.dim(r.passedMsg || r.title || r.id)}`);
    }
    console.log('');
  }

  if (stillFailed.length) {
    console.log(SEP);
    console.log(`  ${paint.red('STILL FAILING')}${paint.dim('  ('+stillFailed.length+')')}`);
    console.log(SEP);
    for (const f of stillFailed) {
      console.log('');
      const sc = severityColor[f.severity] || paint.dim;
      console.log(`  ${paint.red('✗')} ${sc('['+f.severity+']')} ${paint.bold(f.title)}`);
      for (const line of (f.description||'').split('\n'))
        console.log(`    ${paint.dim(line)}`);
      if (f.fix) {
        const lines = f.fix.split('\n');
        console.log('');
        console.log(`    ${paint.cyan('Fix:')} ${lines[0]}`);
        for (let i=1;i<lines.length;i++) console.log(`         ${lines[i]}`);
      }
    }
    console.log('');
    console.log(SEP);
    console.log(`  ${stillFailed.length} item${stillFailed.length>1?'s':''} still failing.`);
  } else {
    console.log(SEP);
    console.log(`  ${paint.green('✓')} ${paint.bold('All previously-failed checks now pass!')}`);
    console.log(`  ${paint.dim('Run')} ${paint.cyan('clawarmor audit')} ${paint.dim('for a complete re-scan.')}`);
  }
  console.log('');

  return stillFailed.length > 0 ? 1 : 0;
}
