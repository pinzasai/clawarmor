#!/usr/bin/env node
// ClawArmor v2.0.0-alpha.2 — Security armor for OpenClaw agents

import { paint } from './lib/output/colors.js';

const VERSION = '3.0.0';
const GATEWAY_PORT_DEFAULT = 18789;

function isLocalhost(host) {
  return host === '127.0.0.1' || host === 'localhost' || host === '::1';
}

function parseUrlFlag(urlArg) {
  // Accepts host:port or plain host (defaults to GATEWAY_PORT_DEFAULT)
  if (!urlArg) return null;
  const lastColon = urlArg.lastIndexOf(':');
  if (lastColon !== -1 && lastColon !== 0) {
    const maybePort = urlArg.slice(lastColon + 1);
    if (/^\d+$/.test(maybePort)) {
      return { host: urlArg.slice(0, lastColon), port: parseInt(maybePort, 10) };
    }
  }
  return { host: urlArg, port: GATEWAY_PORT_DEFAULT };
}

function trustHeader(port, targetHost) {
  const isRemote = targetHost && !isLocalhost(targetHost);
  const probeTarget = targetHost ? `${targetHost}:${port}` : `127.0.0.1:${port}`;
  console.log('');
  console.log(`  ${paint.dim('ℹ')}  ${paint.dim('Config: local (~/.openclaw/openclaw.json)')}`);
  console.log(`     ${paint.dim('Probes: ' + probeTarget + (isRemote ? ' (remote)' : ' (local)'))}`);
  console.log(`     ${paint.dim('Sends nothing. Source: github.com/pinzasai/clawarmor')}`);
}

function usage() {
  console.log('');
  console.log(`  ${paint.bold('ClawArmor')} ${paint.dim('v'+VERSION)} — Security armor for OpenClaw agents`);
  console.log('');
  console.log(`  ${paint.cyan('Usage:')}  clawarmor <command> [flags]`);
  console.log('');
  console.log(`  ${paint.bold('Commands:')}`);
  console.log(`    ${paint.cyan('audit')}    Score your OpenClaw config (0-100), zero false positives`);
  console.log(`    ${paint.cyan('scan')}     Scan ALL skill files for malicious code + SKILL.md instructions`);
  console.log(`    ${paint.cyan('verify')}   Re-check only previously-failed items`);
  console.log(`    ${paint.cyan('trend')}    Show score over last N audits (ASCII chart)`);
  console.log(`    ${paint.cyan('compare')}  Compare coverage vs openclaw security audit`);
  console.log(`    ${paint.cyan('fix')}      Auto-apply safe fixes (--dry-run to preview, --apply to run)`);
  console.log(`    ${paint.cyan('harden')}   Interactive hardening wizard (--dry-run, --auto, --monitor)`);
  console.log(`    ${paint.cyan('rollback')} Restore config from a snapshot (--list, --id <id>)`);
  console.log(`    ${paint.cyan('status')}   One-screen security posture dashboard`);
  console.log(`    ${paint.cyan('watch')}    Monitor config and skill changes in real time`);
  console.log(`    ${paint.cyan('protect')}  Install/uninstall/status the full guard system`);
  console.log(`    ${paint.cyan('prescan')}  Pre-scan a skill before installing it`);
  console.log(`    ${paint.cyan('stack')}    Security orchestrator — deploy Invariant + IronCurtain from audit data`);
  console.log(`    ${paint.cyan('log')}      View the audit event log`);
  console.log(`    ${paint.cyan('digest')}   Show weekly security digest`);
  console.log('');
  console.log(`  ${paint.dim('Flags:')}`);
  console.log(`    ${paint.dim('--url <host:port>')}   Probe a specific host:port instead of 127.0.0.1`);
  console.log(`    ${paint.dim('--config <path>')}     Use a specific config file instead of ~/.openclaw/openclaw.json`);
  console.log(`    ${paint.dim('--json')}              Machine-readable JSON output (audit only)`);
  console.log(`    ${paint.dim('--explain-reads')}     Print every file read and network call before executing
    ${paint.dim('--accept-changes')}    Update config baseline after reviewing detected changes`);
  console.log('');
  console.log(`  ${paint.dim('Examples:')}`);
  console.log(`    ${paint.dim('clawarmor audit')}                         ${paint.dim('# local, default')}`);
  console.log(`    ${paint.dim('clawarmor audit --url 10.0.0.5:18789')}    ${paint.dim('# probe LAN instance')}`);
  console.log(`    ${paint.dim('clawarmor audit --url myserver.com:18789')} ${paint.dim('# probe remote (auth warning)')}`);
  console.log('');
  console.log(`  ${paint.dim('github.com/pinzasai/clawarmor')}`);
  console.log('');
}

const args = process.argv.slice(2);
const cmd = args[0];

// Parse --url flag
const urlIdx = args.indexOf('--url');
const urlArg = urlIdx !== -1 ? args[urlIdx + 1] : null;
const parsedUrl = parseUrlFlag(urlArg);

// Parse --config flag
const configIdx = args.indexOf('--config');
const configPathArg = configIdx !== -1 ? args[configIdx + 1] : null;

const flags = {
  json: args.includes('--json'),
  explainReads: args.includes('--explain-reads'),
  targetHost: parsedUrl?.host || null,
  targetPort: parsedUrl?.port || null,
  configPath: configPathArg || null,
  acceptChanges: args.includes('--accept-changes'),
};

if (!cmd || cmd === '--help' || cmd === '-h' || cmd === 'help') { usage(); process.exit(0); }
if (cmd === '--version' || cmd === '-v') { console.log(VERSION); process.exit(0); }

// Load config once for port info (used in trust header)
const { loadConfig } = await import('./lib/config.js');
const { config } = loadConfig(flags.configPath);
const gatewayPort = flags.targetPort || config?.gateway?.port || GATEWAY_PORT_DEFAULT;
const targetHost = flags.targetHost || null;

if (flags.explainReads) {
  const probeTarget = targetHost ? `${targetHost}:${gatewayPort}` : `127.0.0.1:${gatewayPort}`;
  console.log('');
  console.log(`  ${paint.cyan('--explain-reads')} — files and network calls this command will make:`);
  console.log(`    ${paint.dim('Read:')}    ${flags.configPath || '~/.openclaw/openclaw.json'}`);
  console.log(`    ${paint.dim('Read:')}    ~/.openclaw/agent-accounts.json (permissions only)`);
  console.log(`    ${paint.dim('Read:')}    ~/.openclaw/ (directory permissions)`);
  console.log(`    ${paint.dim('Read:')}    ~/.clawarmor/history.json (audit history)`);
  if (['audit', 'verify'].includes(cmd)) {
    console.log(`    ${paint.dim('Network:')} ${probeTarget} (TCP/WebSocket/HTTP live probes — gateway only)`);
  }
  console.log(`    ${paint.dim('Network:')} registry.npmjs.org (version check)`);
  console.log('');
}

// Remote host warning (printed before trust header so it's prominent)
if (targetHost && !isLocalhost(targetHost)) {
  console.log('');
  console.log(`  ${paint.yellow('⚠')}  ${paint.bold('Probing remote host — ensure you have authorization')}`);
  console.log(`     ${paint.dim('Target: ' + targetHost + ':' + gatewayPort)}`);
}

// Print trust header before every command (except --json mode)
if (!flags.json) {
  trustHeader(gatewayPort, targetHost);
}

if (cmd === 'audit') {
  const { runAudit } = await import('./lib/audit.js');
  process.exit(await runAudit(flags));
}

if (cmd === 'scan') {
  const { runScan } = await import('./lib/scan.js');
  process.exit(await runScan());
}

if (cmd === 'verify') {
  const { runVerify } = await import('./lib/verify.js');
  process.exit(await runVerify());
}

if (cmd === 'trend') {
  const idx = args.indexOf('--last');
  const n = (idx !== -1 && args[idx+1]) ? (parseInt(args[idx+1], 10) || 10) : 10;
  const { runTrend } = await import('./lib/trend.js');
  process.exit(await runTrend({ n }));
}

if (cmd === 'compare') {
  const { runCompare } = await import('./lib/compare.js');
  process.exit(await runCompare());
}


if (cmd === 'fix') {
  const { runFix } = await import('./lib/fix.js');
  const fixFlags = { apply: process.argv.includes('--apply'), dryRun: process.argv.includes('--dry-run'), force: process.argv.includes('--force') };
  process.exit(await runFix(fixFlags));
}

if (cmd === 'watch') {
  const { runWatch } = await import('./lib/watch.js');
  const watchFlags = { daemon: args.includes('--daemon') };
  process.exit(await runWatch(watchFlags));
}

if (cmd === 'protect') {
  const { runProtect } = await import('./lib/protect.js');
  const protectFlags = {
    install: args.includes('--install'),
    uninstall: args.includes('--uninstall'),
    status: args.includes('--status'),
  };
  process.exit(await runProtect(protectFlags));
}

if (cmd === 'prescan') {
  const skillArg = args[1];
  if (!skillArg) {
    console.log(`  Usage: clawarmor prescan <skill-name>`);
    process.exit(1);
  }
  const { runPrescan } = await import('./lib/prescan.js');
  process.exit(await runPrescan(skillArg));
}

if (cmd === 'log') {
  const sinceIdx = args.indexOf('--since');
  const sinceArg = sinceIdx !== -1 ? args[sinceIdx + 1] : null;
  const logFlags = {
    json: args.includes('--json'),
    tokens: args.includes('--tokens'),
    since: sinceArg || null,
  };
  const { runLog } = await import('./lib/log-viewer.js');
  process.exit(await runLog(logFlags));
}

if (cmd === 'harden') {
  const hardenFlags = {
    dryRun: args.includes('--dry-run'),
    auto: args.includes('--auto'),
    force: args.includes('--force'),
    monitor: args.includes('--monitor'),
    monitorReport: args.includes('--monitor-report'),
    monitorOff: args.includes('--monitor-off'),
  };
  const { runHarden } = await import('./lib/harden.js');
  process.exit(await runHarden(hardenFlags));
}

if (cmd === 'rollback') {
  const idIdx = args.indexOf('--id');
  const rollbackFlags = {
    list: args.includes('--list'),
    id: idIdx !== -1 ? args[idIdx + 1] : null,
  };
  const { runRollback } = await import('./lib/rollback.js');
  process.exit(await runRollback(rollbackFlags));
}

if (cmd === 'status') {
  const { runStatus } = await import('./lib/status.js');
  process.exit(await runStatus());
}

if (cmd === 'digest') {
  const { runDigest } = await import('./lib/digest.js');
  process.exit(await runDigest());
}

if (cmd === 'stack') {
  const { runStack } = await import('./lib/stack.js');
  const stackArgs = args.slice(1);
  process.exit(await runStack(stackArgs));
}

console.log(`  ${paint.red('✗')} Unknown command: ${paint.bold(cmd)}`);
usage(); process.exit(1);
