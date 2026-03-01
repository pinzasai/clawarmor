#!/usr/bin/env node
// ClawArmor v0.6 — Security armor for OpenClaw agents

import { paint } from './lib/output/colors.js';

const VERSION = '1.0.0';
const GATEWAY_PORT_DEFAULT = 18789;

function trustHeader(port) {
  console.log('');
  console.log(`  ${paint.dim('ℹ')}  ${paint.dim('Reads: ~/.openclaw/openclaw.json + file permissions only')}`);
  console.log(`     ${paint.dim('Network: registry.npmjs.org (version check) + 127.0.0.1:' + port + ' (live probes)')}`);
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
  console.log(`    ${paint.cyan('monitor')}  Coming soon
    ${paint.cyan('fix')}      Auto-apply safe fixes (--dry-run to preview, --apply to run)`);
  console.log('');
  console.log(`  ${paint.dim('Flags:')}`);
  console.log(`    ${paint.dim('--json')}           Machine-readable JSON output (audit only)`);
  console.log(`    ${paint.dim('--explain-reads')}  Print every file read and network call before executing`);
  console.log('');
  console.log(`  ${paint.dim('github.com/pinzasai/clawarmor')}`);
  console.log('');
}

const args = process.argv.slice(2);
const cmd = args[0];
const flags = {
  json: args.includes('--json'),
  explainReads: args.includes('--explain-reads'),
};

if (!cmd || cmd === '--help' || cmd === '-h' || cmd === 'help') { usage(); process.exit(0); }
if (cmd === '--version' || cmd === '-v') { console.log(VERSION); process.exit(0); }

// Load config once for port info (used in trust header)
const { loadConfig } = await import('./lib/config.js');
const { config } = loadConfig();
const gatewayPort = config?.gateway?.port || GATEWAY_PORT_DEFAULT;

if (flags.explainReads) {
  console.log('');
  console.log(`  ${paint.cyan('--explain-reads')} — files and network calls this command will make:`);
  console.log(`    ${paint.dim('Read:')}    ~/.openclaw/openclaw.json`);
  console.log(`    ${paint.dim('Read:')}    ~/.openclaw/agent-accounts.json (permissions only)`);
  console.log(`    ${paint.dim('Read:')}    ~/.openclaw/ (directory permissions)`);
  console.log(`    ${paint.dim('Read:')}    ~/.clawarmor/history.json (audit history)`);
  if (['audit', 'verify'].includes(cmd)) {
    console.log(`    ${paint.dim('Network:')} 127.0.0.1:${gatewayPort} (TCP/WebSocket/HTTP live probes — gateway only)`);
  }
  console.log(`    ${paint.dim('Network:')} registry.npmjs.org (version check)`);
  console.log('');
}

// Print trust header before every command (except --json mode)
if (!flags.json) {
  trustHeader(gatewayPort);
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
  const fixFlags = { apply: process.argv.includes('--apply'), dryRun: process.argv.includes('--dry-run') };
  process.exit(await runFix(fixFlags));
}

if (cmd === 'monitor') {
  const { runMonitor } = await import('./lib/monitor.js');
  runMonitor(); process.exit(0);
}

console.log(`  ${paint.red('✗')} Unknown command: ${paint.bold(cmd)}`);
usage(); process.exit(1);
