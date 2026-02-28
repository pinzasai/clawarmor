#!/usr/bin/env node
// ClawArmor v0.5 — Security armor for OpenClaw agents
// clawarmor.dev

import { paint } from './lib/output/colors.js';

const VERSION = '0.5.0';

function usage() {
  console.log('');
  console.log(`  ${paint.bold('ClawArmor')} ${paint.dim('v'+VERSION)} — Security armor for OpenClaw agents`);
  console.log('');
  console.log(`  ${paint.cyan('Usage:')}  clawarmor <command> [flags]`);
  console.log('');
  console.log(`  ${paint.bold('Commands:')}`);
  console.log(`    ${paint.cyan('audit')}    Score your OpenClaw config (0-100), zero false positives`);
  console.log(`    ${paint.cyan('scan')}     Scan ALL skill files for malicious code patterns`);
  console.log(`    ${paint.cyan('compare')} Compare coverage vs openclaw security audit`);
  console.log(`    ${paint.cyan('monitor')}  Continuous external monitoring — clawarmor.dev ($9/mo)`);
  console.log('');
  console.log(`  ${paint.dim('Flags:')}`);
  console.log(`    ${paint.dim('--json')}   Machine-readable JSON output (audit only)`);
  console.log('');
  console.log(`  ${paint.dim('clawarmor.dev · hello@clawarmor.dev')}`);
  console.log('');
}

const cmd = process.argv[2];
const flags = { json: process.argv.includes('--json') };

if (!cmd || cmd === '--help' || cmd === '-h' || cmd === 'help') { usage(); process.exit(0); }
if (cmd === '--version' || cmd === '-v') { console.log(VERSION); process.exit(0); }

if (cmd === 'audit') {
  const { runAudit } = await import('./lib/audit.js');
  process.exit(await runAudit(flags));
}

if (cmd === 'scan') {
  const { runScan } = await import('./lib/scan.js');
  process.exit(await runScan());
}

if (cmd === 'compare') {
  const { runCompare } = await import('./lib/compare.js');
  process.exit(await runCompare());
}

if (cmd === 'monitor') {
  const { runMonitor } = await import('./lib/monitor.js');
  runMonitor(); process.exit(0);
}

console.log(`  ${paint.red('✗')} Unknown command: ${paint.bold(cmd)}`);
usage(); process.exit(1);
