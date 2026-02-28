#!/usr/bin/env node
// ClawArmor — Security armor for OpenClaw agents
// clawarmor.dev

import { paint } from './lib/output/colors.js';

const VERSION = '0.1.0';
const TAGLINE = 'Security armor for OpenClaw agents';

function usage() {
  console.log('');
  console.log(`  ${paint.bold('ClawArmor')} ${paint.dim('v' + VERSION)} — ${TAGLINE}`);
  console.log('');
  console.log(`  ${paint.cyan('Usage:')}  clawarmor <command>`);
  console.log('');
  console.log(`  ${paint.bold('Commands:')}`);
  console.log(`    ${paint.cyan('audit')}    Score your OpenClaw config (0-100) and get exact fixes`);
  console.log(`    ${paint.cyan('scan')}     Scan installed skills for malicious code patterns`);
  console.log(`    ${paint.cyan('monitor')}  Continuous monitoring — $9/month (clawarmor.dev)`);
  console.log('');
  console.log(`  ${paint.dim('Examples:')}`);
  console.log(`    ${paint.dim('npx clawarmor audit')}`);
  console.log(`    ${paint.dim('npx clawarmor scan')}`);
  console.log('');
  console.log(`  ${paint.dim('clawarmor.dev · hello@clawarmor.dev')}`);
  console.log('');
}

const cmd = process.argv[2];

if (!cmd || cmd === '--help' || cmd === '-h' || cmd === 'help') {
  usage();
  process.exit(0);
}

if (cmd === '--version' || cmd === '-v' || cmd === 'version') {
  console.log(VERSION);
  process.exit(0);
}

if (cmd === 'audit') {
  const { runAudit } = await import('./lib/audit.js');
  const exitCode = await runAudit();
  process.exit(exitCode);
}

if (cmd === 'scan') {
  const { runScan } = await import('./lib/scan.js');
  const exitCode = await runScan();
  process.exit(exitCode);
}

if (cmd === 'monitor') {
  const { runMonitor } = await import('./lib/monitor.js');
  runMonitor();
  process.exit(0);
}

console.log('');
console.log(`  ${paint.red('✗')} Unknown command: ${paint.bold(cmd)}`);
usage();
process.exit(1);
