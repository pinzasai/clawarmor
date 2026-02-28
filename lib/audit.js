// clawarmor audit — local config linter
import { loadConfig } from './config.js';
import { paint, severityColor } from './output/colors.js';
import { progressBar, scoreColor, gradeColor, scoreToGrade } from './output/progress.js';
import gatewayChecks from './checks/gateway.js';
import filesystemChecks from './checks/filesystem.js';
import channelChecks from './checks/channels.js';
import authChecks from './checks/auth.js';
import toolChecks from './checks/tools.js';
import versionChecks from './checks/version.js';

const SEVERITY_WEIGHTS = { CRITICAL: 25, HIGH: 15, MEDIUM: 10, LOW: 5 };
const WIDTH = 50;
const HR = paint.dim('─'.repeat(WIDTH));

function box(title) {
  const pad = Math.max(0, WIDTH - 2 - title.length);
  const l = Math.floor(pad / 2), r = pad - l;
  return [
    paint.dim('╔' + '═'.repeat(WIDTH - 2) + '╗'),
    paint.dim('║') + ' '.repeat(l) + paint.bold(title) + ' '.repeat(r) + paint.dim('║'),
    paint.dim('╚' + '═'.repeat(WIDTH - 2) + '╝'),
  ].join('\n');
}

function printFinding(f) {
  const icon = paint.red('  ✗');
  console.log('');
  console.log(`${icon} ${paint.bold(f.title)}`);
  if (f.description) {
    for (const line of f.description.split('\n')) {
      console.log(`    ${paint.dim(line)}`);
    }
  }
  if (f.fix) {
    console.log('');
    const fixLines = f.fix.split('\n');
    console.log(`    ${paint.cyan('Fix:')} ${fixLines[0]}`);
    for (let i = 1; i < fixLines.length; i++) {
      console.log(`         ${fixLines[i]}`);
    }
  }
}

function sectionHeader(label, count) {
  const colorFn = severityColor[label] || paint.bold;
  const suffix = count !== undefined ? paint.dim(`  (${count} ${count === 1 ? 'finding' : 'findings'})`) : '';
  console.log('');
  console.log(HR);
  console.log(`  ${colorFn(label)}${suffix}`);
  console.log(HR);
}

export async function runAudit() {
  const { config, configPath, error } = loadConfig();

  console.log('');
  console.log(box('ClawArmor Audit Report'));
  console.log('');

  if (error) {
    console.log(`  ${paint.red('✗')} ${paint.bold('Cannot load OpenClaw config')}`);
    console.log(`    ${paint.dim(error)}`);
    console.log('');
    process.exit(2);
  }

  const now = new Date().toLocaleString('en-US', { dateStyle: 'medium', timeStyle: 'short' });
  console.log(`  ${paint.dim('Config:')}   ${configPath}`);
  console.log(`  ${paint.dim('Scanned:')}  ${now}`);
  console.log('');

  // Run all checks
  const allChecks = [
    ...gatewayChecks,
    ...filesystemChecks,
    ...channelChecks,
    ...authChecks,
    ...toolChecks,
    ...versionChecks,
  ];

  const results = [];
  for (const check of allChecks) {
    try {
      const result = await check(config);
      results.push(result);
    } catch (err) {
      results.push({
        id: 'error',
        severity: 'LOW',
        passed: true,
        title: 'Check error',
        passedMsg: `Check failed with: ${err.message}`,
      });
    }
  }

  // Compute score
  let score = 100;
  const failed = results.filter(r => !r.passed);
  const passed = results.filter(r => r.passed);
  for (const f of failed) {
    score -= SEVERITY_WEIGHTS[f.severity] || 5;
  }
  score = Math.max(0, score);
  const grade = scoreToGrade(score);
  const colorFn = scoreColor(score);

  // Score display
  const bar = progressBar(score, 20);
  console.log(`  ${paint.bold('Security Score:')} ${colorFn(String(score) + '/100')}  ${paint.dim('┃')}  Grade: ${gradeColor(grade)}`);
  console.log(`  ${colorFn(bar)}  ${paint.dim(score + '%')}`);

  // Group by severity
  const bySeverity = { CRITICAL: [], HIGH: [], MEDIUM: [], LOW: [] };
  for (const f of failed) {
    if (bySeverity[f.severity]) bySeverity[f.severity].push(f);
  }

  // Print failed by severity
  for (const [sev, findings] of Object.entries(bySeverity)) {
    if (findings.length === 0) continue;
    sectionHeader(sev, findings.length);
    for (const f of findings) printFinding(f);
  }

  // Passed section
  if (passed.length > 0) {
    console.log('');
    console.log(HR);
    console.log(`  ${paint.green('PASSED')}${paint.dim(`  (${passed.length} checks)`)}`);
    console.log(HR);
    for (const p of passed) {
      console.log(`  ${paint.green('✓')} ${paint.dim(p.passedMsg || p.title)}`);
    }
  }

  // Footer
  console.log('');
  console.log(HR);
  if (failed.length === 0) {
    console.log(`  ${paint.green('✓')} ${paint.bold('All checks passed. Your instance looks secure.')}`);
  } else {
    console.log(`  ${paint.dim('Found')} ${paint.bold(String(failed.length))} ${paint.dim('issue' + (failed.length > 1 ? 's' : '') + '. Fix the items above to improve your score.')}`);
  }
  console.log(`  ${paint.dim('Run')} ${paint.cyan('clawarmor scan')} ${paint.dim('to check installed skills.')}`);
  console.log(`  ${paint.dim('Continuous monitoring:')} ${paint.cyan('clawarmor.dev/monitor')}`);
  console.log('');

  return failed.length > 0 ? 1 : 0;
}
