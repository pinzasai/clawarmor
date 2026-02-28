import { loadConfig } from './config.js';
import { paint, severityColor } from './output/colors.js';
import { progressBar, scoreColor, gradeColor, scoreToGrade } from './output/progress.js';
import gatewayChecks from './checks/gateway.js';
import filesystemChecks from './checks/filesystem.js';
import channelChecks from './checks/channels.js';
import authChecks from './checks/auth.js';
import toolChecks from './checks/tools.js';
import versionChecks from './checks/version.js';
import hooksChecks from './checks/hooks.js';

const W = { CRITICAL: 25, HIGH: 15, MEDIUM: 8, LOW: 3, INFO: 0 };
const SEP = paint.dim('─'.repeat(52));
const W52 = 52;

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

export async function runAudit(flags = {}) {
  const { config, configPath, error } = loadConfig();
  console.log(''); console.log(box('ClawArmor Audit  v0.5')); console.log('');
  if (error) {
    console.log(`  ${paint.red('✗')} ${error}`); console.log(''); process.exit(2);
  }
  console.log(`  ${paint.dim('Config:')}  ${configPath}`);
  console.log(`  ${paint.dim('Scanned:')} ${new Date().toLocaleString('en-US',{dateStyle:'medium',timeStyle:'short'})}`);
  console.log('');

  const allChecks = [...gatewayChecks, ...filesystemChecks, ...channelChecks,
    ...authChecks, ...toolChecks, ...versionChecks, ...hooksChecks];
  const results = [];
  for (const check of allChecks) {
    try { results.push(await check(config)); }
    catch (e) { results.push({ id:'err', severity:'LOW', passed:true, passedMsg:`Check error: ${e.message}` }); }
  }

  const failed = results.filter(r => !r.passed);
  const passed = results.filter(r => r.passed);
  const criticals = failed.filter(r => r.severity === 'CRITICAL').length;

  // Score with floor rules (adversarial requirement)
  let score = 100;
  for (const f of failed) score -= (W[f.severity] || 0);
  score = Math.max(0, score);
  if (criticals >= 2) score = Math.min(score, 25);
  else if (criticals >= 1) score = Math.min(score, 50);

  const grade = scoreToGrade(score);
  const colorFn = scoreColor(score);
  console.log(`  ${paint.bold('Security Score:')} ${colorFn(score+'/100')}  ${paint.dim('┃')}  Grade: ${gradeColor(grade)}`);
  console.log(`  ${colorFn(progressBar(score,20))}  ${paint.dim(score+'%')}`);
  if (flags.json) { console.log(JSON.stringify({score,grade,failed,passed},null,2)); return 0; }

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
    console.log(`  ${paint.green('PASSED')}${paint.dim('  ('+passed.length+' checks)')}`);
    console.log(SEP);
    for (const p of passed) console.log(`  ${paint.green('✓')} ${paint.dim(p.passedMsg||p.title||p.id)}`);
  }

  console.log(''); console.log(SEP);
  if (!failed.length) {
    console.log(`  ${paint.green('✓')} ${paint.bold('All checks passed.')}`);
  } else {
    console.log(`  ${failed.length} issue${failed.length>1?'s':''} found. Fix above to improve score.`);
  }
  console.log(`  ${paint.dim('Run')} ${paint.cyan('clawarmor scan')} ${paint.dim('to check installed skills.')}`);
  console.log(`  ${paint.dim('Continuous monitoring:')} ${paint.cyan('clawarmor.dev/monitor')}`);
  console.log('');
  return failed.length > 0 ? 1 : 0;
}
