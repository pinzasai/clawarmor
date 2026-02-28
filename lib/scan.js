import { paint, severityColor } from './output/colors.js';
import { scanFile } from './scanner/file-scanner.js';
import { findInstalledSkills } from './scanner/skill-finder.js';

const SEP = paint.dim('─'.repeat(52));
const HOME = process.env.HOME || '';

function short(p) { return p.replace(HOME,'~'); }

function box(title) {
  const W=52, pad=W-2-title.length, l=Math.floor(pad/2), r=pad-l;
  return [paint.dim('╔'+'═'.repeat(W-2)+'╗'),
    paint.dim('║')+' '.repeat(l)+paint.bold(title)+' '.repeat(r)+paint.dim('║'),
    paint.dim('╚'+'═'.repeat(W-2)+'╝')].join('\n');
}

export async function runScan() {
  console.log(''); console.log(box('ClawArmor Skill Scan  v0.5')); console.log('');
  console.log(`  ${paint.dim('Scanning:')} Installed OpenClaw skills`);
  console.log(`  ${paint.dim('Started:')}  ${new Date().toLocaleString('en-US',{dateStyle:'medium',timeStyle:'short'})}`);
  console.log('');

  const skills = findInstalledSkills();
  if (!skills.length) {
    console.log(`  ${paint.dim('No installed skills found.')}`); console.log(''); return 0;
  }

  const userSkills = skills.filter(s => !s.isBuiltin);
  const builtinSkills = skills.filter(s => s.isBuiltin);
  console.log(`  ${paint.dim('Found')} ${paint.bold(String(skills.length))} ${paint.dim('skills')} ${paint.dim(`(${userSkills.length} user-installed, ${builtinSkills.length} built-in)`)}`);
  console.log('');

  let totalCritical = 0, totalHigh = 0;
  const flagged = [];

  for (const skill of skills) {
    process.stdout.write(`  ${skill.isBuiltin ? paint.dim('⊙') : paint.cyan('▶')} ${paint.bold(skill.name)}${paint.dim(skill.isBuiltin?' [built-in]':' [user]')}...`);
    const allFindings = skill.files.flatMap(f => scanFile(f, skill.isBuiltin));

    const critical = allFindings.filter(f => f.severity==='CRITICAL');
    const high = allFindings.filter(f => f.severity==='HIGH');
    const medium = allFindings.filter(f => f.severity==='MEDIUM');
    const info = allFindings.filter(f => f.severity==='INFO'||f.severity==='LOW');

    totalCritical += critical.length; totalHigh += high.length;

    if (!allFindings.length) { process.stdout.write(` ${paint.green('✓ clean')}\n`); continue; }

    const parts = [];
    if (critical.length) parts.push(paint.red(`${critical.length} critical`));
    if (high.length) parts.push(paint.yellow(`${high.length} high`));
    if (medium.length) parts.push(paint.cyan(`${medium.length} medium`));
    if (info.length) parts.push(paint.dim(`${info.length} info`));
    process.stdout.write(` ${parts.join(', ')}\n`);

    if (critical.length || high.length || medium.length) flagged.push({skill, findings: allFindings});
  }

  // Detailed report for flagged skills
  for (const {skill, findings} of flagged) {
    console.log(''); console.log(SEP);
    console.log(`  ${paint.bold(skill.name)}  ${paint.dim(short(skill.path))}`);
    if (skill.isBuiltin) console.log(`  ${paint.dim('ℹ  Built-in skill — review only if recently updated or unexpected')}`);
    else console.log(`  ${paint.yellow('⚠')}  ${paint.bold('Third-party skill — review carefully')}`);
    console.log(SEP);

    for (const sev of ['CRITICAL','HIGH','MEDIUM','INFO','LOW']) {
      for (const f of findings.filter(x=>x.severity===sev)) {
        console.log('');
        console.log(`  ${paint.red('✗')} ${(severityColor[sev]||paint.dim)('['+sev+']')} ${paint.bold(f.title)}`);
        console.log(`    ${paint.dim(f.description)}`);
        if (f.note) console.log(`    ${paint.dim('Note: '+f.note)}`);
        for (const m of f.matches) {
          console.log(`    ${paint.dim('→')} ${paint.cyan(short(f.file)+':'+m.line)}`);
          console.log(`      ${paint.dim(m.snippet)}`);
        }
      }
    }
  }

  console.log(''); console.log(SEP);
  if (!totalCritical && !totalHigh) {
    console.log(`  ${paint.green('✓')} No critical or high findings across ${skills.length} skills.`);
  } else {
    if (totalCritical) console.log(`  ${paint.red('✗')} ${paint.bold(String(totalCritical))} CRITICAL — review immediately`);
    if (totalHigh) console.log(`  ${paint.yellow('✗')} ${paint.bold(String(totalHigh))} HIGH — review before next session`);
    console.log('');
    console.log(`  ${paint.dim('ClawArmor scans ALL skill files (.js .sh .py .ts)')}`);
    console.log(`  ${paint.dim('not just SKILL.md — the gap every other scanner has.')}`);
  }
  console.log(`  ${paint.dim('Run')} ${paint.cyan('clawarmor audit')} ${paint.dim('to check your config.')}`);
  console.log('');
  return totalCritical > 0 ? 1 : 0;
}
