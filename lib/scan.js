import { paint, severityColor } from './output/colors.js';
import { scanFile } from './scanner/file-scanner.js';
import { findInstalledSkills } from './scanner/skill-finder.js';
import { scanSkillMdFiles } from './scanner/skill-md-scanner.js';
import { append as auditLogAppend } from './audit-log.js';

const SEP = paint.dim('─'.repeat(52));
const HOME = process.env.HOME || '';

function short(p) { return p.replace(HOME,'~'); }

function box(title) {
  const W=52, pad=W-2-title.length, l=Math.floor(pad/2), r=pad-l;
  return [paint.dim('╔'+'═'.repeat(W-2)+'╗'),
    paint.dim('║')+' '.repeat(l)+paint.bold(title)+' '.repeat(r)+paint.dim('║'),
    paint.dim('╚'+'═'.repeat(W-2)+'╝')].join('\n');
}

export async function runScan(flags = {}) {
  const jsonMode = flags.json || false;

  if (!jsonMode) {
    console.log(''); console.log(box('ClawArmor Skill Scan  v0.6')); console.log('');
    console.log(`  ${paint.dim('Scanning:')} Installed OpenClaw skills (code + SKILL.md)`);
    console.log(`  ${paint.dim('Started:')}  ${new Date().toLocaleString('en-US',{dateStyle:'medium',timeStyle:'short'})}`);
    console.log('');
  }

  const skills = findInstalledSkills();
  if (!skills.length) {
    if (jsonMode) {
      process.stdout.write(JSON.stringify({ verdict: 'PASS', score: 100, totalSkills: 0, flaggedSkills: 0, findings: [], scannedAt: new Date().toISOString() }, null, 2) + '\n');
    } else {
      console.log(`  ${paint.dim('No installed skills found.')}`); console.log('');
    }
    return 0;
  }

  const userSkills = skills.filter(s => !s.isBuiltin);
  const builtinSkills = skills.filter(s => s.isBuiltin);
  if (!jsonMode) {
    console.log(`  ${paint.dim('Found')} ${paint.bold(String(skills.length))} ${paint.dim('skills')} ${paint.dim(`(${userSkills.length} user-installed, ${builtinSkills.length} built-in)`)}`);
    console.log('');
  }

  let totalCritical = 0, totalHigh = 0;
  const flagged = [];
  const auditFindings = []; // accumulated for audit log
  const jsonFindings = []; // for --json output

  for (const skill of skills) {
    if (!jsonMode) process.stdout.write(`  ${skill.isBuiltin ? paint.dim('⊙') : paint.cyan('▶')} ${paint.bold(skill.name)}${paint.dim(skill.isBuiltin?' [built-in]':' [user]')}...`);

    // Code findings (JS, py, sh, etc.)
    const codeFindings = skill.files.flatMap(f => scanFile(f, skill.isBuiltin));

    // SKILL.md instruction findings
    const mdResults = scanSkillMdFiles(skill.files, skill.isBuiltin);
    const mdFindings = mdResults.flatMap(r => r.findings);

    const allFindings = [...codeFindings, ...mdFindings];
    for (const f of allFindings) auditFindings.push({ id: f.patternId || f.id || '?', severity: f.severity });

    const critical = allFindings.filter(f => f.severity==='CRITICAL');
    const high = allFindings.filter(f => f.severity==='HIGH');
    const medium = allFindings.filter(f => f.severity==='MEDIUM');
    const info = allFindings.filter(f => f.severity==='INFO'||f.severity==='LOW');

    totalCritical += critical.length; totalHigh += high.length;

    // Collect findings for JSON output
    for (const f of allFindings) {
      if (['CRITICAL','HIGH','MEDIUM','LOW'].includes(f.severity)) {
        for (const m of (f.matches || [])) {
          jsonFindings.push({
            skill: skill.name,
            severity: f.severity,
            patternId: f.patternId || f.id || 'unknown',
            message: f.title || f.description || '',
            file: (f.file || '').replace(HOME, '~'),
            line: m.line,
          });
        }
        if (!(f.matches && f.matches.length)) {
          jsonFindings.push({
            skill: skill.name,
            severity: f.severity,
            patternId: f.patternId || f.id || 'unknown',
            message: f.title || f.description || '',
            file: (f.file || '').replace(HOME, '~'),
            line: null,
          });
        }
      }
    }

    if (!jsonMode) {
      if (!allFindings.length) { process.stdout.write(` ${paint.green('✓ clean')}\n`); continue; }

      const parts = [];
      if (critical.length) parts.push(paint.red(`${critical.length} critical`));
      if (high.length) parts.push(paint.yellow(`${high.length} high`));
      if (medium.length) parts.push(paint.cyan(`${medium.length} medium`));
      if (info.length) parts.push(paint.dim(`${info.length} info`));
      process.stdout.write(` ${parts.join(', ')}\n`);
    }

    if (critical.length || high.length || medium.length) {
      flagged.push({ skill, codeFindings, mdResults });
    }
  }

  // JSON output mode
  if (jsonMode) {
    // Compute scan score: start 100, -25 per CRITICAL, -10 per HIGH, -3 per MEDIUM
    let scanScore = 100;
    for (const f of jsonFindings) {
      if (f.severity === 'CRITICAL') scanScore -= 25;
      else if (f.severity === 'HIGH') scanScore -= 10;
      else if (f.severity === 'MEDIUM') scanScore -= 3;
    }
    scanScore = Math.max(0, scanScore);

    let verdict = 'PASS';
    if (totalCritical > 0) verdict = 'BLOCK';
    else if (totalHigh > 0) verdict = 'WARN';

    const output = {
      verdict,
      score: scanScore,
      totalSkills: skills.length,
      flaggedSkills: flagged.length,
      findings: jsonFindings,
      scannedAt: new Date().toISOString(),
    };
    process.stdout.write(JSON.stringify(output, null, 2) + '\n');

    auditLogAppend({ cmd: 'scan', trigger: 'manual', score: null, delta: null,
      findings: auditFindings, blocked: null, skill: null });

    return totalCritical > 0 ? 1 : 0;
  }

  // Detailed human report for flagged skills
  for (const {skill, codeFindings, mdResults} of flagged) {
    console.log(''); console.log(SEP);
    console.log(`  ${paint.bold(skill.name)}  ${paint.dim(short(skill.path))}`);
    if (skill.isBuiltin) console.log(`  ${paint.dim('ℹ  Built-in skill — review only if recently updated or unexpected')}`);
    else console.log(`  ${paint.yellow('⚠')}  ${paint.bold('Third-party skill — review carefully')}`);
    console.log(SEP);

    // Code findings
    const codeFlagged = codeFindings.filter(f => ['CRITICAL','HIGH','MEDIUM'].includes(f.severity));
    if (codeFlagged.length) {
      console.log(`\n  ${paint.dim('── Code Findings ──')}`);
      for (const sev of ['CRITICAL','HIGH','MEDIUM','INFO','LOW']) {
        for (const f of codeFindings.filter(x=>x.severity===sev)) {
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

    // SKILL.md findings
    if (mdResults.length) {
      console.log(`\n  ${paint.dim('── SKILL.md Instruction Findings ──')}`);
      for (const { filePath, findings } of mdResults) {
        console.log(`  ${paint.dim(short(filePath))}`);
        for (const f of findings) {
          const sc = severityColor[f.severity] || paint.dim;
          console.log('');
          console.log(`  ${paint.red('✗')} ${sc('['+f.severity+']')} ${paint.bold(f.title)}`);
          console.log(`    ${paint.dim(f.description)}`);
          if (f.note) console.log(`    ${paint.dim('Note: '+f.note)}`);
          for (const m of f.matches) {
            console.log(`    ${paint.dim('→')} ${paint.cyan(short(filePath)+':'+m.line)}`);
            console.log(`      ${paint.dim(m.snippet)}`);
          }
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
    console.log(`  ${paint.dim('ClawArmor scans ALL skill files (.js .sh .py .ts) + SKILL.md')}`);
    console.log(`  ${paint.dim('not just code — dangerous natural language instructions caught too.')}`);
  }
  console.log(`  ${paint.dim('Run')} ${paint.cyan('clawarmor audit')} ${paint.dim('to check your config.')}`);
  console.log('');

  auditLogAppend({
    cmd: 'scan',
    trigger: 'manual',
    score: null,
    delta: null,
    findings: auditFindings,
    blocked: null,
    skill: null,
  });

  return totalCritical > 0 ? 1 : 0;
}
