// clawarmor scan — skill supply chain scanner
import { paint, severityColor } from './output/colors.js';
import { scanFile } from './scanner/file-scanner.js';
import { findInstalledSkills } from './scanner/skill-finder.js';
import { extname } from 'path';

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

function shortPath(filePath) {
  const home = process.env.HOME || '';
  return filePath.replace(home, '~');
}

export async function runScan() {
  console.log('');
  console.log(box('ClawArmor Skill Scan'));
  console.log('');

  const now = new Date().toLocaleString('en-US', { dateStyle: 'medium', timeStyle: 'short' });
  console.log(`  ${paint.dim('Scanning:')} Installed OpenClaw skills`);
  console.log(`  ${paint.dim('Started:')}  ${now}`);
  console.log('');

  const skills = findInstalledSkills();

  if (skills.length === 0) {
    console.log(`  ${paint.dim('No installed skills found.')}`);
    console.log(`  ${paint.dim('Skills are looked for in ~/.openclaw/skills/ and related paths.')}`);
    console.log('');
    return 0;
  }

  console.log(`  ${paint.dim('Found')} ${paint.bold(String(skills.length))} ${paint.dim('skill' + (skills.length > 1 ? 's' : '') + ' to scan...')}`);

  let totalFindings = 0;
  let totalCritical = 0;
  const skillResults = [];

  for (const skill of skills) {
    process.stdout.write(`  ${paint.dim('Scanning')} ${paint.cyan(skill.name)}...`);

    const allFindings = [];
    for (const file of skill.files) {
      const findings = scanFile(file);
      allFindings.push(...findings);
    }

    const critical = allFindings.filter(f => f.severity === 'CRITICAL');
    const high = allFindings.filter(f => f.severity === 'HIGH');
    const medium = allFindings.filter(f => f.severity === 'MEDIUM');

    totalFindings += allFindings.length;
    totalCritical += critical.length;

    if (allFindings.length === 0) {
      process.stdout.write(` ${paint.green('✓ clean')}\n`);
    } else {
      const summary = [];
      if (critical.length) summary.push(paint.red(`${critical.length} critical`));
      if (high.length) summary.push(paint.yellow(`${high.length} high`));
      if (medium.length) summary.push(paint.dim(`${medium.length} medium`));
      process.stdout.write(` ${paint.red('✗')} ${summary.join(', ')}\n`);
    }

    if (allFindings.length > 0) {
      skillResults.push({ skill, findings: allFindings });
    }
  }

  // Detailed report for flagged skills
  if (skillResults.length > 0) {
    for (const { skill, findings } of skillResults) {
      console.log('');
      console.log(HR);
      console.log(`  ${paint.bold(skill.name)}  ${paint.dim(shortPath(skill.path))}`);
      console.log(HR);

      const bySeverity = { CRITICAL: [], HIGH: [], MEDIUM: [] };
      for (const f of findings) {
        if (bySeverity[f.severity]) bySeverity[f.severity].push(f);
      }

      for (const [sev, sevFindings] of Object.entries(bySeverity)) {
        if (!sevFindings.length) continue;
        const colorFn = severityColor[sev] || paint.bold;
        for (const f of sevFindings) {
          console.log('');
          console.log(`  ${paint.red('✗')} ${colorFn('[' + sev + ']')} ${paint.bold(f.title)}`);
          console.log(`    ${paint.dim(f.description)}`);
          for (const m of f.matches) {
            const relFile = shortPath(f.file);
            console.log(`    ${paint.dim('→')} ${paint.cyan(relFile + ':' + m.line)}`);
            console.log(`      ${paint.dim(m.snippet)}`);
          }
        }
      }

      if (skill.isBuiltIn) {
        console.log('');
        console.log(`  ${paint.dim('ℹ  Built-in skill — consider reporting to the OpenClaw team.')}`);
      } else {
        console.log('');
        console.log(`  ${paint.yellow('⚠')}  ${paint.dim('Third-party skill — review carefully before continuing to use.')}`);
      }
    }
  }

  // Summary
  console.log('');
  console.log(HR);
  if (totalFindings === 0) {
    console.log(`  ${paint.green('✓')} ${paint.bold('All skills clean.')} No suspicious patterns found.`);
  } else {
    console.log(`  ${paint.red('✗')} ${paint.bold(String(totalFindings))} finding${totalFindings > 1 ? 's' : ''} across ${skillResults.length} skill${skillResults.length > 1 ? 's' : ''}.`);
    if (totalCritical > 0) {
      console.log(`  ${paint.red('!')} ${paint.bold(String(totalCritical))} CRITICAL — review immediately.`);
    }
    console.log('');
    console.log(`  ${paint.dim('Note: ClawArmor scans ALL skill files (.js, .sh, .py, .ts etc.)')}`);
    console.log(`  ${paint.dim('not just SKILL.md — catching patterns other scanners miss.')}`);
  }
  console.log(`  ${paint.dim('Run')} ${paint.cyan('clawarmor audit')} ${paint.dim('to check your OpenClaw config.')}`);
  console.log('');

  return totalCritical > 0 ? 1 : 0;
}
