// lib/skill-report.js — Show post-install skill audit impact report
// Generated automatically after each skill install via the clawarmor-guard hook.

import { existsSync, readFileSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import { spawnSync } from 'child_process';
import { paint } from './output/colors.js';

const HOME = homedir();
const CLAWARMOR_DIR = join(HOME, '.clawarmor');
const SKILL_REPORT_FILE = join(CLAWARMOR_DIR, 'skill-install-report.json');
const SEP = paint.dim('─'.repeat(52));

function box(title) {
  const W = 52, pad = W - 2 - title.length, l = Math.floor(pad / 2), r = pad - l;
  return [
    paint.dim('╔' + '═'.repeat(W - 2) + '╗'),
    paint.dim('║') + ' '.repeat(l) + paint.bold(title) + ' '.repeat(r) + paint.dim('║'),
    paint.dim('╚' + '═'.repeat(W - 2) + '╝'),
  ].join('\n');
}

function readReport() {
  try {
    if (!existsSync(SKILL_REPORT_FILE)) return null;
    return JSON.parse(readFileSync(SKILL_REPORT_FILE, 'utf8'));
  } catch { return null; }
}

function applyFixes(fixes) {
  let applied = 0, failed = 0;
  for (const fix of fixes) {
    try {
      const result = spawnSync(fix, { shell: true, encoding: 'utf8', timeout: 30000, stdio: 'pipe' });
      if (result.status === 0) {
        console.log(`  ${paint.green('✓')} ${fix}`);
        applied++;
      } else {
        console.log(`  ${paint.red('✗')} ${fix} — ${(result.stderr || '').split('\n')[0]}`);
        failed++;
      }
    } catch (e) {
      console.log(`  ${paint.red('✗')} ${fix} — ${e.message?.split('\n')[0]}`);
      failed++;
    }
  }
  return { applied, failed };
}

export async function runSkillReport(flags = {}) {
  console.log(''); console.log(box('ClawArmor Skill Report')); console.log('');

  const report = readReport();

  if (!report) {
    console.log(`  ${paint.dim('No skill install report found.')}`);
    console.log(`  ${paint.dim('Reports are generated automatically after each skill install.')}`);
    console.log('');
    return 0;
  }

  const installedAt = new Date(report.installedAt).toLocaleString('en-US', { dateStyle: 'medium', timeStyle: 'short' });
  const deltaStr = report.scoreDelta > 0
    ? paint.green(`+${report.scoreDelta}`)
    : report.scoreDelta < 0
      ? paint.red(String(report.scoreDelta))
      : paint.dim('±0');

  console.log(`  ${paint.bold('Skill:')}        ${report.skill}`);
  console.log(`  ${paint.bold('Installed:')}    ${installedAt}`);
  console.log(`  ${paint.bold('Score:')}        ${report.scoreBefore}/100 → ${report.scoreAfter}/100  (${deltaStr})`);
  console.log('');

  if (report.newFindings && report.newFindings.length > 0) {
    console.log(SEP);
    console.log(`  ${paint.bold('New findings after install:')}`);
    console.log('');
    for (const f of report.newFindings) {
      const sev = f.severity || 'INFO';
      const sevColors = { CRITICAL: paint.red, HIGH: paint.red, MEDIUM: paint.yellow, LOW: paint.dim, INFO: paint.dim };
      const sevColor = sevColors[sev] || paint.dim;
      console.log(`  ${paint.red('✗')} ${paint.bold(f.title || f.id)}  ${paint.dim('←')} ${sevColor(sev)}`);
      if (f.description) {
        for (const line of (f.description || '').split('\n').slice(0, 2)) {
          console.log(`    ${paint.dim(line)}`);
        }
      }
    }
    console.log('');
  } else {
    console.log(`  ${paint.green('✓')} No new findings introduced by this install.`);
    console.log('');
  }

  if (report.proposedFixes && report.proposedFixes.length > 0) {
    console.log(SEP);
    console.log(`  ${paint.bold('Proposed fixes:')}`);
    console.log('');
    for (const fix of report.proposedFixes) {
      console.log(`    ${paint.cyan('$')} ${fix}`);
    }
    console.log('');

    if (flags.apply) {
      console.log(SEP);
      console.log(`  ${paint.cyan('Applying proposed fixes...')}`);
      console.log('');
      const { applied, failed } = applyFixes(report.proposedFixes);
      console.log('');
      console.log(`  Applied: ${paint.green(String(applied))}  Failed: ${failed > 0 ? paint.red(String(failed)) : paint.dim('0')}`);
      console.log('');
      return failed > 0 ? 1 : 0;
    } else {
      console.log(`  ${paint.dim('Run')} ${paint.cyan('clawarmor skill-report --apply')} ${paint.dim('to apply these fixes.')}`);
      console.log('');
    }
  } else {
    console.log(`  ${paint.dim('No auto-fixable issues proposed.')}`);
    console.log('');
  }

  return 0;
}
