// Beautiful terminal output for audit + scan results
import { paint, severityColor } from './colors.js';
import { progressBar, scoreColor, gradeColor } from './progress.js';

const WIDTH = 46;
const HR = '─'.repeat(WIDTH);

function line(s = '') {
  return s;
}

function box(title) {
  const pad = Math.max(0, WIDTH - 2 - title.length);
  const left = Math.floor(pad / 2);
  const right = pad - left;
  return [
    `╔${'═'.repeat(WIDTH - 2)}╗`,
    `║${' '.repeat(left)}${paint.bold(title)}${' '.repeat(right)}║`,
    `╚${'═'.repeat(WIDTH - 2)}╝`,
  ].join('\n');
}

function sectionHeader(label, count) {
  const countStr = count !== undefined ? `  (${count} ${count === 1 ? 'finding' : count === 0 ? 'checks' : 'findings'})` : '';
  const colorFn = severityColor[label] || paint.bold;
  return [
    line(HR),
    line(`  ${colorFn(label)}${paint.dim(countStr)}`),
    line(HR),
  ].join('\n');
}

function passedSection(findings) {
  const lines = [
    line(HR),
    line(`  ${paint.green('PASSED')}${paint.dim(`  (${findings.length} checks)`)}`),
    line(HR),
  ];
  for (const f of findings) {
    lines.push(`  ${paint.pass('✓')} ${paint.dim(f.passedMsg || f.title)}`);
  }
  return lines.join('\n');
}

function finding(f) {
  const icon = paint.fail('✗');
  const title = paint.bold(f.title);
  const lines = [``, `  ${icon} ${title}`];

  if (f.description) {
    for (const descLine of f.description.split('\n')) {
      lines.push(`    ${paint.dim(descLine)}`);
    }
  }

  if (f.fix) {
    lines.push('');
    const fixLines = f.fix.split('\n');
    lines.push(`    ${paint.cyan('Fix:')} ${fixLines[0]}`);
    for (let i = 1; i < fixLines.length; i++) {
      lines.push(`         ${fixLines[i]}`);
    }
  }

  return lines.join('\n');
}

export function formatAuditReport({ configPath, score, grade, findings, passed, scannedAt }) {
  const out = [];

  out.push('');
  out.push(box('ClawArmor Audit Report'));
  out.push('');
  out.push(`  ${paint.dim('Config:')}  ${paint.white(configPath)}`);
  out.push(`  ${paint.dim('Scanned:')} ${paint.white(scannedAt)}`);
  out.push('');

  const scoreStr = `${score}/100`;
  const gradeStr = `Grade: ${grade}`;
  const colorScore = scoreColor(score);
  const colorGrade = gradeColor(grade);
  out.push(`  ${paint.bold('Security Score:')} ${colorScore(scoreStr)}  ${paint.dim('┃')}  ${colorGrade(gradeStr)}`);
  out.push(`  ${progressBar(score)}  ${paint.dim(`${score}%`)}`);
  out.push('');

  // Group findings by severity
  const bySeverity = { CRITICAL: [], HIGH: [], MEDIUM: [], LOW: [] };
  for (const f of findings) {
    if (bySeverity[f.severity]) bySeverity[f.severity].push(f);
  }

  for (const [sev, sevFindings] of Object.entries(bySeverity)) {
    if (sevFindings.length === 0) continue;
    out.push(sectionHeader(sev, sevFindings.length));
    for (const f of sevFindings) {
      out.push(finding(f));
    }
    out.push('');
  }

  if (passed.length > 0) {
    out.push(passedSection(passed));
    out.push('');
  }

  out.push(line(HR));
  out.push('');

  if (findings.length === 0) {
    out.push(`  ${paint.pass('✓')} ${paint.bold('All checks passed. Your config looks secure.')}`);
  } else {
    out.push(`  ${paint.dim('Run')} ${paint.cyan('clawarmor scan')} ${paint.dim('to check installed skills.')}`);
    out.push(`  ${paint.dim('Continuous monitoring:')} ${paint.cyan('github.com/pinzasai/clawarmor')}`);
  }
  out.push('');

  return out.join('\n');
}

// ─── Scan formatter ──────────────────────────────────────────────────────────

function scanFinding(f) {
  const icon = paint.fail('✗');
  const title = paint.bold(f.title);
  const lines = [``, `    ${icon} ${title}`];
  lines.push(`      ${paint.dim('File:')} ${paint.white(f.file)}${f.line ? paint.dim(`:${f.line}`) : ''}`);
  if (f.snippet) {
    lines.push(`      ${paint.dim('Code:')} ${paint.yellow(f.snippet.slice(0, 120))}`);
  }
  if (f.description) {
    lines.push(`      ${paint.dim(f.description)}`);
  }
  return lines.join('\n');
}

export function formatScanReport({ skillsScanned, findings, scannedAt, skillsDir }) {
  const out = [];

  out.push('');
  out.push(box('ClawArmor Skill Scan'));
  out.push('');
  out.push(`  ${paint.dim('Directory:')} ${paint.white(skillsDir || 'multiple locations')}`);
  out.push(`  ${paint.dim('Scanned:')}   ${paint.white(scannedAt)}`);
  out.push(`  ${paint.dim('Skills:')}    ${paint.white(String(skillsScanned))}`);
  out.push('');

  if (findings.length === 0) {
    out.push(line(HR));
    out.push('');
    out.push(`  ${paint.pass('✓')} ${paint.bold('No suspicious patterns found in installed skills.')}`);
    out.push('');
    out.push(line(HR));
    out.push('');
    return out.join('\n');
  }

  // Group by skill, then severity
  const bySkill = {};
  for (const f of findings) {
    if (!bySkill[f.skill]) bySkill[f.skill] = [];
    bySkill[f.skill].push(f);
  }

  for (const [skillName, skillFindings] of Object.entries(bySkill)) {
    const critCount = skillFindings.filter(f => f.severity === 'CRITICAL').length;
    const highCount = skillFindings.filter(f => f.severity === 'HIGH').length;
    const badge = critCount > 0 ? paint.critical(`CRITICAL`) : highCount > 0 ? paint.high('HIGH') : paint.medium('MEDIUM');
    out.push(line(HR));
    out.push(`  ${paint.bold(skillName)}  ${badge}`);
    out.push(line(HR));

    const bySev = { CRITICAL: [], HIGH: [], MEDIUM: [], LOW: [] };
    for (const f of skillFindings) {
      if (bySev[f.severity]) bySev[f.severity].push(f);
    }

    for (const [sev, sevFindings] of Object.entries(bySev)) {
      if (sevFindings.length === 0) continue;
      const colorFn = severityColor[sev];
      out.push(`  ${colorFn(sev)}  ${paint.dim(`(${sevFindings.length})`)}`);
      for (const f of sevFindings) {
        out.push(scanFinding(f));
      }
      out.push('');
    }
  }

  out.push(line(HR));
  out.push('');
  out.push(`  ${paint.bold(`${findings.length} suspicious ${findings.length === 1 ? 'pattern' : 'patterns'} found`)} across ${Object.keys(bySkill).length} ${Object.keys(bySkill).length === 1 ? 'skill' : 'skills'}.`);
  out.push(`  ${paint.dim('Review findings carefully before using these skills.')}`);
  out.push('');

  return out.join('\n');
}

export function formatNoSkills(dirs) {
  const out = [];
  out.push('');
  out.push(box('ClawArmor Skill Scan'));
  out.push('');
  out.push(`  ${paint.dim('No installed skills found.')}`);
  out.push('');
  out.push(`  ${paint.dim('Checked:')}`);
  for (const d of dirs) {
    out.push(`    ${paint.dim('•')} ${d}`);
  }
  out.push('');
  out.push(`  ${paint.dim('Install skills via OpenClaw, then run')} ${paint.cyan('clawarmor scan')} ${paint.dim('again.')}`);
  out.push('');
  return out.join('\n');
}
