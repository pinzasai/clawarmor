import { existsSync, writeFileSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';
import { homedir, hostname, platform } from 'os';
import { spawnSync } from 'child_process';
import { paint, severityColor } from './output/colors.js';
import { scanFile } from './scanner/file-scanner.js';
import { findInstalledSkills } from './scanner/skill-finder.js';
import { scanSkillMdFiles } from './scanner/skill-md-scanner.js';
import { append as auditLogAppend } from './audit-log.js';

const SEP = paint.dim('─'.repeat(52));
const HOME = homedir();
const VERSION = '3.5.1';

function short(p) { return p.replace(HOME,'~'); }

function box(title) {
  const W=52, pad=W-2-title.length, l=Math.floor(pad/2), r=pad-l;
  return [paint.dim('╔'+'═'.repeat(W-2)+'╗'),
    paint.dim('║')+' '.repeat(l)+paint.bold(title)+' '.repeat(r)+paint.dim('║'),
    paint.dim('╚'+'═'.repeat(W-2)+'╝')].join('\n');
}

// ── Report support ────────────────────────────────────────────────────────────

function getSystemInfo() {
  let ocVersion = 'unknown';
  try {
    const r = spawnSync('openclaw', ['--version'], { encoding: 'utf8', timeout: 5000 });
    if (r.stdout) ocVersion = r.stdout.trim().split('\n')[0] || 'unknown';
  } catch { /* non-fatal */ }
  return {
    hostname: hostname(),
    platform: platform(),
    node_version: process.version,
    openclaw_version: ocVersion,
  };
}

function defaultReportBasePath() {
  const date = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
  return join(HOME, '.openclaw', `clawarmor-scan-report-${date}`);
}

function computeScanScore(findings) {
  let score = 100;
  for (const f of findings) {
    if (f.severity === 'CRITICAL') score -= 25;
    else if (f.severity === 'HIGH') score -= 10;
    else if (f.severity === 'MEDIUM') score -= 3;
  }
  return Math.max(0, score);
}

function buildReportChecks(skills, allJsonFindings) {
  // Build per-skill check entries
  const checks = [];

  // Skills with no findings
  for (const skill of skills) {
    const skillFindings = allJsonFindings.filter(f => f.skill === skill.name);
    if (!skillFindings.length) {
      checks.push({
        name: skill.name,
        status: 'pass',
        severity: 'NONE',
        detail: 'No findings',
        type: skill.isBuiltin ? 'builtin' : 'user',
      });
    } else {
      const maxSev = ['CRITICAL','HIGH','MEDIUM','LOW','INFO'].find(s =>
        skillFindings.some(f => f.severity === s)
      ) || 'INFO';
      const status = maxSev === 'CRITICAL' ? 'block' : maxSev === 'HIGH' ? 'warn' : 'info';
      checks.push({
        name: skill.name,
        status,
        severity: maxSev,
        detail: `${skillFindings.length} finding(s): ${skillFindings.map(f => f.patternId).join(', ')}`,
        type: skill.isBuiltin ? 'builtin' : 'user',
        findings: skillFindings.map(f => ({
          patternId: f.patternId,
          severity: f.severity,
          message: f.message,
          file: f.file,
          line: f.line,
        })),
      });
    }
  }
  return checks;
}

function writeJsonReport(reportPath, { skills, allJsonFindings, totalCritical, totalHigh }) {
  const sysInfo = getSystemInfo();
  const checks = buildReportChecks(skills, allJsonFindings);
  const score = computeScanScore(allJsonFindings);
  const passed = checks.filter(c => c.status === 'pass').length;
  const failed = checks.filter(c => c.status === 'block').length;
  const warnings = checks.filter(c => c.status === 'warn').length;

  let verdict = 'PASS';
  if (totalCritical > 0) verdict = 'BLOCK';
  else if (totalHigh > 0) verdict = 'WARN';

  const report = {
    version: VERSION,
    timestamp: new Date().toISOString(),
    system: sysInfo,
    verdict,
    score,
    summary: {
      total: checks.length,
      passed,
      failed,
      warnings,
      critical_findings: totalCritical,
      high_findings: totalHigh,
    },
    checks,
  };

  try { mkdirSync(dirname(reportPath), { recursive: true }); } catch {}
  writeFileSync(reportPath, JSON.stringify(report, null, 2), 'utf8');
  return report;
}

function writeMarkdownReport(reportPath, { skills, allJsonFindings, totalCritical, totalHigh }) {
  const sysInfo = getSystemInfo();
  const checks = buildReportChecks(skills, allJsonFindings);
  const score = computeScanScore(allJsonFindings);
  const passed = checks.filter(c => c.status === 'pass').length;
  const failed = checks.filter(c => c.status === 'block').length;
  const warnings = checks.filter(c => c.status === 'warn').length;

  let verdict = 'PASS';
  if (totalCritical > 0) verdict = 'BLOCK';
  else if (totalHigh > 0) verdict = 'WARN';

  const now = new Date();
  const dateStr = now.toLocaleString('en-US', {
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', hour12: false
  });

  let verdictEmoji = verdict === 'BLOCK' ? '🔴' : verdict === 'WARN' ? '🟡' : '🟢';

  let md = `# ClawArmor Skill Scan Report
Generated: ${dateStr}
ClawArmor: v${VERSION} | Hostname: ${sysInfo.hostname} | Platform: ${sysInfo.platform} | Node: ${sysInfo.node_version} | OpenClaw: ${sysInfo.openclaw_version}

## Executive Summary

| Metric | Value |
|--------|-------|
| Verdict | ${verdictEmoji} **${verdict}** |
| Score | ${score}/100 |
| Total Skills | ${skills.length} |
| Passed (clean) | ✅ ${passed} |
| Warnings | ⚠️ ${warnings} |
| Blocked (critical) | ❌ ${failed} |
| Critical Findings | ${totalCritical} |
| High Findings | ${totalHigh} |

`;

  if (checks.some(c => c.status !== 'pass')) {
    md += `## Skill Check Results

| Skill | Type | Status | Severity | Detail |
|-------|------|--------|----------|--------|
`;
    for (const check of checks) {
      const statusEmoji = check.status === 'pass' ? '✅ pass' : check.status === 'block' ? '❌ block' : '⚠️ warn';
      md += `| ${check.name} | ${check.type} | ${statusEmoji} | ${check.severity} | ${check.detail} |\n`;
    }
  } else {
    md += `## Skill Check Results

All ${skills.length} skills are clean. No findings detected.
`;
  }

  // Detailed findings for flagged skills
  const flaggedChecks = checks.filter(c => c.status !== 'pass' && c.findings && c.findings.length);
  if (flaggedChecks.length) {
    md += `
## Findings Detail

`;
    for (const check of flaggedChecks) {
      md += `### ${check.name} (${check.type})\n\n`;
      md += `| Pattern ID | Severity | Message | File | Line |\n`;
      md += `|------------|----------|---------|------|------|\n`;
      for (const f of check.findings) {
        md += `| ${f.patternId} | ${f.severity} | ${f.message || '—'} | ${f.file || '—'} | ${f.line ?? '—'} |\n`;
      }
      md += '\n';
    }
  }

  // Remediation
  md += `## Remediation Steps

`;
  if (totalCritical > 0) {
    md += `### 🔴 Critical — Immediate Action Required

- Remove or replace any skill with CRITICAL findings immediately
- Run \`clawarmor prescan <skill-name>\` before reinstalling
- Check for data exfiltration attempts: look for external HTTP calls, encoded payloads
- Review git history of the skill if available

`;
  }
  if (totalHigh > 0) {
    md += `### 🟡 High — Review Before Next Session

- Audit HIGH-severity skills before running your agent
- Run \`clawarmor skill verify <name>\` for a deeper inspection
- Consider disabling suspect skills temporarily: check your OpenClaw skill config

`;
  }
  md += `### General

- Run \`clawarmor scan\` regularly to catch new findings
- Use \`clawarmor prescan <skill-name>\` before installing any new skill
- Keep skills updated — malicious patterns are added to ClawArmor signatures continuously
- Run \`clawarmor audit\` to check your broader OpenClaw configuration
`;

  try { mkdirSync(dirname(reportPath), { recursive: true }); } catch {}
  writeFileSync(reportPath, md, 'utf8');
}

// ── Main export ───────────────────────────────────────────────────────────────

export async function runScan(flags = {}) {
  const jsonMode = flags.json || false;
  const reportMode = flags.report || false;

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

    if (reportMode) {
      const basePath = defaultReportBasePath();
      const jsonPath = basePath + '.json';
      const mdPath = basePath + '.md';
      writeJsonReport(jsonPath, { skills: [], allJsonFindings: [], totalCritical: 0, totalHigh: 0 });
      writeMarkdownReport(mdPath, { skills: [], allJsonFindings: [], totalCritical: 0, totalHigh: 0 });
      const date = new Date().toISOString().slice(0, 10);
      console.log(`\n  ${paint.dim('Report saved:')} clawarmor-scan-report-${date}.json + .md`);
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
  const jsonFindings = []; // for --json output and --report

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

    // Collect findings for JSON output and report
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
    const scanScore = computeScanScore(jsonFindings);

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

  // ── Write report if requested ──────────────────────────────────────────────
  if (reportMode) {
    const basePath = defaultReportBasePath();
    const jsonPath = basePath + '.json';
    const mdPath = basePath + '.md';
    const reportData = { skills, allJsonFindings: jsonFindings, totalCritical, totalHigh };
    writeJsonReport(jsonPath, reportData);
    writeMarkdownReport(mdPath, reportData);
    const date = new Date().toISOString().slice(0, 10);
    console.log(`  ${paint.dim('Report saved:')} clawarmor-scan-report-${date}.json + .md`);
    console.log('');
  }

  return totalCritical > 0 ? 1 : 0;
}
