// ClawArmor v2.0 — Pre-scan a skill before installing
// Downloads the npm package to a temp dir, scans it with the full
// ClawArmor scanner, and exits 1 (blocks install) only on CRITICAL findings.

import { mkdirSync, rmSync, readdirSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import { execSync } from 'child_process';
import { scanFile } from './scanner/file-scanner.js';
import { scanSkillMdFiles } from './scanner/skill-md-scanner.js';
import { paint, severityColor } from './output/colors.js';
import { append } from './audit-log.js';

const SEP = paint.dim('─'.repeat(52));

function getAllFiles(dir, files = []) {
  try {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      if (e.name.startsWith('.') || e.name === 'node_modules' || e.name === '__pycache__') continue;
      const fp = join(dir, e.name);
      if (e.isDirectory()) getAllFiles(fp, files);
      else files.push(fp);
    }
  } catch { /* permission denied */ }
  return files;
}

function cleanupTmp(dir) {
  try { rmSync(dir, { recursive: true, force: true }); } catch { /* non-fatal */ }
}

export async function runPrescan(skillName) {
  console.log('');
  console.log(`  ${paint.bold('ClawArmor Prescan')} — ${paint.cyan(skillName)}`);
  console.log(`  ${paint.dim('Fetching package from npm registry...')}`);
  console.log('');

  const tmpDir = join(tmpdir(), `clawarmor-prescan-${Date.now()}`);
  mkdirSync(tmpDir, { recursive: true });

  // ── Step 1: Download via npm pack ─────────────────────────────────────────
  let tarball;
  try {
    execSync(`npm pack ${skillName}`, {
      cwd: tmpDir,
      timeout: 30000,
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    const tarballs = readdirSync(tmpDir).filter(f => f.endsWith('.tgz'));
    if (!tarballs.length) throw new Error('npm pack produced no tarball');
    tarball = join(tmpDir, tarballs[0]);
  } catch {
    cleanupTmp(tmpDir);
    console.log(`  ${paint.dim('ℹ')}  Could not fetch skill for scanning`);
    console.log(`     ${paint.dim('(package not found or network error — install not blocked)')}`);
    console.log('');
    return 0;
  }

  // ── Step 2: Extract tarball ────────────────────────────────────────────────
  const extractDir = join(tmpDir, 'extracted');
  mkdirSync(extractDir, { recursive: true });
  try {
    execSync(`tar -xzf "${tarball}" -C "${extractDir}"`, {
      timeout: 15000,
      stdio: ['ignore', 'ignore', 'ignore'],
    });
  } catch {
    cleanupTmp(tmpDir);
    console.log(`  ${paint.dim('ℹ')}  Could not extract skill package — install not blocked`);
    console.log('');
    return 0;
  }

  // ── Step 3: Collect all files ──────────────────────────────────────────────
  const allFiles = getAllFiles(extractDir);
  console.log(`  ${paint.dim('Scanning')} ${allFiles.length} file${allFiles.length !== 1 ? 's' : ''}...`);
  console.log('');

  // ── Step 4: Run ClawArmor scanners ────────────────────────────────────────
  // Not a built-in — treat as third-party (isBuiltin = false)
  const codeFindings = allFiles.flatMap(f => scanFile(f, false));
  const mdResults = scanSkillMdFiles(allFiles, false);
  const mdFindings = mdResults.flatMap(r => r.findings);
  const allFindings = [...codeFindings, ...mdFindings];

  const criticals = allFindings.filter(f => f.severity === 'CRITICAL');
  const highs = allFindings.filter(f => f.severity === 'HIGH');
  const mediums = allFindings.filter(f => f.severity === 'MEDIUM');
  const lows = allFindings.filter(f => f.severity === 'LOW' || f.severity === 'INFO');

  // ── Cleanup (always) ──────────────────────────────────────────────────────
  cleanupTmp(tmpDir);

  // ── Audit log ─────────────────────────────────────────────────────────────
  append({
    cmd: 'prescan',
    trigger: 'prescan',
    score: null,
    delta: null,
    findings: allFindings.map(f => ({ id: f.patternId || f.id || '?', severity: f.severity })),
    blocked: criticals.length > 0,
    skill: skillName,
  });

  // ── Output ────────────────────────────────────────────────────────────────
  if (!allFindings.length) {
    console.log(`  ${paint.green('✓')} ClawArmor prescan: clean — 0 findings`);
    console.log('');
    return 0;
  }

  // CRITICAL → print details, block install (exit 1)
  if (criticals.length) {
    console.log(SEP);
    console.log(`  ${paint.red('✗')} ${paint.bold(`CRITICAL (${criticals.length}) — install blocked`)}`);
    console.log(SEP);
    for (const f of criticals) {
      console.log('');
      console.log(`  ${paint.red('✗')} ${(severityColor['CRITICAL'] || paint.red)('[CRITICAL]')} ${paint.bold(f.title)}`);
      console.log(`    ${paint.dim(f.description || '')}`);
      for (const m of (f.matches || []).slice(0, 2)) {
        console.log(`    ${paint.dim('→')} ${paint.cyan(':' + m.line)}  ${paint.dim(m.snippet)}`);
      }
    }

    if (highs.length || mediums.length) {
      console.log('');
      const extra = [];
      if (highs.length) extra.push(`${highs.length} HIGH`);
      if (mediums.length) extra.push(`${mediums.length} MEDIUM`);
      console.log(`  ${paint.yellow('!')} Additional: ${extra.join(', ')} (fix criticals first)`);
    }

    console.log('');
    console.log(`  ${paint.red('✗')} Skill blocked. Do NOT install ${paint.bold(skillName)}.`);
    console.log('');
    return 1;
  }

  // HIGH → warn, allow install
  if (highs.length) {
    console.log(SEP);
    console.log(`  ${paint.yellow('⚠')} ${paint.bold(`HIGH (${highs.length}) — review before using`)}`);
    console.log(SEP);
    for (const f of highs) {
      console.log('');
      console.log(`  ${paint.yellow('!')} ${(severityColor['HIGH'] || paint.yellow)('[HIGH]')} ${paint.bold(f.title)}`);
      console.log(`    ${paint.dim(f.description || '')}`);
      for (const m of (f.matches || []).slice(0, 2)) {
        console.log(`    ${paint.dim('→')} ${paint.cyan(':' + m.line)}  ${paint.dim(m.snippet)}`);
      }
    }
    console.log('');
  }

  // MEDIUM/LOW → summary line only
  if (mediums.length || lows.length) {
    const parts = [];
    if (mediums.length) parts.push(`${mediums.length} medium`);
    if (lows.length) parts.push(`${lows.length} low/info`);
    console.log(`  ${paint.dim('ℹ')}  ${parts.join(', ')} additional finding${(mediums.length + lows.length) > 1 ? 's' : ''} (review manually)`);
    console.log('');
  }

  return 0;
}
