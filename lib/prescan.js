// ClawArmor v2.0 — Pre-scan a skill before installing
// Supports both npm packages and ClawHub skills.
// ClawHub skills are checked locally first; npm is used as fallback.

import { mkdirSync, rmSync, readdirSync, existsSync } from 'fs';
import { join } from 'path';
import { tmpdir, homedir } from 'os';
import { execSync } from 'child_process';
import { scanFile } from './scanner/file-scanner.js';
import { scanSkillMdFiles } from './scanner/skill-md-scanner.js';
import { paint, severityColor } from './output/colors.js';
import { append } from './audit-log.js';

const HOME = homedir();
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

// ── ClawHub skill detection ──────────────────────────────────────────────────

function isNpmScoped(name) {
  // Scoped npm package: @org/pkg
  return name.startsWith('@') && name.includes('/');
}

function looksLikeClawHubSkill(name) {
  // Plain name, no scope, no slash — could be a ClawHub skill; try local first
  return !name.startsWith('@') && !name.includes('/');
}

// Returns the local install path for a ClawHub skill, or null if not found.
function findLocalClawHubSkill(name) {
  // Path 1: ~/.openclaw/skills/<name>/
  const userSkillsPath = join(HOME, '.openclaw', 'skills', name);
  if (existsSync(userSkillsPath)) return userSkillsPath;

  // Path 2: openclaw npm module's skills directory
  // Try common global npm locations
  const candidates = [
    join(HOME, '.npm-global', 'lib', 'node_modules', 'openclaw', 'skills', name),
    '/usr/local/lib/node_modules/openclaw/skills/' + name,
    '/usr/lib/node_modules/openclaw/skills/' + name,
    join(HOME, '.nvm', 'versions', 'node'),  // nvm — we check dirs below
  ];

  // Try to resolve openclaw via node resolution from this file's location
  try {
    const result = execSync('node -e "console.log(require.resolve(\'openclaw/package.json\'))"', {
      encoding: 'utf8',
      timeout: 5000,
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
    if (result) {
      // result is like /path/to/node_modules/openclaw/package.json
      const ocDir = result.replace(/[\\/]package\.json$/, '');
      const skillPath = join(ocDir, 'skills', name);
      if (existsSync(skillPath)) return skillPath;
    }
  } catch { /* openclaw may not be installed */ }

  for (const candidate of candidates) {
    if (existsSync(candidate)) return candidate;
  }

  return null;
}

// ── Scan a directory of files ────────────────────────────────────────────────

function scanDirectory(dir) {
  const allFiles = getAllFiles(dir);
  const codeFindings = allFiles.flatMap(f => scanFile(f, false));
  const mdResults = scanSkillMdFiles(allFiles, false);
  const mdFindings = mdResults.flatMap(r => r.findings);
  return { allFiles, allFindings: [...codeFindings, ...mdFindings] };
}

// ── Result printer ───────────────────────────────────────────────────────────

function printResult(skillName, allFiles, allFindings) {
  const criticals = allFindings.filter(f => f.severity === 'CRITICAL');
  const highs = allFindings.filter(f => f.severity === 'HIGH');
  const mediums = allFindings.filter(f => f.severity === 'MEDIUM');
  const lows = allFindings.filter(f => f.severity === 'LOW' || f.severity === 'INFO');
  const fileCount = allFiles.length;

  if (!allFindings.length) {
    console.log(`  ${paint.green('✓')} ${paint.bold(skillName)} ${paint.dim('—')} clean ${paint.dim('(' + fileCount + ' file' + (fileCount !== 1 ? 's' : '') + ' scanned, 0 findings)')}`);
    console.log('');
    return 0;
  }

  if (criticals.length) {
    console.log(`  ${paint.red('✗')} ${paint.bold(skillName)} ${paint.dim('—')} ${paint.red('BLOCKED')} ${paint.dim('(' + criticals.length + ' critical finding' + (criticals.length !== 1 ? 's' : '') + ')')}`);
    console.log('');
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

  // HIGH → warn, allow
  if (highs.length) {
    console.log(`  ${paint.yellow('⚠')} ${paint.bold(skillName)} ${paint.dim('—')} ${paint.yellow('review recommended')} ${paint.dim('(' + highs.length + ' high finding' + (highs.length !== 1 ? 's' : '') + ', ' + fileCount + ' files)')}`);
    console.log('');
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
  } else {
    console.log(`  ${paint.yellow('!')} ${paint.bold(skillName)} ${paint.dim('—')} ${paint.dim(fileCount + ' files scanned, ' + (mediums.length + lows.length) + ' low/medium findings')}`);
  }

  if (mediums.length || lows.length) {
    const parts = [];
    if (mediums.length) parts.push(`${mediums.length} medium`);
    if (lows.length) parts.push(`${lows.length} low/info`);
    console.log(`  ${paint.dim('ℹ')}  ${parts.join(', ')} additional finding${(mediums.length + lows.length) > 1 ? 's' : ''} (review manually)`);
    console.log('');
  }

  return 0;
}

// ── Download via npm pack ────────────────────────────────────────────────────

async function scanViaNpm(skillName, tmpDir) {
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
    return null; // not found or network error
  }

  const extractDir = join(tmpDir, 'extracted');
  mkdirSync(extractDir, { recursive: true });
  try {
    execSync(`tar -xzf "${tarball}" -C "${extractDir}"`, {
      timeout: 15000,
      stdio: ['ignore', 'ignore', 'ignore'],
    });
  } catch {
    return null;
  }

  return extractDir;
}

// ── Main export ───────────────────────────────────────────────────────────────

export async function runPrescan(skillName) {
  console.log('');
  console.log(`  ${paint.bold('ClawArmor Prescan')} — ${paint.cyan(skillName)}`);
  console.log('');

  let scanDir = null;
  let usedTmp = null;
  let source = 'npm';

  // ── Step 1: Check local ClawHub install (for plain skill names) ───────────
  if (looksLikeClawHubSkill(skillName)) {
    const localPath = findLocalClawHubSkill(skillName);
    if (localPath) {
      console.log(`  ${paint.dim('Found locally:')} ${paint.dim(localPath)}`);
      console.log(`  ${paint.dim('Scanning local files...')}`);
      console.log('');
      scanDir = localPath;
      source = 'local';
    } else {
      console.log(`  ${paint.dim('Not found locally — fetching from npm registry...')}`);
      console.log('');
    }
  } else {
    console.log(`  ${paint.dim('Fetching package from npm registry...')}`);
    console.log('');
  }

  // ── Step 2: Fallback to npm pack if not local ─────────────────────────────
  if (!scanDir) {
    const tmpDir = join(tmpdir(), `clawarmor-prescan-${Date.now()}`);
    mkdirSync(tmpDir, { recursive: true });
    usedTmp = tmpDir;

    const extractDir = await scanViaNpm(skillName, tmpDir);
    if (!extractDir) {
      cleanupTmp(tmpDir);
      console.log(`  ${paint.dim('ℹ')}  Could not fetch skill for scanning`);
      console.log(`     ${paint.dim('(package not found or network error — install not blocked)')}`);
      console.log('');
      return 0;
    }
    scanDir = extractDir;
  }

  // ── Step 3: Scan ──────────────────────────────────────────────────────────
  const { allFiles, allFindings } = scanDirectory(scanDir);
  console.log(`  ${paint.dim('Scanning')} ${allFiles.length} file${allFiles.length !== 1 ? 's' : ''}...`);
  console.log('');

  // ── Cleanup tmp (always, only if we created one) ──────────────────────────
  if (usedTmp) cleanupTmp(usedTmp);

  // ── Audit log ─────────────────────────────────────────────────────────────
  const criticals = allFindings.filter(f => f.severity === 'CRITICAL');
  append({
    cmd: 'prescan',
    trigger: 'prescan',
    score: null,
    delta: null,
    findings: allFindings.map(f => ({ id: f.patternId || f.id || '?', severity: f.severity })),
    blocked: criticals.length > 0,
    skill: skillName,
    source,
  });

  // ── Output ────────────────────────────────────────────────────────────────
  return printResult(skillName, allFiles, allFindings);
}
