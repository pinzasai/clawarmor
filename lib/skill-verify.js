// ClawArmor skill verify — check a skill directory against ClawGear publishing standards.
// Usage: clawarmor skill verify <skill-dir>
//
// Exit codes: 0=VERIFIED, 1=WARN, 2=BLOCK

import { existsSync, readdirSync, readFileSync, statSync } from 'fs';
import { join, extname, basename } from 'path';
import { paint } from './output/colors.js';
import { scanFile } from './scanner/file-scanner.js';

const SEP = '━'.repeat(52);

// Well-known API hosts that are allowed without flagging
const KNOWN_HOSTS = new Set([
  'github.com', 'api.github.com', 'raw.githubusercontent.com',
  'api.anthropic.com',
  'api.openai.com',
  'registry.npmjs.org',
  'api.cloudflare.com',
  'api.stripe.com',
  'hooks.slack.com',
  'discord.com', 'discordapp.com',
  'api.telegram.org',
  'clawhub.com', 'shopclawmart.com', 'clawgear.io',
]);

// Patterns for hardcoded credentials (value, not variable reference)
const CRED_PATTERNS = [
  /api_key\s*=\s*["'][^${\s"']{8,}/i,
  /token\s*=\s*["'][^${\s"']{8,}/i,
  /password\s*=\s*["'][^${\s"']{4,}/i,
  /secret\s*=\s*["'][^${\s"']{8,}/i,
  /api_key\s*:\s*["'][^${\s"']{8,}/i,
  /token\s*:\s*["'][^${\s"']{8,}/i,
  /password\s*:\s*["'][^${\s"']{4,}/i,
  /secret\s*:\s*["'][^${\s"']{8,}/i,
];

// Patterns for elevated/exec commands
const EXEC_PATTERNS = [
  /\bexec\b/,
  /child_process/,
  /subprocess/,
  /\bsudo\b/,
  /\bchmod\b/,
  /\bchown\b/,
  /execSync|execFile|spawnSync/,
  /\bsh\s+-c\b/,
  /\bbash\s+-c\b/,
];

// Patterns for external network calls
const FETCH_PATTERNS = [
  /\bfetch\s*\(\s*["'`]https?:\/\/([^/"'`\s]+)/gi,
  /\bcurl\s+(?:-\S+\s+)*["']?https?:\/\/([^"'\s]+)/gi,
  /\bwget\s+(?:-\S+\s+)*["']?https?:\/\/([^"'\s]+)/gi,
  /new\s+URL\s*\(\s*["'`]https?:\/\/([^/"'`\s]+)/gi,
  /axios\.\w+\s*\(\s*["'`]https?:\/\/([^/"'`\s]+)/gi,
];

const SCANNABLE_EXTS = new Set(['js', 'ts', 'sh', 'py', 'rb', 'md']);

function collectFiles(dir) {
  const files = [];
  try {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (entry.name.startsWith('.')) continue;
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        files.push(...collectFiles(full));
      } else {
        files.push(full);
      }
    }
  } catch { /* ignore unreadable dirs */ }
  return files;
}

function readSafe(filePath) {
  try { return readFileSync(filePath, 'utf8'); }
  catch { return ''; }
}

function extractHosts(content) {
  const hosts = [];
  for (const pattern of FETCH_PATTERNS) {
    const re = new RegExp(pattern.source, 'gi');
    let m;
    while ((m = re.exec(content)) !== null) {
      const host = m[1].split('/')[0].split('?')[0];
      if (host) hosts.push(host);
    }
  }
  return [...new Set(hosts)];
}

/**
 * Main skill verify command.
 * @param {string} skillDir - path to skill directory
 * @returns {Promise<number>} exit code: 0=VERIFIED, 1=WARN, 2=BLOCK
 */
export async function runSkillVerify(skillDir) {
  if (!skillDir) {
    console.log(`  Usage: clawarmor skill verify <skill-dir>`);
    return 2;
  }

  const resolvedDir = skillDir.replace(/^~/, process.env.HOME || '');

  if (!existsSync(resolvedDir)) {
    console.log(`  ${paint.red('✗')} Directory not found: ${skillDir}`);
    return 2;
  }

  const skillName = basename(resolvedDir);
  const files = collectFiles(resolvedDir);
  const codeFiles = files.filter(f => {
    const ext = extname(f).replace('.', '').toLowerCase();
    return SCANNABLE_EXTS.has(ext);
  });
  const skillMdPath = join(resolvedDir, 'SKILL.md');

  console.log('');
  console.log(`  ${paint.bold('ClawArmor Skill Verify')} ${paint.dim('—')} ${paint.cyan(skillName)}`);
  console.log(`  ${SEP}`);

  const checks = [];
  let hasWarn = false;
  let hasBlock = false;

  // ── Check 1: SKILL.md exists ────────────────────────────────────────────────
  const skillMdExists = existsSync(skillMdPath);
  if (skillMdExists) {
    checks.push({ icon: '✅', label: 'SKILL.md present' });
  } else {
    checks.push({ icon: '❌', label: 'SKILL.md missing — required for ClawGear publishing', severity: 'BLOCK' });
    hasBlock = true;
  }

  const skillMdContent = skillMdExists ? readSafe(skillMdPath) : '';
  const allContent = files.map(f => ({ path: f, content: readSafe(f) }));

  // ── Check 2: No hardcoded credentials ───────────────────────────────────────
  let credFound = false;
  let credDetails = null;
  for (const { path: fp, content } of allContent) {
    const ext = extname(fp).replace('.', '').toLowerCase();
    if (!SCANNABLE_EXTS.has(ext)) continue;
    for (const pattern of CRED_PATTERNS) {
      if (pattern.test(content)) {
        credFound = true;
        credDetails = `${fp.replace(process.env.HOME || '', '~')}`;
        break;
      }
    }
    if (credFound) break;
  }
  if (credFound) {
    checks.push({ icon: '❌', label: `Hardcoded credentials found in ${credDetails}`, severity: 'BLOCK' });
    hasBlock = true;
  } else {
    checks.push({ icon: '✅', label: 'No hardcoded credentials' });
  }

  // ── Check 3: No obfuscation ──────────────────────────────────────────────────
  let obfuscFound = false;
  for (const fp of codeFiles) {
    const findings = scanFile(fp, false);
    const serious = findings.filter(f => ['CRITICAL', 'HIGH'].includes(f.severity));
    if (serious.length) {
      obfuscFound = true;
      break;
    }
  }
  if (obfuscFound) {
    checks.push({ icon: '❌', label: 'Obfuscation or malicious patterns detected — run clawarmor scan for details', severity: 'BLOCK' });
    hasBlock = true;
  } else {
    checks.push({ icon: '✅', label: 'No obfuscation patterns' });
  }

  // ── Check 4: Permissions declared if exec commands found ────────────────────
  let execFound = false;
  for (const { path: fp, content } of allContent) {
    const ext = extname(fp).replace('.', '').toLowerCase();
    if (!SCANNABLE_EXTS.has(ext)) continue;
    for (const p of EXEC_PATTERNS) {
      if (p.test(content)) {
        execFound = true;
        break;
      }
    }
    if (execFound) break;
  }

  if (execFound) {
    const permsDeclared = /\b(requires|permissions|elevated)\b/i.test(skillMdContent);
    if (permsDeclared) {
      checks.push({ icon: '✅', label: 'Exec commands found — permissions declared in SKILL.md' });
    } else {
      checks.push({ icon: '⚠️ ', label: 'Exec commands found — verify permissions are declared in SKILL.md', severity: 'WARN' });
      hasWarn = true;
    }
  } else {
    checks.push({ icon: '✅', label: 'No elevated exec commands' });
  }

  // ── Check 5: No external fetch to unknown hosts ─────────────────────────────
  const unknownHosts = [];
  for (const { content } of allContent) {
    for (const host of extractHosts(content)) {
      // Strip port
      const cleanHost = host.split(':')[0];
      if (!KNOWN_HOSTS.has(cleanHost)) {
        unknownHosts.push(cleanHost);
      }
    }
  }
  const uniqueUnknown = [...new Set(unknownHosts)];
  if (uniqueUnknown.length) {
    checks.push({ icon: '⚠️ ', label: `External fetch to unknown host(s): ${uniqueUnknown.join(', ')}`, severity: 'WARN' });
    hasWarn = true;
  } else {
    checks.push({ icon: '✅', label: 'No unknown external hosts' });
  }

  // ── Check 6: Description present in SKILL.md frontmatter ────────────────────
  const descPresent = /^description\s*:/m.test(skillMdContent);
  if (descPresent) {
    checks.push({ icon: '✅', label: 'Description present in SKILL.md' });
  } else {
    checks.push({ icon: '⚠️ ', label: 'No description: field in SKILL.md frontmatter', severity: 'WARN' });
    hasWarn = true;
  }

  // ── Print results ────────────────────────────────────────────────────────────
  for (const c of checks) {
    console.log(`  ${c.icon} ${c.severity === 'BLOCK' ? paint.red(c.label) : c.severity === 'WARN' ? paint.yellow(c.label) : paint.dim(c.label)}`);
  }

  console.log('');

  const advisories = checks.filter(c => c.severity === 'WARN').length;
  const blocks = checks.filter(c => c.severity === 'BLOCK').length;

  if (hasBlock) {
    console.log(`  ${paint.bold('Verdict:')} ${paint.red('❌ BLOCK')} ${paint.dim('— ' + blocks + ' blocking issue' + (blocks > 1 ? 's' : ''))}`);
    console.log('');
    return 2;
  } else if (hasWarn) {
    console.log(`  ${paint.bold('Verdict:')} ${paint.yellow('⚠️  WARN')} ${paint.dim('— ' + advisories + ' advisor' + (advisories > 1 ? 'ies' : 'y'))}`);
    console.log('');
    return 1;
  } else {
    console.log(`  ${paint.bold('Verdict:')} ${paint.green('✅ VERIFIED')}`);
    console.log('');
    return 0;
  }
}
