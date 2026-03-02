// clawarmor fix — auto-apply safe one-liner fixes
// Now with impact classification: safe / caution / breaking
import { readFileSync } from 'fs';
import { homedir } from 'os';
import { join } from 'path';
import { execSync, spawnSync } from 'child_process';
import { paint } from './output/colors.js';
import { loadConfig, get } from './config.js';

const HISTORY_PATH = join(homedir(), '.clawarmor', 'history.json');
const SEP = paint.dim('─'.repeat(52));

// Impact levels
const IMPACT = { SAFE: 'safe', CAUTION: 'caution', BREAKING: 'breaking' };

const IMPACT_BADGE = {
  [IMPACT.SAFE]:     () => paint.green('🟢 Safe'),
  [IMPACT.CAUTION]:  () => paint.yellow('🟡 Caution'),
  [IMPACT.BREAKING]: () => paint.red('🔴 Breaking'),
};

// Fixes that are safe to auto-apply (single config set command, no restart risk)
const AUTO_FIXABLE = {
  'browser.ssrf': {
    cmd: 'openclaw config set browser.ssrfPolicy.dangerouslyAllowPrivateNetwork false',
    desc: 'Block browser SSRF to private networks',
    needsRestart: true,
    impact: IMPACT.CAUTION,
    impactDetail: 'Browser tool will no longer be able to access local/private network URLs.\n' +
      '      If your agent browses internal dashboards or local services, those will be blocked.',
  },
  'discovery.mdns': {
    cmd: 'openclaw config set discovery.mdns.mode minimal',
    desc: 'Set mDNS to minimal mode',
    needsRestart: true,
    impact: IMPACT.SAFE,
    impactDetail: 'Only reduces network advertisement. No functionality change.',
  },
  'logging.redact': {
    cmd: 'openclaw config set logging.redactSensitive tools',
    desc: 'Enable log redaction',
    needsRestart: false,
    impact: IMPACT.SAFE,
    impactDetail: 'Redacts sensitive data from logs. No functionality change.',
  },
  'tools.fs.workspaceOnly': {
    cmd: 'openclaw config set tools.fs.workspaceOnly true',
    desc: 'Restrict filesystem to workspace',
    needsRestart: true,
    impact: IMPACT.BREAKING,
    impactDetail: 'Agent will ONLY be able to read/write files inside the workspace directory.\n' +
      '      Access to home directory, system files, and other paths will be blocked.\n' +
      '      Skills or workflows that read files outside workspace will break.',
  },
  'tools.applyPatch.workspaceOnly': {
    cmd: 'openclaw config set tools.exec.applyPatch.workspaceOnly true',
    desc: 'Restrict apply_patch to workspace',
    needsRestart: true,
    impact: IMPACT.CAUTION,
    impactDetail: 'Patches can only be applied to files in the workspace. Usually fine unless\n' +
      '      your agent patches system files or configs outside the workspace.',
  },
  'fs.config.perms': {
    cmd: 'chmod 600 ~/.openclaw/openclaw.json',
    desc: 'Lock down config file permissions',
    needsRestart: false,
    shell: true,
    impact: IMPACT.SAFE,
    impactDetail: 'Only restricts other system users. Your agent runs as you.',
  },
  'fs.accounts.perms': {
    cmd: 'chmod 600 ~/.openclaw/agent-accounts.json',
    desc: 'Lock down credentials file permissions',
    needsRestart: false,
    shell: true,
    impact: IMPACT.SAFE,
    impactDetail: 'Only restricts other system users. Your agent runs as you.',
  },
  'agents.sandbox': {
    cmd: "openclaw config set agents.defaults.sandbox.mode non-main && openclaw config set agents.defaults.sandbox.workspaceAccess rw && openclaw config set agents.defaults.sandbox.scope session",
    desc: 'Enable sandbox isolation (with workspace access preserved for Telegram/group sessions)',
    needsRestart: true,
    requiresDocker: true,
    impact: IMPACT.BREAKING,
    impactDetail: 'Non-main sessions will run inside Docker containers.\n' +
      '      Requires Docker Desktop to be installed and running.\n' +
      '      Telegram/group sessions will lose direct host access (shell commands,\n' +
      '      file reads outside workspace). Workspace files remain accessible.',
  },
  'fs.dir.perms': {
    cmd: 'chmod 700 ~/.openclaw',
    desc: 'Lock down ~/.openclaw directory',
    needsRestart: false,
    shell: true,
    impact: IMPACT.SAFE,
    impactDetail: 'Only restricts other system users from listing the directory.',
  },
};

function box(title) {
  const W=52, pad=W-2-title.length, l=Math.floor(pad/2), r=pad-l;
  return [paint.dim('╔'+'═'.repeat(W-2)+'╗'),
    paint.dim('║')+' '.repeat(l)+paint.bold(title)+' '.repeat(r)+paint.dim('║'),
    paint.dim('╚'+'═'.repeat(W-2)+'╝')].join('\n');
}

export async function runFix(flags = {}) {
  console.log(''); console.log(box('ClawArmor Fix  v2.1')); console.log('');

  // Load last audit failures
  let lastFailed = [];
  try {
    const h = JSON.parse(readFileSync(HISTORY_PATH,'utf8'));
    const last = h[h.length-1];
    lastFailed = last?.failedIds || [];
  } catch { /* no history */ }

  if (!lastFailed.length) {
    console.log(`  ${paint.dim('No previous audit found. Run')} ${paint.cyan('clawarmor audit')} ${paint.dim('first.')}`);
    console.log(''); return 0;
  }

  const fixable = lastFailed.filter(id => AUTO_FIXABLE[id]);
  const manual = lastFailed.filter(id => !AUTO_FIXABLE[id]);

  const safeFixes = fixable.filter(id => AUTO_FIXABLE[id].impact === IMPACT.SAFE);
  const cautionFixes = fixable.filter(id => AUTO_FIXABLE[id].impact === IMPACT.CAUTION);
  const breakingFixes = fixable.filter(id => AUTO_FIXABLE[id].impact === IMPACT.BREAKING);

  console.log(`  ${paint.dim('Last audit had')} ${paint.bold(String(lastFailed.length))} ${paint.dim('failing checks.')}`);
  console.log(`  ${paint.bold(String(fixable.length))} ${paint.dim('can be auto-fixed:')} ${paint.green(String(safeFixes.length) + ' safe')} ${paint.dim('·')} ${paint.yellow(String(cautionFixes.length) + ' caution')} ${paint.dim('·')} ${paint.red(String(breakingFixes.length) + ' breaking')}`);
  console.log(`  ${paint.dim(String(manual.length))} ${paint.dim('require manual steps.')}`);

  if (!fixable.length) {
    console.log('');
    console.log(`  ${paint.yellow('!')} No auto-fixable issues. Fix manually:`);
    for (const id of manual) console.log(`    ${paint.dim('•')} ${id}`);
    console.log(''); return 0;
  }

  // Load config for mainKey check
  const { config: cfg } = loadConfig();
  const mainKey = get(cfg, 'agents.mainKey', 'main');

  console.log('');
  if (flags.dryRun) {
    console.log(`  ${paint.cyan('Dry run — would apply:')}`);
    console.log('');
    for (const id of fixable) {
      const f = AUTO_FIXABLE[id];
      const badge = IMPACT_BADGE[f.impact]();
      if (id === 'agents.sandbox' && mainKey !== 'main') {
        console.log(`  ${paint.yellow('⚠')} ${paint.bold('Custom mainKey detected:')} agents.mainKey="${mainKey}"`);
        console.log(`     ${paint.dim('Verify that sandbox.mode=non-main won\'t affect your main session.')}`);
      }
      console.log(`  ${badge}  ${paint.dim('→')} ${f.desc}`);
      console.log(`      ${paint.dim('Impact:')} ${f.impactDetail}`);
      console.log(`      ${paint.dim(f.cmd)}`);
      if (f.requiresDocker) console.log(`      ${paint.yellow('⚠')} ${paint.dim('Requires Docker Desktop to be installed and running')}`);
      if (f.needsRestart) console.log(`      ${paint.dim('↻ gateway restart required after applying')}`);
      console.log('');
    }
    console.log(`  ${paint.dim('Run')} ${paint.cyan('clawarmor fix --apply')} ${paint.dim('to apply safe + caution fixes.')}`);
    if (breakingFixes.length) {
      console.log(`  ${paint.dim('Run')} ${paint.cyan('clawarmor fix --apply --force')} ${paint.dim('to apply ALL fixes (including breaking).')}`);
    }
    console.log(''); return 0;
  }

  if (!flags.apply) {
    console.log(`  ${paint.dim('Run')} ${paint.cyan('clawarmor fix --dry-run')} ${paint.dim('to preview fixes with impact analysis.')}`);
    console.log(`  ${paint.dim('Run')} ${paint.cyan('clawarmor fix --apply')} ${paint.dim('to apply safe + caution fixes.')}`);
    if (breakingFixes.length) {
      console.log(`  ${paint.dim('Run')} ${paint.cyan('clawarmor fix --apply --force')} ${paint.dim('to apply ALL fixes (including breaking).')}`);
    }
    console.log(''); return 0;
  }

  // Apply fixes
  let applied = 0, failed = 0, skippedBreaking = 0, needsRestart = false;
  console.log(SEP);
  for (const id of fixable) {
    const f = AUTO_FIXABLE[id];
    const badge = IMPACT_BADGE[f.impact]();

    // Skip breaking unless --force
    if (f.impact === IMPACT.BREAKING && !flags.force) {
      console.log(`  ${badge}  ${f.desc}`);
      console.log(`      ${paint.dim('Impact:')} ${f.impactDetail}`);
      console.log(`      ${paint.red('⊘ Skipped')} ${paint.dim('(breaking — use --apply --force to include)')}`);
      console.log('');
      skippedBreaking++;
      continue;
    }

    // Warn about custom mainKey before sandbox fix
    if (id === 'agents.sandbox' && mainKey !== 'main') {
      console.log(`  ${paint.yellow('⚠')} ${paint.bold('Custom mainKey detected:')} agents.mainKey="${mainKey}"`);
      console.log(`     ${paint.dim('Verify that sandbox.mode=non-main won\'t affect your main session.')}`);
    }

    process.stdout.write(`  ${badge}  ${f.desc}...`);
    // Check Docker requirement
    if (f.requiresDocker) {
      const dockerCheck = spawnSync('docker', ['info'], { stdio: 'ignore' });
      if (dockerCheck.error || dockerCheck.status !== 0) {
        process.stdout.write(` ${paint.yellow('⚠')} Docker not running — install Docker Desktop first\n`);
        failed++;
        continue;
      }
    }
    try {
      execSync(f.cmd, { stdio: 'ignore', shell: true });
      process.stdout.write(` ${paint.green('✓')}\n`);
      applied++;
      if (f.needsRestart) needsRestart = true;
    } catch (e) {
      process.stdout.write(` ${paint.red('✗')} ${e.message.split('\n')[0]}\n`);
      failed++;
    }
  }

  console.log('');
  if (skippedBreaking > 0) {
    console.log(`  ${paint.dim(`${skippedBreaking} breaking fix${skippedBreaking !== 1 ? 'es' : ''} skipped — use --apply --force to include`)}`);
  }
  if (needsRestart) {
    console.log(`  ${paint.yellow('!')} ${paint.bold('Restart required:')} ${paint.dim('openclaw gateway restart')}`);
  }
  if (manual.length) {
    console.log(`  ${paint.dim('Still needs manual fix:')}`);
    for (const id of manual) console.log(`    ${paint.dim('•')} ${id}`);
  }
  console.log('');
  console.log(`  Applied ${applied} fix${applied!==1?'es':''}. Run ${paint.cyan('clawarmor verify')} to confirm.`);
  console.log(''); return failed > 0 ? 1 : 0;
}
