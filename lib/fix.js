// clawarmor fix — auto-apply safe one-liner fixes
import { readFileSync } from 'fs';
import { homedir } from 'os';
import { join } from 'path';
import { execSync } from 'child_process';
import { paint } from './output/colors.js';

const HISTORY_PATH = join(homedir(), '.clawarmor', 'history.json');
const SEP = paint.dim('─'.repeat(52));

// Fixes that are safe to auto-apply (single config set command, no restart risk)
const AUTO_FIXABLE = {
  'browser.ssrf': {
    cmd: 'openclaw config set browser.ssrfPolicy.dangerouslyAllowPrivateNetwork false',
    desc: 'Block browser SSRF to private networks',
    needsRestart: true,
  },
  'discovery.mdns': {
    cmd: 'openclaw config set discovery.mdns.mode minimal',
    desc: 'Set mDNS to minimal mode',
    needsRestart: true,
  },
  'logging.redact': {
    cmd: 'openclaw config set logging.redactSensitive tools',
    desc: 'Enable log redaction',
    needsRestart: false,
  },
  'tools.fs.workspaceOnly': {
    cmd: 'openclaw config set tools.fs.workspaceOnly true',
    desc: 'Restrict filesystem to workspace',
    needsRestart: true,
  },
  'tools.applyPatch.workspaceOnly': {
    cmd: 'openclaw config set tools.exec.applyPatch.workspaceOnly true',
    desc: 'Restrict apply_patch to workspace',
    needsRestart: true,
  },
  'fs.config.perms': {
    cmd: 'chmod 600 ~/.openclaw/openclaw.json',
    desc: 'Lock down config file permissions',
    needsRestart: false,
    shell: true,
  },
  'fs.accounts.perms': {
    cmd: 'chmod 600 ~/.openclaw/agent-accounts.json',
    desc: 'Lock down credentials file permissions',
    needsRestart: false,
    shell: true,
  },
  'fs.dir.perms': {
    cmd: 'chmod 700 ~/.openclaw',
    desc: 'Lock down ~/.openclaw directory',
    needsRestart: false,
    shell: true,
  },
};

function box(title) {
  const W=52, pad=W-2-title.length, l=Math.floor(pad/2), r=pad-l;
  return [paint.dim('╔'+'═'.repeat(W-2)+'╗'),
    paint.dim('║')+' '.repeat(l)+paint.bold(title)+' '.repeat(r)+paint.dim('║'),
    paint.dim('╚'+'═'.repeat(W-2)+'╝')].join('\n');
}

export async function runFix(flags = {}) {
  console.log(''); console.log(box('ClawArmor Fix  v0.7.0')); console.log('');

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

  console.log(`  ${paint.dim('Last audit had')} ${paint.bold(String(lastFailed.length))} ${paint.dim('failing checks.')}`);
  console.log(`  ${paint.bold(String(fixable.length))} ${paint.dim('can be auto-fixed.')} ${paint.dim(String(manual.length))} ${paint.dim('require manual steps.')}`);

  if (!fixable.length) {
    console.log('');
    console.log(`  ${paint.yellow('!')} No auto-fixable issues. Fix manually:`);
    for (const id of manual) console.log(`    ${paint.dim('•')} ${id}`);
    console.log(''); return 0;
  }

  console.log('');
  if (flags.dryRun) {
    console.log(`  ${paint.cyan('Dry run — would apply:')}`);
    for (const id of fixable) {
      const f = AUTO_FIXABLE[id];
      console.log(`  ${paint.dim('→')} ${f.desc}`);
      console.log(`    ${paint.dim(f.cmd)}`);
    }
    console.log('');
    console.log(`  ${paint.dim('Run')} ${paint.cyan('clawarmor fix --apply')} ${paint.dim('to apply these fixes.')}`);
    console.log(''); return 0;
  }

  if (!flags.apply) {
    console.log(`  ${paint.dim('Run')} ${paint.cyan('clawarmor fix --dry-run')} ${paint.dim('to preview fixes.')}`);
    console.log(`  ${paint.dim('Run')} ${paint.cyan('clawarmor fix --apply')} ${paint.dim('to apply them.')}`);
    console.log(''); return 0;
  }

  // Apply fixes
  let applied = 0, failed = 0, needsRestart = false;
  console.log(SEP);
  for (const id of fixable) {
    const f = AUTO_FIXABLE[id];
    process.stdout.write(`  ${paint.dim('→')} ${f.desc}...`);
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
