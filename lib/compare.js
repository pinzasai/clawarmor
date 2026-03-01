import { paint, severityColor } from './output/colors.js';
import { execSync } from 'child_process';

const SEP = paint.dim('─'.repeat(52));

function box(title) {
  const W=52, pad=W-2-title.length, l=Math.floor(pad/2), r=pad-l;
  return [paint.dim('╔'+'═'.repeat(W-2)+'╗'),
    paint.dim('║')+' '.repeat(l)+paint.bold(title)+' '.repeat(r)+paint.dim('║'),
    paint.dim('╚'+'═'.repeat(W-2)+'╝')].join('\n');
}

export async function runCompare() {
  console.log(''); console.log(box('ClawArmor vs openclaw audit')); console.log('');

  // Run ClawArmor audit (capture)
  console.log(`  ${paint.dim('Running clawarmor audit...')}`);
  let caFindings = [];
  try {
    const { loadConfig } = await import('./config.js');
    const { config } = loadConfig();
    const mods = ['./checks/gateway.js','./checks/filesystem.js','./checks/channels.js',
      './checks/auth.js','./checks/tools.js','./checks/version.js','./checks/hooks.js'];
    for (const m of mods) {
      const mod = await import(m);
      const checks = mod.default || [];
      for (const check of checks) {
        try { const r = await check(config); if (!r.passed) caFindings.push(r); }
        catch { /* skip */ }
      }
    }
  } catch(e) { console.log(`  ${paint.red('✗')} ClawArmor error: ${e.message}`); }

  // Run openclaw security audit --json
  console.log(`  ${paint.dim('Running openclaw security audit --json...')}`);
  let ocFindings = [];
  let ocAvailable = false;
  try {
    const raw = execSync('openclaw security audit --json 2>/dev/null', { timeout: 15000, encoding: 'utf8' });
    const data = JSON.parse(raw);
    ocFindings = (data.findings || data.checks || []).filter(f => !f.passed);
    ocAvailable = true;
  } catch { /* openclaw audit not available or no --json */ }

  console.log('');

  // What ClawArmor catches
  console.log(SEP);
  console.log(`  ${paint.cyan('ClawArmor findings')} ${paint.dim('('+caFindings.length+')')}`);
  console.log(SEP);
  if (!caFindings.length) {
    console.log(`  ${paint.green('✓')} No issues found`);
  } else {
    for (const f of caFindings) {
      const col = severityColor[f.severity] || paint.dim;
      console.log(`  ${paint.red('✗')} ${col('['+f.severity+']')} ${f.title}`);
    }
  }

  if (ocAvailable) {
    console.log('');
    console.log(SEP);
    console.log(`  ${paint.cyan('openclaw security audit findings')} ${paint.dim('('+ocFindings.length+')')}`);
    console.log(SEP);
    if (!ocFindings.length) {
      console.log(`  ${paint.green('✓')} No issues found`);
    } else {
      for (const f of ocFindings) {
        console.log(`  ${paint.yellow('!')} [${f.severity||'warn'}] ${f.checkId||f.id||f.title||'unknown'}`);
      }
    }

    // Unique to each
    console.log(''); console.log(SEP);
    console.log(`  ${paint.bold('Coverage gap analysis')}`);
    console.log(SEP);
    console.log(`  ${paint.cyan('Only in ClawArmor:')}       supply chain scan, external probe, compare command`);
    console.log(`  ${paint.cyan('Only in openclaw audit:')}  gateway probe (--deep), live WS test, auto-fix`);
    console.log(`  ${paint.cyan('Both cover:')}              config checks, file permissions, channel policies`);
  } else {
    console.log('');
    console.log(`  ${paint.dim('openclaw security audit --json not available.')}`);
    console.log(`  ${paint.dim('Run both manually to compare.')}`);
  }

  console.log('');
  console.log(SEP);
  console.log(`  ${paint.bold('What ClawArmor adds over the built-in auditor:')}`);
  console.log(`  ${paint.green('✓')} ${paint.dim('Skill supply chain scan (ALL files, not just SKILL.md)')}`);
  console.log(`  ${paint.green('✓')} ${paint.dim('External exposure detection (github.com/pinzasai/clawarmor)')}`);
  console.log(`  ${paint.green('✓')} ${paint.dim('Zero-FP scoring with floor rules for CRITICAL findings')}`);
  console.log(`  ${paint.green('✓')} ${paint.dim('Context-aware scan (binary wrappers, built-in skills)')}`);
  console.log(`  ${paint.green('✓')} ${paint.dim('Attack scenario descriptions per finding')}`);
  console.log('');
  return 0;
}
