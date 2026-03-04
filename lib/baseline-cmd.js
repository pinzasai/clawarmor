// ClawArmor baseline command handler.
// Usage:
//   clawarmor baseline save [--name <label>]
//   clawarmor baseline list
//   clawarmor baseline diff [--from <label>] [--to <label>]

import { paint } from './output/colors.js';
import { saveBaseline, listBaselines, diffBaselines, loadBaseline } from './baseline.js';
import { runAuditQuiet } from './audit-quiet.js';

const SEP = paint.dim('─'.repeat(52));

function box(title) {
  const W = 52, pad = W - 2 - title.length, l = Math.floor(pad / 2), r = pad - l;
  return [
    paint.dim('╔' + '═'.repeat(W - 2) + '╗'),
    paint.dim('║') + ' '.repeat(l) + paint.bold(title) + ' '.repeat(r) + paint.dim('║'),
    paint.dim('╚' + '═'.repeat(W - 2) + '╝'),
  ].join('\n');
}

function fmtDate(iso) {
  if (!iso) return 'unknown';
  try { return new Date(iso).toLocaleString(); } catch { return iso; }
}

function todayLabel() {
  const d = new Date();
  return `baseline-${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;
}

/**
 * Main baseline command router.
 * @param {string[]} args - args after "baseline"
 */
export async function runBaseline(args) {
  const sub = args[0];

  if (!sub || sub === '--help' || sub === 'help') {
    console.log('');
    console.log(`  ${paint.bold('clawarmor baseline')} — save and compare security baselines`);
    console.log('');
    console.log(`  ${paint.cyan('Subcommands:')}`);
    console.log(`    ${paint.cyan('save')}   [--name <label>]             Save current audit as a baseline`);
    console.log(`    ${paint.cyan('list')}                                List all saved baselines`);
    console.log(`    ${paint.cyan('diff')}   [--from <label>] [--to <label>]  Diff two baselines`);
    console.log('');
    return 0;
  }

  // ── SAVE ────────────────────────────────────────────────────────────────────
  if (sub === 'save') {
    const nameIdx = args.indexOf('--name');
    const label = nameIdx !== -1 && args[nameIdx + 1] ? args[nameIdx + 1] : todayLabel();

    console.log(''); console.log(box('ClawArmor Baseline Save')); console.log('');
    console.log(`  ${paint.dim('Running audit to capture current security posture...')}`);
    console.log('');

    let auditResult;
    try {
      auditResult = await runAuditQuiet({});
    } catch (e) {
      console.log(`  ${paint.red('✗')} Audit failed: ${e.message}`);
      console.log('');
      return 1;
    }

    const filePath = saveBaseline({
      label,
      score: auditResult.score,
      findings: auditResult.findings,
      profile: auditResult.profile || null,
    });

    console.log(`  ${paint.green('✓')} Baseline saved`);
    console.log(`  ${paint.dim('Label:')}  ${paint.bold(label)}`);
    console.log(`  ${paint.dim('Score:')}  ${paint.bold(String(auditResult.score))}/100`);
    console.log(`  ${paint.dim('Findings:')} ${auditResult.findings.length}`);
    console.log(`  ${paint.dim('File:')}   ${filePath}`);
    console.log('');
    return 0;
  }

  // ── LIST ─────────────────────────────────────────────────────────────────────
  if (sub === 'list') {
    console.log(''); console.log(box('ClawArmor Baselines')); console.log('');
    const baselines = listBaselines();
    if (!baselines.length) {
      console.log(`  ${paint.dim('No baselines saved yet.')}`);
      console.log(`  ${paint.dim('Run')} ${paint.cyan('clawarmor baseline save')} ${paint.dim('to create one.')}`);
      console.log('');
      return 0;
    }
    console.log(`  ${paint.bold(String(baselines.length))} baseline${baselines.length !== 1 ? 's' : ''} saved:\n`);
    for (const b of baselines) {
      const scoreStr = b.score != null ? `${b.score}/100` : 'n/a';
      const profileStr = b.profile ? `  ${paint.dim('[' + b.profile + ']')}` : '';
      console.log(`  ${paint.cyan(b.label)}${profileStr}`);
      console.log(`    ${paint.dim('Date:')}   ${fmtDate(b.savedAt)}`);
      console.log(`    ${paint.dim('Score:')}  ${scoreStr}`);
      console.log('');
    }
    console.log(`  ${paint.dim('To compare:')} ${paint.cyan('clawarmor baseline diff --from <label> --to <label>')}`);
    console.log('');
    return 0;
  }

  // ── DIFF ──────────────────────────────────────────────────────────────────────
  if (sub === 'diff') {
    const fromIdx = args.indexOf('--from');
    const toIdx = args.indexOf('--to');

    // Resolve from/to — default: latest vs previous
    let fromLabel = fromIdx !== -1 && args[fromIdx + 1] ? args[fromIdx + 1] : null;
    let toLabel = toIdx !== -1 && args[toIdx + 1] ? args[toIdx + 1] : null;

    if (!fromLabel || !toLabel) {
      const all = listBaselines();
      if (all.length < 2) {
        console.log('');
        console.log(`  ${paint.yellow('!')} Need at least 2 baselines to diff.`);
        console.log(`  ${paint.dim('Run')} ${paint.cyan('clawarmor baseline save')} ${paint.dim('to create baselines.')}`);
        console.log('');
        return 1;
      }
      if (!fromLabel) fromLabel = all[all.length - 2].label;
      if (!toLabel) toLabel = all[all.length - 1].label;
    }

    console.log(''); console.log(box('ClawArmor Baseline Diff')); console.log('');

    let diff;
    try {
      diff = diffBaselines(fromLabel, toLabel);
    } catch (e) {
      console.log(`  ${paint.red('✗')} ${e.message}`);
      console.log('');
      return 1;
    }

    const deltaStr = diff.scoreDelta > 0
      ? paint.green(`+${diff.scoreDelta}`)
      : diff.scoreDelta < 0
        ? paint.red(String(diff.scoreDelta))
        : paint.dim('0');

    console.log(`  ${paint.dim('From:')}  ${paint.bold(diff.fromLabel)}  ${paint.dim('(score: ' + diff.fromScore + ')')}`);
    console.log(`  ${paint.dim('To:')}    ${paint.bold(diff.toLabel)}  ${paint.dim('(score: ' + diff.toScore + ')')}`);
    console.log(`  ${paint.dim('Delta:')} ${deltaStr}`);
    console.log('');

    if (diff.newFindings.length) {
      console.log(SEP);
      console.log(`  ${paint.yellow('New findings')} ${paint.dim('(' + diff.newFindings.length + ' since ' + diff.fromLabel + ')')}`);
      console.log(SEP);
      for (const f of diff.newFindings) {
        const sev = f.severity || 'MEDIUM';
        const sevColor = sev === 'CRITICAL' ? paint.red : sev === 'HIGH' ? paint.yellow : paint.cyan;
        console.log(`  ${sevColor('[' + sev + ']')} ${paint.bold(f.skill || '?')}  ${paint.dim(f.message || f.patternId || '')}`);
      }
      console.log('');
    } else {
      console.log(`  ${paint.green('✓')} No new findings.`);
    }

    if (diff.resolvedFindings.length) {
      console.log(SEP);
      console.log(`  ${paint.green('Resolved findings')} ${paint.dim('(' + diff.resolvedFindings.length + ' fixed since ' + diff.fromLabel + ')')}`);
      console.log(SEP);
      for (const f of diff.resolvedFindings) {
        console.log(`  ${paint.dim('✓')} ${f.skill || '?'}  ${paint.dim(f.message || f.patternId || '')}`);
      }
      console.log('');
    }

    if (!diff.newFindings.length && !diff.resolvedFindings.length) {
      console.log(`  ${paint.dim('No changes between baselines.')}`);
      console.log('');
    }

    return 0;
  }

  console.log(`  ${paint.red('✗')} Unknown baseline subcommand: ${paint.bold(sub)}`);
  console.log(`  ${paint.dim('Use: save | list | diff')}`);
  console.log('');
  return 1;
}
