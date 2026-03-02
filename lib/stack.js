// lib/stack.js — ClawArmor stack command handler
// Subcommands: status, plan, deploy [--invariant|--ironcurtain|--all], sync, teardown

import { unlinkSync } from 'fs';
import { paint } from './output/colors.js';
import { getStackStatus, getPlan } from './stack/index.js';
import * as Invariant from './stack/invariant.js';
import * as IronCurtain from './stack/ironcurtain.js';

const SEP = paint.dim('─'.repeat(52));
const VERSION = '3.1.0';

function box(title) {
  const W = 52, pad = W - 2 - title.length, l = Math.floor(pad / 2), r = pad - l;
  return [
    paint.dim('╔' + '═'.repeat(W - 2) + '╗'),
    paint.dim('║') + ' '.repeat(l) + paint.bold(title) + ' '.repeat(r) + paint.dim('║'),
    paint.dim('╚' + '═'.repeat(W - 2) + '╝'),
  ].join('\n');
}

function riskBadge(level) {
  if (level === 'critical') return paint.critical('⬤ Critical');
  if (level === 'medium')   return paint.yellow('⬤ Medium');
  if (level === 'low')      return paint.green('⬤ Low');
  return paint.dim('⬤ Unknown');
}

// ── status ────────────────────────────────────────────────────────────────────

async function stackStatus() {
  console.log(''); console.log(box(`ClawArmor Stack  v${VERSION}`)); console.log('');

  const { audit, profile } = await getStackStatus();
  const scoreNote = profile.score != null ? `(audit score: ${profile.score}/100)` : '(no audit data)';
  console.log(`  ${paint.dim('Risk profile')}    ${riskBadge(profile.level)}  ${paint.dim(scoreNote)}`);
  console.log('');
  console.log(SEP);

  // Invariant
  const inv = Invariant.getStatus();
  let invIcon, invStatus;
  if (inv.enforcing) {
    invIcon = paint.green('✓');
    invStatus = `${paint.green('✓ actively enforcing')} ${paint.dim(`(${inv.ruleCount} rule${inv.ruleCount !== 1 ? 's' : ''})`)}`;
  } else if (inv.rulesExist && inv.ruleCount > 0) {
    invIcon = paint.yellow('○');
    invStatus = `${paint.yellow('✓ rules generated')} ${paint.dim(`(${inv.ruleCount} rule${inv.ruleCount !== 1 ? 's' : ''}, not enforcing)`)}`;
  } else {
    invIcon = paint.yellow('○');
    invStatus = paint.dim('not deployed');
  }
  const invPip = inv.installed ? paint.green('pip: installed') : paint.yellow('pip: not installed');
  console.log(`  ${invIcon} ${paint.bold('Invariant')}     ${invStatus}`);
  console.log(`      ${paint.dim('Flow guardrails — detects multi-step attack chains')}`);
  console.log(`      ${paint.dim(invPip)}`);
  if (!inv.rulesExist) {
    console.log(`      ${paint.dim('→ run: clawarmor stack deploy --invariant')}`);
  } else if (!inv.enforcing) {
    console.log(`      ${paint.yellow('⚠')} Rules generated but not enforcing — install invariant-ai to activate: ${paint.cyan('pip3 install invariant-ai')}`);
  }
  console.log('');

  // IronCurtain
  const ic = IronCurtain.getStatus();
  let icIcon, icStatus;
  if (ic.enforcing) {
    icIcon = paint.green('✓');
    icStatus = paint.green('✓ compiled + running');
  } else if (ic.constitutionExists) {
    icIcon = paint.yellow('○');
    icStatus = `${paint.yellow('✓ constitution written')} ${paint.dim('(not compiled)')}`;
  } else {
    icIcon = paint.yellow('○');
    icStatus = paint.dim('not configured');
  }
  const icCli = ic.cliInstalled ? paint.green('cli: installed') : paint.yellow('cli: not installed');
  console.log(`  ${icIcon} ${paint.bold('IronCurtain')}   ${icStatus}`);
  console.log(`      ${paint.dim('Runtime constitution — policy-enforced tool call interception')}`);
  console.log(`      ${paint.dim(icCli)}`);
  if (!ic.constitutionExists) {
    console.log(`      ${paint.dim('→ run: clawarmor stack deploy --ironcurtain')}`);
  } else if (!ic.enforcing) {
    console.log(`      ${paint.yellow('⚠')} Constitution written but not compiled — run: ${paint.cyan('ironcurtain compile-policy ~/.ironcurtain/constitution-clawarmor.md')}`);
  }
  console.log('');

  console.log(SEP);
  // Count enforcing layers, not just deployed
  const enforcingLayers = (inv.enforcing ? 1 : 0) + (ic.enforcing ? 1 : 0);
  const layerColor = enforcingLayers >= 2 ? paint.green : enforcingLayers === 1 ? paint.yellow : paint.red;
  console.log(`  Stack coverage:  ${layerColor(String(enforcingLayers))} / 2 layers enforcing`);
  if (enforcingLayers < 2) {
    const generatedLayers = (inv.rulesExist ? 1 : 0) + (ic.constitutionExists ? 1 : 0);
    if (generatedLayers > enforcingLayers) {
      console.log(`  ${paint.dim(`(${generatedLayers} layer${generatedLayers !== 1 ? 's' : ''} generated but not yet enforcing)`)}`);
    }
    console.log(`  ${paint.dim('→ run: clawarmor stack deploy --all')}`);
  }
  console.log('');
  return 0;
}

// ── plan ──────────────────────────────────────────────────────────────────────

async function stackPlan() {
  console.log(''); console.log(box(`ClawArmor Stack  v${VERSION}`)); console.log('');
  console.log(`  ${paint.cyan('Plan — what would be deployed (no changes made):')}`);
  console.log('');

  const { audit, profile } = await getStackStatus();
  const plan = getPlan(profile);

  console.log(`  ${paint.dim('Risk profile')}  ${riskBadge(profile.level)}`);
  if (profile.score != null) console.log(`  ${paint.dim('Audit score')}   ${profile.score}/100`);
  if (audit?.findings?.length) console.log(`  ${paint.dim('Findings')}      ${audit.findings.length} total`);
  console.log('');
  console.log(`  ${paint.dim('Deployment rationale:')}`);
  console.log(`    ${plan.reason}`);
  console.log('');
  console.log(SEP);
  console.log(`  ${paint.bold('Components:')}`);
  console.log('');

  const inv = Invariant.getStatus();
  const invMark = plan.invariant
    ? (inv.rulesExist ? paint.dim('○ already deployed') : paint.green('→ would deploy'))
    : paint.dim('– not recommended for this risk level');
  console.log(`  Invariant     ${invMark}`);
  if (plan.invariant && !inv.rulesExist) {
    console.log(`    ${paint.dim('Would: pip3 install invariant-ai')}`);
    console.log(`    ${paint.dim('Would: generate rules from ' + (audit?.findings?.length || 0) + ' audit findings')}`);
    console.log(`    ${paint.dim('Would: write ~/.clawarmor/invariant-rules.inv')}`);
  }
  console.log('');

  const ic = IronCurtain.getStatus();
  const icMark = plan.ironcurtain
    ? (ic.constitutionExists ? paint.dim('○ already deployed') : paint.green('→ would deploy'))
    : paint.dim('– not recommended for this risk level');
  console.log(`  IronCurtain   ${icMark}`);
  if (plan.ironcurtain && !ic.constitutionExists) {
    console.log(`    ${paint.dim('Would: generate constitution from audit findings')}`);
    console.log(`    ${paint.dim('Would: write ~/.ironcurtain/constitution-clawarmor.md')}`);
    console.log(`    ${paint.dim('Then:  ironcurtain compile-policy (manual step)')}`);
  }
  console.log('');

  console.log(SEP);
  console.log(`  ${paint.dim('To apply: clawarmor stack deploy --all')}`);
  console.log('');
  return 0;
}

// ── deploy ────────────────────────────────────────────────────────────────────

async function stackDeploy(flags) {
  const doInvariant  = flags.invariant  || flags.all;
  const doIronCurtain = flags.ironcurtain || flags.all;

  console.log(''); console.log(box(`ClawArmor Stack  v${VERSION}`)); console.log('');

  if (!doInvariant && !doIronCurtain) {
    console.log(`  ${paint.yellow('!')} Specify a component to deploy:`);
    console.log(`    ${paint.cyan('clawarmor stack deploy --invariant')}`);
    console.log(`    ${paint.cyan('clawarmor stack deploy --ironcurtain')}`);
    console.log(`    ${paint.cyan('clawarmor stack deploy --all')}`);
    console.log('');
    return 1;
  }

  const { audit, profile } = await getStackStatus();
  const findings = audit?.findings ?? [];

  console.log(`  ${paint.dim('Risk profile')}  ${riskBadge(profile.level)}`);
  if (findings.length) {
    console.log(`  ${paint.dim('Findings')}      ${findings.length} — generating configs from audit data`);
  } else {
    console.log(`  ${paint.dim('Findings')}      ${paint.dim('none — run clawarmor audit first for best results')}`);
  }
  console.log('');

  let exitCode = 0;

  // ── Invariant ──────────────────────────────────────────────────────────────
  if (doInvariant) {
    console.log(SEP);
    console.log(`  ${paint.bold('Invariant')} — flow guardrails`);
    console.log('');

    const alreadyInstalled = Invariant.checkInstalled();
    if (!alreadyInstalled) {
      process.stdout.write(`  ${paint.dim('Installing invariant-ai via pip3...')} `);
      const result = Invariant.install();
      if (result.ok) {
        process.stdout.write(paint.green('✓\n'));
      } else {
        process.stdout.write(paint.red('✗\n'));
        console.log(`  ${paint.red('Error:')} ${result.err}`);
        console.log(`  ${paint.dim('Try manually: pip3 install invariant-ai')}`);
        exitCode = 1;
      }
    } else {
      console.log(`  ${paint.green('✓')} invariant-ai already installed`);
    }

    process.stdout.write(`  ${paint.dim('Generating rules from audit findings...')} `);
    const rules = Invariant.generateRules(findings);
    process.stdout.write(paint.green('✓\n'));

    process.stdout.write(`  ${paint.dim('Writing ~/.clawarmor/invariant-rules.inv...')} `);
    const deployResult = Invariant.deploy(rules);
    if (deployResult.ok) {
      process.stdout.write(paint.green('✓\n'));
      const s = Invariant.getStatus();
      console.log(`  ${paint.green('✓')} Deployed: ${s.ruleCount} rule${s.ruleCount !== 1 ? 's' : ''}`);
      console.log(`  ${paint.dim('Path:')} ${deployResult.rulesPath}`);
    } else {
      process.stdout.write(paint.red('✗\n'));
      console.log(`  ${paint.red('Error:')} ${deployResult.err}`);
      exitCode = 1;
    }
    console.log('');
  }

  // ── IronCurtain ────────────────────────────────────────────────────────────
  if (doIronCurtain) {
    console.log(SEP);
    console.log(`  ${paint.bold('IronCurtain')} — runtime constitution`);
    console.log('');

    const icInstalled = IronCurtain.checkInstalled();
    if (icInstalled) {
      console.log(`  ${paint.green('✓')} ironcurtain CLI installed`);
    } else {
      console.log(`  ${paint.yellow('○')} ironcurtain CLI not installed ${paint.dim('(constitution generated regardless)')}`);
      console.log(`  ${paint.dim('Install: npm install -g ironcurtain')}`);
    }

    process.stdout.write(`  ${paint.dim('Generating constitution from audit findings...')} `);
    const constitution = IronCurtain.generateConstitution(findings);
    process.stdout.write(paint.green('✓\n'));

    process.stdout.write(`  ${paint.dim('Writing ~/.ironcurtain/constitution-clawarmor.md...')} `);
    const writeResult = IronCurtain.writeConstitution(constitution);
    if (writeResult.ok) {
      process.stdout.write(paint.green('✓\n'));
      console.log(`  ${paint.green('✓')} Constitution written: ${writeResult.path}`);
    } else {
      process.stdout.write(paint.red('✗\n'));
      console.log(`  ${paint.red('Error:')} ${writeResult.err}`);
      exitCode = 1;
    }

    console.log('');
    console.log(`  ${paint.yellow('!')} Next step — compile the constitution into deterministic rules:`);
    console.log(`    ${paint.dim('ironcurtain compile-policy ~/.ironcurtain/constitution-clawarmor.md')}`);
    console.log('');
  }

  console.log(SEP);
  const invS = Invariant.getStatus();
  const icS  = IronCurtain.getStatus();
  const deployedLayers = (invS.rulesExist ? 1 : 0) + (icS.constitutionExists ? 1 : 0);
  const layerColor = deployedLayers >= 2 ? paint.green : deployedLayers === 1 ? paint.yellow : paint.red;
  console.log(`  Stack coverage: ${layerColor(String(deployedLayers))} / 2 layers generated`);
  if (exitCode === 0) {
    console.log(`  ${paint.green('✓')} Done. Run ${paint.cyan('clawarmor stack status')} to verify.`);
  } else {
    console.log(`  ${paint.yellow('!')} Completed with errors. Check output above.`);
  }
  console.log('');
  return exitCode;
}

// ── sync ──────────────────────────────────────────────────────────────────────

async function stackSync() {
  console.log(''); console.log(box(`ClawArmor Stack  v${VERSION}`)); console.log('');
  console.log(`  ${paint.cyan('Sync — regenerating stack configs from latest audit...')}`);
  console.log('');

  const { audit, profile } = await getStackStatus();
  if (!audit) {
    console.log(`  ${paint.yellow('!')} No audit data found.`);
    console.log(`  ${paint.dim('Run clawarmor audit first, then clawarmor stack sync.')}`);
    console.log('');
    return 1;
  }

  const findings = audit.findings ?? [];
  console.log(`  ${paint.dim('Audit score')}   ${profile.score ?? 'n/a'}/100  ${paint.dim('(' + findings.length + ' findings)')}`);
  console.log('');

  const invStatus = Invariant.getStatus();
  const icStatus  = IronCurtain.getStatus();
  let updated = 0;

  if (invStatus.rulesExist) {
    process.stdout.write(`  ${paint.dim('Invariant: regenerating rules...')} `);
    const rules  = Invariant.generateRules(findings);
    const result = Invariant.deploy(rules);
    if (result.ok) { process.stdout.write(paint.green('✓\n')); updated++; }
    else           { process.stdout.write(paint.red('✗\n')); console.log(`    ${paint.dim(result.err)}`); }
  } else {
    console.log(`  ${paint.dim('Invariant: not deployed — skipping')}`);
  }

  if (icStatus.constitutionExists) {
    process.stdout.write(`  ${paint.dim('IronCurtain: regenerating constitution...')} `);
    const constitution = IronCurtain.generateConstitution(findings);
    const result = IronCurtain.writeConstitution(constitution);
    if (result.ok) { process.stdout.write(paint.green('✓\n')); updated++; }
    else           { process.stdout.write(paint.red('✗\n')); console.log(`    ${paint.dim(result.err)}`); }
  } else {
    console.log(`  ${paint.dim('IronCurtain: not deployed — skipping')}`);
  }

  console.log('');
  if (updated > 0) {
    console.log(`  ${paint.green('✓')} Synced ${updated} component${updated !== 1 ? 's' : ''} from latest audit.`);
    if (icStatus.constitutionExists && IronCurtain.checkInstalled()) {
      console.log(`  ${paint.yellow('!')} Re-compile IronCurtain constitution to take effect:`);
      console.log(`    ${paint.dim('ironcurtain compile-policy ~/.ironcurtain/constitution-clawarmor.md')}`);
    }
  } else {
    console.log(`  ${paint.dim('Nothing synced. Run clawarmor stack deploy --all to set up the stack.')}`);
  }
  console.log('');
  return 0;
}

// ── teardown ──────────────────────────────────────────────────────────────────

async function stackTeardown(flags) {
  const doInvariant   = flags.invariant   || flags.all;
  const doIronCurtain = flags.ironcurtain || flags.all;

  console.log(''); console.log(box(`ClawArmor Stack  v${VERSION}`)); console.log('');

  if (!doInvariant && !doIronCurtain) {
    console.log(`  ${paint.yellow('!')} Specify a component to teardown:`);
    console.log(`    ${paint.cyan('clawarmor stack teardown --invariant')}`);
    console.log(`    ${paint.cyan('clawarmor stack teardown --ironcurtain')}`);
    console.log(`    ${paint.cyan('clawarmor stack teardown --all')}`);
    console.log('');
    return 1;
  }

  console.log(`  ${paint.cyan('Teardown — removing deployed stack components...')}`);
  console.log('');

  const invStatus = Invariant.getStatus();
  const icStatus  = IronCurtain.getStatus();
  let removed = 0;

  if (doInvariant) {
    if (invStatus.rulesExist) {
      try {
        unlinkSync(invStatus.rulesPath);
        console.log(`  ${paint.green('✓')} Invariant rules removed: ${invStatus.rulesPath}`);
        removed++;
      } catch (e) {
        console.log(`  ${paint.red('✗')} Failed to remove Invariant rules: ${e.message?.split('\n')[0]}`);
      }
    } else {
      console.log(`  ${paint.dim('○')} Invariant rules not found — nothing to remove`);
    }
  }

  if (doIronCurtain) {
    if (icStatus.constitutionExists) {
      try {
        unlinkSync(icStatus.constitutionPath);
        console.log(`  ${paint.green('✓')} IronCurtain constitution removed: ${icStatus.constitutionPath}`);
        removed++;
      } catch (e) {
        console.log(`  ${paint.red('✗')} Failed to remove IronCurtain constitution: ${e.message?.split('\n')[0]}`);
      }
    } else {
      console.log(`  ${paint.dim('○')} IronCurtain constitution not found — nothing to remove`);
    }
  }

  console.log('');
  if (removed > 0) {
    console.log(`  ${paint.green('✓')} Teardown complete. Removed ${removed} component${removed !== 1 ? 's' : ''}.`);
  } else {
    console.log(`  ${paint.dim('Nothing removed.')}`);
  }
  console.log('');
  return 0;
}

// ── Main export ───────────────────────────────────────────────────────────────

export async function runStack(args = []) {
  const sub = args[0];

  if (!sub || sub === 'status')  return stackStatus();
  if (sub === 'plan')            return stackPlan();
  if (sub === 'sync')            return stackSync();

  if (sub === 'deploy') {
    return stackDeploy({
      invariant:   args.includes('--invariant'),
      ironcurtain: args.includes('--ironcurtain'),
      all:         args.includes('--all'),
    });
  }

  if (sub === 'teardown') {
    return stackTeardown({
      invariant:   args.includes('--invariant'),
      ironcurtain: args.includes('--ironcurtain'),
      all:         args.includes('--all'),
    });
  }

  console.log('');
  console.log(`  ${paint.red('✗')} Unknown stack subcommand: ${paint.bold(sub)}`);
  console.log('');
  console.log(`  ${paint.bold('Stack subcommands:')}`);
  console.log(`    ${paint.cyan('clawarmor stack status')}`);
  console.log(`    ${paint.cyan('clawarmor stack plan')}`);
  console.log(`    ${paint.cyan('clawarmor stack deploy --invariant | --ironcurtain | --all')}`);
  console.log(`    ${paint.cyan('clawarmor stack sync')}`);
  console.log(`    ${paint.cyan('clawarmor stack teardown --invariant | --ironcurtain | --all')}`);
  console.log('');
  return 1;
}
