// clawarmor rollback — Restore config from a saved snapshot.
//   clawarmor rollback           Restore most recent snapshot
//   clawarmor rollback --list    List all available snapshots with details
//   clawarmor rollback --id <id> Restore a specific snapshot by id

import { paint } from './output/colors.js';
import { listSnapshots, loadSnapshot, loadLatestSnapshot, restoreSnapshot } from './snapshot.js';

const SEP = paint.dim('─'.repeat(52));

function box(title) {
  const W = 52, pad = W - 2 - title.length, l = Math.floor(pad / 2), r = pad - l;
  return [
    paint.dim('╔' + '═'.repeat(W - 2) + '╗'),
    paint.dim('║') + ' '.repeat(l) + paint.bold(title) + ' '.repeat(r) + paint.dim('║'),
    paint.dim('╚' + '═'.repeat(W - 2) + '╝'),
  ].join('\n');
}

function fmtDate(isoString) {
  if (!isoString) return 'unknown';
  try { return new Date(isoString).toLocaleString(); } catch { return isoString; }
}

/**
 * Main rollback command.
 * @param {{ list?: boolean, id?: string }} flags
 */
export async function runRollback(flags = {}) {
  console.log(''); console.log(box('ClawArmor Rollback')); console.log('');

  // ── LIST mode ─────────────────────────────────────────────────────────────
  if (flags.list) {
    const snapshots = listSnapshots();
    if (!snapshots.length) {
      console.log(`  ${paint.dim('No snapshots found.')}`);
      console.log(`  ${paint.dim('Snapshots are created automatically before every harden or fix run.')}`);
      console.log('');
      return 0;
    }

    console.log(`  ${paint.bold(String(snapshots.length))} snapshot${snapshots.length !== 1 ? 's' : ''} available:`);
    console.log('');
    for (const s of snapshots) {
      const fixList = s.appliedFixes.length ? s.appliedFixes.join(', ') : 'no fixes recorded';
      console.log(`  ${paint.cyan(s.id)}`);
      console.log(`    ${paint.dim('Date:')}    ${fmtDate(s.timestamp)}`);
      console.log(`    ${paint.dim('Trigger:')} ${s.trigger}`);
      console.log(`    ${paint.dim('Fixes:')}   ${fixList}`);
      console.log('');
    }
    console.log(`  ${paint.dim('To restore a specific snapshot:')} clawarmor rollback --id <id>`);
    console.log('');
    return 0;
  }

  // ── RESTORE specific snapshot or most recent ───────────────────────────────
  let snapshot;
  if (flags.id) {
    snapshot = loadSnapshot(flags.id);
    if (!snapshot) {
      console.log(`  ${paint.red('✗')} Snapshot not found: ${paint.bold(flags.id)}`);
      console.log(`  ${paint.dim('Run')} ${paint.cyan('clawarmor rollback --list')} ${paint.dim('to see available snapshots.')}`);
      console.log('');
      return 1;
    }
  } else {
    snapshot = loadLatestSnapshot();
    if (!snapshot) {
      console.log(`  ${paint.dim('No snapshots found.')}`);
      console.log(`  ${paint.dim('Snapshots are created automatically before every harden or fix run.')}`);
      console.log('');
      return 0;
    }
  }

  console.log(`  ${paint.dim('Snapshot:')}  ${fmtDate(snapshot.timestamp)}`);
  console.log(`  ${paint.dim('Trigger:')}   ${snapshot.trigger}`);
  if (snapshot.appliedFixes?.length) {
    console.log(`  ${paint.dim('Fixes:')}     ${snapshot.appliedFixes.join(', ')}`);
  }
  console.log('');
  console.log(SEP);
  console.log('');

  const result = restoreSnapshot(snapshot);
  if (!result.ok) {
    console.log(`  ${paint.red('✗')} Restore failed: ${result.err}`);
    console.log('');
    return 1;
  }

  const dateStr = fmtDate(snapshot.timestamp);
  console.log(`  ${paint.green('✓')} Restored to snapshot from ${paint.bold(dateStr)}.`);
  console.log(`  ${paint.dim('Run')} ${paint.cyan('openclaw gateway restart')} ${paint.dim('to apply.')}`);
  console.log('');
  return 0;
}
