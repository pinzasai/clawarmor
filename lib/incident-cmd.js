// ClawArmor incident command handler.
// Usage:
//   clawarmor incident create --finding <description> --severity <CRITICAL|HIGH|MEDIUM> [--action <quarantine|rollback|notify>]
//   clawarmor incident list

import { writeFileSync, mkdirSync, existsSync, readdirSync, readFileSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import { paint } from './output/colors.js';

const INCIDENT_DIR = join(homedir(), '.openclaw', 'workspace', 'memory', 'incidents');
const CLAWARMOR_VERSION = '3.2.0';

function box(title) {
  const W = 52, pad = W - 2 - title.length, l = Math.floor(pad / 2), r = pad - l;
  return [
    paint.dim('╔' + '═'.repeat(W - 2) + '╗'),
    paint.dim('║') + ' '.repeat(l) + paint.bold(title) + ' '.repeat(r) + paint.dim('║'),
    paint.dim('╚' + '═'.repeat(W - 2) + '╝'),
  ].join('\n');
}

function slugify(str) {
  return str.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').substring(0, 40);
}

function nowStr() {
  const d = new Date();
  const date = `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;
  const time = `${String(d.getHours()).padStart(2,'0')}:${String(d.getMinutes()).padStart(2,'0')}`;
  return { date, time, iso: d.toISOString() };
}

function buildIncidentMarkdown({ description, severity, action, date, time }) {
  const actionLabel = action || 'manual-review';
  const checkboxes = [
    action === 'quarantine' || action === 'rollback' || action === 'notify'
      ? `- [x] ${action === 'quarantine' ? 'Quarantine affected extension' : action === 'rollback' ? 'Rollback config to last snapshot' : 'Notify operator'}`
      : null,
    action !== 'quarantine' ? `- [ ] Quarantine affected extension` : null,
    action !== 'rollback' ? `- [ ] Rollback config to last snapshot` : null,
    action !== 'notify' ? `- [ ] Notify operator` : null,
  ].filter(Boolean);

  // Deduplicate checkboxes (action already checked, rest unchecked)
  const seenLabels = new Set();
  const uniqueCheckboxes = [];
  for (const line of checkboxes) {
    const label = line.replace(/^- \[.\] /, '');
    if (!seenLabels.has(label)) {
      seenLabels.add(label);
      uniqueCheckboxes.push(line);
    }
  }

  return `# Incident: ${description}
**Date:** ${date} ${time}
**Severity:** ${severity}
**Action Taken:** ${actionLabel}
**ClawArmor Version:** ${CLAWARMOR_VERSION}

## Finding
${description}

## Actions Taken
${uniqueCheckboxes.join('\n')}

## Resolution
(fill in manually)
`;
}

/**
 * Main incident command router.
 * @param {string[]} args - args after "incident"
 */
export async function runIncident(args) {
  const sub = args[0];

  if (!sub || sub === '--help' || sub === 'help') {
    console.log('');
    console.log(`  ${paint.bold('clawarmor incident')} — log and manage security incidents`);
    console.log('');
    console.log(`  ${paint.cyan('Subcommands:')}`);
    console.log(`    ${paint.cyan('create')}  --finding <desc> --severity <CRITICAL|HIGH|MEDIUM> [--action <quarantine|rollback|notify>]`);
    console.log(`    ${paint.cyan('list')}    List all incidents`);
    console.log('');
    return 0;
  }

  // ── CREATE ──────────────────────────────────────────────────────────────────
  if (sub === 'create') {
    const findingIdx = args.indexOf('--finding');
    const severityIdx = args.indexOf('--severity');
    const actionIdx = args.indexOf('--action');

    const finding = findingIdx !== -1 && args[findingIdx + 1] ? args[findingIdx + 1] : null;
    const severity = severityIdx !== -1 && args[severityIdx + 1] ? args[severityIdx + 1].toUpperCase() : null;
    const action = actionIdx !== -1 && args[actionIdx + 1] ? args[actionIdx + 1].toLowerCase() : null;

    if (!finding) {
      console.log(`  ${paint.red('✗')} --finding <description> is required`);
      console.log('');
      return 1;
    }
    if (!severity || !['CRITICAL', 'HIGH', 'MEDIUM'].includes(severity)) {
      console.log(`  ${paint.red('✗')} --severity must be CRITICAL, HIGH, or MEDIUM`);
      console.log('');
      return 1;
    }

    const { date, time } = nowStr();
    const slug = slugify(finding);
    const filename = `${date}-${slug}.md`;

    mkdirSync(INCIDENT_DIR, { recursive: true });
    const filePath = join(INCIDENT_DIR, filename);

    const content = buildIncidentMarkdown({ description: finding, severity, action, date, time });
    writeFileSync(filePath, content, 'utf8');

    console.log(''); console.log(box('ClawArmor Incident Created')); console.log('');
    const sevColor = severity === 'CRITICAL' ? paint.red : severity === 'HIGH' ? paint.yellow : paint.cyan;
    console.log(`  ${sevColor('[' + severity + ']')} ${paint.bold(finding)}`);
    console.log(`  ${paint.dim('Date:')}   ${date} ${time}`);
    if (action) console.log(`  ${paint.dim('Action:')} ${action}`);
    console.log(`  ${paint.dim('File:')}   ${filePath}`);
    console.log('');

    // If --action includes rollback, trigger rollback
    if (action === 'rollback') {
      console.log(`  ${paint.cyan('→')} Triggering rollback to last snapshot...`);
      try {
        const { runRollback } = await import('./rollback.js');
        const rc = await runRollback({});
        if (rc !== 0) {
          console.log(`  ${paint.yellow('!')} Rollback returned non-zero. Check snapshots manually.`);
        }
      } catch (e) {
        console.log(`  ${paint.yellow('!')} Rollback error: ${e.message}`);
      }
      console.log('');
    }

    return 0;
  }

  // ── LIST ─────────────────────────────────────────────────────────────────────
  if (sub === 'list') {
    console.log(''); console.log(box('ClawArmor Incidents')); console.log('');

    if (!existsSync(INCIDENT_DIR)) {
      console.log(`  ${paint.dim('No incidents logged yet.')}`);
      console.log(`  ${paint.dim('Use')} ${paint.cyan('clawarmor incident create')} ${paint.dim('to log one.')}`);
      console.log('');
      return 0;
    }

    const files = readdirSync(INCIDENT_DIR)
      .filter(f => f.endsWith('.md'))
      .sort()
      .reverse(); // newest first

    if (!files.length) {
      console.log(`  ${paint.dim('No incidents logged yet.')}`);
      console.log('');
      return 0;
    }

    console.log(`  ${paint.bold(String(files.length))} incident${files.length !== 1 ? 's' : ''} logged:\n`);

    for (const f of files) {
      const filePath = join(INCIDENT_DIR, f);
      let severity = 'UNKNOWN';
      let description = f.replace(/^\d{4}-\d{2}-\d{2}-/, '').replace('.md', '');
      let date = f.substring(0, 10);

      try {
        const raw = readFileSync(filePath, 'utf8');
        const sevMatch = raw.match(/\*\*Severity:\*\*\s*(\w+)/);
        if (sevMatch) severity = sevMatch[1];
        const descMatch = raw.match(/^# Incident: (.+)$/m);
        if (descMatch) description = descMatch[1];
        const dateMatch = raw.match(/\*\*Date:\*\*\s*(\S+)/);
        if (dateMatch) date = dateMatch[1];
      } catch { /* use filename defaults */ }

      const sevColor = severity === 'CRITICAL' ? paint.red : severity === 'HIGH' ? paint.yellow : paint.cyan;
      console.log(`  ${sevColor('[' + severity + ']')} ${paint.bold(description)}`);
      console.log(`    ${paint.dim('Date:')} ${date}  ${paint.dim('File:')} ${f}`);
      console.log('');
    }

    return 0;
  }

  console.log(`  ${paint.red('✗')} Unknown incident subcommand: ${paint.bold(sub)}`);
  console.log(`  ${paint.dim('Use: create | list')}`);
  console.log('');
  return 1;
}
