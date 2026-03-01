#!/usr/bin/env node
// ClawArmor Project Tracker — internal tool
// Usage: node .tracker/tracker.js [status|update <id> <field> <value>|done <id>|block <id> <reason>]

import { readFileSync, writeFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dir = dirname(fileURLToPath(import.meta.url));
const DB = join(__dir, 'tracker.json');

const COLORS = {
  reset: '\x1b[0m', bold: '\x1b[1m', dim: '\x1b[2m',
  red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m',
  blue: '\x1b[34m', cyan: '\x1b[36m', white: '\x1b[37m',
};
const c = (color, text) => `${COLORS[color]}${text}${COLORS.reset}`;
const SEP = c('dim', '─'.repeat(60));

const STATUS_ICON = {
  'done':        c('green',  '✓'),
  'building':    c('cyan',   '⚙'),
  'in-progress': c('cyan',   '⚙'),
  'ready':       c('green',  '●'),
  'not-started': c('dim',    '○'),
  'blocked':     c('red',    '✗'),
  'planned':     c('dim',    '○'),
};
const PRIORITY_COLOR = {
  'critical': 'red', 'high': 'yellow', 'medium': 'cyan', 'low': 'dim'
};

function load() { return JSON.parse(readFileSync(DB, 'utf8')); }
function save(data) {
  data.lastUpdated = new Date().toISOString();
  writeFileSync(DB, JSON.stringify(data, null, 2));
}

function status() {
  const d = load();
  console.log('');
  console.log(c('bold', `🛡  ClawArmor Project Tracker`));
  console.log(c('dim', `   ${d.mission}`));
  console.log(c('dim', `   ${d.repo}`));
  console.log(c('dim', `   Last updated: ${new Date(d.lastUpdated).toLocaleString()}`));
  console.log('');

  // Version + score
  console.log(SEP);
  console.log(`  ${c('bold','Version:')}  ${c('green', 'v'+d.currentVersion)} (live)   ${c('dim','→')}  ${c('cyan','v'+d.nextVersion)} (building)`);
  console.log(`  ${c('bold','Score:')}    ${c('green', d.score.current+'/100')}  on ${d.score.machine}`);
  console.log(SEP);

  for (const phase of d.phases) {
    console.log('');
    const pIcon = phase.status === 'in-progress' ? c('cyan','▶') : phase.status === 'done' ? c('green','✓') : c('dim','○');
    console.log(`  ${pIcon}  ${c('bold', phase.id + ' — ' + phase.name)}  ${c('dim','[target: '+phase.target+']')}`);
    console.log('');

    for (const task of phase.tasks) {
      const icon = STATUS_ICON[task.status] || '?';
      const pri = c(PRIORITY_COLOR[task.priority] || 'white', task.priority.toUpperCase());
      console.log(`     ${icon}  ${c('bold', task.id)}  ${task.title}`);
      console.log(`        ${c('dim','[')}${pri}${c('dim',']')}  ${c('dim', task.status)}`);
      if (task.blockedBy) console.log(`        ${c('red','⚠ Blocked by:')} ${task.blockedBy}`);
    }
  }

  console.log('');
  console.log(SEP);
  console.log(`  ${c('bold','Needs Alberto:')}`);
  for (const item of d.needsAlberto) {
    const icon = item.urgent ? c('red','!') : c('dim','·');
    console.log(`  ${icon}  ${c('bold', item.id)}  ${item.what}  ${c('dim','— '+item.why)}`);
  }
  console.log(SEP);
  console.log(`  ${c('dim','Updates: ')}${d.updateSchedule.join('  ')}`);
  console.log('');
}

function updateTask(id, field, value) {
  const d = load();
  let found = false;
  for (const phase of d.phases) {
    for (const task of phase.tasks) {
      if (task.id === id) {
        task[field] = value;
        found = true;
        break;
      }
    }
    if (found) break;
  }
  if (!found) { console.error(`Task ${id} not found`); process.exit(1); }
  save(d);
  console.log(c('green', `✓ Updated ${id}.${field} = ${value}`));
}

function done(id) { updateTask(id, 'status', 'done'); }
function block(id, reason) {
  const d = load();
  for (const phase of d.phases) {
    for (const task of phase.tasks) {
      if (task.id === id) {
        task.status = 'blocked';
        task.blockedBy = reason;
        save(d);
        console.log(c('yellow', `⚠ Blocked ${id}: ${reason}`));
        return;
      }
    }
  }
  console.error(`Task ${id} not found`);
}

function setVersion(v) {
  const d = load();
  d.currentVersion = v;
  save(d);
  console.log(c('green', `✓ Version → ${v}`));
}

function setScore(score) {
  const d = load();
  d.score.current = parseInt(score);
  save(d);
  console.log(c('green', `✓ Score → ${score}/100`));
}

function note(id, text) {
  const d = load();
  for (const phase of d.phases) {
    for (const task of phase.tasks) {
      if (task.id === id) {
        task.note = text;
        task.noteTime = new Date().toISOString();
        save(d);
        console.log(c('green', `✓ Note added to ${id}`));
        return;
      }
    }
  }
  console.error(`Task ${id} not found`);
}

const [,, cmd, ...args] = process.argv;
if (!cmd || cmd === 'status') status();
else if (cmd === 'done') done(args[0]);
else if (cmd === 'block') block(args[0], args.slice(1).join(' '));
else if (cmd === 'update') updateTask(args[0], args[1], args.slice(2).join(' '));
else if (cmd === 'version') setVersion(args[0]);
else if (cmd === 'score') setScore(args[0]);
else if (cmd === 'note') note(args[0], args.slice(1).join(' '));
else { console.error(`Unknown command: ${cmd}`); process.exit(1); }
