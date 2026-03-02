// lib/profile-cmd.js — clawarmor profile command
// Subcommands: list, detect, set <name>, show

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import { paint } from './output/colors.js';
import { listProfiles, getProfile, detectProfile } from './profiles.js';
import { loadConfig } from './config.js';

const HOME = homedir();
const CLAWARMOR_DIR = join(HOME, '.clawarmor');
const PROFILE_FILE = join(CLAWARMOR_DIR, 'profile.json');
const SEP = paint.dim('─'.repeat(52));

function box(title) {
  const W = 52, pad = W - 2 - title.length, l = Math.floor(pad / 2), r = pad - l;
  return [
    paint.dim('╔' + '═'.repeat(W - 2) + '╗'),
    paint.dim('║') + ' '.repeat(l) + paint.bold(title) + ' '.repeat(r) + paint.dim('║'),
    paint.dim('╚' + '═'.repeat(W - 2) + '╝'),
  ].join('\n');
}

function readCurrentProfile() {
  try {
    if (!existsSync(PROFILE_FILE)) return null;
    return JSON.parse(readFileSync(PROFILE_FILE, 'utf8'));
  } catch { return null; }
}

function writeProfile(name) {
  try {
    mkdirSync(CLAWARMOR_DIR, { recursive: true });
    writeFileSync(PROFILE_FILE, JSON.stringify({ name, setAt: new Date().toISOString() }, null, 2), 'utf8');
    return true;
  } catch { return false; }
}

function profileBadge(name) {
  const badges = {
    coding:    paint.cyan('coding'),
    browsing:  paint.green('browsing'),
    messaging: paint.yellow('messaging'),
    general:   paint.dim('general'),
  };
  return badges[name] || paint.dim(name);
}

async function listCmd() {
  console.log(''); console.log(box('ClawArmor Profiles')); console.log('');
  console.log(`  ${paint.bold('Available profiles:')}`);
  console.log('');

  const current = readCurrentProfile();
  const profiles = listProfiles();

  for (const p of profiles) {
    const isCurrent = current?.name === p.name;
    const marker = isCurrent ? paint.green('→') : paint.dim('·');
    const badge = profileBadge(p.name);
    console.log(`  ${marker} ${badge.padEnd(12)}  ${p.description}`);
    if (p.allowedCapabilities.length > 0) {
      console.log(`       ${paint.dim('allows:')} ${paint.dim(p.allowedCapabilities.join(', '))}`);
    }
    if (p.restrictedCapabilities.length > 0) {
      console.log(`       ${paint.dim('restricts:')} ${paint.dim(p.restrictedCapabilities.join(', '))}`);
    }
    console.log('');
  }

  if (current) {
    console.log(`  ${paint.dim('Current profile:')} ${profileBadge(current.name)}`);
  } else {
    console.log(`  ${paint.dim('No profile set. Defaulting to')} ${profileBadge('general')}`);
    console.log(`  ${paint.dim('Set with:')} ${paint.cyan('clawarmor profile set <name>')}`);
  }
  console.log('');
  return 0;
}

async function detectCmd() {
  console.log(''); console.log(box('ClawArmor Profile Detect')); console.log('');

  const { config } = loadConfig();
  const { profile: detected, reasons } = detectProfile(config);

  console.log(`  ${paint.bold('Auto-detected profile:')} ${profileBadge(detected)}`);
  console.log('');
  console.log(`  ${paint.dim('Reasoning:')}`);
  for (const reason of reasons) {
    console.log(`    ${paint.dim('·')} ${reason}`);
  }
  console.log('');

  const profileDef = getProfile(detected);
  if (profileDef) {
    console.log(`  ${paint.dim('Profile description:')} ${profileDef.description}`);
  }

  const current = readCurrentProfile();
  if (current && current.name !== detected) {
    console.log('');
    console.log(`  ${paint.yellow('!')} Current profile is ${profileBadge(current.name)}, detected ${profileBadge(detected)}`);
    console.log(`  ${paint.dim('Run')} ${paint.cyan(`clawarmor profile set ${detected}`)} ${paint.dim('to switch.')}`);
  } else if (!current) {
    console.log('');
    console.log(`  ${paint.dim('Run')} ${paint.cyan(`clawarmor profile set ${detected}`)} ${paint.dim('to activate this profile.')}`);
  }

  console.log('');
  return 0;
}

async function setCmd(name) {
  if (!name) {
    console.log('');
    console.log(`  ${paint.red('✗')} Profile name required.`);
    console.log(`  Usage: ${paint.cyan('clawarmor profile set <name>')}`);
    console.log(`  Available: ${listProfiles().map(p => p.name).join(', ')}`);
    console.log('');
    return 1;
  }

  const profile = getProfile(name);
  if (!profile) {
    console.log('');
    console.log(`  ${paint.red('✗')} Unknown profile: ${paint.bold(name)}`);
    console.log(`  Available: ${listProfiles().map(p => p.name).join(', ')}`);
    console.log('');
    return 1;
  }

  const ok = writeProfile(name);
  console.log('');
  if (ok) {
    console.log(`  ${paint.green('✓')} Profile set to ${profileBadge(name)}`);
    console.log(`  ${paint.dim(profile.description)}`);
    console.log('');
    console.log(`  ${paint.dim('Run')} ${paint.cyan('clawarmor harden --profile ' + name)} ${paint.dim('for profile-aware recommendations.')}`);
    console.log(`  ${paint.dim('Run')} ${paint.cyan('clawarmor audit --profile ' + name)} ${paint.dim('for profile-adjusted scoring.')}`);
  } else {
    console.log(`  ${paint.red('✗')} Failed to write profile to ${PROFILE_FILE}`);
  }
  console.log('');
  return ok ? 0 : 1;
}

async function showCmd() {
  console.log(''); console.log(box('ClawArmor Current Profile')); console.log('');

  const current = readCurrentProfile();

  if (!current) {
    console.log(`  ${paint.dim('No profile set.')}`);
    console.log(`  ${paint.dim('Defaulting to general — no relaxations or restrictions applied.')}`);
    console.log('');
    console.log(`  ${paint.dim('Set a profile:')} ${paint.cyan('clawarmor profile set <name>')}`);
    console.log(`  ${paint.dim('Auto-detect:')}   ${paint.cyan('clawarmor profile detect')}`);
    console.log('');
    return 0;
  }

  const profileDef = getProfile(current.name);
  const setAt = current.setAt ? new Date(current.setAt).toLocaleString('en-US', { dateStyle: 'medium', timeStyle: 'short' }) : 'unknown';

  console.log(`  ${paint.bold('Profile:')}  ${profileBadge(current.name)}`);
  console.log(`  ${paint.bold('Set at:')}   ${setAt}`);
  console.log('');

  if (profileDef) {
    console.log(`  ${paint.dim(profileDef.description)}`);
    console.log('');
    if (profileDef.allowedCapabilities.length > 0) {
      console.log(`  ${paint.green('Allowed:')}    ${profileDef.allowedCapabilities.join(', ')}`);
    }
    if (profileDef.restrictedCapabilities.length > 0) {
      console.log(`  ${paint.yellow('Restricted:')} ${profileDef.restrictedCapabilities.join(', ')}`);
    }
    if (Object.keys(profileDef.checkWeightOverrides).length > 0) {
      console.log('');
      console.log(`  ${paint.dim('Check overrides:')}`);
      for (const [check, severity] of Object.entries(profileDef.checkWeightOverrides)) {
        console.log(`    ${paint.dim(check)} → ${severity}`);
      }
    }
  }

  console.log('');
  console.log(`  ${paint.dim('Change profile:')} ${paint.cyan('clawarmor profile set <name>')}`);
  console.log(`  ${paint.dim('List profiles:')}  ${paint.cyan('clawarmor profile list')}`);
  console.log('');
  return 0;
}

export async function runProfileCmd(args = []) {
  const sub = args[0];

  if (!sub || sub === 'list') return listCmd();
  if (sub === 'detect')       return detectCmd();
  if (sub === 'set')          return setCmd(args[1]);
  if (sub === 'show')         return showCmd();

  console.log('');
  console.log(`  ${paint.red('✗')} Unknown profile subcommand: ${paint.bold(sub)}`);
  console.log('');
  console.log(`  ${paint.bold('Profile subcommands:')}`);
  console.log(`    ${paint.cyan('clawarmor profile list')}`);
  console.log(`    ${paint.cyan('clawarmor profile detect')}`);
  console.log(`    ${paint.cyan('clawarmor profile set <name>')}`);
  console.log(`    ${paint.cyan('clawarmor profile show')}`);
  console.log('');
  return 1;
}
