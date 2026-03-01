// T-ACCESS-003 — Token Age Hygiene
// Checks agent-accounts.json for stale credentials (by date fields only).
// NEVER logs or prints actual credential values.

import { readFileSync, existsSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';

const HOME = homedir();
const ACCOUNTS_FILE = join(HOME, '.openclaw', 'agent-accounts.json');

const CRED_KEY_PATTERN = /token|key|secret|password|credential/i;
const DATE_KEY_PATTERN = /creat|updat|generat|issu|born|added|refresh|rotat|expir|since|timestamp|date|time/i;

const WARN_DAYS = 90;
const HIGH_DAYS = 180;
const MS_PER_DAY = 86400000;

function parseDate(value) {
  if (value == null) return null;
  // Unix timestamp (seconds) — must be between 2015 and 2040
  if (typeof value === 'number' && value > 1420000000 && value < 2208988800) {
    return new Date(value * 1000);
  }
  if (typeof value === 'string' && value.length >= 8) {
    const d = new Date(value);
    if (!isNaN(d.getTime()) && d.getFullYear() >= 2015 && d.getFullYear() <= 2040) {
      return d;
    }
  }
  return null;
}

function ageInDays(date) {
  return Math.floor((Date.now() - date.getTime()) / MS_PER_DAY);
}

// Walk an object and collect { keyPath, date } for any date-like values
// that appear alongside credential-like keys.
function collectDateFields(obj, parentPath = '') {
  const results = [];
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return results;

  for (const [key, value] of Object.entries(obj)) {
    const keyPath = parentPath ? `${parentPath}.${key}` : key;

    if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
      results.push(...collectDateFields(value, keyPath));
      continue;
    }

    if (Array.isArray(value)) {
      value.forEach((item, i) => {
        if (typeof item === 'object' && item !== null) {
          results.push(...collectDateFields(item, `${keyPath}[${i}]`));
        }
      });
      continue;
    }

    // Only consider date-like values attached to date-named keys
    // that appear in an object that also has credential-like keys
    if (DATE_KEY_PATTERN.test(key)) {
      const date = parseDate(value);
      if (date) {
        results.push({ keyPath, date });
      }
    }
  }

  return results;
}

// Find objects in the tree that contain at least one credential-key
// and return any date fields within those objects.
function findCredentialDates(obj, parentPath = '') {
  const results = [];
  if (!obj || typeof obj !== 'object') return results;

  if (Array.isArray(obj)) {
    obj.forEach((item, i) => {
      results.push(...findCredentialDates(item, `${parentPath}[${i}]`));
    });
    return results;
  }

  const keys = Object.keys(obj);
  const hasCredKey = keys.some(k => CRED_KEY_PATTERN.test(k));

  if (hasCredKey) {
    // This object has credential-like keys; look for date fields within it
    for (const [key, value] of Object.entries(obj)) {
      const keyPath = parentPath ? `${parentPath}.${key}` : key;
      if (DATE_KEY_PATTERN.test(key)) {
        const date = parseDate(value);
        if (date) results.push({ keyPath, date });
      }
    }
  }

  // Always recurse into child objects
  for (const [key, value] of Object.entries(obj)) {
    const keyPath = parentPath ? `${parentPath}.${key}` : key;
    if (value && typeof value === 'object') {
      results.push(...findCredentialDates(value, keyPath));
    }
  }

  return results;
}

export function checkTokenAge() {
  if (!existsSync(ACCOUNTS_FILE)) {
    return { id: 'access.token_age', severity: 'INFO', passed: true,
      passedMsg: 'agent-accounts.json not found — token age check skipped' };
  }

  let accounts;
  try {
    accounts = JSON.parse(readFileSync(ACCOUNTS_FILE, 'utf8'));
  } catch {
    return { id: 'access.token_age', severity: 'INFO', passed: true,
      passedMsg: 'agent-accounts.json could not be parsed — token age check skipped' };
  }

  const dateFields = findCredentialDates(accounts);
  if (!dateFields.length) {
    return { id: 'access.token_age', severity: 'INFO', passed: true,
      passedMsg: 'No date fields found in agent-accounts.json — token age check skipped' };
  }

  // Deduplicate by keyPath, keep earliest date
  const byPath = new Map();
  for (const { keyPath, date } of dateFields) {
    if (!byPath.has(keyPath) || date < byPath.get(keyPath)) {
      byPath.set(keyPath, date);
    }
  }

  const critical180 = [];
  const warn90 = [];

  for (const [keyPath, date] of byPath) {
    const days = ageInDays(date);
    if (days >= HIGH_DAYS) {
      critical180.push({ keyPath, days });
    } else if (days >= WARN_DAYS) {
      warn90.push({ keyPath, days });
    }
  }

  if (critical180.length) {
    const list = critical180.map(({ keyPath, days }) => `• ${keyPath} (${days} days old)`).join('\n');
    return {
      id: 'access.token_age',
      severity: 'HIGH',
      passed: false,
      title: `Credentials older than ${HIGH_DAYS} days detected`,
      description: `The following credential date fields indicate tokens/keys that have not been\nrotated in over ${HIGH_DAYS} days. Stale credentials increase exposure window if leaked.\n\n${list}`,
      fix: `Rotate these credentials at their respective service dashboards.\nThen update agent-accounts.json with new values and fresh dates.`,
    };
  }

  if (warn90.length) {
    const list = warn90.map(({ keyPath, days }) => `• ${keyPath} (${days} days old)`).join('\n');
    return {
      id: 'access.token_age',
      severity: 'MEDIUM',
      passed: false,
      title: `Credentials older than ${WARN_DAYS} days detected`,
      description: `The following credential date fields indicate tokens/keys not rotated in\nover ${WARN_DAYS} days. Consider rotating them proactively.\n\n${list}`,
      fix: `Rotate these credentials at their respective service dashboards.\nThen update agent-accounts.json with new values and fresh dates.`,
    };
  }

  return { id: 'access.token_age', severity: 'INFO', passed: true,
    passedMsg: `All credential date fields are within ${WARN_DAYS} days` };
}

export default [checkTokenAge];
