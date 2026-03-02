// lib/profiles.js — Contextual hardening profiles
// Profiles adjust harden/audit recommendations based on what the agent actually does.

const PROFILES = {
  coding: {
    name: 'coding',
    description: 'Code-focused agent — exec, file write, git are expected. External sends are restricted.',
    allowedCapabilities: ['exec', 'file.write', 'git', 'file.read'],
    restrictedCapabilities: ['external.send', 'external.network', 'channel.external'],
    checkWeightOverrides: {
      // exec being enabled is EXPECTED for a coding agent — downgrade severity
      'exec.ask.off': 'INFO',
      'exec.approval': 'INFO',
      // external sends from a coding agent are UNEXPECTED — upgrade severity
      'channel.groupPolicy': 'HIGH',
      'channel.allowFrom': 'HIGH',
    },
  },
  browsing: {
    name: 'browsing',
    description: 'Web browsing agent — fetch and read are expected. File writes and exec are restricted.',
    allowedCapabilities: ['fetch', 'file.read', 'web'],
    restrictedCapabilities: ['exec', 'file.write', 'channel.external'],
    checkWeightOverrides: {
      // file writes from a browsing agent are UNEXPECTED
      'filesystem.perms': 'HIGH',
      // exec from a browsing agent is UNEXPECTED
      'exec.ask.off': 'HIGH',
      'exec.approval': 'HIGH',
    },
  },
  messaging: {
    name: 'messaging',
    description: 'Messaging agent — channel access and send are expected. Exec and file access are restricted.',
    allowedCapabilities: ['channel.send', 'channel.read', 'message'],
    restrictedCapabilities: ['exec', 'file.write', 'file.read'],
    checkWeightOverrides: {
      // channel sends are EXPECTED for a messaging agent — downgrade severity
      'channel.groupPolicy': 'INFO',
      'channel.allowFrom': 'INFO',
      // exec from a messaging agent is UNEXPECTED
      'exec.ask.off': 'HIGH',
      'exec.approval': 'HIGH',
    },
  },
  general: {
    name: 'general',
    description: 'General-purpose agent — balanced defaults. No relaxations or extra restrictions.',
    allowedCapabilities: [],
    restrictedCapabilities: [],
    checkWeightOverrides: {},
  },
};

/**
 * Get a profile by name.
 * @param {string} name
 * @returns {object|null}
 */
export function getProfile(name) {
  return PROFILES[name] || null;
}

/**
 * List all available profiles.
 * @returns {object[]}
 */
export function listProfiles() {
  return Object.values(PROFILES);
}

/**
 * Auto-detect profile from openclaw config.
 * @param {object} config - parsed openclaw.json
 * @returns {{ profile: string, reasons: string[] }}
 */
export function detectProfile(config) {
  if (!config) return { profile: 'general', reasons: ['No config found — using general profile'] };

  const reasons = [];

  // Check for exec tools
  const execEnabled = config?.tools?.exec?.enabled !== false && config?.exec?.enabled !== false;
  const execAsk = config?.tools?.exec?.ask ?? config?.exec?.ask;
  const hasExec = execEnabled && execAsk !== 'always';

  // Check for web/fetch tools
  const hasWeb = !!(
    config?.tools?.fetch || config?.tools?.web ||
    (config?.skills && JSON.stringify(config.skills).toLowerCase().includes('browser'))
  );

  // Check for channel/messaging tools
  const hasChannels = !!(
    config?.channels || config?.messaging ||
    (config?.tools && JSON.stringify(config.tools).toLowerCase().includes('channel'))
  );

  // Check for git
  const hasGit = !!(
    config?.tools?.git ||
    (config?.skills && JSON.stringify(config.skills).toLowerCase().includes('git'))
  );

  // Decision logic
  if (hasExec && hasGit && !hasChannels) {
    reasons.push('exec tools present → coding agent');
    if (hasGit) reasons.push('git tools detected → coding profile');
    return { profile: 'coding', reasons };
  }

  if (hasChannels && !hasExec) {
    reasons.push('channel/messaging tools present → messaging agent');
    return { profile: 'messaging', reasons };
  }

  if (hasWeb && !hasExec && !hasChannels) {
    reasons.push('web/fetch tools present → browsing agent');
    return { profile: 'browsing', reasons };
  }

  reasons.push('No strong signal detected → using general profile');
  return { profile: 'general', reasons };
}

/**
 * Check if a finding is expected for a given profile.
 * @param {string} profileName
 * @param {string} checkId - the check/finding id
 * @returns {boolean}
 */
export function isExpectedFinding(profileName, checkId) {
  const profile = getProfile(profileName);
  if (!profile) return false;
  const id = (checkId || '').toLowerCase();
  // Check if this finding's id matches any allowed capability patterns
  // For exec findings in a coding profile, they're expected
  if (profileName === 'coding' && (id.includes('exec') && (id.includes('ask') || id.includes('approval')))) return true;
  if (profileName === 'messaging' && (id.includes('channel') && (id.includes('group') || id.includes('allow')))) return true;
  return false;
}

/**
 * Get overridden severity for a check in a given profile.
 * @param {string} profileName
 * @param {string} checkId
 * @param {string} defaultSeverity
 * @returns {string} overridden or original severity
 */
export function getOverriddenSeverity(profileName, checkId) {
  const profile = getProfile(profileName);
  if (!profile) return null;
  const id = (checkId || '').toLowerCase();
  // Check overrides by matching check id prefixes
  for (const [pattern, overrideSev] of Object.entries(profile.checkWeightOverrides)) {
    if (id.includes(pattern.toLowerCase())) return overrideSev;
  }
  return null;
}
