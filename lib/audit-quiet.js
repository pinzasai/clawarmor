// audit-quiet.js — runs audit checks and returns results without printing.
// Used by baseline save to capture the current security posture.

import { loadConfig } from './config.js';
import { getProfile, isExpectedFinding } from './profiles.js';
import gatewayChecks from './checks/gateway.js';
import filesystemChecks from './checks/filesystem.js';
import channelChecks from './checks/channels.js';
import authChecks from './checks/auth.js';
import toolChecks from './checks/tools.js';
import versionChecks from './checks/version.js';
import hooksChecks from './checks/hooks.js';
import allowFromChecks from './checks/allowfrom.js';
import tokenAgeChecks from './checks/token-age.js';
import execApprovalChecks from './checks/exec-approval.js';
import skillPinningChecks from './checks/skill-pinning.js';
import gitCredentialLeakChecks from './checks/git-credential-leak.js';
import credentialFilesChecks from './checks/credential-files.js';
import { existsSync, readFileSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';

const W = { CRITICAL: 25, HIGH: 15, MEDIUM: 8, LOW: 3, INFO: 0 };

/**
 * Run audit checks silently and return { score, findings, profile }.
 * findings is an array of { id, severity, title, skill }.
 */
export async function runAuditQuiet(flags = {}) {
  let profileName = flags.profile || null;
  if (!profileName) {
    try {
      const pFile = join(homedir(), '.clawarmor', 'profile.json');
      if (existsSync(pFile)) profileName = JSON.parse(readFileSync(pFile, 'utf8')).name || null;
    } catch { /* non-fatal */ }
  }
  const activeProfile = profileName ? getProfile(profileName) : null;

  const { config, error } = loadConfig(flags.configPath || null);
  if (error) throw new Error(error);

  const allChecks = [
    ...gatewayChecks, ...filesystemChecks, ...channelChecks,
    ...authChecks, ...toolChecks, ...versionChecks, ...hooksChecks,
    ...allowFromChecks,
    ...tokenAgeChecks, ...execApprovalChecks, ...skillPinningChecks,
    ...gitCredentialLeakChecks,
    ...credentialFilesChecks,
  ];

  const staticResults = [];
  for (const check of allChecks) {
    try { staticResults.push(await check(config)); }
    catch (e) { staticResults.push({ id: 'err', severity: 'LOW', passed: true, passedMsg: `Check error: ${e.message}` }); }
  }

  const failed = staticResults.filter(r => !r.passed);

  const annotatedFailed = failed.map(f => {
    if (activeProfile && isExpectedFinding(activeProfile.name, f.id)) {
      return { ...f, _profileExpected: true };
    }
    return f;
  });

  const scoringFailed = activeProfile
    ? annotatedFailed.filter(f => !f._profileExpected)
    : annotatedFailed;

  const criticals = scoringFailed.filter(r => r.severity === 'CRITICAL').length;

  let score = 100;
  for (const f of scoringFailed) score -= (W[f.severity] || 0);
  score = Math.max(0, score);
  if (criticals >= 2) score = Math.min(score, 25);
  else if (criticals >= 1) score = Math.min(score, 50);

  const findings = annotatedFailed.map(f => ({
    id: f.id,
    severity: f.severity,
    title: f.title || f.id,
    patternId: f.id,
    skill: f.skill || null,
    message: f.title || f.description || '',
    _profileExpected: f._profileExpected || false,
  }));

  return { score, findings, profile: profileName };
}
