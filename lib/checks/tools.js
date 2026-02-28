// Tool restriction checks: elevated tools, filesystem workspace
import { get } from '../config.js';

export function checkElevatedTools(config) {
  const elevated = get(config, 'tools.elevated', null);
  const allowFrom = get(config, 'tools.elevated.allowFrom', null);

  if (!elevated) {
    // No elevated tools configured — safe by default
    return {
      id: 'tools.elevated.allowFrom',
      severity: 'MEDIUM',
      passed: true,
      title: 'Elevated tools access',
      passedMsg: 'No elevated tools configured',
    };
  }

  // If elevated tools exist but allowFrom is not restricted
  const isRestricted =
    Array.isArray(allowFrom) && allowFrom.length > 0 ||
    typeof allowFrom === 'string' && allowFrom !== 'all' && allowFrom !== '*' && allowFrom !== '';

  if (!isRestricted) {
    return {
      id: 'tools.elevated.allowFrom',
      severity: 'MEDIUM',
      passed: false,
      title: 'Elevated tools available from untrusted sources',
      description: `tools.elevated.allowFrom is not restricted.\nElevated tools (those with broader system access) can be invoked\nby any channel or untrusted input source.`,
      fix: `openclaw config set tools.elevated.allowFrom [your-trusted-source-id]\nRestrict to specific channels or user IDs only.`,
    };
  }

  return {
    id: 'tools.elevated.allowFrom',
    severity: 'MEDIUM',
    passed: true,
    title: 'Elevated tools access',
    passedMsg: 'Elevated tools restricted to allowlist',
  };
}

export function checkWorkspaceOnly(config) {
  const workspaceOnly = get(config, 'tools.fs.workspaceOnly', null);

  if (workspaceOnly !== true) {
    return {
      id: 'tools.fs.workspaceOnly',
      severity: 'LOW',
      passed: false,
      title: 'Agent can read/write anywhere on filesystem',
      description: `tools.fs.workspaceOnly is not set to true.\nThe agent can read and write any file your user account can access,\nincluding SSH keys, credentials, and personal documents.`,
      fix: `openclaw config set tools.fs.workspaceOnly true\nThis restricts filesystem access to the configured workspace directory.`,
    };
  }

  return {
    id: 'tools.fs.workspaceOnly',
    severity: 'LOW',
    passed: true,
    title: 'Filesystem workspace restriction',
    passedMsg: 'Workspace filesystem restrictions enabled (tools.fs.workspaceOnly: true)',
  };
}

export default [checkElevatedTools, checkWorkspaceOnly];
