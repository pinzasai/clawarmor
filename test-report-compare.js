#!/usr/bin/env node
// Unit tests for report-compare diffReports logic
// Run: node test-report-compare.js

import assert from 'assert';
import { diffReports } from './lib/report-compare.js';

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (e) {
    console.log(`  ✗ ${name}`);
    console.log(`    ${e.message}`);
    failed++;
  }
}

const baseReport = (checks, score = 80) => ({
  version: '3.5.1',
  timestamp: '2026-03-01T10:00:00Z',
  score,
  checks,
});

console.log('\n  ClawArmor — diffReports unit tests\n');

// ── Regressions ──────────────────────────────────────────────────────────────

test('detects regression: PASS → WARN', () => {
  const r1 = baseReport([{ name: 'gateway', status: 'pass', severity: 'NONE', detail: '' }]);
  const r2 = baseReport([{ name: 'gateway', status: 'warn', severity: 'HIGH', detail: 'exposed' }]);
  const diff = diffReports(r1, r2);
  assert.strictEqual(diff.regressions.length, 1);
  assert.strictEqual(diff.regressions[0].id, 'gateway');
  assert.strictEqual(diff.regressions[0].oldStatus, 'pass');
  assert.strictEqual(diff.regressions[0].newStatus, 'warn');
});

test('detects regression: PASS → block (CRITICAL)', () => {
  const r1 = baseReport([{ name: 'auth', status: 'pass', severity: 'NONE', detail: '' }]);
  const r2 = baseReport([{ name: 'auth', status: 'block', severity: 'CRITICAL', detail: 'exposed token' }]);
  const diff = diffReports(r1, r2);
  assert.strictEqual(diff.regressions.length, 1);
  assert.strictEqual(diff.regressions[0].severity, 'CRITICAL');
});

// ── Improvements ────────────────────────────────────────────────────────────

test('detects improvement: WARN → PASS', () => {
  const r1 = baseReport([{ name: 'gateway', status: 'warn', severity: 'HIGH', detail: 'exposed' }]);
  const r2 = baseReport([{ name: 'gateway', status: 'pass', severity: 'NONE', detail: '' }]);
  const diff = diffReports(r1, r2);
  assert.strictEqual(diff.improvements.length, 1);
  assert.strictEqual(diff.improvements[0].id, 'gateway');
});

test('detects improvement: block → PASS', () => {
  const r1 = baseReport([{ name: 'auth', status: 'block', severity: 'CRITICAL', detail: '' }]);
  const r2 = baseReport([{ name: 'auth', status: 'pass', severity: 'NONE', detail: '' }]);
  const diff = diffReports(r1, r2);
  assert.strictEqual(diff.improvements.length, 1);
});

// ── New Issues ───────────────────────────────────────────────────────────────

test('detects new issues (check in file2 but not file1)', () => {
  const r1 = baseReport([{ name: 'old-check', status: 'pass', severity: 'NONE', detail: '' }]);
  const r2 = baseReport([
    { name: 'old-check', status: 'pass', severity: 'NONE', detail: '' },
    { name: 'new-check', status: 'warn', severity: 'HIGH', detail: 'new problem' },
  ]);
  const diff = diffReports(r1, r2);
  assert.strictEqual(diff.newIssues.length, 1);
  assert.strictEqual(diff.newIssues[0].id, 'new-check');
});

test('new passing checks are NOT in newIssues', () => {
  const r1 = baseReport([]);
  const r2 = baseReport([{ name: 'new-pass', status: 'pass', severity: 'NONE', detail: '' }]);
  const diff = diffReports(r1, r2);
  assert.strictEqual(diff.newIssues.length, 0);
});

// ── Resolved ─────────────────────────────────────────────────────────────────

test('detects resolved: failing check no longer in file2', () => {
  const r1 = baseReport([
    { name: 'old-issue', status: 'block', severity: 'CRITICAL', detail: 'bad' },
    { name: 'keep', status: 'pass', severity: 'NONE', detail: '' },
  ]);
  const r2 = baseReport([{ name: 'keep', status: 'pass', severity: 'NONE', detail: '' }]);
  const diff = diffReports(r1, r2);
  assert.strictEqual(diff.resolved.length, 1);
  assert.strictEqual(diff.resolved[0].id, 'old-issue');
});

// ── Unchanged ────────────────────────────────────────────────────────────────

test('unchanged count is correct', () => {
  const r1 = baseReport([
    { name: 'a', status: 'pass', severity: 'NONE', detail: '' },
    { name: 'b', status: 'warn', severity: 'HIGH', detail: '' },
  ]);
  const r2 = baseReport([
    { name: 'a', status: 'pass', severity: 'NONE', detail: '' },
    { name: 'b', status: 'warn', severity: 'HIGH', detail: 'same' },
  ]);
  const diff = diffReports(r1, r2);
  assert.strictEqual(diff.unchanged, 2);
  assert.strictEqual(diff.regressions.length, 0);
  assert.strictEqual(diff.improvements.length, 0);
});

// ── Score delta ──────────────────────────────────────────────────────────────

test('score delta is extracted', () => {
  const r1 = baseReport([], 72);
  const r2 = baseReport([], 85);
  const diff = diffReports(r1, r2);
  assert.strictEqual(diff.scoreOld, 72);
  assert.strictEqual(diff.scoreNew, 85);
});

test('score null when not in report', () => {
  const r1 = { version: '1.0', timestamp: '2026-01-01T00:00:00Z', items: [] };
  const r2 = { version: '1.0', timestamp: '2026-01-01T00:00:00Z', items: [] };
  const diff = diffReports(r1, r2);
  assert.strictEqual(diff.scoreOld, null);
  assert.strictEqual(diff.scoreNew, null);
});

// ── Harden report format ─────────────────────────────────────────────────────

test('handles harden report format (items[] instead of checks[])', () => {
  const r1 = {
    version: '3.5.0', timestamp: '2026-03-01T00:00:00Z',
    items: [{ check: 'cred-perms', status: 'already_good', action: 'Files are 600' }],
  };
  const r2 = {
    version: '3.5.1', timestamp: '2026-03-08T00:00:00Z',
    items: [{ check: 'cred-perms', status: 'failed', action: 'Could not fix' }],
  };
  const diff = diffReports(r1, r2);
  assert.strictEqual(diff.regressions.length, 1);
  assert.strictEqual(diff.regressions[0].id, 'cred-perms');
});

// ── Results ──────────────────────────────────────────────────────────────────

console.log('');
console.log(`  Results: ${passed} passed, ${failed} failed`);
console.log('');
if (failed > 0) process.exit(1);
