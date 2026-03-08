# ClawArmor v3.4.0 Sprint Report
**Sprint:** `harden --report` feature
**Date:** 2026-03-08
**Status:** ✅ SHIPPED

---

## Summary

Shipped `clawarmor harden --report` — a portable hardening report command that exports a structured summary of every hardening run.

## Done Criteria

- [x] `clawarmor harden --report` runs and writes JSON report to `~/.openclaw/clawarmor-harden-report-YYYY-MM-DD.json`
- [x] `clawarmor harden --report /tmp/test.md --report-format text` writes Markdown report
- [x] `npm publish` succeeded — v3.4.0 live on npm
- [x] README updated with new `--report` flag and example output
- [x] Sprint report written to `~/clawarmor/sprint-output/v340-sprint-report.md`

---

## Changes Shipped

### `lib/harden.js`
- Added `--report` flag support via `flags.report`, `flags.reportPath`, `flags.reportFormat`
- Added `getSystemInfo()` — captures OS and OpenClaw version for report metadata
- Added `defaultReportPath(format)` — auto-generates path `~/.openclaw/clawarmor-harden-report-YYYY-MM-DD.{json|md}`
- Added `buildReportItems()` — assembles per-check items from applied/skipped/failed tracking
- Added `writeJsonReport()` — writes structured JSON with version, timestamp, system, summary, items
- Added `writeMarkdownReport()` — writes human-readable Markdown table with summary, actions, skipped, failed
- Added `printReportSummary()` — prints inline summary to stdout after writing the report
- Modified main loop to track `appliedIds`, `skippedIds`, `failedIds`, `applyResults` per fix
- Added `_reportBefore` and `_reportAfter` fields to each fix for before/after capture
- Existing behavior **fully preserved** when `--report` not passed

### `cli.js`
- Added `--report`, `--report-format`, `--report-path` flag parsing for `harden` command
- `--report` can be bare flag or `--report <path>` (path detected if next arg doesn't start with `--`)
- Version constant bumped: `3.3.0` → `3.4.0`

### `package.json`
- Version bumped to `3.4.0`

### `README.md`
- Updated harden command row to include `--report`
- Added new "Hardening reports (v3.4.0)" section with all usage examples

### `CHANGELOG.md`
- Added `[3.4.0]` entry with full feature description and examples

---

## Report Format: JSON

```json
{
  "version": "3.4.0",
  "timestamp": "2026-03-08T07:11:00.023Z",
  "system": {
    "os": "darwin 24.3.0",
    "openclaw_version": "2026.2.26"
  },
  "summary": {
    "total_checks": 3,
    "hardened": 1,
    "already_good": 0,
    "skipped": 2,
    "failed": 0
  },
  "items": [
    {
      "check": "exec.ask.off",
      "status": "hardened",
      "before": "off",
      "after": "on-miss",
      "action": "Enable exec approval for unrecognized commands"
    },
    {
      "check": "gateway.host.open",
      "status": "skipped",
      "skipped_reason": "Breaking fix — skipped in auto mode (use --auto --force to include)"
    }
  ]
}
```

## Report Format: Markdown

```markdown
# ClawArmor Hardening Report
Generated: 03/07/2026, 23:07
ClawArmor: v3.4.0 | OS: darwin 24.3.0 | OpenClaw: 2026.2.26

## Summary
- ✅ 0 checks already good
- 🔧 1 hardened
- ⚠️  2 skipped

## Actions Taken

| Check | Before | After | Action |
|-------|--------|-------|--------|
| exec.ask.off | off | on-miss | Enable exec approval... |

## Skipped

- **gateway.host.open**: Breaking fix — skipped in auto mode
```

---

## npm Publish

```
npm notice name: clawarmor
npm notice version: 3.4.0
npm notice total files: 67
+ clawarmor@3.4.0
```

Published with tag: `latest`
Registry: https://registry.npmjs.org/

---

## Git

- Commit: `d856232`
- Branch: `main`
- Pushed: `origin/main`
