# ClawArmor

The security control plane for OpenClaw agents — audit, harden, and orchestrate your full protection stack.

[![npm version](https://img.shields.io/npm/v/clawarmor?color=3fb950&label=npm&style=flat-square)](https://www.npmjs.com/package/clawarmor)
[![license](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)
[![zero deps](https://img.shields.io/badge/deps-zero-green?style=flat-square)](package.json)

## What it does

AI agent security isn't one tool — it's a stack. ClawArmor is the foundation and control plane:

1. **Audits** your OpenClaw config and live gateway — 30+ checks, scored 0–100
2. **Hardens** your setup — auto-applies safe fixes, snapshots before every change
3. **Orchestrates** the full security stack — deploys and configures [Invariant Guardrails](https://github.com/invariantlabs-ai/invariant) and [IronCurtain](https://github.com/provos/ironcurtain) based on your audit results

```
clawarmor audit          → understand your risk (0–100 score)
clawarmor stack plan     → see what protection stack your risk profile needs
clawarmor stack deploy   → deploy it in one command
clawarmor stack sync     → keep everything aligned after changes
```

## Quick start

```bash
npm install -g clawarmor
clawarmor protect --install   # install guard hooks
clawarmor audit               # score your setup
clawarmor stack deploy --all  # deploy full protection stack
```

## The Stack

ClawArmor sits at the foundation and orchestrates the layers above it:

| Layer | Tool | What it does | ClawArmor role |
|---|---|---|---|
| **Foundation** | ClawArmor | Config hygiene, credential checks, skill supply chain | Audits + hardens |
| **Flow guardrails** | [Invariant](https://github.com/invariantlabs-ai/invariant) | Detects multi-step attack chains at runtime | Generates rules from audit findings |
| **Runtime sandbox** | [IronCurtain](https://github.com/provos/ironcurtain) | Policy-enforced tool call interception, V8 isolate | Generates constitution from audit findings |
| **Action gating** | [Latch](https://github.com/latchagent/latch) | Human approval for risky actions via Telegram | Coming in v3.2 |

`clawarmor stack deploy` reads your audit score, generates the right config for each tool, and deploys them. `clawarmor stack sync` keeps everything updated as your setup changes.

## Commands

### Core

| Command | Description |
|---|---|
| `audit` | Score your OpenClaw config (0–100), live gateway probes, plain-English verdict |
| `scan` | Scan all installed skill files for malicious code and SKILL.md instructions |
| `scan --json` | Machine-readable scan output — pipe to CI, scripts, or dashboards |
| `scan --report` | Write structured JSON + Markdown reports after scanning (v3.5.1) |
| `prescan <skill>` | Pre-scan a skill before installing — blocks on CRITICAL findings |
| `skill verify <name>` | Deep-verify a specific installed skill — checks SKILL.md + all referenced scripts |
| `fix` | Auto-apply safe fixes (--dry-run to preview, --apply to run) |
| `harden` | Interactive hardening wizard (--dry-run, --auto, --monitor, --report) |
| `status` | One-screen security posture dashboard |
| `verify` | Re-run only previously-failed checks (CI-friendly, exit 0 = all fixed) |

### Stack Orchestration

| Command | Description |
|---|---|
| `stack status` | Show all stack components, install state, config state |
| `stack plan` | Preview what would be deployed based on current audit (no changes) |
| `stack deploy` | Deploy stack components (--invariant, --ironcurtain, --all) |
| `stack sync` | Regenerate stack configs from latest audit — run after harden/fix |
| `stack teardown` | Remove deployed stack components |

### Invariant Deep Integration (v3.3.0)

| Command | Description |
|---|---|
| `invariant sync` | Generate severity-tiered Invariant policies from latest audit findings |
| `invariant sync --dry-run` | Preview policies without writing |
| `invariant sync --push` | Generate + validate + push to running Invariant instance |
| `invariant sync --json` | Machine-readable output for scripting |
| `invariant status` | Show current policy file and last sync report |

**Severity tiers:**
- `CRITICAL`/`HIGH` findings → `raise "..."` (hard enforcement — blocks trace)
- `MEDIUM` findings → `warn "..."` (monitoring/alerting — logged)
- `LOW`/`INFO` findings → `# comment` (informational only)

Policies are written to `~/.clawarmor/invariant-policies/clawarmor.inv`. With `--push`, ClawArmor validates the policy syntax via `invariant-ai` and live-reloads a running Invariant instance. If no instance is running, the policy is written to disk and enforces on next start.

```bash
pip3 install invariant-ai           # required for --push validation
clawarmor audit                     # run audit to capture findings
clawarmor invariant sync            # generate tiered policies
clawarmor invariant sync --push     # push to running Invariant instance
clawarmor invariant status          # check what's deployed
```

### History & Monitoring

| Command | Description |
|---|---|
| `trend` | ASCII chart of your security score over time |
| `compare` | Compare coverage vs openclaw security audit |
| `log` | View the audit event log |
| `digest` | Show weekly security digest |
| `watch` | Monitor config and skill changes in real time |
| `baseline save` | Save current scan results as baseline |
| `baseline diff` | Compare current scan against saved baseline — see what changed |
| `incident create` | Log a security incident with timestamp, findings, and remediation notes |
| `protect --install` | Install guard hook, shell intercept (zsh/bash/fish), and watch daemon |
| `snapshot` | Save a config snapshot manually (auto-saved before every harden/fix) |
| `rollback` | Restore config from auto-snapshot (--list, --id <id>) |

## What it catches

| Threat | Description | Coverage |
|---|---|---|
| Token/config exposure | File permission checks, config hardening | Full |
| Malicious skill supply chain | All skill files scanned — not just SKILL.md | Full |
| Credential hygiene | Token age, rotation reminders, access scope | Full |
| Config drift | Baseline hashing, change detection on every startup | Full |
| Obfuscation | Base64 blobs, dynamic eval, encoded payloads | Partial |
| Prompt injection via SKILL.md | Instruction patterns, exfil, deception, system overrides | Full |
| Live gateway auth | WebSocket probe — does server actually reject unauthenticated connections? | Full |
| CORS misconfiguration | OPTIONS probe with arbitrary origin | Full |
| Gateway exposure | TCP-connects to every non-loopback interface | Full |
| Multi-step attack chains | read→exfil, inject→execute flows (via Invariant) | Full (with stack) |
| Runtime tool call interception | Policy-enforced sandboxing (via IronCurtain) | Full (with stack) |

## Safety features

**Impact classification** — Every fix is tagged 🟢 Safe, 🟡 Caution, or 🔴 Breaking. `--auto` skips breaking changes unless you pass `--force`.

**Config snapshots** — Auto-saves before every `harden` or `fix` run:

```bash
clawarmor rollback --list    # see all snapshots
clawarmor rollback           # restore the latest
clawarmor rollback --id <n>  # restore a specific one
```

**Monitor mode** — Observe what `harden` would change before enforcing:

```bash
clawarmor harden --monitor        # start monitoring
clawarmor harden --monitor-report # see what it observed
clawarmor harden --monitor-off    # stop monitoring
```

**Hardening reports** (v3.4.0) — Export a structured report after hardening:

```bash
# Write JSON report to default location (~/.openclaw/clawarmor-harden-report-YYYY-MM-DD.json)
clawarmor harden --report

# Write JSON report to a custom path
clawarmor harden --report /path/to/report.json

# Write Markdown report (human-readable, shareable)
clawarmor harden --report /path/to/report.md --report-format text

# Combine with auto mode
clawarmor harden --auto --report
```

Report structure includes: version, timestamp, OS/OpenClaw info, summary counts (hardened/skipped/already-good), and per-check action details with before/after values.

**Scan reports** (v3.5.1) — Export a structured report after scanning skills:

```bash
# Write JSON + Markdown reports (e.g. ~/.openclaw/clawarmor-scan-report-2025-03-08.json + .md)
clawarmor scan --report
```

Two files are always written together:
- `clawarmor-scan-report-YYYY-MM-DD.json` — machine-readable, includes per-skill status, severity, findings, and overall score
- `clawarmor-scan-report-YYYY-MM-DD.md` — human-readable with executive summary table, findings detail, and remediation steps

Example JSON structure:
```json
{
  "version": "3.5.1",
  "timestamp": "2025-03-08T12:00:00.000Z",
  "system": { "hostname": "myhost", "platform": "darwin", "node_version": "v20.0.0", "openclaw_version": "1.2.0" },
  "verdict": "PASS",
  "score": 100,
  "summary": { "total": 12, "passed": 12, "failed": 0, "warnings": 0, "critical_findings": 0, "high_findings": 0 },
  "checks": [
    { "name": "weather", "status": "pass", "severity": "NONE", "detail": "No findings", "type": "user" }
  ]
}
```

Terminal output is still shown when `--report` is used — the flag only adds file output on top.

## Philosophy

ClawArmor runs entirely on your machine — no telemetry, no cloud, no accounts.
It has zero npm runtime dependencies, using only Node.js built-ins.
Every run prints exactly what files it reads and what network calls it makes before executing anything.

The full security stack for AI agents doesn't exist as one product. ClawArmor is the foundation that ties it together.

## License

MIT
