# ClawArmor

Security armor for OpenClaw agents — audit, scan, monitor.

[![npm version](https://img.shields.io/npm/v/clawarmor?color=3fb950&label=npm&style=flat-square)](https://www.npmjs.com/package/clawarmor)
[![license](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)
[![zero deps](https://img.shields.io/badge/deps-zero-green?style=flat-square)](package.json)

## What it does

- Audits your OpenClaw config and live gateway with 30+ checks — scored 0–100
- Scans every installed skill file for malicious code and prompt injection patterns
- Guards every install: intercepts `openclaw clawhub install`, pre-scans before activation

## Quick start

```bash
npm install -g clawarmor
clawarmor protect --install
clawarmor audit
```

## Commands

| Command | Description |
|---|---|
| `audit` | Score your OpenClaw config (0–100), live gateway probes, plain-English verdict |
| `scan` | Scan all installed skill files for malicious code and SKILL.md instructions |
| `prescan <skill>` | Pre-scan a skill before installing — blocks on CRITICAL findings |
| `protect --install` | Install guard hook, shell intercept (zsh/bash/fish), and watch daemon |
| `protect --uninstall` | Remove all ClawArmor protection components |
| `protect --status` | Show current protection state |
| `watch` | Monitor config and skill changes in real time |
| `watch --daemon` | Start the watcher as a background daemon |
| `harden` | Interactive hardening wizard (--dry-run, --auto) |
| `status` | One-screen security posture dashboard |
| `log` | View the audit event log |
| `digest` | Show weekly security digest |
| `verify` | Re-run only previously-failed checks (CI-friendly, exit 0 = all fixed) |
| `trend` | ASCII chart of your security score over time |
| `compare` | Compare coverage vs openclaw security audit |
| `fix` | Auto-apply safe fixes (--dry-run to preview, --apply to run) |
| `snapshot` | Save a config snapshot manually (auto-saved before every harden/fix) |
| `rollback` | Restore config from auto-snapshot (--list, --id <id>) |
| `harden --monitor` | Enable monitor mode — observe before enforcing |
| `harden --monitor-report` | Show what monitor mode has observed |
| `harden --monitor-off` | Disable monitor mode |

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
| Runtime policy enforcement | Requires a runtime layer (SupraWall) | None |

## Safety features

**Impact classification** — Every fix is tagged 🟢 Safe, 🟡 Caution, or 🔴 Breaking. `--auto` mode skips breaking changes unless you pass `--force`.

**Config snapshots** — ClawArmor auto-saves your config before every `harden` or `fix` run. If something breaks, roll back instantly:

```bash
clawarmor rollback --list    # see all snapshots
clawarmor rollback           # restore the latest
clawarmor rollback --id <n>  # restore a specific one
```

**Monitor mode** — Observe what `harden` would do before enforcing:

```bash
clawarmor harden --monitor        # start monitoring
clawarmor harden --monitor-report # see what it observed
clawarmor harden --monitor-off    # stop monitoring
```

## Philosophy

ClawArmor runs entirely on your machine — no telemetry, no cloud, no accounts.
It has zero npm runtime dependencies, using only Node.js built-ins.
Every run prints exactly what files it reads and what network calls it makes before executing anything.

## License

MIT
