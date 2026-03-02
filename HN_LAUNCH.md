# HackerNews Launch Post — ClawArmor v2.0

## Title options (pick one)
- "Show HN: ClawArmor v2.0 – security system for OpenClaw agents (not just a linter)"
- "Show HN: I turned an OpenClaw config auditor into a security system that watches, intercepts, and hardens automatically"
- "Show HN: ClawArmor – goes from Grade D to A+ in one command for your AI agent"

---

## Body

**Show HN: ClawArmor v2.0 — security system for OpenClaw agents**

I built ClawArmor v1 a few weeks ago as a config linter for OpenClaw agents. People used it but the problem was obvious: you run it, get a score, nothing happens until you run it again. That's a questionnaire, not security.

v2.0 changes the model. It watches. It intercepts. It hardens automatically.

**Three layers, one install command:**

```bash
npm install -g clawarmor
clawarmor protect --install
```

That one command installs:

1. **clawarmor-guard** — an OpenClaw hook that fires on every gateway startup, runs a silent audit, alerts via your agent if the score drops or a critical issue appears
2. **clawarmor watch** — a lightweight fs.watch daemon (Node built-in, zero deps) on `~/.openclaw/` that re-audits on config changes and alerts on regressions in real time
3. **clawhub-intercept** — a shell function that wraps `openclaw clawhub install` to scan skills from ClawHub *before* they're activated. Blocks CRITICAL findings.

**New commands in v2.0:**

`clawarmor prescan <skill>` — downloads and scans a skill before you install it. Resolves local OpenClaw built-ins first, falls back to npm registry.

`clawarmor harden` — auto-fix engine. Three modes:
- `--dry-run`: shows what would change, no writes
- interactive (default): confirms each fix before applying
- `--auto`: applies all safe fixes for CI/scripts

`clawarmor status` — one-screen dashboard: posture grade, watcher state, intercept state, audit log count, credential age, next digest date.

`clawarmor digest` — weekly security summary delivered via your agent's own channels. No network calls. Local data only.

`clawarmor log` — JSONL audit trail of every run, every finding, every trigger.

**The threat model:**

Based on the MITRE ATLAS framework applied to OpenClaw. v1 covered 4 of 18 documented attack vectors. v2.0 covers 14. The three I care most about:

- **T-PERSIST-001** (malicious skill install) — Critical/P0. ClawHub moderation only checks slug/displayName/summary metadata with regex. It does NOT analyze skill code. clawhub-intercept + prescan fills this gap.
- **T-ACCESS-003** (token theft) — credential file permissions, age tracking (>90d WARN, >180d HIGH), git history scan for committed secrets
- **T-PERSIST-003** (config tampering) — config integrity hashing from v1 + real-time watch daemon in v2

**Running it on my own machine right now:**

```
Security Score: 50/100  Grade: D
```

Three real findings: world-readable credential files, API key patterns in ~/.openclaw/ JSON files, exec approval not configured. Zero false positives — tested against 52 built-in OpenClaw skills.

**Tech:**

- Node.js built-ins only — `fs`, `net`, `http`, `crypto`, `child_process`. Zero runtime npm dependencies.
- ESM, Node 18+
- All analysis is local. No telemetry. No phone home. The only external call is `prescan` downloading the skill you were about to install anyway.

```bash
npm install -g clawarmor
clawarmor audit              # see your score + grade
clawarmor harden             # fix what's fixable
clawarmor protect --install  # activate always-on protection
```

Source: https://github.com/pinzasai/clawarmor

Happy to answer questions about the threat model or the intercept architecture.

---

## Notes for Alberto before posting
- "50/100 Grade D on my own machine" is honest and good — shows it actually finds things
- Title 1 or 2 recommended over 3 (3 reads as marketing)
- Timing: Sunday afternoon HN is low traffic — Monday morning PST gets more eyes
- After posting: reply to every comment in first 2 hours (velocity matters for front page)
