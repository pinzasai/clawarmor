# Changelog

## [3.2.0] — 2026-03-03

### New Features

#### `clawarmor scan --json`
- Added `--json` flag to `clawarmor scan`
- Outputs a clean JSON object to stdout with: `verdict` (PASS/WARN/BLOCK), `score`, `totalSkills`, `flaggedSkills`, `findings[]`, `scannedAt`
- Verdict rules: BLOCK if any CRITICAL findings, WARN if any HIGH findings, PASS otherwise
- Designed for scripting and CI/CD integration (pipe to `jq`, parse in shell scripts)

#### `clawarmor baseline` command
- New command: `clawarmor baseline save [--name <label>]` — saves current audit result as a named baseline to `~/.openclaw/workspace/memory/clawarmor-baselines/`
- `clawarmor baseline list` — lists all saved baselines with date and score
- `clawarmor baseline diff [--from <label>] [--to <label>]` — diffs two baselines showing score delta, new findings, and resolved findings
- Enables tracking security posture over time and catching regressions after skill installs

#### `clawarmor incident` command
- New command: `clawarmor incident create --finding <description> --severity <CRITICAL|HIGH|MEDIUM> [--action <quarantine|rollback|notify>]`
- Creates a structured markdown incident log at `~/.openclaw/workspace/memory/incidents/YYYY-MM-DD-<slug>.md`
- `--action rollback` automatically triggers config rollback via existing snapshot system
- `clawarmor incident list` — lists all logged incidents with date and severity

#### `clawarmor skill verify <skill-dir>`
- New command that validates a skill directory against ClawGear publishing standards
- Checks: SKILL.md presence, no hardcoded credentials, no obfuscation, permissions declared if exec used, no fetches to unknown hosts, description in frontmatter
- Exit codes: 0=VERIFIED, 1=WARN, 2=BLOCK
- Human-readable output with emoji status per check

### ClawGear Security Skills
- Added 4 security skill SKILL.md files in `clawgear-skills/`:
  - `clawarmor-live-monitor` — heartbeat monitoring with Telegram alerts on score drops
  - `skill-security-scanner` — pre-install gate for skills using `scan --json`
  - `hardened-operator-baseline` — 3-command full hardening sequence
  - `incident-response-playbook` — automated incident response with rollback + alerting

---

## [3.1.0] — 2026-02-XX

- Stack honesty fix + post-install audit + contextual profiles

## [3.0.1] — 2026-02-XX

- README rewrite — control plane positioning, stack orchestration docs

## [3.0.0] — 2026-02-XX

- Stack orchestrator — Invariant + IronCurtain integration

## [2.2.1] — 2026-01-XX

- Fix npm bloat (6.2MB→273KB), clean up README with v2.2 features

## [2.2.0] — 2026-01-XX

- Config snapshots + rollback, monitor mode for harden
