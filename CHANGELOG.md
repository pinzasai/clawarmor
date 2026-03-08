# Changelog

## [3.4.0] — 2026-03-08

### New Features

#### `clawarmor harden --report` — Structured Hardening Reports
Export a portable, structured summary of every hardening run — what was hardened, what was
skipped, why, and what was already good. The #1 feature gap for enterprise adoption.

**Flags:**
- `--report [path]` — Write JSON report (default: `~/.openclaw/clawarmor-harden-report-YYYY-MM-DD.json`)
- `--report-format text` — Write Markdown report instead of JSON

**JSON report structure:**
```json
{
  "version": "3.4.0",
  "timestamp": "...",
  "system": { "os": "...", "openclaw_version": "..." },
  "summary": { "total_checks": N, "hardened": N, "already_good": N, "skipped": N },
  "items": [
    { "check": "exec.ask.off", "status": "hardened", "before": "off", "after": "on-miss", "action": "..." },
    { "check": "gateway.host.open", "status": "skipped", "skipped_reason": "Breaking fix..." }
  ]
}
```

**Examples:**
```bash
clawarmor harden --report
clawarmor harden --report /tmp/my-report.json
clawarmor harden --report /tmp/report.md --report-format text
clawarmor harden --auto --report
```

Existing `clawarmor harden` behavior unchanged when `--report` is not passed.

---

## [3.3.0] — 2026-03-07

### New Features

#### `clawarmor invariant sync` — Invariant Deep Integration
The Invariant integration in v3.0 detected presence of `invariant-ai`. v3.3.0 does the real work:
it reads your latest audit findings and generates severity-tiered Invariant DSL policies that
actually enforce behavioral guardrails at runtime.

**Severity tiers:**
- `CRITICAL`/`HIGH` findings → `raise "..."` hard enforcement rules (blocks the trace)
- `MEDIUM` findings → `warn "..."` monitoring/alerting rules (logs but allows)
- `LOW`/`INFO` findings → `# informational` comments (guidance only)

**Policy mappings (finding → Invariant rule):**
| Finding type | Generated policy |
|---|---|
| `exec.ask=off` / unrestricted exec | `raise` on any `exec` tool call |
| Credential files world-readable | `raise` on `read_file` to sensitive paths (`.ssh`, `.aws`, `agent-accounts`, `.openclaw`) |
| Open channel policy (no `allowFrom`) | `raise`/`warn` on `read_file → send_message` without channel restriction |
| Elevated tool calls unrestricted | `raise`/`warn` on elevated calls with no `allowFrom_restricted` metadata |
| Skill supply chain / unpinned | `raise`/`warn` on tool calls lacking `skill_verified` or `skill_pinned` metadata |
| API key/secret in config files | `raise`/`warn` on `read_file` output containing secret patterns → `send_message` |
| Baseline: prompt injection | `raise` on web content → outbound message (always included) |

**New commands:**
```
clawarmor invariant sync                  # generate tiered policies from latest audit
clawarmor invariant sync --dry-run        # preview without writing
clawarmor invariant sync --push           # generate + validate + push to Invariant instance
clawarmor invariant sync --push --host <host> --port <port>
clawarmor invariant sync --json           # machine-readable output
clawarmor invariant status                # show current policy file + last sync report
```

**Policy output:**
- Policy file: `~/.clawarmor/invariant-policies/clawarmor.inv`
- Sync report: `~/.clawarmor/invariant-policies/sync-report.json`

**`--push` behavior:**
1. Validates policy syntax via `LocalPolicy.from_file()` (requires `pip3 install invariant-ai`)
2. If Invariant instance running on `localhost:8000` → live-reloads policy immediately
3. If not running → policy written to disk, enforces on next Invariant start

**Relationship to `clawarmor stack`:**
- `stack deploy/sync` generates basic `.inv` rules in `~/.clawarmor/invariant-rules.inv`
- `invariant sync` generates richer severity-tiered policies in `~/.clawarmor/invariant-policies/clawarmor.inv`
- They are complementary; `invariant sync` is the recommended path for serious deployments

---

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
