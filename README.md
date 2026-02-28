# ClawArmor 🛡️

**Security armor for OpenClaw agents.**

ClawArmor is the only security tool that runs real code against your OpenClaw deployment — not an LLM prompt pretending to be a scanner.

```bash
npx clawarmor audit    # score your config 0-100, get exact fixes
npx clawarmor scan     # scan every skill file for malicious code
npx clawarmor monitor  # continuous monitoring (clawarmor.dev)
```

---

## What it does

### `clawarmor audit`
Reads your `~/.openclaw/openclaw.json` and scores your security posture from 0 to 100 across 12 checks:

| Severity | Check |
|---|---|
| CRITICAL | Gateway bind address (exposed to internet?) |
| CRITICAL | Tailscale Funnel without password auth |
| HIGH | Telegram DM policy open to anyone |
| HIGH | Agent sandbox isolation |
| HIGH | Credential file permissions (`agent-accounts.json`) |
| HIGH | Config file permissions (`openclaw.json`) |
| MEDIUM | Weak or default auth token |
| MEDIUM | Channel group policies |
| MEDIUM | OpenClaw version currency |
| MEDIUM | Elevated tools access |
| LOW | Thinking mode streaming |
| LOW | Filesystem workspace restriction |

Every finding includes the exact fix command. No guessing.

### `clawarmor scan`
Scans **all files** in every installed skill directory — `.js`, `.ts`, `.sh`, `.py`, `.rb` and more. Not just `SKILL.md`.

This is the gap every other security tool on ClawHub has. They scan markdown. We scan code.

Detects:
- `eval()` and `new Function()` — arbitrary code execution
- `child_process` imports — shell access
- `spawnSync`/`execSync` — shell command execution
- Pipe-to-shell patterns (`curl | bash`)
- Credential file reads (`agent-accounts.json`, `.env`)
- SSH key path references
- Known data exfiltration domains
- Large base64 blobs (obfuscated payloads)
- Dynamic `require()` (unanalyzable module loading)

### `clawarmor monitor`
Continuous external monitoring — we check your instance from outside your network and alert you before attackers find it. $9/month at [clawarmor.dev](https://clawarmor.dev).

---

## Installation

```bash
# Run directly (no install)
npx clawarmor audit

# Or install globally
npm install -g clawarmor
clawarmor audit
```

Requires Node.js 18+. Zero runtime dependencies.

---

## What makes this different

Every security skill on ClawHub (25+ of them) is an LLM prompt telling the model to think about security. ClawArmor runs actual code.

- **Real network probes** — not "please describe your config"
- **Real file scanning** — AST-level pattern detection across all skill files
- **Real scoring** — weighted 0-100 with letter grade
- **Real fixes** — exact commands, not generic advice
- **Zero network calls** — `audit` and `scan` are 100% local

---

## Threat coverage

| Threat | ClawArmor | Notes |
|---|---|---|
| T-ACCESS-003: Token theft | ✅ | `audit` checks file permissions + config exposure |
| T-PERSIST-001: Malicious skill | ✅ | `scan` catches code patterns across all skill files |
| T-IMPACT-002: API cost DoS | ✅ | `monitor` detects exposure before attackers do |
| T-EXEC-001/002: Prompt injection | — | Use [SupraWall](https://suprawall.io) for runtime policy |
| T-EXFIL-001: Data exfiltration | — | Runtime policy layer required |

---

## Privacy

`clawarmor audit` and `clawarmor scan` run entirely locally. They read your config and skill files on disk and print results to your terminal. Nothing is sent anywhere.

`clawarmor monitor` is an optional paid service. See [clawarmor.dev/privacy](https://clawarmor.dev/privacy).

---

## License

MIT — [clawarmor.dev](https://clawarmor.dev)
