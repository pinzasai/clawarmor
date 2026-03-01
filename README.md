# ClawArmor 🛡️

**Security armor for OpenClaw agents.**

The only tool that checks both your OpenClaw config AND probes your live gateway behavior — so you know you're actually secure, not just configured correctly.

```bash
npm install -g clawarmor
clawarmor audit     # 32-check audit + live gateway probes, 0-100 score
clawarmor scan      # scan every skill file for malicious code
clawarmor fix       # auto-apply safe fixes
clawarmor verify    # re-check previously failed items (CI-friendly)
clawarmor trend     # score history chart
```

---

## What makes this different

Every other OpenClaw security tool reads your config file. ClawArmor also **connects to your running gateway** and verifies live behavior.

Config says `bind: loopback`. Is your gateway *actually* not reachable on LAN? Config says auth is enabled. Does the live WebSocket endpoint *actually* reject unauthenticated connections? Only behavioral probes can answer these.

---

## `clawarmor audit`

32 checks across two layers:

### Layer 1 — Live gateway probes (behavioral)

| Probe | What it checks |
|---|---|
| Port reachability | TCP-connects to gateway on every non-loopback interface |
| Auth enforcement | WebSocket handshake with no token — does server reject it? |
| Health endpoint leak | GET /health — does it expose config data in the response? |
| CORS misconfiguration | OPTIONS with `Origin: https://evil.example.com` |

### Layer 2 — Static config checks (32 total)

Gateway · Auth · File permissions · Channel policies · Tool restrictions · Sandbox · Plugins · Version · Browser SSRF · Webhooks · mDNS · Trust model · AllowFrom wildcards · Trusted proxies

Every finding includes:
- The attack scenario it enables
- The exact fix command
- Severity: CRITICAL / HIGH / MEDIUM / LOW / INFO

Score floors: 1 CRITICAL → max 50/100. 2+ CRITICAL → max 25/100.

```
  Security Score: 89/100  ┃  Grade: B
  ████████████████████░░  89%

  Verdict: Your instance is well-configured. Open items are low-risk hardening.
```

---

## `clawarmor scan`

Scans **all files** in every installed skill — `.js`, `.ts`, `.sh`, `.py`, `.rb` and SKILL.md. Not just markdown.

**Code patterns detected:**
- `eval()` and `new Function()` — arbitrary code execution
- `child_process` imports — shell access
- Credential file reads (`agent-accounts.json`, `.env`, SSH keys)
- Pipe-to-shell patterns (`curl | bash`)
- Known exfiltration domains
- Large base64 blobs (obfuscated payloads)
- Dynamic `require()` — unanalyzable at static analysis time

**SKILL.md instruction patterns detected:**
- Instructions to read credential files
- System prompt override attempts
- Data exfiltration instructions
- Persistent context injection
- Deception instructions (hide from user)
- Hardcoded IP fetch instructions

Context-aware severity: built-in skills capped at INFO (OpenClaw-team reviewed). User-installed skills get full severity.

---

## `clawarmor fix`

Auto-applies safe one-liner fixes from the last audit.

```bash
clawarmor fix --dry-run   # preview what would change
clawarmor fix --apply     # apply and report
```

Shows which fixes need a gateway restart. Unfixable items (Docker install, FileVault) listed separately.

---

## `clawarmor verify`

Re-runs only previously-failed checks. Exits 0 if all now pass — designed for CI pipelines.

```bash
clawarmor verify   # exit 0 = all fixed, exit 1 = still failing
```

---

## `clawarmor trend`

ASCII score chart across all previous audits, stored in `~/.clawarmor/history.json`.

---

## Installation

```bash
npm install -g clawarmor
clawarmor audit
```

Requires **Node.js 18+**. Zero runtime npm dependencies (Node.js built-ins only).

---

## Threat coverage

| Threat | ClawArmor | Notes |
|---|---|---|
| T-ACCESS-003: Token/config exposure | ✅ | `audit` — file permissions + config checks |
| T-PERSIST-001: Malicious skill supply chain | ✅ | `scan` — all skill files, not just SKILL.md |
| T-IMPACT-002: API cost DoS via exposure | ✅ | `audit` live probes detect local exposure |
| T-EXEC-001/002: Prompt injection | ❌ | Runtime policy layer — use SupraWall |
| T-EXFIL-001: Data exfiltration | ❌ | Runtime policy layer — use SupraWall |

---

## Privacy

`audit`, `scan`, `fix`, `verify`, and `trend` run entirely locally. One optional network call: `registry.npmjs.org` for version check (can be skipped with `--offline`).

`clawarmor monitor` — not yet implemented.

Every run prints what it reads and what network calls it makes before executing.

---

## License

MIT · [github.com/pinzasai/clawarmor](https://github.com/pinzasai/clawarmor)
