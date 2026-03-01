<div align="center">

# 🛡 ClawArmor

**The security auditor for OpenClaw agents.**

Checks your config. Probes your live gateway. Scans your skills.  
Runs in 30 seconds. Finds what config-only tools miss. Free forever.

[![npm version](https://img.shields.io/npm/v/clawarmor?color=3fb950&label=npm&style=flat-square)](https://www.npmjs.com/package/clawarmor)
[![license](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)
[![node](https://img.shields.io/badge/node-%3E%3D18-green?style=flat-square)](package.json)

```bash
npm install -g clawarmor && clawarmor audit
```

</div>

---

```
  ℹ  Reads: ~/.openclaw/openclaw.json + file permissions only
     Network: registry.npmjs.org (version check) + 127.0.0.1:18789 (live probes)
     Sends nothing. Source: github.com/pinzasai/clawarmor

  ── LIVE GATEWAY PROBES  (connecting to 127.0.0.1) ──
  ✓ Gateway running on port 18789
  ✓ Not reachable on network interfaces (probed live)
  ✓ Authentication required (WebSocket probe confirmed)
  ✓ /health endpoint does not leak sensitive data
  ✓ CORS not open to arbitrary origins

  Security Score: 100/100  ┃  Grade: A
  ████████████████████  100%

  Verdict: Your instance is secure. No issues found.

  ── PASSED (30 checks) ──────────────────────────────
  ✓ Gateway bound to loopback only
  ✓ Auth token is strong
  ✓ Agent sandbox mode: "non-main" (sessions isolated)
  ✓ Browser SSRF to private networks blocked
  ✓ All channel allowFrom settings are restricted
  ... 25 more
```

---

## Why ClawArmor

Every other OpenClaw security tool reads your config file and tells you if things look right on paper.

**ClawArmor also connects to your running gateway and verifies live behavior.**

Config says `bind: loopback`. Is your gateway *actually* unreachable on LAN? Config says auth is enabled. Does the live WebSocket endpoint *actually* reject unauthenticated connections? A misconfigured nginx in front can make your config lie. Live probes can't be faked.

---

## Five commands

```bash
clawarmor audit     # 30 checks + 5 live gateway probes. Score 0-100. Plain-English verdict.
clawarmor scan      # Scan every skill file (.js .sh .py .ts SKILL.md) for malicious code.
clawarmor fix       # Auto-apply safe fixes. --dry-run to preview, --apply to execute.
clawarmor verify    # Re-run only previously-failed checks. Exit 0 if all fixed (CI-friendly).
clawarmor trend     # ASCII chart of your security score over time.
```

---

## What it checks

### Live gateway probes (behavioral — not just config reads)

| Probe | What it checks |
|---|---|
| Port reachability | TCP-connects to gateway on every non-loopback interface |
| Auth enforcement | WebSocket handshake without token — does server reject it? |
| Health endpoint | GET /health — does response contain config data or secrets? |
| CORS headers | OPTIONS with `Origin: https://evil.example.com` |

These probes are **read-only and non-destructive**. They observe — they don't modify anything.

### Config audit (30 checks)

Gateway bind · auth mode · token strength · dangerous flags · mDNS exposure · real-IP fallback · trusted proxy config · file permissions (`~/.openclaw/`, `openclaw.json`, `agent-accounts.json`, `credentials/`) · channel allowFrom policies · wildcard detection · group policies · elevated tools · exec sandbox · tool restrictions (filesystem scope, apply_patch scope) · browser SSRF policy · plugin allowlist · log redaction · version currency · webhook security · multi-user trust model

### Skill supply chain scan

Scans **all files** in every installed skill — `.js`, `.ts`, `.sh`, `.py`, `.rb` and `SKILL.md`. Not just markdown.

**Code patterns:** `eval()`, `new Function()`, `child_process`, credential file reads, pipe-to-shell, known exfil domains, large base64 blobs, dynamic `require()`

**SKILL.md instruction patterns:** credential read instructions, system prompt overrides, exfiltration instructions, deception instructions, hardcoded IP fetches

> **Honest limitation:** The scanner catches unsophisticated threats and common patterns. Obfuscated code (string concatenation, encoded payloads) can bypass static analysis. Treat a clean scan as a good signal, not a guarantee.

---

## What it protects against

| Threat | Covered | Notes |
|---|---|---|
| T-ACCESS-003: Token/config exposure | ✅ | File permission checks + config hardening |
| T-PERSIST-001: Malicious skill supply chain | ✅ | All skill files scanned, not just SKILL.md |
| T-EXEC-001/002: Prompt injection | ❌ | Runtime policy layer — use [SupraWall](https://suprawall.io) |
| T-EXFIL-001: Data exfiltration | ❌ | Runtime policy layer — use SupraWall |

ClawArmor hardens your configuration and detects supply chain threats. It does not provide runtime policy enforcement — that's a different layer.

---

## Auto-fix

```bash
clawarmor fix --dry-run   # preview what would change
clawarmor fix --apply     # apply safe one-liner fixes + gateway restart instructions
```

Sandbox isolation is enabled safely: if Docker is installed, `fix --apply` sets `sandbox.mode=non-main` + `workspaceAccess=rw` so your Telegram/group sessions keep workspace access.

---

## CI integration

```bash
# Fail CI if security score drops
clawarmor verify   # exit 0 = all previously-failed checks now pass
                   # exit 1 = still failing
```

Score history persists in `~/.clawarmor/history.json`.

---

## Privacy & security

- `audit`, `scan`, `fix`, `verify`, `trend` run **entirely locally**
- One optional network call: `registry.npmjs.org` for version check (skippable with `--offline`)
- Every run prints exactly what files it reads and what network calls it makes before executing
- Nothing is sent anywhere

**Found a vulnerability in ClawArmor itself?** Please email `pinzasrojas@proton.me` before public disclosure.

---

## Installation

```bash
npm install -g clawarmor   # requires Node.js 18+
clawarmor audit
```

Zero runtime npm dependencies. Node.js built-ins only (`net`, `http`, `os`, `fs`, `crypto`).

---

## License

MIT — see [LICENSE](LICENSE)
