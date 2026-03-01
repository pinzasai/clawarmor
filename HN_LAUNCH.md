# HackerNews Launch Post — ClawArmor

## Title (pick one)
- "Show HN: ClawArmor – security auditor for OpenClaw agents with live gateway probes"
- "Show HN: I built a security tool for OpenClaw that actually connects to your gateway instead of just reading config files"

---

## Body

**Show HN: ClawArmor – security auditor for OpenClaw agents (live probes, not just config reads)**

Every OpenClaw security tool I found reads your config file and tells you if things look wrong. That's not enough.

Config says `bind: loopback`. Is your gateway *actually* not reachable on LAN? Config says `auth.mode: token`. Does the live WebSocket endpoint *actually* reject unauthenticated connections? I wanted a tool that checks both — and that's ClawArmor.

**What it does:**

`clawarmor audit` — 32 checks including 5 live behavioral probes:
- Tries to TCP-connect to your gateway on every non-loopback interface
- Sends a WebSocket handshake with no auth token and checks if the server rejects it
- GETs /health and checks if it leaks config data in the response body
- Sends a CORS OPTIONS request with `Origin: https://evil.example.com`
- All probes timeout at 2s, fail gracefully if gateway isn't running

`clawarmor scan` — scans installed skills for malicious code:
- All .js, .sh, .py, .ts files (not just SKILL.md markdown)
- Built-in skills capped at INFO severity (reviewed by OpenClaw team); user-installed get full severity
- SKILL.md natural language instruction scanning (credential read instructions, system prompt overrides, exfiltration instructions)

`clawarmor fix` — auto-applies safe fixes:
- `--dry-run` to preview what would change
- `--apply` to execute
- Shows which fixes need a gateway restart

`clawarmor verify` — re-runs only previously-failed checks. Exit 0 if all fixed (CI-friendly).

`clawarmor trend` — ASCII chart of score history.

**The background:**

Researchers found ~42,000 exposed OpenClaw instances in Jan–Feb 2026 (Bitsight, Maor Dayan). Most were exposed due to the default `0.0.0.0` bind behavior combined with reverse proxy misconfiguration. The existing `openclaw security audit` command reads config but doesn't probe live behavior. Someone with a misconfigured nginx in front could have `bind: loopback` in their config while the gateway is actually reachable via proxy headers.

**Tech:**

- Node.js built-ins only (net, http, os, fs, crypto) — zero runtime npm dependencies
- ESM, works on Node 18+
- The SKILL.md scanner exists because existing ClawHub security skills only scan the markdown file, not the .js scripts that skills actually run

```
npm install -g clawarmor
clawarmor audit
```

Source: https://github.com/pinzasai/clawarmor

Happy to answer questions about the probe implementation or the threat model.

---

## Tags
security, nodejs, openclaw, ai-agents, open-source

## Best time to post
Tuesday–Thursday 9am–11am Eastern (peak HN traffic)
