# ClawArmor — Build Brief
**Product:** Security armor for OpenClaw agents
**Domain:** clawarmor.dev
**Repo:** ~/clawarmor/
**Stack:** Node.js ESM, zero runtime dependencies (dev deps ok), ships as npm CLI

---

## What ClawArmor Is

Three commands, one product:

```bash
npx clawarmor audit    # score your OpenClaw config (free, local, zero network)
npx clawarmor scan     # scan installed skills for malicious code (free, local)
npx clawarmor monitor  # continuous monitoring daemon (paid tier, $9/mo)
```

This is a security tool for OpenClaw users. OpenClaw is an AI agent platform (~42k instances, many exposed to internet without auth). ClawArmor finds and fixes those misconfigs.

---

## `/deepen-plan` — Read This Before Writing a Line of Code

Before implementing, reason through the full architecture:

1. **What are all the checks `clawarmor audit` needs to do?** Think through every OpenClaw config key that could be dangerous. Don't just implement the obvious ones.

2. **What should a "security score" actually measure?** Think about weighting — a misconfigured gateway bind is more dangerous than a missing file permission. Design the scoring system to reflect real risk, not just a count of issues.

3. **How should `clawarmor scan` work?** It needs to scan ALL files in installed skill directories — not just SKILL.md (that's the gap in every existing tool). Think about what patterns to look for in .js, .sh, .py files.

4. **What does the output look like?** This is a developer tool. The output should be beautiful, scannable, actionable. Think about color coding, grouping by severity, exact fix commands. Study how tools like `eslint`, `npm audit`, and `trivy` format their output.

5. **What's the architecture?** Think about: single entry CLI → subcommand routing → each subcommand is a module → shared utilities (scoring, output formatting, config reading). Don't make a monolith.

Think deeply about each of these before implementing.

---

## `clawarmor audit` — The Config Linter

Reads `~/.openclaw/openclaw.json` and scores it 0-100.

### Checks to implement (all 12, in order of severity):

**CRITICAL (each costs -25 points):**
1. `gateway.bind` is `0.0.0.0` or not `loopback` → "Your gateway is exposed to the network"
2. Tailscale Funnel enabled (`tailscale.mode: funnel`) AND `auth.mode` is NOT `password` → "Funnel is on but no password set — anyone on the internet can connect"

**HIGH (each costs -15 points):**
3. `channels.telegram.dmPolicy` is `open` (not `pairing`) AND no `allowFrom` set → "Telegram DMs are open to anyone"
4. `agents.defaults.sandbox` not set to `non-main` or `all` for channel sessions → "Agent sessions have no sandbox isolation"
5. `~/.openclaw/agent-accounts.json` exists but permissions are not 600 → "Credential file is world-readable"
6. `~/.openclaw/openclaw.json` permissions are not 600 → "Config file with tokens is world-readable"

**MEDIUM (each costs -10 points):**
7. `gateway.auth.mode` is `token` but token is the default/example token pattern → "You may be using a weak or default auth token"
8. Any channel `groupPolicy` is `open` (not `allowlist`) → "Telegram/Discord groups allow anyone to message your agent"
9. OpenClaw version is not current (check npm registry for latest) → "Running outdated version — may have known vulnerabilities"
10. `tools.elevated.allowFrom` is not restricted → "Elevated tools available from untrusted sources"

**LOW (each costs -5 points):**
11. `agents.defaults.thinkingDefault` is `on` with `stream` — minor info leak risk
12. No `tools.fs.workspaceOnly: true` set → "Agent can read/write anywhere on filesystem"

### Scoring:
- Start at 100
- Deduct per finding
- Floor at 0
- Display as: score + letter grade (A=90+, B=75+, C=60+, D=40+, F=below 40)

### Output format (study this carefully):

```
╔═══════════════════════════════════════╗
║        ClawArmor Audit Report         ║
╚═══════════════════════════════════════╝

  Config: ~/.openclaw/openclaw.json
  Scanned: Fri Feb 27 2026, 5:04 PM PST

  Security Score: 42/100  ┃  Grade: D
  ████████░░░░░░░░░░░░  42%

──────────────────────────────────────────
  CRITICAL  (2 findings)
──────────────────────────────────────────

  ✗ Gateway exposed to network
    gateway.bind is "0.0.0.0" — your OpenClaw control port
    is reachable by anyone on your network or the internet.
    
    Fix: Set "bind": "loopback" in your openclaw.json
         then run: openclaw gateway restart

  ✗ Tailscale Funnel without authentication  
    tailscale.mode is "funnel" but auth.mode is not "password".
    Anyone with your Tailscale URL can access your agent.
    
    Fix: openclaw config set gateway.auth.mode password

──────────────────────────────────────────
  HIGH  (1 finding)
──────────────────────────────────────────

  ✗ Credential file is world-readable
    ~/.openclaw/agent-accounts.json has permissions 644.
    Any user on this system can read your API keys.
    
    Fix: chmod 600 ~/.openclaw/agent-accounts.json

──────────────────────────────────────────
  PASSED  (9 checks)
──────────────────────────────────────────

  ✓ DM policy uses pairing (secure)
  ✓ Workspace filesystem restrictions enabled
  ✓ Telegram groups use allowlist
  ... (show all passing checks)

──────────────────────────────────────────

  Run clawarmor scan to check installed skills.
  Continuous monitoring: clawarmor.dev/monitor
```

---

## `clawarmor scan` — Skill Scanner

Scans all installed OpenClaw skills for malicious code patterns.

Installed skills are in: `~/.openclaw/skills/` or wherever OpenClaw installs them (check both `~/.openclaw/` and the workspace skills directory).

### What to scan:
- ALL text files in each skill directory (.js, .ts, .mjs, .sh, .bash, .py, .rb)
- Also SKILL.md (for dangerous instructions to the agent)
- IGNORE: node_modules/, .git/, *.lock files, binary files

### Detection patterns (implement all):

**CRITICAL patterns:**
- `eval(` in JS/TS (code execution)
- `new Function(` in JS/TS
- `child_process` require/import
- `execSync|exec|spawn|spawnSync` calls
- `curl.*\|.*sh|wget.*\|.*sh` (pipe to shell)
- Outbound `fetch`/`axios` to non-standard IPs (hardcoded IPs that aren't localhost)
- Base64 strings > 100 chars that decode to suspicious content
- `process.env` access combined with network calls (credential exfil pattern)

**HIGH patterns:**
- `fs.readFile.*agent-accounts|credentials|\.env` (reading credential files)
- `require\(.*variable` (dynamic require — can't be statically analyzed)
- Known malicious domains (maintain a list: webhook.site, requestbin.com, etc.)
- SSH key paths in strings (`.ssh/id_rsa`, etc.)

**MEDIUM patterns:**
- Any `http://` (not https) outbound calls
- Hardcoded IP addresses in network calls
- `setTimeout` with encoded callbacks (evasion technique)
- Obfuscated variable names combined with network activity

### Whitelist (don't flag these):
- `api.anthropic.com`, `api.openai.com`, `api.github.com`
- `registry.npmjs.org`, `raw.githubusercontent.com`
- `127.0.0.1`, `localhost`, `::1`

### Output format:
Similar to audit but per-skill. Show skill name, finding, file, line number, the actual suspicious code snippet (redacted if needed).

---

## `clawarmor monitor` (stub for v0.1)

For now, just print:
```
ClawArmor Monitor — Continuous Protection

  Monitors your OpenClaw instance 24/7 and alerts you
  when your security posture changes.

  • External exposure detection (we check from outside)
  • Daily security score reports
  • Instant Telegram/Signal alerts
  • Skill supply chain monitoring

  Pricing: $9/month

  Get started: clawarmor.dev/monitor
```

We'll build the actual daemon later. For now the stub is fine.

---

## Technical Requirements

### Architecture:
```
~/clawarmor/
  cli.js              ← entry point, subcommand router
  lib/
    audit.js          ← clawarmor audit logic
    scan.js           ← clawarmor scan logic  
    monitor.js        ← clawarmor monitor (stub)
    config.js         ← reads openclaw.json, resolves paths
    checks/
      gateway.js      ← gateway-related checks
      auth.js         ← auth/credential checks
      channels.js     ← channel policy checks
      filesystem.js   ← file permission checks
      version.js      ← version currency check
    scanner/
      patterns.js     ← malicious pattern definitions
      file-scanner.js ← scans individual files
      skill-finder.js ← finds installed skill directories
    output/
      formatter.js    ← beautiful terminal output
      colors.js       ← ANSI color utilities (no deps)
      progress.js     ← progress indicators
  package.json
  README.md
  SECURITY.md         ← our own security policy + ethics statement
```

### Rules:
- Zero runtime npm dependencies (use Node.js built-ins only: fs, path, crypto, os, child_process, net)
- Node 18+ required (use native fetch, no node-fetch)
- ESM modules (type: module in package.json)
- Graceful degradation: if config file not found, explain clearly
- Never send data anywhere — audit and scan are 100% local
- Never store or log anything the user didn't ask us to store
- Exit codes: 0 = all clear, 1 = findings found, 2 = error

### Quality bar:
- Works on macOS and Linux
- Handles missing files gracefully (config not found, no skills installed, etc.)
- Fast: audit should complete in < 500ms, scan in < 5s for typical installs
- The output must be genuinely beautiful — use box-drawing characters, color, progress bars
- Every finding must include: what it is, why it matters, exact fix command

---

## What Makes This Different From Everything Else on ClawHub

Every other security skill on ClawHub (25+ of them) is an LLM prompt telling the agent to think about security. ClawArmor runs real code. The `scan` command is the first tool that scans ALL skill files (not just SKILL.md) — every existing scanner explicitly says it only scans markdown.

Make it feel like that. Make it feel like a real security tool, not a wrapper around an LLM.

---

## When Done

1. `npm install -g .` should work from the ~/clawarmor/ directory
2. `clawarmor audit` should run against the actual openclaw.json on this machine
3. `clawarmor scan` should find and scan skills in the actual openclaw install
4. All output should be polished and production-ready
5. README.md should be excellent — explain what it does, why it's different, how to install
6. SECURITY.md should explain our ethics: what we scan, what we don't, what we send (nothing)

When completely finished, run this command to notify:
openclaw system event --text "ClawArmor v0.1 build complete — audit + scan + monitor stub ready" --mode now
