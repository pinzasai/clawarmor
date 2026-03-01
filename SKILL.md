# ClawArmor

Security armor for your OpenClaw agent. Audits your config, probes your live gateway, and scans installed skills for threats.

## When to use this skill

Call `clawarmor` when you want to:
- Check if your OpenClaw instance is securely configured
- Verify your live gateway actually requires authentication (not just config)
- Scan installed skills for malicious code or dangerous instructions
- Auto-fix common misconfigurations
- Track your security score over time

## Commands

### Audit (most important — run this first)
```
Run: clawarmor audit
```
Performs 32 security checks including live behavioral probes of the running gateway. Returns a 0-100 score, letter grade, plain-English verdict, and specific findings with fix commands.

### Scan installed skills
```
Run: clawarmor scan
```
Scans all installed skill files (.js, .sh, .py, .ts, SKILL.md) for malicious patterns: credential theft, RCE, exfiltration, prompt injection.

### Auto-fix safe issues
```
Run: clawarmor fix --dry-run   # preview what would change
Run: clawarmor fix --apply     # apply safe one-liner fixes
```

### Verify fixes worked
```
Run: clawarmor verify
```
Re-runs only previously-failed checks. Exits 0 if all now pass.

### Track score over time
```
Run: clawarmor trend
```
Shows ASCII chart of score history across all previous audits.

## What it checks

**Live gateway probes** (behavioral — not just config reads):
- Is the gateway port actually open on non-loopback network interfaces?
- Does the live WebSocket endpoint reject connections without an auth token?
- Does the /health endpoint leak sensitive config data?
- Are CORS headers misconfigured to allow arbitrary origins?

**Config audit** (32 static checks):
- Gateway bind address, auth mode, token strength
- File permissions on ~/.openclaw/, openclaw.json, agent-accounts.json, credentials/
- Channel allowFrom policies — allowlist enforcement, wildcard detection
- Tool restrictions — filesystem scope, apply_patch scope, elevated tools
- Sandbox isolation configuration
- Plugin allowlist enforcement
- OpenClaw version currency
- Browser SSRF policy
- Webhook security
- mDNS exposure mode
- Multi-user trust model vs sandbox isolation

**Skill supply chain scan**:
- Malicious code patterns in .js, .sh, .py, .ts skill scripts
- Dangerous natural language instructions in SKILL.md files
- Context-aware severity: built-in skills capped at INFO, user-installed get full severity

## Installation

```
npm install -g clawarmor
```

Zero runtime dependencies. Node.js 18+ required. Local only — nothing sent to external servers except one version check to registry.npmjs.org.

Source and full documentation: https://github.com/pinzasai/clawarmor

## Notes

- Run `clawarmor audit` after any config change to verify your security posture
- The `verify` command is CI-friendly (exit codes: 0 = all fixed, 1 = still failing)
- Score history is stored at `~/.clawarmor/history.json`
- This skill does NOT replace runtime policy enforcement (see SupraWall for that)
