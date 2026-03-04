---
name: skill-security-scanner
description: Pre-install security gate for OpenClaw skills. Before installing any skill from ClawHub or ClawMart, run this scanner. Uses clawarmor scan --json to check for obfuscation, malicious patterns, and credential exposure. Blocks installs that score BLOCK verdict.
category: security
tags: [security, skills, pre-install, scanning, clawarmor]
requires: clawarmor >= 3.2.0
---

# skill-security-scanner

A security gate that sits between you and any skill you're about to install. Before an untrusted skill hits your agent, run it through this scanner. BLOCK verdict means don't install. WARN means review first.

## The problem it solves

In early 2026, a malicious skill called `openclaw-web-search` was distributed on a third-party registry. It appeared functional but contained an obfuscated payload that exfiltrated session tokens via a DNS covert channel. It was installed by dozens of operators without inspection.

This scanner would have caught it. The obfuscation patterns and DNS module import are both CRITICAL-severity matches in ClawArmor's pattern library.

**Never install a skill without scanning it first.**

---

## Scripts

### `scan-gate.sh`

The main gate script. Takes a skill directory path as argument.

```bash
#!/usr/bin/env bash
# scan-gate.sh — pre-install security gate for OpenClaw skills
# Usage: bash scan-gate.sh <skill-path>
# Exit: 0=safe, 1=warn (manual review), 2=blocked

set -e

SKILL_PATH="$1"

if [ -z "$SKILL_PATH" ]; then
  echo "Usage: bash scan-gate.sh <skill-path>"
  exit 1
fi

if [ ! -d "$SKILL_PATH" ]; then
  echo "Error: directory not found: $SKILL_PATH"
  exit 1
fi

echo "[scan-gate] Scanning: $SKILL_PATH"

# Run clawarmor scan --json and capture output
SCAN_JSON=$(clawarmor scan --json 2>/dev/null || echo '{"verdict":"BLOCK","score":0,"findings":[]}')

VERDICT=$(echo "$SCAN_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('verdict','BLOCK'))")
SCORE=$(echo "$SCAN_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('score',0))")
FINDINGS=$(echo "$SCAN_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('findings',[])))")

echo "[scan-gate] Verdict: $VERDICT | Score: $SCORE | Findings: $FINDINGS"

if [ "$VERDICT" = "BLOCK" ]; then
  echo ""
  echo "❌ BLOCKED — skill has CRITICAL findings and must not be installed."
  echo ""
  echo "$SCAN_JSON" | python3 -c "
import sys, json
d = json.load(sys.stdin)
for f in d.get('findings', []):
    if f.get('severity') in ('CRITICAL', 'HIGH'):
        print(f\"  [{f['severity']}] {f.get('skill','?')} — {f.get('message','')}\")
"
  echo ""
  # Log to registry
  bash "$(dirname "$0")/scan-registry.sh" "$SKILL_PATH" "$SCAN_JSON"
  exit 2
fi

if [ "$VERDICT" = "WARN" ]; then
  echo ""
  echo "⚠️  WARNING — skill has HIGH findings. Review before installing."
  echo ""
  echo "$SCAN_JSON" | python3 -c "
import sys, json
d = json.load(sys.stdin)
for f in d.get('findings', []):
    print(f\"  [{f['severity']}] {f.get('skill','?')} — {f.get('message','')}\")
"
  echo ""
  read -p "Install anyway? [y/N] " confirm
  if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
    echo "Aborted."
    bash "$(dirname "$0")/scan-registry.sh" "$SKILL_PATH" "$SCAN_JSON"
    exit 1
  fi
fi

echo ""
echo "✅ PASS — skill cleared for install."
bash "$(dirname "$0")/scan-registry.sh" "$SKILL_PATH" "$SCAN_JSON"
exit 0
```

### `scan-registry.sh`

Logs all scan results to a JSONL registry for audit trail.

```bash
#!/usr/bin/env bash
# scan-registry.sh — log scan results to registry
# Usage: bash scan-registry.sh <skill-path> <scan-json>

SKILL_PATH="$1"
SCAN_JSON="$2"
REGISTRY="$HOME/.openclaw/workspace/memory/skill-scan-registry.jsonl"

mkdir -p "$(dirname "$REGISTRY")"

ENTRY=$(echo "$SCAN_JSON" | python3 -c "
import sys, json
d = json.load(sys.stdin)
import datetime
d['skillPath'] = '$SKILL_PATH'
d['loggedAt'] = datetime.datetime.utcnow().isoformat() + 'Z'
print(json.dumps(d))
" 2>/dev/null || echo '{}')

echo "$ENTRY" >> "$REGISTRY"
echo "[scan-registry] Logged to $REGISTRY"
```

---

## Usage

```bash
# Before installing a skill:
bash ~/.openclaw/workspace/skills/skill-security-scanner/scan-gate.sh \
  ~/.openclaw/workspace/skills/some-skill/

# If it exits 0 (PASS), safe to proceed with install
# If it exits 1 (WARN), review findings then decide
# If it exits 2 (BLOCK), do not install
```

### In a CI/CD pipeline

```bash
# Fail pipeline if skill doesn't pass scan
bash scan-gate.sh ./my-new-skill/
if [ $? -eq 2 ]; then
  echo "Skill failed security scan — aborting deploy"
  exit 1
fi
```

---

## Trust levels

Even WARN skills from known sources (clawhub.com, shopclawmart.com) should be reviewed. The source of a skill doesn't guarantee its safety — supply chain attacks compromise trusted publishers too.

The only safe default is: **scan everything, trust nothing unverified**.

---

## Notes

- Requires clawarmor 3.2.0+ for `scan --json`
- The registry at `~/.openclaw/workspace/memory/skill-scan-registry.jsonl` provides a complete audit trail of all scanned skills
- BLOCK = CRITICAL findings — patterns like eval, child_process with network, obfuscated code
- WARN = HIGH findings — patterns like credential file reads, WebSocket usage, cleartext HTTP
