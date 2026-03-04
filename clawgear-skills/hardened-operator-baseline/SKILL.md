---
name: hardened-operator-baseline
description: Full ClawArmor hardening in 3 commands. Detects your operator role (coding/browsing/messaging), applies contextual hardening, deploys Invariant + IronCurtain stack, saves a security baseline, and writes a SECURITY_RUNBOOK.md to your workspace. One-time setup for production-grade security posture.
category: security
tags: [security, hardening, baseline, clawarmor, invariant, ironcurtain]
requires: clawarmor >= 3.2.0
---

# hardened-operator-baseline

Production-grade security hardening in 3 commands. Run this once to go from default OpenClaw config to a hardened, monitored, documented security posture.

## What it does

1. **Detects your operator role** (`clawarmor profile detect`) — coding, browsing, or messaging
2. **Applies contextual hardening** (`clawarmor harden --profile <detected>`) — tightens the settings that matter for your role without breaking your workflow
3. **Deploys the security stack and saves a baseline** (`clawarmor stack deploy && clawarmor baseline save --name post-harden`) — Invariant flow guardrails + IronCurtain instruction boundaries + a snapshot of your hardened posture

After running, a `SECURITY_RUNBOOK.md` is written to your workspace documenting what was done and how to respond to incidents.

---

## The 3 commands

```bash
# Step 1: Detect your operator role
clawarmor profile detect

# Step 2: Apply contextual hardening (replace <profile> with detected value)
clawarmor harden --profile <profile>

# Step 3: Deploy security stack and save baseline
clawarmor stack deploy && clawarmor baseline save --name post-harden
```

---

## Script

### `setup.sh`

Runs all 3 steps in sequence and writes `SECURITY_RUNBOOK.md` to your workspace.

```bash
#!/usr/bin/env bash
# setup.sh — full ClawArmor hardening sequence
# Run once to set up production-grade security posture

set -e

WORKSPACE="$HOME/.openclaw/workspace"
RUNBOOK="$WORKSPACE/SECURITY_RUNBOOK.md"

echo ""
echo "=== ClawArmor Hardened Operator Baseline ==="
echo ""

# Step 1: Detect profile
echo "[1/3] Detecting operator profile..."
PROFILE=$(clawarmor profile detect 2>/dev/null | grep -oP 'Detected:\s*\K\w+' | head -1)
if [ -z "$PROFILE" ]; then
  PROFILE="general"
  echo "  Profile detection failed — using 'general'"
else
  echo "  Detected profile: $PROFILE"
fi

# Step 2: Apply hardening
echo ""
echo "[2/3] Applying contextual hardening (profile: $PROFILE)..."
clawarmor harden --profile "$PROFILE" --auto
echo "  Hardening applied."

# Step 3: Deploy stack and save baseline
echo ""
echo "[3/3] Deploying security stack and saving baseline..."
clawarmor stack deploy
clawarmor baseline save --name post-harden
SCORE=$(clawarmor baseline list 2>/dev/null | grep -A2 'post-harden' | grep -oP 'Score:\s*\K[\d]+' | head -1)
SCORE="${SCORE:-unknown}"
echo "  Stack deployed. Baseline saved. Score: $SCORE/100"

# Write SECURITY_RUNBOOK.md
DATE=$(date +%Y-%m-%d)
mkdir -p "$WORKSPACE"

cat > "$RUNBOOK" << EOF
# Security Runbook
**Hardened:** $DATE
**Profile:** $PROFILE
**Score:** $SCORE/100
**Stack:** Invariant + IronCurtain

## What's Protected
- Config locked via clawarmor harden
- Runtime guardrails via Invariant
- Instruction boundaries via IronCurtain

## Incident Response
1. Run: clawarmor audit
2. Check: clawarmor incident list
3. If CRITICAL: clawarmor rollback && clawarmor incident create --finding "..." --severity CRITICAL

## Contacts
- ClawArmor docs: github.com/pinzasai/clawarmor
- ClawGear support: clawgear.io
EOF

echo ""
echo "=== Done ==="
echo ""
echo "  SECURITY_RUNBOOK.md written to: $RUNBOOK"
echo "  Baseline saved as: post-harden"
echo "  Score: $SCORE/100"
echo ""
echo "  Next steps:"
echo "  - Review SECURITY_RUNBOOK.md"
echo "  - Run 'clawarmor audit' anytime to check current posture"
echo "  - Run 'clawarmor baseline diff --from post-harden --to <new>' to track changes"
echo ""
```

---

## After running

Your workspace will contain:
- **`SECURITY_RUNBOOK.md`** — incident response procedures, what's protected, contacts
- **`post-harden` baseline** — snapshot of your hardened posture for future diffs

```bash
# Check posture after any config changes
clawarmor baseline save --name $(date +%Y-%m-%d) && \
  clawarmor baseline diff --from post-harden --to $(date +%Y-%m-%d)
```

---

## SECURITY_RUNBOOK.md template

The script generates this file automatically. You can also create it manually:

```markdown
# Security Runbook
**Hardened:** <date>
**Profile:** <profile>
**Score:** <score>/100
**Stack:** Invariant + IronCurtain

## What's Protected
- Config locked via clawarmor harden
- Runtime guardrails via Invariant
- Instruction boundaries via IronCurtain

## Incident Response
1. Run: clawarmor audit
2. Check: clawarmor incident list
3. If CRITICAL: clawarmor rollback && clawarmor incident create --finding "..." --severity CRITICAL

## Contacts
- ClawArmor docs: github.com/pinzasai/clawarmor
- ClawGear support: clawgear.io
```

---

## Notes

- Run `clawarmor baseline save` after any significant config changes to keep your diff history meaningful
- The `--auto` flag on harden applies SAFE and CAUTION fixes without prompting — omit it if you want to review each fix interactively
- Stack deploy requires Invariant and IronCurtain to be available in your environment
- Requires clawarmor 3.2.0+ for baseline commands
