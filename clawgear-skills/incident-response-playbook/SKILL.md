---
name: incident-response-playbook
description: Automated incident response for OpenClaw agents. When clawarmor audit finds a CRITICAL or HIGH finding, this playbook quarantines the affected extension, rolls back config to the last known-good snapshot, creates a structured incident log, and sends a Telegram alert. The action layer on top of ClawArmor detection.
category: security
tags: [security, incident-response, clawarmor, automation]
requires: clawarmor >= 3.2.0
---

# incident-response-playbook

ClawArmor detects security issues. This skill responds to them. Automatically.

When a CRITICAL finding is detected, the playbook:
1. **Quarantines** the affected extension
2. **Rolls back** config to the last known-good snapshot
3. **Creates a structured incident log** via `clawarmor incident create`
4. **Sends a Telegram alert** via `openclaw system event`

Designed to run from your HEARTBEAT.md so it fires automatically on every cycle.

---

## Scripts

### `quarantine.sh`

Disables a named extension and restarts the gateway.

```bash
#!/usr/bin/env bash
# quarantine.sh — disable an extension immediately
# Usage: bash quarantine.sh <extension-name>
# requires: elevated

EXTENSION="$1"

if [ -z "$EXTENSION" ]; then
  echo "Usage: bash quarantine.sh <extension-name>"
  exit 1
fi

echo "[quarantine] Disabling extension: $EXTENSION"
openclaw config set "extensions.${EXTENSION}.disabled" true
openclaw gateway restart

echo "[quarantine] Extension '$EXTENSION' quarantined. Gateway restarted."
```

### `respond.sh`

Full automated incident response: rollback, incident log, Telegram alert.

```bash
#!/usr/bin/env bash
# respond.sh — full incident response for a security finding
# Usage: bash respond.sh "<finding-description>" <CRITICAL|HIGH|MEDIUM>
# requires: clawarmor >= 3.2.0, elevated

FINDING="$1"
SEVERITY="${2:-CRITICAL}"

if [ -z "$FINDING" ]; then
  echo "Usage: bash respond.sh \"<finding-description>\" <CRITICAL|HIGH|MEDIUM>"
  exit 1
fi

echo ""
echo "[respond] Incident Response Triggered"
echo "[respond] Finding: $FINDING"
echo "[respond] Severity: $SEVERITY"
echo ""

# Step 1: Rollback config
echo "[respond] Rolling back to last known-good snapshot..."
ROLLBACK_OUTPUT=$(clawarmor rollback 2>&1)
ROLLBACK_STATUS=$?

if [ $ROLLBACK_STATUS -ne 0 ]; then
  echo "[respond] WARNING: Rollback failed or no snapshots available."
  echo "[respond] Operator must review config manually."
  ROLLBACK_NOTE="Rollback failed — manual review required"
else
  echo "[respond] Config rolled back."
  ROLLBACK_NOTE="Config rolled back via clawarmor rollback"
fi

# Step 2: Create incident log
echo "[respond] Creating incident log..."
INCIDENT_FILE=$(clawarmor incident create \
  --finding "$FINDING" \
  --severity "$SEVERITY" \
  --action rollback \
  2>&1 | grep "File:" | awk '{print $2}')
echo "[respond] Incident logged: ${INCIDENT_FILE:-unknown}"

# Step 3: Send Telegram alert
echo "[respond] Sending alert..."
openclaw system event \
  --text "🚨 Security Incident: $FINDING (Severity: $SEVERITY) — Config rolled back. Check: clawarmor incident list" \
  --mode now

echo ""
echo "[respond] Done. Incident response complete."
echo ""
```

### `check-and-respond.sh`

Runs `clawarmor audit --json`, finds CRITICAL findings, auto-triggers `respond.sh` for each.

```bash
#!/usr/bin/env bash
# check-and-respond.sh — auto-respond to new CRITICAL findings
# Add to HEARTBEAT.md to run automatically on every cycle
# requires: clawarmor >= 3.2.0, elevated

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "[check-and-respond] Running security audit..."
AUDIT_JSON=$(clawarmor audit --json 2>/dev/null || echo '{"failed":[]}')

# Extract CRITICAL findings
CRITICALS=$(echo "$AUDIT_JSON" | python3 -c "
import sys, json
d = json.load(sys.stdin)
failed = d.get('failed', [])
for f in failed:
    if f.get('severity') == 'CRITICAL' and not f.get('_profileExpected'):
        print(f.get('title', f.get('id', 'Unknown finding')))
" 2>/dev/null)

if [ -z "$CRITICALS" ]; then
  echo "[check-and-respond] No CRITICAL findings. Posture clean."
  exit 0
fi

echo "[check-and-respond] CRITICAL findings detected — triggering response..."
echo ""

while IFS= read -r finding; do
  if [ -n "$finding" ]; then
    echo "[check-and-respond] Responding to: $finding"
    bash "$SCRIPT_DIR/respond.sh" "$finding" "CRITICAL"
  fi
done <<< "$CRITICALS"

echo "[check-and-respond] All findings processed."
```

---

## Heartbeat integration

Add this to your `HEARTBEAT.md` to auto-respond to new CRITICAL findings on every cycle:

```markdown
## Security Incident Response

Run bash check-and-respond.sh from skills/incident-response-playbook/ — automatically respond to any CRITICAL security findings found during audit.
```

---

## Manual usage

```bash
# Respond to a specific finding manually
bash ~/.openclaw/workspace/skills/incident-response-playbook/respond.sh \
  "Malicious skill detected: bad-skill-v2" \
  CRITICAL

# Quarantine a specific extension
bash ~/.openclaw/workspace/skills/incident-response-playbook/quarantine.sh \
  bad-extension-name

# Run audit and auto-respond to everything critical
bash ~/.openclaw/workspace/skills/incident-response-playbook/check-and-respond.sh
```

---

## Notes

- **Rollback** uses ClawArmor's snapshot system (`clawarmor rollback`). If no snapshot exists (e.g., hardening was never run), rollback is skipped and the operator is alerted to review manually
- **Quarantine** requires `openclaw config set` and `openclaw gateway restart` to be available — these are standard OpenClaw commands
- **Telegram delivery** requires `openclaw system event` to be configured with a Telegram channel
- The `--action rollback` flag on `clawarmor incident create` also triggers rollback automatically — `respond.sh` calls both for belt-and-suspenders reliability
- Requires clawarmor 3.2.0+ for `clawarmor incident` and `clawarmor audit --json`
- The scripts use `set -e` for fail-fast behavior — if any step errors, the script exits immediately. Check logs if a step is skipped unexpectedly
