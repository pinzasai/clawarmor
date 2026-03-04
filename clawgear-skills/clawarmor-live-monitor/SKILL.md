---
name: clawarmor-live-monitor
description: Monitors your OpenClaw agent security posture on every heartbeat. Diffs against a saved baseline and sends a Telegram alert if your score drops (e.g., after installing a new skill). Uses clawarmor baseline diff under the hood.
category: security
tags: [security, monitoring, heartbeat, clawarmor]
requires: clawarmor >= 3.2.0
---

# clawarmor-live-monitor

Monitors your OpenClaw agent's security posture on every heartbeat cycle. After a new skill is installed, your score can silently drop — this skill catches that and alerts you before it becomes a problem.

## What it does

On every heartbeat, this skill:
1. Saves the current security posture as a `current` baseline
2. Diffs it against the saved `initial` baseline
3. If the score dropped by more than 5 points, fires a Telegram alert via `openclaw system event`

It uses `clawarmor baseline diff` under the hood — no custom scoring logic, just wiring.

## Why it matters

You install a skill, it looks fine. But it quietly adds an exec call or an outbound network fetch that ClawArmor would flag. Without continuous monitoring, you'd never know until the next manual audit. This skill closes that gap.

---

## Scripts

### `baseline-init.sh`

Run this once on first install to save your initial baseline.

```bash
#!/usr/bin/env bash
# baseline-init.sh — save initial security baseline
set -e

echo "[clawarmor-live-monitor] Saving initial baseline..."
clawarmor baseline save --name initial
echo "[clawarmor-live-monitor] Initial baseline saved."
echo "Now paste heartbeat-fragment.md into your HEARTBEAT.md to enable continuous monitoring."
```

### `monitor.sh`

Run on every heartbeat to check for score regressions.

```bash
#!/usr/bin/env bash
# monitor.sh — diff current posture against initial baseline
set -e

SKILL_DIR="$(cd "$(dirname "$0")" && pwd)"

# Save current posture
clawarmor baseline save --name current

# Diff against initial
DIFF_OUTPUT=$(clawarmor baseline diff --from initial --to current 2>&1)
SCORE_DELTA=$(echo "$DIFF_OUTPUT" | grep -oP 'Delta:\s*\K[+-]?\d+' | head -1)

echo "[clawarmor-live-monitor] Score delta: ${SCORE_DELTA:-0}"

# Alert if score dropped more than 5 points
if [ -n "$SCORE_DELTA" ] && [ "$SCORE_DELTA" -lt -5 ]; then
  openclaw system event \
    --text "⚠️ ClawArmor score dropped ${SCORE_DELTA} points since initial baseline. Run: clawarmor audit" \
    --mode now
  echo "[clawarmor-live-monitor] Alert sent."
fi
```

### `heartbeat-fragment.md`

Paste this snippet into your `HEARTBEAT.md` to enable automatic monitoring:

```markdown
## Security Monitor

Run bash monitor.sh from skills/clawarmor-live-monitor/ — if score dropped, alert Alberto.
```

---

## Setup

1. **Install ClawArmor 3.2.0+**: `npm install -g clawarmor`
2. **Save your initial baseline** (run once):
   ```bash
   bash ~/.openclaw/workspace/skills/clawarmor-live-monitor/baseline-init.sh
   ```
3. **Enable heartbeat monitoring** — paste the contents of `heartbeat-fragment.md` into your `HEARTBEAT.md`

That's it. On every heartbeat, your score will be checked against the initial baseline.

---

## Manual usage

```bash
# Check current posture vs initial baseline
bash ~/.openclaw/workspace/skills/clawarmor-live-monitor/monitor.sh

# See all saved baselines
clawarmor baseline list

# Detailed diff
clawarmor baseline diff --from initial --to current
```

---

## Notes

- Requires clawarmor 3.2.0+ for the `baseline` commands
- The `current` baseline is overwritten on every heartbeat — it tracks the most recent posture only
- The `initial` baseline persists until you re-run `baseline-init.sh`
- Alert threshold is hardcoded at -5 points; edit `monitor.sh` to adjust
- Telegram delivery requires `openclaw system event` to be configured with a Telegram channel
