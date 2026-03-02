#!/usr/bin/env python3
"""
Generate a scripted asciinema .cast file for ClawArmor v2.0 demo.
Captures real command output with simulated typing for professional pacing.
"""
import json
import subprocess
import time
import os

CAST_FILE = os.path.expanduser("~/clawarmor/demo.cast")
COLS = 110
ROWS = 35
PROMPT = "$ "

def run_cmd(cmd):
    """Run a command and return its output."""
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                          env={**os.environ, "FORCE_COLOR": "0", "NO_COLOR": "1", "TERM": "dumb"})
    return result.stdout + result.stderr

def write_cast(events):
    """Write asciicast v2 file."""
    header = {
        "version": 2,
        "width": COLS,
        "height": ROWS,
        "timestamp": int(time.time()),
        "title": "ClawArmor v2.0 — Security Audit Demo",
        "env": {"SHELL": "/bin/zsh", "TERM": "xterm-256color"}
    }
    with open(CAST_FILE, 'w') as f:
        f.write(json.dumps(header) + '\n')
        for ts, etype, data in events:
            f.write(json.dumps([round(ts, 6), etype, data]) + '\n')
    print(f"Written to {CAST_FILE}")

def type_text(events, t, text, char_delay=0.045):
    for ch in text:
        events.append((t, "o", ch))
        t += char_delay
    return t

def output_text(events, t, text, line_delay=0.008):
    lines = text.split('\n')
    for i, line in enumerate(lines):
        events.append((t, "o", line + ('\n' if i < len(lines) - 1 else '')))
        t += line_delay
    return t

def pause(t, seconds):
    return t + seconds

def main():
    events = []
    t = 0.0

    # Opening
    t = output_text(events, t, PROMPT)
    t = pause(t, 0.8)

    # 1. Audit
    t = type_text(events, t, "# Step 1: Check your OpenClaw security posture", 0.03)
    events.append((t, "o", "\n")); t += 0.1
    t = output_text(events, t, PROMPT); t = pause(t, 0.5)
    t = type_text(events, t, "clawarmor audit")
    events.append((t, "o", "\n")); t += 0.2
    output = run_cmd("clawarmor audit 2>&1")
    t = output_text(events, t, output, 0.012)
    t = pause(t, 3.0)

    # 2. Harden dry-run
    t = output_text(events, t, PROMPT); t = pause(t, 0.5)
    t = type_text(events, t, "# Step 2: See what ClawArmor can fix automatically", 0.03)
    events.append((t, "o", "\n")); t += 0.1
    t = output_text(events, t, PROMPT); t = pause(t, 0.5)
    t = type_text(events, t, "clawarmor harden --dry-run")
    events.append((t, "o", "\n")); t += 0.2
    output = run_cmd("clawarmor harden --dry-run 2>&1")
    t = output_text(events, t, output, 0.012)
    t = pause(t, 3.0)

    # 3. Harden auto
    t = output_text(events, t, PROMPT); t = pause(t, 0.5)
    t = type_text(events, t, "# Step 3: Fix everything automatically", 0.03)
    events.append((t, "o", "\n")); t += 0.1
    t = output_text(events, t, PROMPT); t = pause(t, 0.5)
    t = type_text(events, t, "clawarmor harden --auto")
    events.append((t, "o", "\n")); t += 0.2
    output = run_cmd("clawarmor harden --auto 2>&1")
    t = output_text(events, t, output, 0.012)
    t = pause(t, 2.5)

    # 4. Re-audit
    t = output_text(events, t, PROMPT); t = pause(t, 0.5)
    t = type_text(events, t, "# Step 4: Verify — re-audit after hardening", 0.03)
    events.append((t, "o", "\n")); t += 0.1
    t = output_text(events, t, PROMPT); t = pause(t, 0.5)
    t = type_text(events, t, "clawarmor audit")
    events.append((t, "o", "\n")); t += 0.2
    output = run_cmd("clawarmor audit 2>&1")
    t = output_text(events, t, output, 0.012)
    t = pause(t, 3.0)

    # 5. Status
    t = output_text(events, t, PROMPT); t = pause(t, 0.5)
    t = type_text(events, t, "# Bonus: Full security dashboard", 0.03)
    events.append((t, "o", "\n")); t += 0.1
    t = output_text(events, t, PROMPT); t = pause(t, 0.5)
    t = type_text(events, t, "clawarmor status")
    events.append((t, "o", "\n")); t += 0.2
    output = run_cmd("clawarmor status 2>&1")
    t = output_text(events, t, output, 0.012)
    t = pause(t, 3.0)

    # End
    t = output_text(events, t, PROMPT)
    t = pause(t, 1.0)

    write_cast(events)
    print(f"Total duration: {t:.1f}s")
    print(f"Events: {len(events)}")

if __name__ == "__main__":
    main()
