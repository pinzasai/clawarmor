# Security Policy & Ethics Statement

## What ClawArmor scans

**`clawarmor audit`** reads a single file: `~/.openclaw/openclaw.json`. It checks configuration values — bind address, auth mode, file permissions, channel policies. It never reads credentials or sends any data over the network.

**`clawarmor scan`** reads source files in installed skill directories. It runs regex patterns against file content to detect suspicious code. It does not execute any skill code. It never sends file contents anywhere.

**`clawarmor monitor`** is a planned future command. Details TBD.

## What ClawArmor never does

- Sends your config, credentials, or file contents to any server
- Stores anything on disk beyond what you explicitly configure
- Executes skill code during scanning
- Makes outbound network calls during `audit` or `scan` (except: `clawarmor audit` fetches the latest OpenClaw version from the npm registry to check if you're up to date — this is a GET request with no identifying information)
- Shares scan results with third parties

## Responsible disclosure

ClawArmor is built on research into exposed OpenClaw instances. We follow responsible disclosure principles:

1. We notify owners before publishing any findings about their specific instances
2. We do not exploit vulnerabilities we discover — we report them
3. We do not store or log the content of notifications sent to exposed instances
4. We maintain a public transparency log of notifications sent (IP + timestamp + message hash, no content)

## Reporting vulnerabilities in ClawArmor

If you find a security vulnerability in ClawArmor itself, please email **pinzasrojas@proton.me** before public disclosure. We commit to:

- Acknowledging your report within 48 hours
- Providing a fix or mitigation within 14 days for critical issues
- Crediting you in the release notes (if desired)

## False positives

ClawArmor's `scan` command uses static pattern matching. Some findings — particularly in built-in skills — are legitimate uses of flagged patterns (e.g., `spawnSync` in a TTS binary wrapper). Always review findings in context before taking action.

If you believe a pattern produces excessive false positives, please open an issue at github.com/pinzasai/clawarmor.
