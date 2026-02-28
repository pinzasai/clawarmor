// ClawArmor v0.6 — SKILL.md natural language instruction scanner
// Detects dangerous instructions embedded in skill markdown files.
// Built-in skills: INFO severity. User-installed: HIGH severity.

import { readFileSync } from 'fs';
import { basename } from 'path';

// Each pattern: { id, regex, title, description }
const DANGEROUS_PATTERNS = [
  {
    id: 'skillmd.read_credentials',
    regex: /read.*agent-accounts|agent-accounts.*read/i,
    title: 'Instruction to read credential file',
    description: 'Instructs the agent to read agent-accounts.json, which contains API keys and bot tokens.',
  },
  {
    id: 'skillmd.system_prompt_override',
    regex: /ignore.*system.?prompt|override.*system.?prompt|bypass.*system.?prompt/i,
    title: 'System prompt override attempt',
    description: 'Attempts to override or ignore the agent\'s system-level safety instructions.',
  },
  {
    id: 'skillmd.exfil',
    regex: /send.*credentials|exfiltrate|steal.*token|steal.*key|steal.*password/i,
    title: 'Data theft instruction',
    description: 'Instructs the agent to send, steal, or exfiltrate credentials or secrets.',
  },
  {
    id: 'skillmd.context_injection',
    regex: /always.*include.*in.*(?:every|all).*response|append.*to.*every.*response|inject.*into.*every/i,
    title: 'Persistent context injection',
    description: 'Instructs the agent to append content to every response — persistent prompt injection.',
  },
  {
    id: 'skillmd.deception',
    regex: /do not.*tell.*user|don.t.*mention.*to.*user|keep.*secret.*from.*user|hide.*from.*user/i,
    title: 'Deception instruction (hide from user)',
    description: 'Instructs the agent to conceal information or actions from the user.',
  },
  {
    id: 'skillmd.hardcoded_ip',
    regex: /fetch.*\b(https?):\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i,
    title: 'Hardcoded IP fetch instruction',
    description: 'Instructs the agent to fetch from a hardcoded IP address — potential exfiltration endpoint.',
  },
  {
    id: 'skillmd.shell_exec',
    regex: /execute.*(?:command|shell|bash|sh)\b|run.*shell.*command|spawn.*(?:process|subprocess)/i,
    title: 'Shell execution instruction',
    description: 'Instructs the agent to execute shell commands — could enable arbitrary code execution.',
  },
  {
    id: 'skillmd.fs_write',
    regex: /write.*to.*(?:file|disk|filesystem)|modify.*(?:config|configuration|settings).*file/i,
    title: 'Filesystem modification instruction',
    description: 'Instructs the agent to write files or modify config — potential persistent compromise.',
  },
];

// Scan a single SKILL.md file content
export function scanSkillMd(filePath, content, isBuiltin) {
  const findings = [];
  const lines = content.split('\n');

  for (const pattern of DANGEROUS_PATTERNS) {
    const regex = new RegExp(pattern.regex.source, 'gi');
    let m;
    const matches = [];
    while ((m = regex.exec(content)) !== null) {
      const lineNum = content.substring(0, m.index).split('\n').length;
      const lineText = lines[lineNum - 1]?.trim() || '';
      // Skip lines that are clearly comments or code fences showing examples
      if (lineText.startsWith('```') || lineText.startsWith('//') || lineText.startsWith('#!')) continue;
      // Skip if this looks like documentation warning about the pattern (not instructing it)
      if (/do not|don't|never|avoid|dangerous|warning|caution|example of/i.test(
        lines.slice(Math.max(0, lineNum - 2), lineNum).join(' ')
      )) continue;
      matches.push({ line: lineNum, snippet: lineText.substring(0, 120) });
      if (matches.length >= 3) break;
    }

    if (!matches.length) continue;

    findings.push({
      patternId: pattern.id,
      severity: isBuiltin ? 'INFO' : 'HIGH',
      title: pattern.title,
      description: pattern.description,
      file: filePath,
      matches,
      note: isBuiltin
        ? 'Built-in skill — review only if recently updated or unexpected.'
        : 'User-installed skill — treat dangerous instructions as HIGH risk.',
    });
  }

  return findings;
}

// Find all SKILL.md files within a skill directory's file list
export function getSkillMdFiles(files) {
  return files.filter(f => basename(f).toLowerCase() === 'skill.md');
}

// Scan all SKILL.md files for a skill
export function scanSkillMdFiles(skillFiles, isBuiltin) {
  const results = [];
  const mdFiles = getSkillMdFiles(skillFiles);

  for (const filePath of mdFiles) {
    let content;
    try { content = readFileSync(filePath, 'utf8'); }
    catch { continue; }
    if (content.length > 200_000) continue;

    const findings = scanSkillMd(filePath, content, isBuiltin);
    if (findings.length) results.push({ filePath, findings });
  }

  return results;
}
