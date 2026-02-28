import { readFileSync } from 'fs';
import { extname } from 'path';
import { CRITICAL_PATTERNS, HIGH_PATTERNS, MEDIUM_PATTERNS, SCANNABLE_EXTENSIONS, SKIP_EXTENSIONS } from './patterns.js';

function getExt(filePath) {
  return extname(filePath).replace('.', '').toLowerCase();
}

function findMatches(content, pattern) {
  const lines = content.split('\n');
  const matches = [];
  const regex = new RegExp(pattern.regex.source, 'gi');
  let match;
  while ((match = regex.exec(content)) !== null) {
    const lineNum = content.substring(0, match.index).split('\n').length;
    const lineContent = lines[lineNum - 1]?.trim() || '';
    if (lineContent.startsWith('//') || lineContent.startsWith('#')) continue;
    matches.push({ line: lineNum, snippet: lineContent.substring(0, 120) });
    if (matches.length >= 3) break;
  }
  return matches;
}

export function scanFile(filePath) {
  const ext = getExt(filePath);
  if (SKIP_EXTENSIONS.has(ext)) return [];
  if (!SCANNABLE_EXTENSIONS.has(ext) && ext !== 'md' && ext !== '') return [];

  let content;
  try {
    content = readFileSync(filePath, 'utf8');
  } catch { return []; }

  if (content.length > 500_000) return [];

  const findings = [];
  const allPatterns = [
    ...CRITICAL_PATTERNS.map(p => ({ ...p, severity: 'CRITICAL' })),
    ...HIGH_PATTERNS.map(p => ({ ...p, severity: 'HIGH' })),
    ...MEDIUM_PATTERNS.map(p => ({ ...p, severity: 'MEDIUM' })),
  ];

  for (const pattern of allPatterns) {
    const matches = findMatches(content, pattern);
    if (matches.length > 0) {
      findings.push({ patternId: pattern.id, severity: pattern.severity, title: pattern.title, description: pattern.description, file: filePath, matches });
    }
  }
  return findings;
}
