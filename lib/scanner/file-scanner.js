import { readFileSync } from 'fs';
import { extname, basename } from 'path';
import { CRITICAL_PATTERNS, HIGH_PATTERNS, MEDIUM_PATTERNS,
  SCANNABLE_EXTENSIONS, SKIP_EXTENSIONS, isSpawnInBinaryWrapper } from './patterns.js';

function getExt(p) { return extname(p).replace('.','').toLowerCase(); }

function findMatches(content, pattern) {
  const lines = content.split('\n');
  const matches = [];
  const regex = new RegExp(pattern.regex.source, 'gi');
  let m;
  while ((m = regex.exec(content)) !== null) {
    const lineNum = content.substring(0, m.index).split('\n').length;
    const line = lines[lineNum-1]?.trim() || '';
    if (/^\s*(\/\/|#|\*)/.test(line)) continue; // skip comments
    matches.push({ line: lineNum, snippet: line.substring(0,120) });
    if (matches.length >= 3) break;
  }
  return matches;
}

export function scanFile(filePath, isBuiltin = false) {
  const ext = getExt(filePath);
  if (SKIP_EXTENSIONS.has(ext)) return [];
  if (!SCANNABLE_EXTENSIONS.has(ext) && ext !== 'md' && ext !== '') return [];

  let content;
  try { content = readFileSync(filePath, 'utf8'); }
  catch { return []; }
  if (content.length > 500_000) return [];

  const findings = [];
  const allPatterns = [
    ...CRITICAL_PATTERNS.map(p => ({...p, severity:'CRITICAL'})),
    ...HIGH_PATTERNS.map(p => ({...p, severity:'HIGH'})),
    ...MEDIUM_PATTERNS.map(p => ({...p, severity:'MEDIUM'})),
  ];

  for (const pattern of allPatterns) {
    const matches = findMatches(content, pattern);
    if (!matches.length) continue;

    // Context-aware severity reduction for built-in skills
    let severity = pattern.severity;
    let note = null;

    if (isBuiltin && pattern.builtinOk) {
      severity = 'INFO';
      note = 'Built-in skill — pattern is likely legitimate. Review only if recently updated.';
    }

    // spawnSync/exec in binary wrapper = legitimate (TTS, image tools)
    if (['eval','child-process','exec-spawn','vm-run'].includes(pattern.id)) {
      if (isSpawnInBinaryWrapper(filePath, matches[0]?.snippet || '')) {
        severity = isBuiltin ? 'INFO' : 'LOW';
        note = 'Pattern detected in binary wrapper context — likely legitimate subprocess call.';
      }
    }

    // built-in skills: cap max severity at LOW for most patterns
    if (isBuiltin && !pattern.builtinOk && severity === 'CRITICAL') severity = 'LOW';
    if (isBuiltin && !pattern.builtinOk && severity === 'HIGH') severity = 'INFO';

    findings.push({ patternId: pattern.id, severity, title: pattern.title,
      description: pattern.description, file: filePath, matches, note });
  }
  return findings;
}
