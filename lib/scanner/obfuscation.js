// obfuscation.js — v1.2.0
// Detects obfuscated code patterns that bypass naive string-grep analysis.
// Zero external dependencies. Pure regex, adversarially reviewed.
//
// Targets:
//   - String concatenation reassembly: 'ev'+'al', 'ex'+'ec'
//   - Bracket property access with concat: obj['ex'+'ec']
//   - Buffer.from(base64).toString() decode chains
//   - eval(atob(...)) decode+exec
//   - globalThis/global bracket access to dangerous names
//   - ['constructor'] escape pattern
//   - Unicode/hex escape sequences for dangerous keywords

export const OBFUSCATION_PATTERNS = [
  {
    id: 'obfus-str-concat-eval',
    severity: 'CRITICAL',
    title: "String-concat 'eval' reassembly",
    description: "Obfuscated eval via string concat: 'ev'+'al'. Bypasses naive keyword grep.",
    note: 'Legitimate code rarely splits the word eval across string literals.',
    regex: /'ev'\s*\+\s*'al'|"ev"\s*\+\s*"al"|'e'\s*\+\s*'val'|"e"\s*\+\s*"val"/,
  },
  {
    id: 'obfus-str-concat-exec',
    severity: 'HIGH',
    title: "String-concat 'exec' reassembly",
    description: "Obfuscated exec via string concat: 'ex'+'ec'. Common shell command injection prep.",
    note: 'Legitimate code rarely splits exec across string literals.',
    regex: /'ex'\s*\+\s*'ec'|"ex"\s*\+\s*"ec"|'e'\s*\+\s*'xec'|"e"\s*\+\s*"xec"/,
  },
  {
    id: 'obfus-bracket-concat',
    severity: 'HIGH',
    title: 'Bracket property access via string concat',
    description: "obj['ex'+'ec'] bypasses static method-name analysis. Common obfuscation technique.",
    note: 'Legitimate code almost never accesses properties via concatenated string literals.',
    regex: /\[\s*'[a-zA-Z]{1,5}'\s*\+\s*'[a-zA-Z]{1,5}'\s*\]|\[\s*"[a-zA-Z]{1,5}"\s*\+\s*"[a-zA-Z]{1,5}"\s*\]/,
  },
  {
    id: 'obfus-buffer-base64',
    severity: 'HIGH',
    title: 'Buffer.from(base64).toString() decode chain',
    description: "Decodes a base64 payload at runtime — common technique for hiding malicious code strings.",
    note: 'May be legitimate for binary data handling, but unusual in skill files.',
    regex: /Buffer\.from\((?:'[A-Za-z0-9+\/=]{20,}'|"[A-Za-z0-9+\/=]{20,}")\s*,\s*(?:'base64'|"base64")\)/,
  },
  {
    id: 'obfus-atob-exec',
    severity: 'CRITICAL',
    title: 'eval(atob(...)) decode+execute',
    description: "Decodes and executes a base64 string. Textbook obfuscation for hiding eval payloads.",
    regex: /(?:eval|Function)\s*\(\s*atob\s*\(/,
  },
  {
    id: 'obfus-globalthis-bracket',
    severity: 'HIGH',
    title: 'globalThis[...] bracket access',
    description: "Accesses global scope via bracket notation — hides dangerous function names from static analysis.",
    note: 'globalThis["eval"] is equivalent to eval but bypasses keyword scanners.',
    regex: /globalThis\s*\[\s*['"][^'"]{1,30}['"]\s*\]|global\s*\[\s*['"][^'"]{1,30}['"]\s*\]/,
  },
  {
    id: 'obfus-constructor-escape',
    severity: 'CRITICAL',
    title: "['constructor'] Function escape",
    description: "Accesses Function constructor via bracket notation to execute arbitrary code strings.",
    note: "Pattern: obj['constructor']('return process')(). Classic prototype escape.",
    regex: /\[\s*['"]constructor['"]\s*\]/,
  },
  {
    id: 'obfus-unicode-escape',
    severity: 'HIGH',
    title: 'Unicode escape for dangerous keyword',
    description: "Uses \\u escapes to spell dangerous keywords: \\u0065val = eval. Bypasses string matching.",
    regex: /\\u00(?:65|45)\\u00(?:76|56)\\u00(?:61|41)\\u00(?:6c|4c)|\\u0065\\u0076\\u0061\\u006c/i,
  },
  {
    id: 'obfus-encoded-require',
    severity: 'HIGH',
    title: 'Encoded require() or import()',
    description: "Calls require() or import() with a runtime-decoded string argument (atob, fromCharCode, etc.).",
    regex: /(?:require|import)\s*\(\s*(?:atob|String\.fromCharCode|Buffer\.from)\s*\(/,
  },
];

/**
 * Scan file content for obfuscation patterns.
 * Returns findings array (same shape as file-scanner.js output).
 */
export function scanForObfuscation(filePath, content, isBuiltin = false) {
  const findings = [];
  const lines = content.split('\n');

  for (const pattern of OBFUSCATION_PATTERNS) {
    const regex = new RegExp(pattern.regex.source, 'gi');
    const matches = [];
    let m;

    while ((m = regex.exec(content)) !== null) {
      const lineNum = content.substring(0, m.index).split('\n').length;
      const line = lines[lineNum - 1]?.trim() || '';

      // Skip comment lines
      if (/^\s*(\/\/|#|\*|<!--)/.test(line)) continue;

      matches.push({ line: lineNum, snippet: line.substring(0, 120) });
      if (matches.length >= 3) break;
    }

    if (!matches.length) continue;

    // Built-in skills: downgrade severity (still worth reporting but lower urgency)
    let severity = pattern.severity;
    if (isBuiltin) {
      severity = severity === 'CRITICAL' ? 'MEDIUM' : 'LOW';
    }

    findings.push({
      patternId: pattern.id,
      severity,
      title: pattern.title,
      description: pattern.description,
      note: pattern.note || null,
      file: filePath,
      matches,
    });
  }

  return findings;
}
