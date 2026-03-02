// obfuscation.js — v1.3.0
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
//   - Dynamic import() with runtime-assembled module name
//   - eval/exec called with interpolated template literal
//   - Proxy/Reflect wrapping of dangerous objects
//   - Variable aliasing of dangerous functions (const e = eval)

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
  {
    // Pattern: const mod = 'child' + '_process'; import(mod)
    // The module name is never visible as a literal string, bypassing child_process regex.
    id: 'obfus-dynamic-import-concat',
    severity: 'CRITICAL',
    title: 'Dynamic import() with runtime-assembled module name',
    description: "import() called with a variable or concatenated string — module name assembled at runtime, bypassing static child_process/net detection.",
    note: "Pattern: const mod = 'child' + '_process'; import(mod). The dangerous module name never appears intact in source.",
    regex: /\bimport\s*\(\s*(?:[a-zA-Z_$][a-zA-Z0-9_$]*\s*\)|['"`][^'"`]*['"`]\s*\+)/,
  },
  {
    // Pattern: eval(`(function() { ${userCode} })()`)
    // Template literal interpolation allows runtime code injection hidden from literal-string scanners.
    id: 'obfus-template-literal',
    severity: 'HIGH',
    title: 'eval/exec called with interpolated template literal',
    description: "eval or exec invoked with a template literal containing ${...} interpolation — injects runtime values into executed code.",
    note: "eval(`code ${var}`) assembles executable code from runtime values. Evades scanners that only check string literals.",
    regex: /\b(?:eval|Function|exec|execSync)\s*\(\s*`[^`]*\$\{/,
  },
  {
    // Pattern: new Proxy(process, handler) or Reflect.get(globalThis, 'eval')
    // Proxying dangerous objects intercepts property access for exfiltration or modification.
    id: 'obfus-proxy-reflect',
    severity: 'HIGH',
    title: 'Proxy/Reflect wrapping of dangerous object',
    description: "Wrapping process, require, or globalThis in a Proxy intercepts all property access — used for covert exfiltration or to modify dangerous function behavior.",
    note: "new Proxy(process, handler) can log every process property access. Reflect.get(globalThis, 'eval') accesses eval indirectly.",
    regex: /new\s+Proxy\s*\(\s*(?:process|require|global|globalThis)\b|Reflect\s*\.\s*(?:get|apply)\s*\(\s*(?:globalThis|global|process)\b/,
  },
  {
    // Pattern: const e = eval; e(code) or const {execSync: run} = require('child_process')
    // Alias hides the dangerous function name at all call sites, bypassing keyword scanners.
    id: 'obfus-var-alias',
    severity: 'HIGH',
    title: 'Variable aliasing of dangerous function',
    description: "Assigning eval, exec, or spawn to a new variable name so call sites evade keyword detection.",
    note: "const e = eval; e(code) — the dangerous eval() call is hidden as e(). Destructuring rename: const {execSync: run} = require('child_process').",
    regex: /(?:const|let|var)\s+\w+\s*=\s*eval\b|(?:const|let|var)\s+\{[^}]*(?:exec|spawn)[^}]*:\s*\w+[^}]*\}\s*=/,
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
