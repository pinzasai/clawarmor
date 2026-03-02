// v0.5 — context-aware patterns, adversarially reviewed

export const CRITICAL_PATTERNS = [
  { id: 'eval', regex: /\beval\s*\((?!\s*\/\/)/, title: 'eval() usage',
    description: 'Executes arbitrary code strings. Classic injection vector.',
    contextDeny: [/\bcomment\b/, /example/i] },
  { id: 'new-function', regex: /new\s+Function\s*\(/, title: 'new Function()',
    description: 'Equivalent to eval() — executes arbitrary code.' },
  { id: 'child-process', regex: /require\(['"`]child_process['"`]\)|from\s+['"`]child_process['"`]/,
    title: 'child_process imported', description: 'Allows shell command execution.' },
  { id: 'pipe-to-shell', regex: /[`'"]\s*\|\s*(sh|bash|zsh|fish)\b/,
    title: 'Pipe-to-shell pattern', description: 'curl|bash or wget|sh — classic RCE.' },
  { id: 'vm-run', regex: /vm\.(runInNewContext|runInThisContext)\s*\(/,
    title: 'vm module code execution', description: 'Executes code in Node.js VM.' },
  // Binding a raw TCP server is the primary reverse-shell / C2 setup technique.
  // net.createServer in skill code has virtually no legitimate use case.
  { id: 'reverse-shell',
    regex: /net\.createServer\s*\(|(?:require\(['"`]net['"`]\)|import\(['"`]net['"`]\))[\s\S]{0,300}\.createServer\s*\(/,
    title: 'net.createServer() — reverse shell / port binding',
    description: 'Creating a raw TCP server is the primary mechanism for reverse shells and covert C2 listeners.' },
];

export const HIGH_PATTERNS = [
  { id: 'credential-file', regex: /agent-accounts|\/\.openclaw\/.*token|credentials\/.*\.json/i,
    title: 'Credential file path referenced',
    description: 'May attempt to read API keys or bot tokens.',
    builtinOk: true }, // gh-issues legitimately reads this — flag as INFO for builtins
  { id: 'ssh-key', regex: /\.ssh\/(id_rsa|id_ed25519|id_ecdsa|authorized_keys)/,
    title: 'SSH key path referenced', description: 'May attempt SSH credential theft.' },
  { id: 'known-bad-domains',
    regex: /webhook\.site|requestbin\.|pipedream\.net|beeceptor\.com|hookbin\.com/,
    title: 'Known data-collection domain', description: 'Used for data interception/exfiltration.' },
  { id: 'exfil-combo', regex: /process\.env[\s\S]{0,200}(fetch|axios|http|request)\s*\(/,
    title: 'Env vars + network call (exfil pattern)',
    description: 'Reading env vars then making network calls — credential exfiltration pattern.' },
  // WebSocket bypasses fetch/axios-based detection entirely — a silent exfil channel.
  { id: 'websocket-exfil',
    regex: /new\s+WebSocket\s*\(|(?:ws|socket)\s*\.send\s*\(/,
    title: 'WebSocket usage (potential data exfiltration)',
    description: 'WebSocket connections can silently exfiltrate data — not caught by fetch/axios-based detection rules.' },
  // DNS can encode secrets in subdomain queries; no HTTP logs, evades most monitoring.
  { id: 'dns-exfil',
    regex: /require\(['"`](?:dns|node:dns)['"`]\)|from\s+['"`](?:dns|node:dns)['"`]/,
    title: 'DNS module imported (covert channel risk)',
    description: 'DNS can encode data in subdomain queries — a covert exfiltration channel that evades HTTP monitoring.' },
  // __proto__ assignment or Object.prototype mutation corrupts the global object graph.
  { id: 'proto-pollution',
    regex: /__proto__\s*["'`]|Object\.prototype\s*\[/,
    title: 'Prototype pollution',
    description: 'Assigning to __proto__ or Object.prototype mutates all JS objects — enables object injection attacks.' },
  // Extends exfil-combo to cover outbound channels beyond fetch: WebSocket and DNS.
  { id: 'exfil-combo-broad',
    regex: /process\.env[\s\S]{0,200}(?:new\s+WebSocket|ws\.send\s*\(|dns\.resolve\s*\(|dns\.lookup\s*\()/,
    title: 'Env vars + WebSocket/DNS outbound (broad exfil)',
    description: 'process.env followed by WebSocket or DNS send — exfiltration path not caught by fetch-only rules.' },
  // Credential file + network call within same scope = high-confidence theft combo.
  { id: 'cred-read-network',
    regex: /readFileSync\s*\(['"`][^'"`]*(?:\.openclaw|agent-accounts|credentials)[^'"`]*['"`][\s\S]{0,500}(?:fetch|axios|new\s+WebSocket|ws\.send|http\.request)/,
    title: 'Credential file read + outbound network call',
    description: 'Reading a credential file then making a network call in the same scope — credential theft combo.' },
];

export const MEDIUM_PATTERNS = [
  { id: 'dynamic-require', regex: /require\s*\(\s*(?!['"`])[a-zA-Z_$][a-zA-Z0-9_$]*\s*\)/,
    title: 'Dynamic require()', description: 'Cannot be statically analyzed — may load arbitrary modules.' },
  { id: 'large-base64', regex: /[A-Za-z0-9+\/]{150,}={0,2}/,
    title: 'Large base64 blob (>150 chars)', description: 'May be obfuscated payload.' },
  { id: 'http-cleartext', regex: /fetch\s*\(\s*['"`]http:\/\/(?!localhost|127\.)/,
    title: 'Cleartext HTTP outbound', description: 'Data sent unencrypted.' },
  { id: 'settimeout-encoded', regex: /setTimeout\s*\([^,)]*(?:atob|fromCharCode|unescape)/,
    title: 'setTimeout with encoded callback', description: 'Evasion technique.' },
  { id: 'fromcharcode-obfuscation', regex: /String\.fromCharCode\s*\(\s*\d{2,3}\s*,\s*\d/,
    title: 'String.fromCharCode obfuscation', description: 'Classic string obfuscation used in malicious code.' },
  { id: 'hex-obfuscation', regex: /\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}/i,
    title: 'Hex-encoded string sequence', description: 'Multiple hex escapes may indicate obfuscated payload.' },
];

// Built-in skills (node_modules/openclaw): these patterns are OK — lower severity
export const BUILTIN_SAFE_PATTERN_IDS = new Set([
  'credential-file', // gh-issues reads config for API key — legitimate
]);

// Spawning a subprocess is OK in binary wrappers (TTS, image tools, etc.)
export function isSpawnInBinaryWrapper(filePath, snippet) {
  const isBinPath = /\/bin\/[^/]+$/.test(filePath);
  const hasTtsContext = /tts|speech|audio|whisper|sherpa|onnx/i.test(filePath + snippet);
  const hasImageContext = /image|vision|ffmpeg|convert/i.test(filePath + snippet);
  return isBinPath && (hasTtsContext || hasImageContext);
}

export const ALLOWLISTED_DOMAINS = new Set([
  'api.anthropic.com', 'api.openai.com', 'api.github.com',
  'registry.npmjs.org', 'raw.githubusercontent.com',
  'api.telegram.org', 'discord.com', 'slack.com',
  '127.0.0.1', 'localhost', '::1',
]);

export const SCANNABLE_EXTENSIONS = new Set([
  'js','ts','mjs','cjs','jsx','tsx','py','rb','sh','bash','zsh',
]);

export const SKIP_EXTENSIONS = new Set([
  'png','jpg','jpeg','gif','webp','ico','svg','ttf','woff','woff2',
  'zip','gz','tar','mp3','mp4','pdf','lock','sum',
]);
