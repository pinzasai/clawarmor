// Malicious code pattern definitions for skill scanning

export const CRITICAL_PATTERNS = [
  {
    id: 'eval',
    regex: /\beval\s*\(/g,
    title: 'eval() usage detected',
    description: 'eval() executes arbitrary code strings — a critical injection vector.',
  },
  {
    id: 'new-function',
    regex: /new\s+Function\s*\(/g,
    title: 'new Function() usage detected',
    description: 'new Function() is equivalent to eval() — executes arbitrary code.',
  },
  {
    id: 'child-process',
    regex: /require\s*\(\s*['"`]child_process['"`]\s*\)|from\s+['"`]child_process['"`]/g,
    title: 'child_process module imported',
    description: 'child_process allows executing shell commands — high risk in a skill.',
  },
  {
    id: 'exec-spawn',
    regex: /\b(execSync|spawnSync|execFileSync)\s*\(/g,
    title: 'Synchronous shell execution',
    description: 'Synchronous exec/spawn runs shell commands — serious risk.',
  },
  {
    id: 'pipe-to-shell',
    regex: /['"]\s*\|\s*(sh|bash|zsh|fish|cmd)\b/g,
    title: 'Pipe-to-shell pattern',
    description: 'Pipe-to-shell (curl|bash, wget|sh, etc.) — classic RCE vector.',
  },
  {
    id: 'vm-run',
    regex: /vm\.(runInNewContext|runInThisContext|Script)\s*\(/g,
    title: 'Node.js vm module code execution',
    description: 'vm module can execute code in sandboxed or unsandboxed contexts.',
  },
];

export const HIGH_PATTERNS = [
  {
    id: 'credential-file-read',
    regex: /agent-accounts|\.openclaw[\/\\].*token|credentials[\/\\].*\.json/gi,
    title: 'Credential file path referenced',
    description: 'References to credential files — may attempt to read API keys or tokens.',
  },
  {
    id: 'ssh-key-path',
    regex: /\.ssh[\/\\](id_rsa|id_ed25519|id_ecdsa|authorized_keys)/g,
    title: 'SSH key path referenced',
    description: 'References to SSH private keys — may attempt credential theft.',
  },
  {
    id: 'dynamic-require',
    regex: /require\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*\s*\)/g,
    title: 'Dynamic require() detected',
    description: 'require(variable) cannot be statically analyzed — may load arbitrary modules.',
  },
  {
    id: 'known-bad-domains',
    regex: /webhook\.site|requestbin\.|pipedream\.net|beeceptor\.com|hookbin\.com|canarytokens\./g,
    title: 'Known data collection domain referenced',
    description: 'Reference to a domain commonly used for data interception/exfiltration.',
  },
];

export const MEDIUM_PATTERNS = [
  {
    id: 'large-base64',
    regex: /[A-Za-z0-9+\/]{120,}={0,2}/g,
    title: 'Large base64 blob detected',
    description: 'Base64 strings >120 chars may be obfuscated code or embedded payloads.',
  },
  {
    id: 'http-not-https',
    regex: /fetch\s*\(\s*['"`]http:\/\/(?!localhost|127\.0\.0\.1)/g,
    title: 'Unencrypted HTTP outbound call',
    description: 'Outbound fetch over HTTP (not HTTPS) — data sent in cleartext.',
  },
];

export const SCANNABLE_EXTENSIONS = new Set([
  'js', 'ts', 'mjs', 'cjs', 'jsx', 'tsx',
  'py', 'rb', 'sh', 'bash', 'zsh',
]);

export const SKIP_EXTENSIONS = new Set([
  'png', 'jpg', 'jpeg', 'gif', 'webp', 'ico', 'svg',
  'ttf', 'woff', 'woff2', 'zip', 'gz', 'tar',
  'mp3', 'mp4', 'pdf', 'lock',
]);
