const C = {
  reset: '\x1b[0m', bold: '\x1b[1m', dim: '\x1b[2m',
  red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m',
  blue: '\x1b[34m', cyan: '\x1b[36m', white: '\x1b[37m',
  bgRed: '\x1b[41m',
};
const noColor = process.env.NO_COLOR || !process.stdout.isTTY;
const c = (code, s) => noColor ? s : `${code}${s}${C.reset}`;

export const paint = {
  bold: s => c(C.bold, s), dim: s => c(C.dim, s),
  red: s => c(C.red, s), green: s => c(C.green, s),
  yellow: s => c(C.yellow, s), cyan: s => c(C.cyan, s),
  pass: s => c(C.green, s), high: s => c(C.yellow, s),
  critical: s => c(C.red, s),
};

export const severityColor = {
  CRITICAL: s => c(C.red + C.bold, s),
  HIGH: s => c(C.yellow, s),
  MEDIUM: s => c(C.cyan, s),
  LOW: s => c(C.dim, s),
  INFO: s => c(C.dim, s),
};
