// ANSI color utilities — zero deps, pure escape codes
const isCI = process.env.CI || process.env.NO_COLOR || !process.stdout.isTTY;

const raw = (code) => isCI ? '' : `\x1b[${code}m`;
const reset = raw(0);

const c = {
  reset,
  bold:    raw(1),
  dim:     raw(2),

  red:     raw(31),
  green:   raw(32),
  yellow:  raw(33),
  cyan:    raw(36),
  white:   raw(37),

  brightRed:    raw(91),
  brightGreen:  raw(92),
  brightYellow: raw(93),
  brightCyan:   raw(96),
  brightWhite:  raw(97),

  bgRed:    raw(41),
  bgYellow: raw(43),
};

export const paint = {
  critical: (s) => `${c.bold}${c.brightRed}${s}${reset}`,
  high:     (s) => `${c.bold}${c.brightYellow}${s}${reset}`,
  medium:   (s) => `${c.bold}${c.yellow}${s}${reset}`,
  low:      (s) => `${c.bold}${c.cyan}${s}${reset}`,
  pass:     (s) => `${c.brightGreen}${s}${reset}`,
  fail:     (s) => `${c.brightRed}${s}${reset}`,
  dim:      (s) => `${c.dim}${s}${reset}`,
  bold:     (s) => `${c.bold}${s}${reset}`,
  cyan:     (s) => `${c.cyan}${s}${reset}`,
  white:    (s) => `${c.brightWhite}${s}${reset}`,
  green:    (s) => `${c.brightGreen}${s}${reset}`,
  red:      (s) => `${c.brightRed}${s}${reset}`,
  yellow:   (s) => `${c.yellow}${s}${reset}`,
};

export const severityColor = {
  CRITICAL: paint.critical,
  HIGH:     paint.high,
  MEDIUM:   paint.medium,
  LOW:      paint.low,
};

export default c;
