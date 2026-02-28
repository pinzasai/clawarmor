import { paint } from './colors.js';

export function progressBar(score, width = 20) {
  const filled = Math.round((score / 100) * width);
  return '█'.repeat(filled) + '░'.repeat(width - filled);
}

export function scoreToGrade(score) {
  if (score >= 90) return 'A';
  if (score >= 75) return 'B';
  if (score >= 60) return 'C';
  if (score >= 40) return 'D';
  return 'F';
}

export function scoreColor(score) {
  if (score >= 90) return paint.green;
  if (score >= 75) return paint.pass;
  if (score >= 60) return paint.yellow;
  if (score >= 40) return paint.high;
  return paint.critical;
}

export function gradeColor(grade) {
  const map = { A: paint.green, B: paint.pass, C: paint.yellow, D: paint.high, F: paint.critical };
  return (map[grade] || paint.dim)(grade);
}
