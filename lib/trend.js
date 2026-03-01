// ClawArmor v1.0.0 — trend command
// Shows score over last N audits as an ASCII line chart.

import { paint } from './output/colors.js';
import { loadHistory } from './audit.js';

const SEP = paint.dim('─'.repeat(52));
const W52 = 52;

function box(title) {
  const pad = W52 - 2 - title.length;
  const l = Math.floor(pad/2), r = pad - l;
  return [
    paint.dim('╔' + '═'.repeat(W52-2) + '╗'),
    paint.dim('║') + ' '.repeat(l) + paint.bold(title) + ' '.repeat(r) + paint.dim('║'),
    paint.dim('╚' + '═'.repeat(W52-2) + '╝'),
  ].join('\n');
}

function scoreColor(score) {
  if (score >= 90) return paint.green;
  if (score >= 75) return s => paint.pass ? paint.pass(s) : s;
  if (score >= 60) return paint.yellow;
  return paint.red;
}

function formatDate(iso) {
  const d = new Date(iso);
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
}

// Build ASCII line chart from score data points
// chartWidth: number of columns, chartHeight: number of rows
function buildChart(scores, chartWidth = 36, chartHeight = 8) {
  if (!scores.length) return [];
  const minScore = 0;
  const maxScore = 100;
  const range = maxScore - minScore;

  // Map each score to a row (0 = bottom, chartHeight-1 = top)
  function scoreToRow(s) {
    return Math.round(((s - minScore) / range) * (chartHeight - 1));
  }

  // Build a 2D grid: rows[row][col]
  const grid = Array.from({ length: chartHeight }, () => Array(chartWidth).fill(' '));

  // Place points and draw connecting lines
  const n = scores.length;
  const colStep = n === 1 ? 0 : (chartWidth - 1) / (n - 1);

  for (let i = 0; i < n; i++) {
    const col = Math.round(i * colStep);
    const row = chartHeight - 1 - scoreToRow(scores[i]);

    if (i > 0) {
      const prevCol = Math.round((i - 1) * colStep);
      const prevRow = chartHeight - 1 - scoreToRow(scores[i - 1]);
      // Draw line between previous and current point
      const dc = col - prevCol;
      const dr = row - prevRow;
      const steps = Math.max(Math.abs(dc), Math.abs(dr), 1);
      for (let s = 0; s <= steps; s++) {
        const ic = Math.round(prevCol + (dc * s) / steps);
        const ir = Math.round(prevRow + (dr * s) / steps);
        if (ic >= 0 && ic < chartWidth && ir >= 0 && ir < chartHeight) {
          if (grid[ir][ic] === ' ') {
            // Choose connecting character based on direction
            if (dr === 0) grid[ir][ic] = '─';
            else if (dc === 0) grid[ir][ic] = '│';
            else if ((dr < 0 && dc > 0) || (dr > 0 && dc < 0)) grid[ir][ic] = '╯';
            else grid[ir][ic] = '╭';
          }
        }
      }
    }
    // Place data point (overwrite connection chars)
    const r2 = chartHeight - 1 - scoreToRow(scores[i]);
    if (col >= 0 && col < chartWidth && r2 >= 0 && r2 < chartHeight) {
      grid[r2][col] = '●';
    }
  }

  return grid;
}

export async function runTrend(flags = {}) {
  const N = flags.n || 10;
  const history = loadHistory();

  console.log(''); console.log(box('ClawArmor Trend  v1.0.0')); console.log('');

  if (!history.length) {
    console.log(`  ${paint.dim('No audit history yet.')}`);
    console.log(`  ${paint.dim('Run')} ${paint.cyan('clawarmor audit')} ${paint.dim('to start tracking your score.')}`);
    console.log('');
    return 0;
  }

  const recent = history.slice(-N);
  const scores = recent.map(h => h.score);
  const first = scores[0];
  const last = scores[scores.length - 1];
  const delta = last - first;

  console.log(`  ${paint.dim('Last')} ${paint.bold(String(recent.length))} ${paint.dim('audit' + (recent.length !== 1 ? 's' : ''))}`);
  console.log('');

  if (recent.length === 1) {
    const sc = scoreColor(last);
    console.log(`  ${paint.dim('Score:')} ${sc(String(last) + '/100')}  ${paint.dim('(only one audit — run more to see trend)')}`);
    console.log('');
    return 0;
  }

  // Build chart
  const CHART_W = 36;
  const CHART_H = 8;
  const grid = buildChart(scores, CHART_W, CHART_H);

  // Y-axis labels: 0, 25, 50, 75, 100
  const yLabels = [100, 75, 50, 25, 0];

  // Print chart with Y-axis
  for (let row = 0; row < CHART_H; row++) {
    // Find nearest y label for this row
    const scoreAtRow = Math.round(100 - (row / (CHART_H - 1)) * 100);
    const showLabel = yLabels.includes(scoreAtRow);
    const label = showLabel ? String(scoreAtRow).padStart(3) : '   ';
    const line = grid[row].join('');
    // Color the chart line
    const colored = line.replace(/●/g, paint.cyan('●'));
    console.log(`  ${paint.dim(label)} ${paint.dim('┤')} ${colored}`);
  }

  // X-axis
  const xAxis = '─'.repeat(CHART_W + 2);
  console.log(`      ${paint.dim('└' + xAxis)}`);

  // Date labels: first and last
  const dateFirst = formatDate(recent[0].timestamp);
  const dateLast = formatDate(recent[recent.length - 1].timestamp);
  const dateGap = Math.max(0, CHART_W - dateFirst.length - dateLast.length + 2);
  console.log(`      ${paint.dim(dateFirst)}${' '.repeat(dateGap)}${paint.dim(dateLast)}`);

  console.log('');

  // Summary line
  const deltaStr = delta > 0 ? paint.green(`+${delta}`) : delta < 0 ? paint.red(String(delta)) : paint.dim('±0');
  const sc = scoreColor(last);
  console.log(`  ${paint.dim('Current score:')} ${sc(String(last) + '/100')}`);

  if (recent.length > 1) {
    if (delta === 0) {
      console.log(`  ${paint.dim('Score unchanged since first audit.')}`);
    } else {
      const word = delta > 0 ? 'improved' : 'dropped';
      console.log(`  Score ${word} ${deltaStr} ${paint.dim('points since')} ${paint.dim(formatDate(recent[0].timestamp))}.`);
    }
  }

  // Show per-audit table if ≤ 7 entries
  if (recent.length <= 7) {
    console.log('');
    console.log(SEP);
    console.log(`  ${paint.dim('Date')}              ${paint.dim('Score')}  ${paint.dim('Grade')}  ${paint.dim('Issues')}`);
    console.log(SEP);
    for (const h of recent) {
      const sc2 = scoreColor(h.score);
      const date = formatDate(h.timestamp).padEnd(16);
      const score = sc2(String(h.score).padStart(3) + '/100');
      const grade = h.grade || '-';
      const issues = h.findings > 0 ? paint.yellow(String(h.findings)) : paint.green('0');
      console.log(`  ${paint.dim(date)}  ${score}   ${grade}      ${issues}`);
    }
  }

  console.log('');
  return 0;
}
