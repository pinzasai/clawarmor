// clawarmor monitor — continuous monitoring (hosted tier)
import { paint } from './output/colors.js';

const WIDTH = 50;
const HR = paint.dim('─'.repeat(WIDTH));

function box(title) {
  const pad = Math.max(0, WIDTH - 2 - title.length);
  const l = Math.floor(pad / 2), r = pad - l;
  return [
    paint.dim('╔' + '═'.repeat(WIDTH - 2) + '╗'),
    paint.dim('║') + ' '.repeat(l) + paint.bold(title) + ' '.repeat(r) + paint.dim('║'),
    paint.dim('╚' + '═'.repeat(WIDTH - 2) + '╝'),
  ].join('\n');
}

export function runMonitor() {
  console.log('');
  console.log(box('ClawArmor Monitor'));
  console.log('');
  console.log(`  ${paint.bold('Continuous protection for your OpenClaw instance.')}`);
  console.log('');
  console.log(HR);
  console.log('');
  console.log(`  ${paint.cyan('What you get:')}  `);
  console.log('');
  console.log(`    ${paint.dim('Know before attackers do.')}`);
  console.log('');
  console.log(`  ${paint.green('✓')} Instant Telegram/Signal alerts`);
  console.log(`    ${paint.dim('Delivered through your own configured channels.')}`);
  console.log('');
  console.log(`  ${paint.green('✓')} Daily security score reports`);
  console.log(`    ${paint.dim('Track your posture over time. See what changed.')}`);
  console.log('');
  console.log(`  ${paint.green('✓')} Skill supply chain monitoring`);
  console.log(`    ${paint.dim('Alerts when a skill you have installed matches')}`);
  console.log(`    ${paint.dim('a new known-bad pattern.')}`);
  console.log('');
  console.log(`  ${paint.green('✓')} Re-check after fixes`);
  console.log(`    ${paint.dim('Confirm your instance is secure — from the outside.')}`);
  console.log('');
  console.log(HR);
  console.log('');
  console.log(`  ${paint.bold('Pricing:')}  ${paint.cyan('$9 / month')}  ${paint.dim('— cancel anytime')}`);
  console.log('');
  console.log(`  ${paint.bold('Get started:')}  ${paint.cyan('github.com/pinzasai/clawarmor')}`);
  console.log('');
  console.log(HR);
  console.log('');
  console.log(`  ${paint.dim('Questions? github.com/pinzasai/clawarmor/issues')}`);
  console.log('');
}
