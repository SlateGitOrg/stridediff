/**
 * The 60-second artefact: the PR comment. Run: `npm run demo`
 */
import { renderComment, gate, diff } from './model.ts';
import { BASE, MUTATIONS } from './fixtures.ts';

console.log('\n  STRIDEDIFF - the threat model is reviewed per change, not per year');
console.log('  ' + '-'.repeat(70));

console.log('\n  Mutations against the payments baseline:\n');
console.log(`  ${'change'.padEnd(46)}${'new'.padEnd(6)}${'worse'.padEnd(7)}gate`);
console.log('  ' + '-'.repeat(70));
for (const m of MUTATIONS) {
  const d = diff(BASE, m.model);
  const r = gate(BASE, m.model);
  console.log(`  ${m.name.padEnd(46)}${String(d.added.length).padEnd(6)}` +
              `${String(d.escalated.length).padEnd(7)}${r.passed ? 'PASS' : 'FAIL'}`);
}

const webhook = MUTATIONS.find(
  (m) => m.name === 'expose an unauthenticated webhook from the internet')!;

console.log('\n  The comment posted on the webhook pull request:');
console.log('  ' + '-'.repeat(70));
console.log(renderComment(BASE, webhook.model)
  .split('\n').map((l) => '    ' + l).join('\n'));

const downgrade = MUTATIONS.find(
  (m) => m.name === 'downgrade an internal hop to plaintext http')!;
const d = diff(BASE, downgrade.model);
console.log('\n  The case an added/removed diff misses entirely:');
console.log('  ' + '-'.repeat(70));
console.log(`    Changing f2 from grpc-tls to http adds ${d.added.length} threat.`);
for (const e of d.escalated) {
  console.log(`    But it also escalates an EXISTING one:`);
  console.log(`      ${e.after.flowId} ${e.after.category}: ` +
              `${e.before.severity} -> ${e.after.severity}`);
}
console.log('    PII was already leaving its zone, so the threat id is not new.');
console.log('    A tool that only diffs ids reports that change as harmless.\n');
