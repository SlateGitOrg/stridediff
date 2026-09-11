import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  diff, gate, threatsFor, crossesBoundary, renderComment, renderMermaid,
} from '../src/model.ts';
import { BASE, MUTATIONS } from '../src/fixtures.ts';

describe('the expected threat delta, mutation by mutation', () => {
  for (const m of MUTATIONS) {
    test(`${m.name}`, () => {
      const d = diff(BASE, m.model);
      assert.deepEqual(d.added.map((t) => t.id).sort(), [...m.expectAdded].sort(),
        `added threats for "${m.name}" did not match what was written first`);
      assert.deepEqual(
        d.escalated.map((e) => e.after.id).sort(),
        [...(m.expectEscalated ?? [])].sort(),
        `escalated threats for "${m.name}" did not match`);
    });
  }
});

describe('the gate', () => {
  test('fails only on NEW threats with no mitigation', () => {
    for (const m of MUTATIONS) {
      const r = gate(BASE, m.model);
      assert.equal(r.passed, m.expectGatePass,
        `gate verdict for "${m.name}" was ${r.passed}`);
    }
  });

  test('THE FALSE-POSITIVE CASE: a recorded mitigation does not fail the gate', () => {
    // Without this, the gate fires on every change that touches a boundary and
    // gets routed around within a sprint.
    const unmitigated = MUTATIONS.find(
      (m) => m.name === 'expose an unauthenticated webhook from the internet')!;
    const mitigated = MUTATIONS.find(
      (m) => m.name === 'the same webhook, with mitigations recorded')!;

    const a = gate(BASE, unmitigated.model);
    const b = gate(BASE, mitigated.model);

    assert.equal(a.passed, false);
    assert.equal(b.passed, true);
    // The threats are identical; only the recorded response differs.
    assert.deepEqual(
      a.delta.added.map((t) => t.id).sort(),
      b.delta.added.map((t) => t.id).sort(),
    );
    assert.equal(b.mitigated.length, 3);
  });

  test('pre-existing threats never fail the gate', () => {
    // The base model already has threats. A change that adds nothing new must
    // pass, or every pull request becomes unmergeable.
    const r = gate(BASE, BASE);
    assert.equal(r.passed, true);
    assert.ok(r.delta.unchanged.length > 0,
      'the base model should already carry threats');
  });

  test('every mitigation names an owner', () => {
    const m = MUTATIONS.find(
      (x) => x.name === 'the same webhook, with mitigations recorded')!;
    for (const mit of gate(BASE, m.model).mitigated) {
      assert.ok(mit.owner.length > 0);
      assert.ok(mit.control.length > 0);
    }
  });

  test('reverting the downgrade removes one threat and de-escalates another', () => {
    const risky = MUTATIONS.find(
      (m) => m.name === 'downgrade an internal hop to plaintext http')!;
    const d = diff(risky.model, BASE);

    assert.deepEqual(d.added, [], 'restoring TLS introduces nothing');
    assert.deepEqual(d.removed.map((t) => t.id), ['f2:Tampering']);
    // Disclosure does not disappear - PII still leaves its zone - it drops
    // from high back to medium. Reporting it as "removed" would overstate the
    // benefit of the fix.
    assert.equal(d.escalated.length, 0);
    const still = d.unchanged.find((t) => t.id === 'f2:InformationDisclosure');
    assert.ok(still);
    assert.equal(still!.severity, 'medium');
  });

  test('an escalation is caught even though the threat id is not new', () => {
    const risky = MUTATIONS.find(
      (m) => m.name === 'downgrade an internal hop to plaintext http')!;
    const d = diff(BASE, risky.model);
    assert.equal(d.escalated.length, 1);
    assert.equal(d.escalated[0]!.after.id, 'f2:InformationDisclosure');
    assert.equal(d.escalated[0]!.before.severity, 'medium');
    assert.equal(d.escalated[0]!.after.severity, 'high');
  });

  test('an escalated threat fails the gate like a new one', () => {
    const risky = MUTATIONS.find(
      (m) => m.name === 'downgrade an internal hop to plaintext http')!;
    const r = gate(BASE, risky.model);
    assert.equal(r.passed, false);
    assert.ok(r.unmitigated.some((t) => t.id === 'f2:InformationDisclosure'));
  });
});

describe('threat derivation rules', () => {
  test('a flow inside one zone crosses no boundary', () => {
    assert.equal(crossesBoundary(BASE, BASE.flows[2]!), false);
  });

  test('a flow between zones does cross one', () => {
    assert.equal(crossesBoundary(BASE, BASE.flows[0]!), true);
  });

  test('plaintext across a boundary raises tampering AND disclosure for PII', () => {
    const m = MUTATIONS.find(
      (x) => x.name === 'downgrade an internal hop to plaintext http')!;
    const ids = threatsFor(m.model).map((t) => t.id);
    assert.ok(ids.includes('f2:Tampering'));
    assert.ok(ids.includes('f2:InformationDisclosure'));
  });

  test('PII crossing a boundary is flagged even when encrypted', () => {
    // Encryption protects it in transit; the receiving zone still holds it.
    const t = threatsFor(BASE).find((x) => x.id === 'f1:InformationDisclosure');
    assert.ok(t, 'encrypted PII egress should still be a recorded threat');
    assert.equal(t!.severity, 'medium');
  });

  test('severity rises when the data is sensitive', () => {
    const m = MUTATIONS.find((x) => x.name.startsWith('expose an unauth'))!;
    const spoof = threatsFor(m.model).find((t) => t.id === 'f5:Spoofing')!;
    assert.equal(spoof.severity, 'high');
  });

  test('not every flow gets all six categories', () => {
    // Emitting all of STRIDE for everything is defensible and useless.
    const perFlow = new Map<string, number>();
    for (const t of threatsFor(BASE)) {
      perFlow.set(t.flowId, (perFlow.get(t.flowId) ?? 0) + 1);
    }
    for (const [, n] of perFlow) assert.ok(n < 6);
  });
});

describe('the PR comment', () => {
  test('names the flow, the category and the reason', () => {
    const m = MUTATIONS.find((x) => x.name.startsWith('expose an unauth'))!;
    const md = renderComment(BASE, m.model);
    assert.match(md, /\*\*FAIL\*\*/);
    assert.match(md, /`f5`/);
    assert.match(md, /Spoofing/);
    assert.match(md, /whoever claims to be the caller/);
  });

  test('reports PASS with the mitigations listed', () => {
    const m = MUTATIONS.find((x) => x.name.startsWith('the same webhook'))!;
    const md = renderComment(BASE, m.model);
    assert.match(md, /\*\*PASS\*\*/);
    assert.match(md, /HMAC signature verification/);
    assert.match(md, /owner: payments-team/);
  });

  test('embeds a diagram that marks boundary-crossing flows', () => {
    const mermaid = renderMermaid(BASE);
    assert.match(mermaid, /flowchart LR/);
    assert.match(mermaid, /subgraph/);
    assert.match(mermaid, /browser ==>/, 'boundary crossings use a bold edge');
    assert.match(mermaid, /api -->/, 'internal flows use a plain edge');
  });
});
