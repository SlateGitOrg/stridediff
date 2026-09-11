/**
 * Architecture as code, and STRIDE derived from it.
 *
 * THE DIFFERENTIATOR LIVES HERE.
 *
 * A threat model is written once during design review, the architecture then
 * changes forty times, and the document is never touched again. Security review
 * becomes a calendar event: it happens when nothing is being built, and the
 * building happens when nobody is reviewing.
 *
 * So the model is code, it lives beside the system it describes, and the unit
 * of review is the DELTA. "This change adds a flow crossing the internet trust
 * boundary carrying PII; new threats: spoofing, tampering, information
 * disclosure" is a review comment. A 40-page PDF is not.
 *
 * The gate fails on a new threat with no recorded mitigation. Nothing else.
 * A gate that fires on every related threat is one people route around.
 */

export type Stride =
  | 'Spoofing' | 'Tampering' | 'Repudiation'
  | 'InformationDisclosure' | 'DenialOfService' | 'ElevationOfPrivilege';

export type DataClass = 'public' | 'internal' | 'pii' | 'secret';

export interface Component {
  readonly id: string;
  readonly kind: 'process' | 'datastore' | 'external';
  /** The trust boundary this component sits inside. */
  readonly zone: string;
  readonly authenticates?: boolean;
  readonly logsAudit?: boolean;
}

export interface Flow {
  readonly id: string;
  readonly from: string;
  readonly to: string;
  readonly data: DataClass;
  readonly protocol: 'http' | 'https' | 'grpc-tls' | 'amqp' | 'sql' | 'file';
  readonly authenticated?: boolean;
  readonly rateLimited?: boolean;
}

export interface Model {
  readonly name: string;
  readonly zones: readonly string[];
  readonly components: readonly Component[];
  readonly flows: readonly Flow[];
  readonly mitigations?: readonly Mitigation[];
}

export interface Mitigation {
  /** `${flowId}:${category}` */
  readonly threatId: string;
  readonly control: string;
  readonly owner: string;
}

export interface Threat {
  readonly id: string;
  readonly flowId: string;
  readonly category: Stride;
  readonly rationale: string;
  readonly crossesBoundary: boolean;
  readonly severity: 'low' | 'medium' | 'high';
}

function componentOf(model: Model, id: string): Component | undefined {
  return model.components.find((c) => c.id === id);
}

export function crossesBoundary(model: Model, flow: Flow): boolean {
  const a = componentOf(model, flow.from);
  const b = componentOf(model, flow.to);
  if (!a || !b) return false;
  return a.zone !== b.zone;
}

const SENSITIVE: DataClass[] = ['pii', 'secret'];
const ENCRYPTED = new Set(['https', 'grpc-tls']);

/**
 * Derive the applicable threats for one flow.
 *
 * The rules are deliberately narrow and explicit. Emitting all six STRIDE
 * categories for every flow is technically defensible and practically useless:
 * it produces a constant, uniform wall of threats with no signal about which
 * change made things worse.
 */
export function threatsForFlow(model: Model, flow: Flow): Threat[] {
  const out: Threat[] = [];
  const boundary = crossesBoundary(model, flow);
  const sensitive = SENSITIVE.includes(flow.data);
  const encrypted = ENCRYPTED.has(flow.protocol);
  const target = componentOf(model, flow.to);

  const add = (
    category: Stride, rationale: string, severity: Threat['severity'],
  ) => out.push({
    id: `${flow.id}:${category}`, flowId: flow.id, category, rationale,
    crossesBoundary: boundary, severity,
  });

  if (boundary && !flow.authenticated) {
    add('Spoofing',
        'unauthenticated flow crosses a trust boundary - the caller is ' +
        'whoever claims to be the caller',
        sensitive ? 'high' : 'medium');
  }
  if (boundary && !encrypted) {
    add('Tampering',
        `unencrypted ${flow.protocol} across a trust boundary can be modified ` +
        'in transit',
        sensitive ? 'high' : 'medium');
    if (sensitive) {
      add('InformationDisclosure',
          `${flow.data} sent unencrypted across a trust boundary`, 'high');
    }
  }
  if (sensitive && boundary && encrypted) {
    add('InformationDisclosure',
        `${flow.data} leaves its trust zone; encrypted in transit, but the ` +
        'receiving zone now holds it',
        'medium');
  }
  if (target?.logsAudit === false && flow.data !== 'public') {
    add('Repudiation',
        `${flow.to} does not keep an audit trail, so this action cannot be ` +
        'attributed afterwards',
        'medium');
  }
  if (boundary && !flow.rateLimited && target?.kind === 'process') {
    add('DenialOfService',
        'externally reachable process with no rate limit', 'medium');
  }
  if (boundary && target?.kind === 'datastore' && !flow.authenticated) {
    add('ElevationOfPrivilege',
        'unauthenticated direct access to a datastore across a boundary',
        'high');
  }
  return out;
}

export function threatsFor(model: Model): Threat[] {
  return model.flows.flatMap((f) => threatsForFlow(model, f));
}

// ---------------------------------------------------------------------------

export interface Escalation {
  readonly before: Threat;
  readonly after: Threat;
}

export interface ThreatDelta {
  readonly added: readonly Threat[];
  readonly removed: readonly Threat[];
  /**
   * A threat that already existed but got WORSE.
   *
   * This category exists because an id-based diff misses it entirely, and it
   * is a very easy thing to miss in review. Downgrading an internal hop from
   * TLS to plaintext does not create a new information-disclosure threat - PII
   * was already leaving its zone, so the threat was already on the register.
   * What changed is that it went from medium to high. A model that only
   * reports added/removed reports that change as nothing at all.
   */
  readonly escalated: readonly Escalation[];
  readonly unchanged: readonly Threat[];
}

const SEVERITY_RANK: Record<Threat['severity'], number> = {
  low: 0, medium: 1, high: 2,
};

export function diff(base: Model, head: Model): ThreatDelta {
  const before = new Map(threatsFor(base).map((t) => [t.id, t]));
  const after = new Map(threatsFor(head).map((t) => [t.id, t]));

  const added = [...after.values()].filter((t) => !before.has(t.id));
  const removed = [...before.values()].filter((t) => !after.has(t.id));

  const escalated: Escalation[] = [];
  const unchanged: Threat[] = [];
  for (const t of after.values()) {
    const prev = before.get(t.id);
    if (!prev) continue;
    if (SEVERITY_RANK[t.severity] > SEVERITY_RANK[prev.severity]) {
      escalated.push({ before: prev, after: t });
    } else {
      unchanged.push(t);
    }
  }
  return { added, removed, escalated, unchanged };
}

export interface GateResult {
  readonly passed: boolean;
  readonly unmitigated: readonly Threat[];
  readonly mitigated: ReadonlyArray<{ threat: Threat; control: string; owner: string }>;
  readonly delta: ThreatDelta;
}

/**
 * The gate fails only on NEW threats with no recorded mitigation.
 *
 * Pre-existing threats are not the business of this pull request, and failing
 * on them would make every change unmergeable - the same dynamic that gets
 * accessibility and lint gates disabled.
 */
export function gate(base: Model, head: Model): GateResult {
  const delta = diff(base, head);
  const mitigations = new Map(
    (head.mitigations ?? []).map((m) => [m.threatId, m]));

  const unmitigated: Threat[] = [];
  const mitigated: Array<{ threat: Threat; control: string; owner: string }> = [];

  // An escalated threat is new risk even though the threat id is not new, so
  // it needs a mitigation just as an added one does.
  const requiresResponse = [
    ...delta.added, ...delta.escalated.map((e) => e.after),
  ];
  for (const t of requiresResponse) {
    const m = mitigations.get(t.id);
    if (m) mitigated.push({ threat: t, control: m.control, owner: m.owner });
    else unmitigated.push(t);
  }
  return { passed: unmitigated.length === 0, unmitigated, mitigated, delta };
}

/** The PR comment, including a diagram - a gate that cannot explain itself
 *  gets overridden. */
export function renderComment(base: Model, head: Model): string {
  const r = gate(base, head);
  const lines: string[] = ['### Threat model delta', ''];

  lines.push(r.passed
    ? '**PASS** - no unmitigated new threats.'
    : `**FAIL** - ${r.unmitigated.length} new threat(s) with no mitigation.`);
  lines.push('');

  if (r.unmitigated.length) {
    lines.push('| flow | threat | severity | why |', '|---|---|---|---|');
    for (const t of r.unmitigated) {
      lines.push(`| \`${t.flowId}\` | ${t.category} | ${t.severity} | ${t.rationale} |`);
    }
    lines.push('');
  }
  if (r.mitigated.length) {
    lines.push('New threats with a recorded mitigation:', '');
    for (const m of r.mitigated) {
      lines.push(`- ${m.threat.category} on \`${m.threat.flowId}\` - ` +
                 `${m.control} (owner: ${m.owner})`);
    }
    lines.push('');
  }
  if (r.delta.escalated.length) {
    lines.push('Existing threats that got worse:', '');
    for (const e of r.delta.escalated) {
      lines.push(`- \`${e.after.flowId}\` ${e.after.category}: ` +
                 `${e.before.severity} -> ${e.after.severity} (${e.after.rationale})`);
    }
    lines.push('');
  }
  if (r.delta.removed.length) {
    lines.push(`${r.delta.removed.length} threat(s) removed by this change.`, '');
  }
  lines.push('```mermaid', renderMermaid(head), '```');
  return lines.join('\n');
}

export function renderMermaid(model: Model): string {
  const lines = ['flowchart LR'];
  for (const zone of model.zones) {
    lines.push(`  subgraph ${zone.replace(/\W/g, '_')}["${zone}"]`);
    for (const c of model.components.filter((x) => x.zone === zone)) {
      const shape = c.kind === 'datastore' ? `[("${c.id}")]` : `["${c.id}"]`;
      lines.push(`    ${c.id.replace(/\W/g, '_')}${shape}`);
    }
    lines.push('  end');
  }
  for (const f of model.flows) {
    const mark = crossesBoundary(model, f) ? '==>' : '-->';
    lines.push(`  ${f.from.replace(/\W/g, '_')} ${mark}|"${f.data}/${f.protocol}"| ` +
               `${f.to.replace(/\W/g, '_')}`);
  }
  return lines.join('\n');
}
