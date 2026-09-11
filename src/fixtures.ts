import type { Model } from './model.ts';

/** A payments service. The baseline everything is diffed against. */
export const BASE: Model = {
  name: 'payments',
  zones: ['internet', 'dmz', 'core'],
  components: [
    { id: 'browser', kind: 'external', zone: 'internet' },
    { id: 'edge', kind: 'process', zone: 'dmz', authenticates: true,
      logsAudit: true },
    { id: 'api', kind: 'process', zone: 'core', authenticates: true,
      logsAudit: true },
    { id: 'ledger_db', kind: 'datastore', zone: 'core', logsAudit: true },
  ],
  flows: [
    { id: 'f1', from: 'browser', to: 'edge', data: 'pii', protocol: 'https',
      authenticated: true, rateLimited: true },
    { id: 'f2', from: 'edge', to: 'api', data: 'pii', protocol: 'grpc-tls',
      authenticated: true, rateLimited: true },
    { id: 'f3', from: 'api', to: 'ledger_db', data: 'pii', protocol: 'sql',
      authenticated: true, rateLimited: true },
  ],
  mitigations: [],
};

export interface Mutation {
  readonly name: string;
  readonly model: Model;
  /** Expected NEW threat ids. Written down before the rule engine was built. */
  readonly expectAdded: readonly string[];
  /** Threats that already existed and got worse. */
  readonly expectEscalated?: readonly string[];
  readonly expectRemoved?: readonly string[];
  readonly expectGatePass: boolean;
}

const withFlows = (flows: Model['flows'], extra: Partial<Model> = {}): Model => ({
  ...BASE, ...extra, flows,
});

export const MUTATIONS: readonly Mutation[] = [
  {
    name: 'no change',
    model: BASE,
    expectAdded: [],
    expectGatePass: true,
  },
  {
    name: 'add an internal flow that stays inside core',
    model: withFlows([...BASE.flows, {
      id: 'f4', from: 'api', to: 'ledger_db', data: 'internal',
      protocol: 'sql', authenticated: true, rateLimited: true,
    }]),
    expectAdded: [],
    expectGatePass: true,
  },
  {
    name: 'expose an unauthenticated webhook from the internet',
    model: {
      ...BASE,
      components: [...BASE.components,
        { id: 'psp', kind: 'external' as const, zone: 'internet' }],
      flows: [...BASE.flows, {
        id: 'f5', from: 'psp', to: 'edge', data: 'pii', protocol: 'https',
        authenticated: false, rateLimited: false,
      }],
    },
    expectAdded: [
      'f5:Spoofing', 'f5:InformationDisclosure', 'f5:DenialOfService',
    ],
    expectGatePass: false,
  },
  {
    name: 'the same webhook, with mitigations recorded',
    model: {
      ...BASE,
      components: [...BASE.components,
        { id: 'psp', kind: 'external' as const, zone: 'internet' }],
      flows: [...BASE.flows, {
        id: 'f5', from: 'psp', to: 'edge', data: 'pii', protocol: 'https',
        authenticated: false, rateLimited: false,
      }],
      mitigations: [
        { threatId: 'f5:Spoofing', control: 'HMAC signature verification',
          owner: 'payments-team' },
        { threatId: 'f5:InformationDisclosure',
          control: 'field-level encryption of the card token',
          owner: 'payments-team' },
        { threatId: 'f5:DenialOfService', control: 'edge rate limit 100 rps',
          owner: 'platform' },
      ],
    },
    expectAdded: [
      'f5:Spoofing', 'f5:InformationDisclosure', 'f5:DenialOfService',
    ],
    expectGatePass: true,
  },
  {
    name: 'downgrade an internal hop to plaintext http',
    model: withFlows(BASE.flows.map((f) =>
      f.id === 'f2' ? { ...f, protocol: 'http' as const } : f)),
    // PII already crossed this boundary, so the disclosure threat was already
    // on the register - what changed is that it went from medium to high.
    expectAdded: ['f2:Tampering'],
    expectEscalated: ['f2:InformationDisclosure'],
    expectGatePass: false,
  },
  {
    name: 'expose the database directly to the dmz',
    model: {
      ...BASE,
      flows: [...BASE.flows, {
        id: 'f6', from: 'edge', to: 'ledger_db', data: 'pii', protocol: 'sql',
        authenticated: false, rateLimited: true,
      }],
    },
    expectAdded: [
      'f6:Spoofing', 'f6:Tampering', 'f6:InformationDisclosure',
      'f6:ElevationOfPrivilege',
    ],
    expectGatePass: false,
  },
  {
    name: 'add a component that does not keep an audit trail',
    model: {
      ...BASE,
      components: [...BASE.components,
        { id: 'reporting', kind: 'process' as const, zone: 'core',
          logsAudit: false }],
      flows: [...BASE.flows, {
        id: 'f7', from: 'api', to: 'reporting', data: 'pii', protocol: 'grpc-tls',
        authenticated: true, rateLimited: true,
      }],
    },
    expectAdded: ['f7:Repudiation'],
    expectGatePass: false,
  },
  {
    name: 'remove the plaintext hop again',
    model: BASE,
    expectAdded: [],
    expectGatePass: true,
  },
];
