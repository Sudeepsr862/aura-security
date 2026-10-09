// ─── AURA Mock Data ──────────────────────────────────────────────────────────
// ⚠️  SAMPLE DATA ONLY — for visual preview during the prototype phase.
// None of these records were detected from real network traffic.
// Replace this file with backend API responses in a later phase.

import type {
  ActivityRow,
  InventoryService,
  RiskCard,
  IncidentRow,
  IntegrationTile,
} from './types';

// ── Overview: summary counters ────────────────────────────────────────────────
export const SAMPLE_SUMMARY = {
  aiLikeEvents: 142,
  servicesNeedingReview: 7,
  highRiskSampleEvents: 3,
  openSampleIncidents: 2,
} as const;

// ── Overview: recent-activity table ──────────────────────────────────────────
export const SAMPLE_ACTIVITY: ActivityRow[] = [
  {
    id: 'act-1',
    destination: 'api.openai.com',
    providerType: 'Cloud AI — OpenAI',
    sampleRisk: 'medium',
    dataLabel: 'Internal',
    time: '10:42 AM (sample)',
  },
  {
    id: 'act-2',
    destination: 'localhost:11434',
    providerType: 'Possible local AI endpoint',
    sampleRisk: 'high',
    dataLabel: 'Confidential',
    time: '10:38 AM (sample)',
  },
  {
    id: 'act-3',
    destination: 'github.com',
    providerType: 'Ordinary web — GitHub',
    sampleRisk: 'low',
    dataLabel: 'Public',
    time: '10:31 AM (sample)',
  },
  {
    id: 'act-4',
    destination: 'bard.google.com',
    providerType: 'Cloud AI — Google',
    sampleRisk: 'medium',
    dataLabel: 'Internal',
    time: '10:17 AM (sample)',
  },
  {
    id: 'act-5',
    destination: '192.168.1.55:8080',
    providerType: 'Unknown destination',
    sampleRisk: 'high',
    dataLabel: 'Restricted',
    time: '09:54 AM (sample)',
  },
];

// ── AI Inventory ──────────────────────────────────────────────────────────────
export const SAMPLE_INVENTORY: InventoryService[] = [
  {
    id: 'svc-1',
    name: 'OpenAI API',
    domainOrPort: 'api.openai.com',
    kind: 'Cloud AI',
    approval: 'Approved',
    firstSeen: '2024-09-01 (sample)',
    sampleEventCount: 84,
  },
  {
    id: 'svc-2',
    name: 'Google Gemini / Bard',
    domainOrPort: 'bard.google.com',
    kind: 'Cloud AI',
    approval: 'Needs review',
    firstSeen: '2024-10-03 (sample)',
    sampleEventCount: 31,
    note: 'Personal Google account detected; enterprise account not confirmed.',
  },
  {
    id: 'svc-3',
    name: 'Ollama (possible local)',
    domainOrPort: 'localhost:11434',
    kind: 'Possible local AI',
    approval: 'Unapproved',
    firstSeen: '2024-10-07 (sample)',
    sampleEventCount: 12,
    note:
      'Port 11434 is commonly used by Ollama. A port match is only a clue — it does not confirm a model is running.',
  },
  {
    id: 'svc-4',
    name: 'GitHub',
    domainOrPort: 'github.com',
    kind: 'Ordinary web',
    approval: 'Approved',
    firstSeen: '2024-08-15 (sample)',
    sampleEventCount: 210,
  },
  {
    id: 'svc-5',
    name: 'Unknown host',
    domainOrPort: '192.168.1.55:8080',
    kind: 'Possible local AI',
    approval: 'Unknown',
    firstSeen: '2024-10-07 (sample)',
    sampleEventCount: 5,
    note: 'Internal IP with unrecognised port. Classification uncertain.',
  },
  {
    id: 'svc-6',
    name: 'Claude (Anthropic)',
    domainOrPort: 'api.anthropic.com',
    kind: 'Cloud AI',
    approval: 'Needs review',
    firstSeen: '2024-10-05 (sample)',
    sampleEventCount: 9,
  },
];

// ── Data & Risk: sample risk cards ───────────────────────────────────────────
export const SAMPLE_RISK_CARDS: RiskCard[] = [
  {
    id: 'risk-1',
    title: 'Confidential file upload to unapproved AI',
    destination: 'localhost:11434',
    dataLabel: 'Confidential',
    score: 82,
    factors: [
      'Service not approved',
      'Data label: Confidential',
      'Device authorization unknown',
      'Transfer volume: moderate',
    ],
    note: 'Illustrative sample value — not a validated prediction.',
  },
  {
    id: 'risk-2',
    title: 'Internal document shared with personal AI account',
    destination: 'bard.google.com',
    dataLabel: 'Internal',
    score: 55,
    factors: [
      'Account type unconfirmed',
      'Data label: Internal',
      'Device authorized',
      'Transfer volume: low',
    ],
    note: 'Illustrative sample value — not a validated prediction.',
  },
  {
    id: 'risk-3',
    title: 'Public repo accessed via approved AI tool',
    destination: 'api.openai.com',
    dataLabel: 'Public',
    score: 14,
    factors: [
      'Service approved',
      'Data label: Public',
      'Device authorized',
      'Transfer volume: low',
    ],
    note: 'Illustrative sample value — not a validated prediction.',
  },
];

// ── Incidents ─────────────────────────────────────────────────────────────────
export const SAMPLE_INCIDENTS: IncidentRow[] = [
  {
    id: 'inc-1',
    severity: 'high',
    title: 'Confidential data sent to unapproved local AI endpoint',
    destination: 'localhost:11434',
    syntheticDevice: 'DEVICE-SYN-042',
    syntheticUser: 'user-syn-7',
    status: 'Open',
    time: '2024-10-07 10:38 (sample)',
  },
  {
    id: 'inc-2',
    severity: 'medium',
    title: 'Unreviewed cloud AI service detected on managed device',
    destination: 'bard.google.com',
    syntheticDevice: 'DEVICE-SYN-018',
    syntheticUser: 'user-syn-3',
    status: 'Under review',
    time: '2024-10-06 14:22 (sample)',
  },
  {
    id: 'inc-3',
    severity: 'critical',
    title: 'Restricted data label observed near unknown internal host',
    destination: '192.168.1.55:8080',
    syntheticDevice: 'DEVICE-SYN-091',
    syntheticUser: 'user-syn-15',
    status: 'Open',
    time: '2024-10-07 09:54 (sample)',
  },
  {
    id: 'inc-4',
    severity: 'low',
    title: 'New AI service observed — pending classification',
    destination: 'api.anthropic.com',
    syntheticDevice: 'DEVICE-SYN-007',
    syntheticUser: 'user-syn-2',
    status: 'Resolved',
    time: '2024-10-05 16:10 (sample)',
  },
];

// ── Governance: integration tiles ─────────────────────────────────────────────
export const INTEGRATION_TILES: IntegrationTile[] = [
  {
    id: 'int-1',
    name: 'Network Telemetry',
    description:
      'DNS query logs, flow metadata, and proxy records. No packet capture or TLS decryption.',
    state: 'Simulated',
    icon: '🌐',
  },
  {
    id: 'int-2',
    name: 'Identity & Device',
    description: 'Employee directory and device registry for authorization checks.',
    state: 'Not connected',
    icon: '🪪',
  },
  {
    id: 'int-3',
    name: 'Prompt Inspection',
    description:
      'Text submitted deliberately in Prompt Lab. Does not monitor other applications.',
    state: 'Planned',
    icon: '🔬',
  },
  {
    id: 'int-4',
    name: 'DLP Signals',
    description: 'Data-sensitivity labels from existing DLP tooling via API.',
    state: 'Not connected',
    icon: '🏷️',
  },
  {
    id: 'int-5',
    name: 'Policy Enforcement',
    description:
      'Block / alert rules. "Would block" labels in this prototype are sample policy outcomes only — no traffic is blocked.',
    state: 'Planned',
    icon: '🛡️',
  },
  {
    id: 'int-6',
    name: 'SIEM / Alerting',
    description: 'Push incidents to an external SIEM or ticketing system.',
    state: 'Planned',
    icon: '🔔',
  },
];
