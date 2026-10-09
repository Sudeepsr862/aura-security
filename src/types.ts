// ─── AURA Type Definitions ─────────────────────────────────────────────────
// All data in this file is structural only. No real network data is used.

export type NavPage =
  | 'overview'
  | 'ai-inventory'
  | 'prompt-lab'
  | 'data-guard'
  | 'data-risk'
  | 'incidents'
  | 'governance';

export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';
export type DataLabel = 'Public' | 'Internal' | 'Confidential' | 'Restricted';
export type ServiceKind = 'Cloud AI' | 'Possible local AI' | 'Ordinary web';
export type ApprovalStatus = 'Approved' | 'Needs review' | 'Unapproved' | 'Unknown';
export type IncidentStatus = 'Open' | 'Investigating' | 'Resolved' | 'False Positive' | 'Under review';
export type IntegrationState = 'Simulated' | 'Not connected' | 'Planned';

export interface ActivityRow {
  id: string;
  destination: string;
  providerType: string;
  sampleRisk: RiskLevel;
  dataLabel: DataLabel;
  time: string;
}

export interface InventoryService {
  id: string;
  name: string;
  domainOrPort: string;
  kind: ServiceKind;
  approval: ApprovalStatus;
  firstSeen: string;
  sampleEventCount: number;
  note?: string;
}

export interface RiskCard {
  id: string;
  title: string;
  destination: string;
  dataLabel: DataLabel;
  score: number; // 0–100
  factors: string[];
  note: string;
}

export interface IncidentRow {
  id: string;
  severity: RiskLevel;
  title: string;
  destination: string;
  syntheticDevice: string;
  syntheticUser: string;
  status: IncidentStatus;
  time: string;
}

export interface IntegrationTile {
  id: string;
  name: string;
  description: string;
  state: IntegrationState;
  icon: string; // emoji used as decorative icon
}
