// ─── AURA API Client ──────────────────────────────────────────────────────────
// Thin typed wrapper around fetch() for all AURA API calls.
// All requests go to /api/ (proxied by Vite in dev, same-origin in production).
// Credentials: 'include' ensures the HttpOnly cookie is sent automatically.

export class ApiError extends Error {
  status: number;
  constructor(
    status: number,
    message: string,
  ) {
    super(message);
    this.status = status;
    this.name = 'ApiError';
  }
}

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`/api${path}`, {
    ...init,
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      ...(init?.headers ?? {}),
    },
  });

  const body = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));

  if (!res.ok) {
    throw new ApiError(res.status, body?.error ?? `HTTP ${res.status}`);
  }

  return body as T;
}

// ── Types mirroring server responses ─────────────────────────────────────────

export interface DemoUser {
  username: string;
  displayName: string;
  role: 'administrator' | 'analyst' | 'viewer';
}

export interface HealthResponse {
  status: string;
  service: string;
  note: string;
  time: string;
}

export interface SignInResponse {
  user: DemoUser;
  expiresAt: string;
  demoNote: string;
}

export interface MeResponse {
  user: DemoUser;
}

export interface SummaryData {
  totalEvents: number;
  aiLikeEvents: number;
  servicesNeedingReview: number;
  highRiskEvents: number;
  openIncidents: number;
  estimatedTotalBytes: number;
  csvImportCount: number;
}

export interface RecentActivityRow {
  id: number;
  destination: string;
  port: number | null;
  provider_name: string;
  classification?: string;
  confidence?: number;
  evidence?: string;
  source_label: string;
  source_type: string;
  risk_level: string;
  sensitivity_label: string;
  byte_count: number;
  occurred_at: string;
}

export interface DashboardBootstrap {
  summary: SummaryData;
  recentActivity: RecentActivityRow[];
  demoNote: string;
}

export interface Service {
  id: number;
  name: string;
  provider: string;
  domains: string[];
  local_ports: number[];
  service_type: string;
  approval_status: string;
  notes: string | null;
  updated_at: string;
}

export interface InventoryItem {
  id: string;
  name: string;
  provider: string;
  endpoint: string;
  classification: string;
  approval_status: string;
  first_seen: string;
  event_count: number;
  estimated_bytes: number;
  confidence: number;
  evidence: string;
  source_types: string[];
  notes: string | null;
}

export interface MetricValue {
  value: number | null;
  formatted: string;
  numerator: number;
  denominator: number;
}

export interface DatasetEvaluationReport {
  totalRows: number;
  labeledRows: number;
  unlabeledRows: number;
  confusionMatrix: {
    truePositives: number;
    falsePositives: number;
    trueNegatives: number;
    falseNegatives: number;
  };
  metrics: {
    precision: MetricValue;
    recall: MetricValue;
    falsePositiveRate: MetricValue;
    accuracy: MetricValue;
  };
  providerEvaluation: {
    totalWithExpected: number;
    matches: number;
    accuracy: MetricValue;
  };
  disclaimer: string;
}

export interface CsvImportResponse {
  success: boolean;
  message: string;
  summary: {
    totalRowsFound: number;
    importedCount: number;
    skippedCount: number;
    ignoredColumns: string[];
  };
  skippedRows: Array<{ rowNumber: number; reason: string; destinationPreview?: string }>;
  privacyNotice: string;
}

export interface IncidentNoteItem {
  id: string;
  actor: string;
  role: string;
  text: string;
  created_at: string;
}

export interface SimulatedActionItem {
  id: string;
  action_type: 'preview_warning' | 'mark_approval' | 'simulate_block' | 'mark_false_positive';
  actor: string;
  timestamp: string;
  summary: string;
  details?: Record<string, unknown>;
  is_simulation: boolean;
}

export interface IncidentItem {
  id: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  destination: string;
  status: 'Open' | 'Investigating' | 'Resolved' | 'False Positive' | 'Under review';
  created_at: string;
  updated_at: string;
  notes: IncidentNoteItem[];
  simulated_actions: SimulatedActionItem[];
  recommended_steps: string[];
  event: {
    id: number | null;
    occurred_at: string | null;
    source_label: string;
    source_type: string;
    port: number | null;
    classification: string;
    confidence: number;
    approval_status: string;
    risk_score: number;
    risk_explanation?: string | null;
    risk_factors: Array<{ id: string; name: string; points: number; evidence: string }>;
    action_recommendation: string;
    byte_count: number;
    sensitivity_label: string;
    evidence?: string | null;
  };
  user: {
    name: string;
    email?: string | null;
    department?: string | null;
    role?: string | null;
  };
  device: {
    label: string;
    os?: string | null;
  };
  service: {
    name: string;
    provider: string;
  };
}

export interface IncidentRow {
  id: number;
  severity: string;
  title: string;
  destination: string;
  person_name: string;
  device_label: string;
  status: string;
  created_at: string;
  updated_at: string;
}

export interface PolicyThresholds {
  medium_threshold: number;
  high_threshold: number;
  critical_threshold: number;
}

export interface PolicyWeights {
  sensitivity_restricted: number;
  sensitivity_confidential: number;
  sensitivity_internal: number;
  service_unapproved: number;
  service_under_review: number;
  auth_denied_or_mismatch: number;
  high_transfer_volume: number;
  anomaly_signal_flagged: number;
}

export interface PolicyRecommendations {
  low: string;
  medium: string;
  high: string;
  critical: string;
}

export interface PoliciesResponse {
  thresholds: PolicyThresholds;
  weights: PolicyWeights;
  volumeThresholdMb: number;
  recommendations: PolicyRecommendations;
  descriptions: Record<string, string>;
  fieldDescriptions: Record<string, string>;
  canEdit: boolean;
  userRole: string;
  policyNotice: string;
  demoNote: string;
}

export interface AuditEntryItem {
  id: number;
  actor: string;
  action: string;
  detail: Record<string, unknown>;
  prevHash: string;
  entryHash: string;
  createdAt: string;
}

export interface AuditLogResponse {
  entries: AuditEntryItem[];
  totalEntries: number;
  isChainValid: boolean;
  chainStatus: string;
  brokenAtId?: number | null;
  disclaimer: string;
}

export interface EventRow {
  id: number;
  occurred_at: string;
  source_label: string;
  source_type: string;
  destination: string;
  port: number | null;
  service_name: string;
  classification: string;
  confidence: number;
  evidence: string;
  person_name: string;
  device_label: string;
  user_email?: string | null;
  device_name?: string | null;
  approval_status: string;
  risk_level: string;
  risk_score: number;
  action_recommendation: string;
  byte_count: number;
  sensitivity_label: string;
  evidence_tags: string[];
  ground_truth_label: string | null;
  expected_provider: string | null;
}

export interface PersonRow {
  id: number;
  display_name: string;
  demo_email: string;
  department: string;
  role_title: string;
  device_count: number;
  permitted_service_count: number;
}

export interface PromptPatternMatch {
  category: string;
  count: number;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  explanation: string;
}

export interface PromptScanResult {
  matches: PromptPatternMatch[];
  totalMatches: number;
  redactedPreview: string;
  sensitivitySuggestion: 'Public' | 'Internal' | 'Confidential' | 'Restricted';
  policyOutcome: 'allow_caution' | 'warn' | 'would_block';
  policyRecommendation: string;
  policyExplanation: string;
  destinationStatus: string;
  confidenceNote: string;
}

export interface PromptScanResponse {
  success: boolean;
  result: PromptScanResult;
  riskAssessment?: {
    score: number;
    severity: 'low' | 'medium' | 'high' | 'critical';
    factors: RiskFactor[];
    confidence: 'High' | 'Medium' | 'Low';
    explanation: string;
    recommendation: string;
    isSimulatedAction: boolean;
  };
  privacyNotice: string;
}

export interface PromptDestination {
  id: string;
  name: string;
  approvalStatus: string;
  serviceType: string;
}

export interface PromptScanHistoryRow {
  id: number;
  scanned_at: string;
  actor: string;
  destination: string;
  destination_status: string;
  categories: string[];
  sensitivity_suggestion: string;
  policy_outcome: string;
  char_count: number;
}

// ── Phase 5 Risk Intelligence Types ──────────────────────────────────────────

export interface RiskFactor {
  id: string;
  name: string;
  points: number;
  evidence: string;
  isMissingContext?: boolean;
}

export interface IdentityCorrelation {
  userListed: boolean;
  userName?: string;
  userEmail?: string;
  deviceKnown: boolean;
  deviceLabel?: string;
  servicePermitted: boolean | 'unknown';
  globalApproval: string;
  authStatus: 'authorized' | 'denied' | 'unknown' | 'mismatch';
  isExplicitAuth: boolean;
  notes: string;
}

export interface RiskOverviewResponse {
  disclaimer: string;
  counts: {
    total: number;
    low: number;
    medium: number;
    high: number;
    critical: number;
    simulationCount: number;
    csvImportCount: number;
  };
  sensitivityCounts: Record<string, number>;
  policyWeights: Record<string, number>;
}

export interface RiskEventRow extends EventRow {
  provider?: string;
  risk_factors: RiskFactor[];
  risk_explanation: string | null;
  risk_confidence: 'High' | 'Medium' | 'Low';
  authorization_status: 'authorized' | 'denied' | 'unknown' | 'mismatch';
  identity_correlation: IdentityCorrelation;
  isSimulatedAction: boolean;
}

export interface RiskEventsResponse {
  events: RiskEventRow[];
  pagination: { total: number; limit: number; offset: number };
  disclaimer: string;
}

export interface RiskEventDetailResponse {
  event: RiskEventRow;
  policyWeights: Record<string, number>;
  disclaimer: string;
}

// ── API functions ─────────────────────────────────────────────────────────────

export const api = {
  health: () => call<HealthResponse>('/health'),

  signIn: (role: DemoUser['role']) =>
    call<SignInResponse>('/auth/signin', {
      method: 'POST',
      body: JSON.stringify({ role }),
    }),

  me: () => call<MeResponse>('/auth/me'),

  signOut: () =>
    call<{ message: string }>('/auth/signout', { method: 'POST' }),

  dashboard: () => call<DashboardBootstrap>('/dashboard/bootstrap'),

  services: () =>
    call<{ services: Service[]; demoNote: string }>('/services'),

  inventory: () =>
    call<{ inventory: InventoryItem[]; privacyNotice: string; demoNote: string }>('/services/inventory'),

  sampleCsv: () =>
    call<{ filename: string; content: string; privacyNotice: string }>('/ingest/sample-csv'),

  importCsv: (csvText: string) =>
    call<CsvImportResponse>('/ingest/csv', {
      method: 'POST',
      body: JSON.stringify({ csvText }),
    }),

  evaluation: () =>
    call<{ report: DatasetEvaluationReport; privacyNotice: string }>('/ingest/evaluation'),

  clearCsv: () =>
    call<{ success: boolean; message: string; deletedCount: number }>('/ingest/clear-csv', {
      method: 'POST',
    }),

  promptDestinations: () =>
    call<{ destinations: PromptDestination[] }>('/prompt-lab/destinations'),

  scanPrompt: (params: { text: string; destination: string; destinationStatus: string }) =>
    call<PromptScanResponse>('/prompt-lab/scan', {
      method: 'POST',
      body: JSON.stringify(params),
    }),

  promptHistory: () =>
    call<{ history: PromptScanHistoryRow[]; privacyNotice: string }>('/prompt-lab/history'),

  events: (params?: { limit?: number; offset?: number; classification?: string; search?: string }) => {
    const qs = new URLSearchParams();
    if (params?.limit != null) qs.set('limit', String(params.limit));
    if (params?.offset != null) qs.set('offset', String(params.offset));
    if (params?.classification != null) qs.set('classification', params.classification);
    if (params?.search != null) qs.set('search', params.search);
    return call<{ events: EventRow[]; pagination: { total: number; limit: number; offset: number }; demoNote: string }>(
      `/events?${qs}`,
    );
  },

  incidents: (params?: {
    severity?: string;
    status?: string;
    search?: string;
    destination?: string;
    provider?: string;
  }) => {
    const qs = new URLSearchParams();
    if (params?.severity) qs.set('severity', params.severity);
    if (params?.status) qs.set('status', params.status);
    if (params?.search) qs.set('search', params.search);
    if (params?.destination) qs.set('destination', params.destination);
    if (params?.provider) qs.set('provider', params.provider);
    return call<{ incidents: IncidentItem[]; canEdit: boolean; userRole: string; demoNotice: string }>(
      `/incidents?${qs}`
    );
  },

  incidentDetail: (id: number) =>
    call<{ incident: IncidentItem; canEdit: boolean; userRole: string }>(`/incidents/${id}`),

  updateIncidentStatus: (id: number, status: string, note?: string) =>
    call<{ success: boolean; message: string; id: number; status: string; notes: IncidentNoteItem[] }>(
      `/incidents/${id}/status`,
      {
        method: 'PATCH',
        body: JSON.stringify({ status, note }),
      }
    ),

  addIncidentNote: (id: number, text: string) =>
    call<{ success: boolean; note: IncidentNoteItem; notes: IncidentNoteItem[] }>(
      `/incidents/${id}/notes`,
      {
        method: 'POST',
        body: JSON.stringify({ text }),
      }
    ),

  simulateIncidentAction: (id: number, actionType: string, reason?: string) =>
    call<{
      success: boolean;
      actionType: string;
      simulationDetail: Record<string, unknown>;
      simulatedActions: SimulatedActionItem[];
      notes: IncidentNoteItem[];
    }>(`/incidents/${id}/simulate-action`, {
      method: 'POST',
      body: JSON.stringify({ actionType, reason }),
    }),

  people: () =>
    call<{ people: PersonRow[]; demoNote: string }>('/people'),

  policies: () =>
    call<PoliciesResponse>('/policies'),

  updatePolicies: (params: {
    thresholds?: PolicyThresholds;
    weights?: Partial<PolicyWeights>;
    volumeThresholdMb?: number;
  }) =>
    call<{ success: boolean; message: string; policyNotice: string }>('/policies', {
      method: 'PATCH',
      body: JSON.stringify(params),
    }),

  updateServiceApproval: (id: number, approval_status: string) =>
    call<{ success: boolean; message: string; service: { id: number; name: string; approval_status: string } }>(
      `/services/${id}/approval`,
      {
        method: 'PATCH',
        body: JSON.stringify({ approval_status }),
      }
    ),

  auditLog: (limit: number = 50) =>
    call<AuditLogResponse>(`/audit?limit=${limit}`),

  riskOverview: () =>
    call<RiskOverviewResponse>('/risk/overview'),

  riskEvents: (params?: {
    limit?: number;
    offset?: number;
    severity?: string;
    classification?: string;
    source?: string;
    search?: string;
  }) => {
    const qs = new URLSearchParams();
    if (params?.limit != null) qs.set('limit', String(params.limit));
    if (params?.offset != null) qs.set('offset', String(params.offset));
    if (params?.severity != null) qs.set('severity', params.severity);
    if (params?.classification != null) qs.set('classification', params.classification);
    if (params?.source != null) qs.set('source', params.source);
    if (params?.search != null) qs.set('search', params.search);
    return call<RiskEventsResponse>(`/risk/events?${qs}`);
  },

  riskEventDetail: (id: number) =>
    call<RiskEventDetailResponse>(`/risk/events/${id}`),

  // ── Phase 7: Data Guard ──────────────────────────────────────────────────

  dataGuardOverview: () =>
    call<DataGuardOverviewResponse>('/data-guard/overview'),

  dataSharingRules: () =>
    call<DataSharingRulesResponse>('/data-guard/rules'),

  createDataSharingRule: (rule: CreateDataSharingRuleParams) =>
    call<{ success: boolean; id: number; message: string }>('/data-guard/rules', {
      method: 'POST',
      body: JSON.stringify(rule),
    }),

  updateDataSharingRule: (id: number, params: Partial<CreateDataSharingRuleParams> & { is_active?: boolean }) =>
    call<{ success: boolean; message: string }>(`/data-guard/rules/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(params),
    }),

  deleteDataSharingRule: (id: number) =>
    call<{ success: boolean; message: string }>(`/data-guard/rules/${id}`, {
      method: 'DELETE',
    }),

  inspectOutbound: (params: { filename: string; content: string; destination: string }) =>
    call<OutboundInspectionResponse>('/data-guard/inspect-outbound', {
      method: 'POST',
      body: JSON.stringify(params),
    }),

  inspectProxy: (params: { filename: string; content: string; destination: string; isEncrypted?: boolean }) =>
    call<ProxyInspectionResponse>('/data-guard/inspect-proxy', {
      method: 'POST',
      body: JSON.stringify(params),
    }),

  inspectIncoming: (params: { filename: string; content: string; sourceOrigin?: string }) =>
    call<IncomingInspectionResponse>('/data-guard/inspect-incoming', {
      method: 'POST',
      body: JSON.stringify(params),
    }),

  transferAttempts: (flagged?: boolean) =>
    call<TransferAttemptsResponse>(`/data-guard/attempts${flagged ? '?flagged=true' : ''}`),

  reviewAttempt: (id: number, review_note: string) =>
    call<{ success: boolean; message: string }>(`/data-guard/attempts/${id}/review`, {
      method: 'PATCH',
      body: JSON.stringify({ review_note }),
    }),

  inspectionHistory: (direction?: 'outbound' | 'inbound') =>
    call<InspectionHistoryResponse>(`/data-guard/history${direction ? `?direction=${direction}` : ''}`),

  incomingHistory: () =>
    call<IncomingHistoryResponse>('/data-guard/incoming-history'),

  // ── Browser AI Extension & Dataset APIs ───────────────────────────────────

  extensionSites: () =>
    call<ExtensionSitesResponse>('/extension/sites'),

  addExtensionSite: (site: { name: string; domain: string; category?: string; adapter?: string }) =>
    call<{ success: boolean; id: number; message: string }>('/extension/sites', {
      method: 'POST',
      body: JSON.stringify(site),
    }),

  updateExtensionSite: (id: number, params: { is_enabled?: boolean; status?: string }) =>
    call<{ success: boolean; message: string }>(`/extension/sites/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(params),
    }),

  deleteExtensionSite: (id: number) =>
    call<{ success: boolean; message: string }>(`/extension/sites/${id}`, {
      method: 'DELETE',
    }),

  extensionEvents: (filters?: { risk?: string; service?: string; review?: string }) => {
    const params = new URLSearchParams();
    if (filters?.risk) params.set('risk', filters.risk);
    if (filters?.service) params.set('service', filters.service);
    if (filters?.review) params.set('review', filters.review);
    const qs = params.toString();
    return call<ExtensionEventsResponse>(`/extension/events${qs ? `?${qs}` : ''}`);
  },

  reviewExtensionEvent: (id: number, review_status: 'Expected' | 'Investigate' | 'Policy exception', reviewer_note?: string) =>
    call<{ success: boolean; message: string }>(`/extension/events/${id}/review`, {
      method: 'PATCH',
      body: JSON.stringify({ review_status, reviewer_note }),
    }),

  extensionSummary: () =>
    call<ExtensionDashboardSummaryResponse>('/extension/dashboard-summary'),

  datasetHistory: (filters?: { service?: string; risk?: string }) => {
    const params = new URLSearchParams();
    if (filters?.service) params.set('service', filters.service);
    if (filters?.risk) params.set('risk', filters.risk);
    const qs = params.toString();
    return call<DatasetHistoryResponse>(`/extension/datasets/history${qs ? `?${qs}` : ''}`);
  },

  datasetIncidents: () =>
    call<DatasetIncidentsResponse>('/extension/datasets/incidents'),
};

// ── Phase 7 Types ──────────────────────────────────────────────────────────

export interface DataGuardOverviewResponse {
  stats: {
    totalRules: number;
    activeRules: number;
    totalOutboundInspections: number;
    totalIncomingInspections: number;
    blockedTransfers: number;
    warnedTransfers: number;
    flaggedAttempts: number;
    totalAttempts: number;
    quarantinedIncoming: number;
    proxyInspections: number;
  };
  demoNote: string;
}

export interface DataSharingRuleItem {
  id: number;
  rule_name: string;
  data_types: string[];
  allowed_tools: string[];
  blocked_tools: string[];
  action: 'allow' | 'warn' | 'block';
  description: string;
  is_active: boolean;
}

export interface DataSharingRulesResponse {
  rules: DataSharingRuleItem[];
  canEdit: boolean;
  userRole: string;
  demoNote: string;
}

export interface CreateDataSharingRuleParams {
  rule_name: string;
  data_types: string[];
  allowed_tools?: string[];
  blocked_tools?: string[];
  action: 'allow' | 'warn' | 'block';
  description?: string;
}

export interface FileInspectionMatch {
  category: string;
  count: number;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  explanation: string;
}

export interface FileInspectionResultData {
  filename: string;
  fileType: string;
  fileSizeBytes: number;
  detectedTypes: FileInspectionMatch[];
  totalFindings: number;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  matchedRules: string[];
  actionTaken: 'allowed' | 'warned' | 'blocked' | 'quarantined';
  actionReason: string;
  limitations: string[];
  redactedPreview: string;
  policyExplanation: string;
  confidenceNote: string;
}

export interface OutboundInspectionResponse {
  success: boolean;
  inspectionId: number;
  result: FileInspectionResultData;
  privacyNotice: string;
}

export interface ProxyInspectionResultData {
  canInspect: boolean;
  inspectionNote: string;
  detectedTypes: FileInspectionMatch[];
  actionTaken: 'allowed' | 'warned' | 'blocked';
  limitation: string;
}

export interface ProxyInspectionResponse {
  success: boolean;
  inspectionId: number;
  localInspection: FileInspectionResultData;
  proxyInspection: ProxyInspectionResultData;
  combinedAction: 'allowed' | 'warned' | 'blocked';
  privacyNotice: string;
}

export interface IncomingInspectionResultData {
  filename: string;
  fileSizeBytes: number;
  sourceOrigin: string;
  detectedRisks: string[];
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  actionTaken: 'allowed' | 'quarantined' | 'blocked';
  actionReason: string;
  malwareIndicators: string[];
  limitations: string[];
}

export interface IncomingInspectionResponse {
  success: boolean;
  result: IncomingInspectionResultData;
  privacyNotice: string;
}

export interface TransferAttemptRow {
  id: number;
  person_id: number | null;
  person_email: string;
  person_name: string | null;
  destination: string;
  data_type: string;
  matched_rule: string;
  attempt_count: number;
  last_attempt_at: string;
  flagged_for_review: number;
  review_note: string | null;
  created_at: string;
}

export interface TransferAttemptsResponse {
  attempts: TransferAttemptRow[];
  disclaimer: string;
}

export interface InspectionHistoryRow {
  id: number;
  filename: string;
  file_size_bytes: number;
  file_type: string;
  destination: string;
  direction: string;
  detected_types: string[];
  matched_rules: string[];
  risk_level: string;
  action_taken: string;
  action_reason: string;
  limitations: string[];
  inspector: string;
  actor: string;
  person_name: string | null;
  created_at: string;
  proxy: {
    canInspect: boolean;
    note: string;
    limitation: string;
    action: string;
  } | null;
}

export interface InspectionHistoryResponse {
  inspections: InspectionHistoryRow[];
  privacyNotice: string;
}

export interface IncomingHistoryRow {
  id: number;
  filename: string;
  file_size_bytes: number;
  source_origin: string;
  detected_risks: string[];
  risk_level: string;
  action_taken: string;
  action_reason: string;
  malware_indicators: string[];
  created_at: string;
}

export interface IncomingHistoryResponse {
  inspections: IncomingHistoryRow[];
  privacyNotice: string;
}

// ── Extension & Reference Dataset Types ─────────────────────────────────────

export interface ExtensionSiteItem {
  id: number;
  service_key: string;
  name: string;
  domain: string;
  category: 'cloud' | 'local' | 'custom';
  adapter: string;
  is_enabled: boolean;
  last_active_at: string | null;
  status: 'protected' | 'inactive' | 'unsupported' | 'changed';
  created_at: string;
  updated_at: string;
}

export interface ExtensionSitesResponse {
  sites: ExtensionSiteItem[];
  totalSites: number;
  activeProtectedCount: number;
  canEdit: boolean;
}

export interface ExtensionEventItem {
  id: number;
  event_time: string;
  employee_id: string;
  ai_service: string;
  domain: string;
  event_type: 'message_send' | 'file_upload';
  file_name: string | null;
  detected_category: string;
  matched_rule: string;
  action_taken: 'blocked' | 'warned' | 'allowed';
  risk_level: 'low' | 'medium' | 'high' | 'critical';
  review_status: 'Pending' | 'Expected' | 'Investigate' | 'Policy exception';
  reviewer_note: string | null;
  reviewed_by: string | null;
  reviewed_at: string | null;
  is_live: number;
  employee_name?: string;
  department?: string;
  job_role?: string;
}

export interface ExtensionEventsResponse {
  events: ExtensionEventItem[];
  total: number;
  canReview: boolean;
}

export interface ExtensionDashboardSummaryResponse {
  catalog: {
    totalSites: number;
    protectedSites: number;
    inactiveSites: number;
    unsupportedSites: number;
  };
  liveEvents: {
    total: number;
    blocked: number;
    warned: number;
    critical: number;
    high: number;
    pendingReview: number;
  };
  datasets: {
    employees: number;
    aiLogs: number;
    assets: number;
    networkLogs: number;
    incidents: number;
  };
}

export interface DatasetHistoryRecord {
  log_id: string;
  timestamp: string;
  employee_id: string;
  ai_service: string;
  destination_domain: string;
  prompt_category: string;
  inspection_result: string;
  service_status: string;
  request_size: string;
  employee_name: string;
  department: string;
  job_role: string;
  device_trust_status: string;
  approved_ai_services: string;
  data_access_level: string;
  is_live: 0;
  source: 'dataset_sample';
}

export interface DatasetHistoryResponse {
  records: DatasetHistoryRecord[];
  total: number;
  disclaimer: string;
}

export interface DatasetIncidentRecord {
  incident_id: string;
  timestamp: string;
  employee_id: string;
  related_event_ids: string;
  detected_categories: string;
  policy_violation: string;
  risk_score: number;
  severity: string;
  explanation: string;
  recommended_action: string;
  response_status: string;
  analyst_resolution: string;
  employee_name: string;
  department: string;
  job_role: string;
  device_trust_status: string;
  is_live: 0;
  source: 'dataset_sample';
}

export interface DatasetIncidentsResponse {
  incidents: DatasetIncidentRecord[];
  total: number;
}

