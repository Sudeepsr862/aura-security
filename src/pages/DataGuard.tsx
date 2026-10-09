// ─── Data Guard Page ──────────────────────────────────────────────────────────
// Phase 7: Comprehensive Data Protection & Transfer Guard
//
// Features:
// 1. Configurable data-sharing policies (Admin CRUD, employee rule view, opt-in/opt-out choice)
// 2. Outbound file transfer inspection (Warn or block risky transfers, explain risk, policy rule matched)
// 3. Repeated attempts tracking (Flagged for authorized compliance review, neutral non-punitive tone)
// 4. Proxy / gateway outbound inspection (Simulated second layer with clear TLS vs decrypted capabilities)
// 5. Detailed file-content analysis (Detected data types, risk assessment, redacted preview)
// 6. Incoming traffic inspection & quarantine (Malware indicators, suspicious scripts, quarantine actions)
// 7. Strict privacy guarantees (In-memory analysis, zero secrets saved, no raw content retained)

import { useState, useEffect } from 'react';
import {
  api,
  type DataGuardOverviewResponse,
  type DataSharingRuleItem,
  type TransferAttemptRow,
  type FileInspectionResultData,
  type FileInspectionMatch,
  type InspectionHistoryRow,
} from '../api/client';
import { RiskBadge, SecurityNotice, PageHeader, Section } from '../components/ui';

type ActiveTab = 'inspector' | 'policies' | 'attempts' | 'history';

interface SampleFilePreset {
  name: string;
  filename: string;
  description: string;
  defaultDestination: string;
  content: string;
}

const SAMPLE_PRESETS: SampleFilePreset[] = [
  {
    name: 'Production Environment Secrets (.env)',
    filename: '.env.production',
    description: 'Contains live database credentials and OpenAI API keys. Should trigger BLOCK policy.',
    defaultDestination: 'ChatGPT (Public)',
    content: `# Production Environment Variables
DATABASE_URL=postgres://admin:MasterDbPass2026!@prod-cluster.internal:5432/main
OPENAI_API_KEY=sk-proj-99887766554433221100aabbccddeeffgghhiijjkkllmmnnoopp
AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
PORT=8080`,
  },
  {
    name: 'Customer PII Export (.csv)',
    filename: 'customer_leads_q3.csv',
    description: 'Contains personal customer emails and phone numbers. Should trigger WARN policy.',
    defaultDestination: 'Claude (Anthropic)',
    content: `customer_id,full_name,email,phone_number,tier
101,Sarah Jenkins,sarah.jenkins@example.com,+1-555-019-2834,Enterprise
102,David Morales,david.m@globex.org,+1-555-847-1920,Standard
103,Amina Chen,amina.chen@innovate.co,+44-20-7946-0912,Executive`,
  },
  {
    name: 'Internal Llama Client (.py)',
    filename: 'llama_client.py',
    description: 'Internal API client sending internal queries to authorized on-prem Llama endpoint. Should ALLOW.',
    defaultDestination: 'Internal Llama Endpoint',
    content: `"""Internal AI pipeline wrapper for secure on-prem LLM."""
import requests

ENDPOINT = "http://llama-internal.local:8000/v1/chat/completions"

def query_internal_model(prompt: str):
    response = requests.post(ENDPOINT, json={"prompt": prompt, "temperature": 0.2})
    return response.json()`,
  },
  {
    name: 'Clean Documentation (README.md)',
    filename: 'README.md',
    description: 'Standard benign markdown documentation with no credentials or PII. Should ALLOW.',
    defaultDestination: 'ChatGPT (Public)',
    content: `# Project Falcon Documentation

Falcon is an internal microservice coordinating distributed job scheduling.
Features:
- Distributed worker coordination
- Graceful shutdown handlers
- Health check telemetry metrics`,
  },
  {
    name: 'Binary Archive Package (.zip)',
    filename: 'reports_bundle.zip',
    description: 'Binary zip file. Demonstrates format limitations of text regex scanner with advisory notice.',
    defaultDestination: 'Hugging Face Hub',
    content: `PK\x03\x04\x14\x00\x00\x00\x08\x00[Simulated binary archive header and compressed payload data]`,
  },
];

export function DataGuard() {
  const [activeTab, setActiveTab] = useState<ActiveTab>('inspector');
  const [overview, setOverview] = useState<DataGuardOverviewResponse['stats'] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [canEditPolicies, setCanEditPolicies] = useState(false);
  const [userRole, setUserRole] = useState('viewer');

  // ── Inspector State ────────────────────────────────────────────────────────
  const [selectedPreset, setSelectedPreset] = useState<number | null>(0);
  const [filename, setFilename] = useState(SAMPLE_PRESETS[0].filename);
  const [destination, setDestination] = useState(SAMPLE_PRESETS[0].defaultDestination);
  const [fileContent, setFileContent] = useState(SAMPLE_PRESETS[0].content);
  const [inspecting, setInspecting] = useState(false);
  const [inspectionResult, setInspectionResult] = useState<FileInspectionResultData | null>(null);
  const [employeeProceedChoice, setEmployeeProceedChoice] = useState<'prompt' | 'proceeded' | 'cancelled' | null>(null);

  // ── Policies State ─────────────────────────────────────────────────────────
  const [rules, setRules] = useState<DataSharingRuleItem[]>([]);
  const [ruleModalOpen, setRuleModalOpen] = useState(false);
  const [newRuleName, setNewRuleName] = useState('');
  const [newRuleDataTypes, setNewRuleDataTypes] = useState<string[]>(['API Keys & Access Tokens']);
  const [newRuleAllowedTools, setNewRuleAllowedTools] = useState('Internal Llama Endpoint');
  const [newRuleBlockedTools, setNewRuleBlockedTools] = useState('*');
  const [newRuleAction, setNewRuleAction] = useState<'allow' | 'warn' | 'block'>('block');
  const [newRuleDesc, setNewRuleDesc] = useState('');
  const [ruleSubmitting, setRuleSubmitting] = useState(false);

  // ── Transfer Attempts State ────────────────────────────────────────────────
  const [attempts, setAttempts] = useState<TransferAttemptRow[]>([]);
  const [selectedAttempt, setSelectedAttempt] = useState<TransferAttemptRow | null>(null);
  const [reviewNote, setReviewNote] = useState('');
  const [reviewSubmitting, setReviewSubmitting] = useState(false);

  // ── History State ──────────────────────────────────────────────────────────
  const [history, setHistory] = useState<InspectionHistoryRow[]>([]);

  // Initial load
  useEffect(() => {
    loadAll();
  }, []);

  async function loadAll() {
    setError(null);
    try {
      const [ov, rl, at, hi] = await Promise.all([
        api.dataGuardOverview().catch(() => null),
        api.dataSharingRules().catch(() => null),
        api.transferAttempts().catch(() => null),
        api.inspectionHistory().catch(() => null),
      ]);

      if (ov) setOverview(ov.stats);
      if (rl) {
        setRules(rl.rules);
        setCanEditPolicies(rl.canEdit);
        setUserRole(rl.userRole);
      }
      if (at) setAttempts(at.attempts);
      if (hi) setHistory(hi.inspections);
    } catch (err: any) {
      setError(err?.message || 'Failed to load Data Guard information.');
    }
  }

  // Handle preset selection
  function handlePresetSelect(idx: number) {
    const p = SAMPLE_PRESETS[idx];
    setSelectedPreset(idx);
    setFilename(p.filename);
    setDestination(p.defaultDestination);
    setFileContent(p.content);
    setInspectionResult(null);
    setEmployeeProceedChoice(null);
  }

  // Run outbound inspection
  async function handleInspectOutbound() {
    if (!filename.trim() || !fileContent.trim()) return;
    setInspecting(true);
    setError(null);
    setEmployeeProceedChoice(null);
    try {
      const res = await api.inspectOutbound({
        filename: filename.trim(),
        content: fileContent,
        destination: destination.trim(),
      });
      setInspectionResult(res.result);
      if (res.result.actionTaken === 'warned') {
        setEmployeeProceedChoice('prompt');
      }
      // Refresh stats & attempts
      const [ov, at, hi] = await Promise.all([
        api.dataGuardOverview(),
        api.transferAttempts(),
        api.inspectionHistory(),
      ]);
      setOverview(ov.stats);
      setAttempts(at.attempts);
      setHistory(hi.inspections);
    } catch (err: any) {
      setError(err?.message || 'Inspection failed.');
    } finally {
      setInspecting(false);
    }
  }

  // Create rule
  async function handleCreateRule(e: React.FormEvent) {
    e.preventDefault();
    if (!newRuleName.trim() || newRuleDataTypes.length === 0) return;
    setRuleSubmitting(true);
    try {
      await api.createDataSharingRule({
        rule_name: newRuleName.trim(),
        data_types: newRuleDataTypes,
        allowed_tools: newRuleAllowedTools.split(',').map((s: string) => s.trim()).filter(Boolean),
        blocked_tools: newRuleBlockedTools.split(',').map((s: string) => s.trim()).filter(Boolean),
        action: newRuleAction,
        description: newRuleDesc.trim(),
      });
      setRuleModalOpen(false);
      setNewRuleName('');
      setNewRuleDesc('');
      const rl = await api.dataSharingRules();
      setRules(rl.rules);
    } catch (err: any) {
      alert(err?.message || 'Failed to create rule.');
    } finally {
      setRuleSubmitting(false);
    }
  }

  // Toggle rule status
  async function handleToggleRule(rule: DataSharingRuleItem) {
    if (!canEditPolicies) return;
    try {
      await api.updateDataSharingRule(rule.id, { is_active: !rule.is_active });
      const rl = await api.dataSharingRules();
      setRules(rl.rules);
    } catch (err: any) {
      alert(err?.message || 'Failed to update rule.');
    }
  }

  // Submit attempt review
  async function handleSubmitReview(e: React.FormEvent) {
    e.preventDefault();
    if (!selectedAttempt || !reviewNote.trim()) return;
    setReviewSubmitting(true);
    try {
      await api.reviewAttempt(selectedAttempt.id, reviewNote.trim());
      setSelectedAttempt(null);
      setReviewNote('');
      const at = await api.transferAttempts();
      setAttempts(at.attempts);
    } catch (err: any) {
      alert(err?.message || 'Failed to record review note.');
    } finally {
      setReviewSubmitting(false);
    }
  }

  return (
    <div className="page-container animate-fade-in" id="main-content">
      <PageHeader
        title="Data Guard & Transfer Assurance"
        subtitle="Configurable sharing policies, pre-transfer file inspection, repeated attempt compliance tracking, and audit history."
      >
        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
          <span className="badge badge-info" style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
            <span>🔒</span> In-Memory Analysis Only
          </span>
          <span className="badge badge-success" style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
            <span>🛡️</span> Zero Persistent Secrets
          </span>
        </div>
      </PageHeader>

      <SecurityNotice message="Privacy & Safety Guarantee: File content is analyzed strictly in-memory and discarded immediately. No raw file text, passwords, or tokens are persisted to disk or audit logs." />

      {error && (
        <div className="banner banner-error" style={{ marginBottom: '16px' }}>
          <span>⚠️ {error}</span>
        </div>
      )}

      {/* KPI Overview Strip */}
      {overview && (
        <div className="grid grid-4" style={{ marginBottom: '24px' }}>
          <div className="card stat-card">
            <span className="stat-label">Active Sharing Policies</span>
            <span className="stat-value">{overview.activeRules} <span style={{ fontSize: '1rem', color: 'var(--color-muted)' }}>/ {overview.totalRules}</span></span>
            <span className="stat-sub">Configured organizational rules</span>
          </div>
          <div className="card stat-card">
            <span className="stat-label">Blocked Outbound Transfers</span>
            <span className="stat-value" style={{ color: 'var(--color-critical)' }}>{overview.blockedTransfers}</span>
            <span className="stat-sub">{overview.warnedTransfers} warned / authorized choices</span>
          </div>
          <div className="card stat-card">
            <span className="stat-label">Flagged Repeat Attempts</span>
            <span className="stat-value" style={{ color: 'var(--color-high)' }}>{overview.flaggedAttempts}</span>
            <span className="stat-sub">Compliance review queue (3+ attempts)</span>
          </div>
          <div className="card stat-card">
            <span className="stat-label">Inbound & Gateway Quarantine</span>
            <span className="stat-value" style={{ color: 'var(--color-accent)' }}>{overview.quarantinedIncoming}</span>
            <span className="stat-sub">{overview.proxyInspections} proxy gateway events</span>
          </div>
        </div>
      )}

      {/* Tab Navigation */}
      <div className="tabs-nav" style={{ display: 'flex', gap: '8px', borderBottom: '1px solid var(--color-border)', marginBottom: '24px', flexWrap: 'wrap' }}>
        <button
          type="button"
          className={`tab-btn ${activeTab === 'inspector' ? 'active' : ''}`}
          onClick={() => setActiveTab('inspector')}
        >
          📤 Outbound File Inspector
        </button>
        <button
          type="button"
          className={`tab-btn ${activeTab === 'policies' ? 'active' : ''}`}
          onClick={() => setActiveTab('policies')}
        >
          📋 Sharing Policies ({rules.length})
        </button>
        <button
          type="button"
          className={`tab-btn ${activeTab === 'attempts' ? 'active' : ''}`}
          onClick={() => setActiveTab('attempts')}
        >
          ⚠️ Repeat Attempts ({attempts.filter((a: TransferAttemptRow) => a.flagged_for_review === 1).length} Flagged)
        </button>
        <button
          type="button"
          className={`tab-btn ${activeTab === 'history' ? 'active' : ''}`}
          onClick={() => setActiveTab('history')}
        >
          📜 Inspection Log ({history.length})
        </button>
      </div>

      {/* ──────────────────────────────────────────────────────────────────────────
          TAB 1: OUTBOUND FILE INSPECTOR
          ────────────────────────────────────────────────────────────────────────── */}
      {activeTab === 'inspector' && (
        <div className="animate-fade-in">
          <Section
            title="Pre-Transfer File Inspector"
            description="Inspect synthetic documents or source files before they leave the boundary. Detects credentials, PII, keys, and applies active data-sharing rules."
          >
            {/* Presets Bar */}
            <div style={{ marginBottom: '16px' }}>
              <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, marginBottom: '8px', color: 'var(--color-muted)' }}>
                Select a Synthetic Scenario Preset:
              </label>
              <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                {SAMPLE_PRESETS.map((preset, idx) => (
                  <button
                    key={idx}
                    type="button"
                    onClick={() => handlePresetSelect(idx)}
                    className={`btn ${selectedPreset === idx ? 'btn-primary' : 'btn-secondary'}`}
                    style={{ fontSize: '0.8rem', padding: '6px 12px' }}
                  >
                    {preset.name}
                  </button>
                ))}
              </div>
            </div>

            <div className="grid grid-2" style={{ gap: '24px' }}>
              {/* Left Column: File Details & Input */}
              <div className="card" style={{ padding: '20px' }}>
                <h3 style={{ fontSize: '1rem', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span>📄</span> Target File Configuration
                </h3>

                <div style={{ marginBottom: '14px' }}>
                  <label htmlFor="inspector-filename" style={{ display: 'block', fontSize: '0.85rem', marginBottom: '4px', fontWeight: 500 }}>
                    Filename & Extension
                  </label>
                  <input
                    id="inspector-filename"
                    type="text"
                    value={filename}
                    onChange={(e) => setFilename(e.target.value)}
                    placeholder="e.g. data_export.csv or .env"
                    className="input"
                    style={{ width: '100%' }}
                  />
                </div>

                <div style={{ marginBottom: '14px' }}>
                  <label htmlFor="inspector-destination" style={{ display: 'block', fontSize: '0.85rem', marginBottom: '4px', fontWeight: 500 }}>
                    Target AI Tool / Destination
                  </label>
                  <select
                    id="inspector-destination"
                    value={destination}
                    onChange={(e) => setDestination(e.target.value)}
                    className="input"
                    style={{ width: '100%' }}
                  >
                    <option value="ChatGPT (Public)">ChatGPT (Public AI - OpenAI)</option>
                    <option value="Claude (Anthropic)">Claude (Public AI - Anthropic)</option>
                    <option value="Internal Llama Endpoint">Internal Llama Endpoint (On-Premises Approved)</option>
                    <option value="Hugging Face Hub">Hugging Face Hub (Public Model Hub)</option>
                    <option value="GitHub Copilot">GitHub Copilot (Enterprise Cloud)</option>
                    <option value="Unapproved Cloud Storage">Unapproved Cloud Storage (Third-Party Web)</option>
                  </select>
                </div>

                <div style={{ marginBottom: '16px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                    <label htmlFor="inspector-content" style={{ fontSize: '0.85rem', fontWeight: 500 }}>
                      Synthetic File Content (In-Memory Analysis)
                    </label>
                    <span style={{ fontSize: '0.75rem', color: 'var(--color-muted)' }}>
                      {fileContent.length} characters
                    </span>
                  </div>
                  <textarea
                    id="inspector-content"
                    value={fileContent}
                    onChange={(e) => setFileContent(e.target.value)}
                    rows={10}
                    className="input"
                    style={{ width: '100%', fontFamily: 'monospace', fontSize: '0.82rem', lineHeight: '1.4' }}
                    placeholder="Paste synthetic file content here..."
                  />
                </div>

                <button
                  type="button"
                  className="btn btn-primary"
                  onClick={handleInspectOutbound}
                  disabled={inspecting || !fileContent.trim()}
                  style={{ width: '100%', padding: '10px' }}
                >
                  {inspecting ? 'Analyzing in Memory...' : '🔍 Inspect File & Check Sharing Policy'}
                </button>
              </div>

              {/* Right Column: Inspection Findings */}
              <div className="card" style={{ padding: '20px' }}>
                <h3 style={{ fontSize: '1rem', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span>🛡️</span> Policy Decision & Risk Evaluation
                </h3>

                {!inspectionResult ? (
                  <div style={{ textAlign: 'center', padding: '48px 16px', color: 'var(--color-muted)' }}>
                    <span style={{ fontSize: '2.5rem', display: 'block', marginBottom: '12px' }}>📁</span>
                    <p>Enter or choose a synthetic file on the left and click <strong>Inspect File</strong> to evaluate data-sharing policies.</p>
                  </div>
                ) : (
                  <div>
                    {/* Action Banner */}
                    <div
                      style={{
                        padding: '14px 18px',
                        borderRadius: '8px',
                        marginBottom: '16px',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        background:
                          inspectionResult.actionTaken === 'blocked' ? 'rgba(239, 68, 68, 0.15)' :
                          inspectionResult.actionTaken === 'warned' ? 'rgba(245, 158, 11, 0.15)' :
                          'rgba(34, 197, 94, 0.15)',
                        border: `1px solid ${
                          inspectionResult.actionTaken === 'blocked' ? 'var(--color-critical)' :
                          inspectionResult.actionTaken === 'warned' ? 'var(--color-high)' :
                          'var(--color-low)'
                        }`,
                      }}
                    >
                      <div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                          <span style={{ fontSize: '1.2rem' }}>
                            {inspectionResult.actionTaken === 'blocked' ? '🛑' : inspectionResult.actionTaken === 'warned' ? '⚠️' : '✅'}
                          </span>
                          <strong style={{ fontSize: '1.05rem', textTransform: 'uppercase' }}>
                            Policy Outcome: {inspectionResult.actionTaken}
                          </strong>
                        </div>
                        <p style={{ margin: 0, fontSize: '0.85rem' }}>
                          {inspectionResult.actionReason}
                        </p>
                      </div>
                      <RiskBadge level={inspectionResult.riskLevel} />
                    </div>

                    {/* Employee Choice Prompt (where policy allows warning override) */}
                    {employeeProceedChoice === 'prompt' && (
                      <div
                        style={{
                          background: 'rgba(59, 130, 246, 0.1)',
                          border: '1px solid var(--color-accent)',
                          padding: '14px',
                          borderRadius: '8px',
                          marginBottom: '16px',
                        }}
                      >
                        <h4 style={{ margin: '0 0 6px 0', fontSize: '0.9rem', color: 'var(--color-accent)' }}>
                          Employee Choice Permitted by Policy
                        </h4>
                        <p style={{ fontSize: '0.82rem', marginBottom: '12px' }}>
                          This transfer triggered a policy warning. Organizational guidelines allow you to confirm whether this data is necessary for your work or cancel the transfer.
                        </p>
                        <div style={{ display: 'flex', gap: '8px' }}>
                          <button
                            type="button"
                            className="btn btn-primary"
                            style={{ fontSize: '0.8rem', padding: '6px 12px' }}
                            onClick={() => setEmployeeProceedChoice('proceeded')}
                          >
                            ✓ Proceed with Acknowledged Warning
                          </button>
                          <button
                            type="button"
                            className="btn btn-secondary"
                            style={{ fontSize: '0.8rem', padding: '6px 12px' }}
                            onClick={() => setEmployeeProceedChoice('cancelled')}
                          >
                            ✕ Cancel Transfer
                          </button>
                        </div>
                      </div>
                    )}

                    {employeeProceedChoice === 'proceeded' && (
                      <div className="banner banner-info" style={{ marginBottom: '14px', fontSize: '0.85rem' }}>
                        <span>ℹ️ Employee acknowledged policy warning and opted to proceed. Acknowledgment recorded in compliance log.</span>
                      </div>
                    )}

                    {employeeProceedChoice === 'cancelled' && (
                      <div className="banner banner-success" style={{ marginBottom: '14px', fontSize: '0.85rem' }}>
                        <span>✓ Transfer cancelled by employee. No data sent.</span>
                      </div>
                    )}

                    {/* Matched Rules */}
                    <div style={{ marginBottom: '14px' }}>
                      <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--color-muted)', display: 'block', marginBottom: '4px' }}>
                        Matched Organizational Rules:
                      </span>
                      {inspectionResult.matchedRules.length === 0 ? (
                        <span style={{ fontSize: '0.85rem', color: 'var(--color-muted)' }}>None (Standard baseline controls apply)</span>
                      ) : (
                        <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                          {inspectionResult.matchedRules.map((r: string, i: number) => (
                            <span key={i} className="badge badge-secondary" style={{ fontSize: '0.8rem' }}>
                              📋 {r}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>

                    {/* Detected Categories */}
                    <div style={{ marginBottom: '14px' }}>
                      <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--color-muted)', display: 'block', marginBottom: '4px' }}>
                        Sensitive Patterns Detected ({inspectionResult.totalFindings} findings):
                      </span>
                      {inspectionResult.detectedTypes.length === 0 ? (
                        <span style={{ fontSize: '0.85rem', color: 'var(--color-muted)' }}>No sensitive patterns detected.</span>
                      ) : (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                          {inspectionResult.detectedTypes.map((dt: FileInspectionMatch, i: number) => (
                            <div
                              key={i}
                              style={{
                                display: 'flex',
                                justifyContent: 'space-between',
                                alignItems: 'center',
                                padding: '6px 10px',
                                background: 'var(--color-surface)',
                                borderRadius: '4px',
                                fontSize: '0.82rem',
                              }}
                            >
                              <span>🏷️ {dt.category} (x{dt.count})</span>
                              <RiskBadge level={dt.riskLevel} />
                            </div>
                          ))}
                        </div>
                      )}
                    </div>

                    {/* Redacted Preview */}
                    <div style={{ marginBottom: '14px' }}>
                      <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--color-muted)', display: 'block', marginBottom: '4px' }}>
                        Safe Redacted Preview (Secrets Removed):
                      </span>
                      <pre
                        style={{
                          background: 'var(--color-surface-hover)',
                          padding: '10px',
                          borderRadius: '6px',
                          fontSize: '0.78rem',
                          maxHeight: '130px',
                          overflowY: 'auto',
                          whiteSpace: 'pre-wrap',
                          wordBreak: 'break-all',
                        }}
                      >
                        {inspectionResult.redactedPreview || '[Empty or non-text content]'}
                      </pre>
                    </div>

                    {/* Limitations & Boundaries */}
                    <div style={{ borderTop: '1px solid var(--color-border)', paddingTop: '10px' }}>
                      <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--color-muted)', display: 'block', marginBottom: '2px' }}>
                        System Limitations:
                      </span>
                      <ul style={{ margin: 0, paddingLeft: '18px', fontSize: '0.75rem', color: 'var(--color-muted)' }}>
                        {inspectionResult.limitations.map((lim: string, i: number) => (
                          <li key={i}>{lim}</li>
                        ))}
                      </ul>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </Section>
        </div>
      )}

      {/* ──────────────────────────────────────────────────────────────────────────
          TAB 2: CONFIGURABLE SHARING POLICIES
          ────────────────────────────────────────────────────────────────────────── */}
      {activeTab === 'policies' && (
        <div className="animate-fade-in">
          <Section
            title="Organizational Data-Sharing Policies"
            description="Define which data types may be shared with which external or internal tools. Viewers and analysts see read-only rules; administrators can modify or create policies."
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
              <div>
                <span style={{ fontSize: '0.85rem', color: 'var(--color-muted)' }}>
                  Current Demo Role: <strong>{userRole}</strong> {canEditPolicies ? '(Admin permissions granted)' : '(Read-only view)'}
                </span>
              </div>
              {canEditPolicies && (
                <button
                  type="button"
                  className="btn btn-primary"
                  onClick={() => setRuleModalOpen(true)}
                  style={{ fontSize: '0.85rem' }}
                >
                  + Add New Sharing Rule
                </button>
              )}
            </div>

            <div className="card" style={{ overflowX: 'auto', padding: 0 }}>
              <table className="table" style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--color-border)', textAlign: 'left', fontSize: '0.8rem', color: 'var(--color-muted)' }}>
                    <th style={{ padding: '12px 16px' }}>Rule Name & Description</th>
                    <th style={{ padding: '12px 16px' }}>Data Categories</th>
                    <th style={{ padding: '12px 16px' }}>Allowed Destinations</th>
                    <th style={{ padding: '12px 16px' }}>Action</th>
                    <th style={{ padding: '12px 16px' }}>Status</th>
                    {canEditPolicies && <th style={{ padding: '12px 16px' }}>Admin Toggle</th>}
                  </tr>
                </thead>
                <tbody>
                  {rules.map((rule) => (
                    <tr key={rule.id} style={{ borderBottom: '1px solid var(--color-border)', fontSize: '0.85rem' }}>
                      <td style={{ padding: '12px 16px' }}>
                        <strong>{rule.rule_name}</strong>
                        {rule.description && (
                          <p style={{ margin: '4px 0 0 0', fontSize: '0.78rem', color: 'var(--color-muted)' }}>
                            {rule.description}
                          </p>
                        )}
                      </td>
                      <td style={{ padding: '12px 16px' }}>
                        <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                          {rule.data_types.map((dt: string, i: number) => (
                            <span key={i} className="badge badge-secondary" style={{ fontSize: '0.75rem' }}>
                              {dt}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td style={{ padding: '12px 16px' }}>
                        <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                          {rule.allowed_tools.includes('*') ? (
                            <span className="badge badge-success" style={{ fontSize: '0.75rem' }}>All Allowed</span>
                          ) : (
                            rule.allowed_tools.map((at: string, i: number) => (
                              <span key={i} className="badge badge-info" style={{ fontSize: '0.75rem' }}>
                                {at}
                              </span>
                            ))
                          )}
                        </div>
                      </td>
                      <td style={{ padding: '12px 16px' }}>
                        <span
                          className={`badge ${
                            rule.action === 'block' ? 'badge-critical' :
                            rule.action === 'warn' ? 'badge-high' : 'badge-low'
                          }`}
                        >
                          {rule.action.toUpperCase()}
                        </span>
                      </td>
                      <td style={{ padding: '12px 16px' }}>
                        <span className={`badge ${rule.is_active ? 'badge-success' : 'badge-secondary'}`}>
                          {rule.is_active ? 'Active' : 'Disabled'}
                        </span>
                      </td>
                      {canEditPolicies && (
                        <td style={{ padding: '12px 16px' }}>
                          <button
                            type="button"
                            className="btn btn-secondary"
                            style={{ fontSize: '0.75rem', padding: '4px 8px' }}
                            onClick={() => handleToggleRule(rule)}
                          >
                            {rule.is_active ? 'Disable' : 'Enable'}
                          </button>
                        </td>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Modal for adding rule */}
            {ruleModalOpen && (
              <div
                style={{
                  position: 'fixed',
                  top: 0,
                  left: 0,
                  right: 0,
                  bottom: 0,
                  background: 'rgba(0,0,0,0.6)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  zIndex: 999,
                }}
              >
                <div className="card" style={{ width: '500px', maxWidth: '90%', padding: '24px' }}>
                  <h3 style={{ marginTop: 0, marginBottom: '16px' }}>Create Data-Sharing Policy Rule</h3>
                  <form onSubmit={handleCreateRule}>
                    <div style={{ marginBottom: '12px' }}>
                      <label style={{ display: 'block', fontSize: '0.85rem', marginBottom: '4px' }}>Rule Name</label>
                      <input
                        type="text"
                        className="input"
                        style={{ width: '100%' }}
                        value={newRuleName}
                        onChange={(e) => setNewRuleName(e.target.value)}
                        placeholder="e.g. Prohibit Source Code to Third-Party AI"
                        required
                      />
                    </div>
                    <div style={{ marginBottom: '12px' }}>
                      <label style={{ display: 'block', fontSize: '0.85rem', marginBottom: '4px' }}>Data Categories (Select)</label>
                      <select
                        multiple
                        className="input"
                        style={{ width: '100%', height: '90px' }}
                        value={newRuleDataTypes}
                        onChange={(e) => setNewRuleDataTypes(Array.from(e.target.selectedOptions, o => o.value))}
                      >
                        <option value="API Keys & Access Tokens">API Keys & Access Tokens</option>
                        <option value="Password-like Assignments">Password-like Assignments</option>
                        <option value="Private Cryptographic Keys">Private Cryptographic Keys</option>
                        <option value="Payment Card Numbers (PCI/Luhn)">Payment Card Numbers (PCI/Luhn)</option>
                        <option value="Email Address (PII)">Email Address (PII)</option>
                        <option value="Sensitive Business Information">Sensitive Business Information</option>
                      </select>
                    </div>
                    <div style={{ marginBottom: '12px' }}>
                      <label style={{ display: 'block', fontSize: '0.85rem', marginBottom: '4px' }}>Allowed Tools (comma-separated)</label>
                      <input
                        type="text"
                        className="input"
                        style={{ width: '100%' }}
                        value={newRuleAllowedTools}
                        onChange={(e) => setNewRuleAllowedTools(e.target.value)}
                        placeholder="e.g. Internal Llama Endpoint"
                      />
                    </div>
                    <div style={{ marginBottom: '12px' }}>
                      <label style={{ display: 'block', fontSize: '0.85rem', marginBottom: '4px' }}>Blocked Tools (comma-separated or * for all other)</label>
                      <input
                        type="text"
                        className="input"
                        style={{ width: '100%' }}
                        value={newRuleBlockedTools}
                        onChange={(e) => setNewRuleBlockedTools(e.target.value)}
                        placeholder="*"
                      />
                    </div>
                    <div style={{ marginBottom: '12px' }}>
                      <label style={{ display: 'block', fontSize: '0.85rem', marginBottom: '4px' }}>Policy Action</label>
                      <select
                        className="input"
                        style={{ width: '100%' }}
                        value={newRuleAction}
                        onChange={(e) => setNewRuleAction(e.target.value as any)}
                      >
                        <option value="block">Block Transfer</option>
                        <option value="warn">Warn & Employee Acknowledgment</option>
                        <option value="allow">Allow Transfer</option>
                      </select>
                    </div>
                    <div style={{ marginBottom: '16px' }}>
                      <label style={{ display: 'block', fontSize: '0.85rem', marginBottom: '4px' }}>Description / Rationale</label>
                      <input
                        type="text"
                        className="input"
                        style={{ width: '100%' }}
                        value={newRuleDesc}
                        onChange={(e) => setNewRuleDesc(e.target.value)}
                        placeholder="Context for why this rule is enforced"
                      />
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px' }}>
                      <button type="button" className="btn btn-secondary" onClick={() => setRuleModalOpen(false)}>
                        Cancel
                      </button>
                      <button type="submit" className="btn btn-primary" disabled={ruleSubmitting}>
                        {ruleSubmitting ? 'Saving...' : 'Save Rule'}
                      </button>
                    </div>
                  </form>
                </div>
              </div>
            )}
          </Section>
        </div>
      )}

      {/* ──────────────────────────────────────────────────────────────────────────
          TAB 3: REPEATED ATTEMPTS TRACKING
          ────────────────────────────────────────────────────────────────────────── */}
      {activeTab === 'attempts' && (
        <div className="animate-fade-in">
          <Section
            title="Repeated Transfer Attempts Review"
            description="Tracks repeated attempts to send restricted or blocked data. Flagged for authorized compliance review after 3+ attempts. Maintained with neutral, non-punitive language to avoid labeling employees as malicious."
          >
            <div className="card" style={{ overflowX: 'auto', padding: 0 }}>
              <table className="table" style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--color-border)', textAlign: 'left', fontSize: '0.8rem', color: 'var(--color-muted)' }}>
                    <th style={{ padding: '12px 16px' }}>User / Identity</th>
                    <th style={{ padding: '12px 16px' }}>Destination</th>
                    <th style={{ padding: '12px 16px' }}>Detected Data Type</th>
                    <th style={{ padding: '12px 16px' }}>Matched Policy Rule</th>
                    <th style={{ padding: '12px 16px' }}>Attempt Count</th>
                    <th style={{ padding: '12px 16px' }}>Status</th>
                    <th style={{ padding: '12px 16px' }}>Review Note</th>
                    <th style={{ padding: '12px 16px' }}>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {attempts.length === 0 ? (
                    <tr>
                      <td colSpan={8} style={{ padding: '24px', textAlign: 'center', color: 'var(--color-muted)' }}>
                        No repeated transfer attempts recorded yet.
                      </td>
                    </tr>
                  ) : (
                    attempts.map((att: TransferAttemptRow) => (
                      <tr key={att.id} style={{ borderBottom: '1px solid var(--color-border)', fontSize: '0.85rem' }}>
                        <td style={{ padding: '12px 16px' }}>
                          <strong>{att.person_name || att.person_email || 'Unattributed User'}</strong>
                        </td>
                        <td style={{ padding: '12px 16px' }}>{att.destination}</td>
                        <td style={{ padding: '12px 16px' }}>
                          <span className="badge badge-secondary" style={{ fontSize: '0.75rem' }}>
                            {att.data_type}
                          </span>
                        </td>
                        <td style={{ padding: '12px 16px' }}>{att.matched_rule}</td>
                        <td style={{ padding: '12px 16px' }}>
                          <span
                            className={`badge ${att.attempt_count >= 3 ? 'badge-critical' : 'badge-high'}`}
                            style={{ fontWeight: 600 }}
                          >
                            {att.attempt_count} attempts
                          </span>
                        </td>
                        <td style={{ padding: '12px 16px' }}>
                          {att.flagged_for_review === 1 ? (
                            <span className="badge badge-high">⚠️ Flagged for Compliance Review</span>
                          ) : (
                            <span className="badge badge-secondary">Under Threshold</span>
                          )}
                        </td>
                        <td style={{ padding: '12px 16px', maxWidth: '200px' }}>
                          {att.review_note ? (
                            <span style={{ fontSize: '0.78rem', color: 'var(--color-text)' }}>{att.review_note}</span>
                          ) : (
                            <span style={{ fontSize: '0.78rem', color: 'var(--color-muted)' }}>No analyst note</span>
                          )}
                        </td>
                        <td style={{ padding: '12px 16px' }}>
                          <button
                            type="button"
                            className="btn btn-secondary"
                            style={{ fontSize: '0.75rem', padding: '4px 8px' }}
                            onClick={() => {
                              setSelectedAttempt(att);
                              setReviewNote(att.review_note || '');
                            }}
                          >
                            {att.review_note ? 'Edit Note' : 'Add Review'}
                          </button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>

            {/* Note Dialog */}
            {selectedAttempt && (
              <div
                style={{
                  position: 'fixed',
                  top: 0,
                  left: 0,
                  right: 0,
                  bottom: 0,
                  background: 'rgba(0,0,0,0.6)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  zIndex: 999,
                }}
              >
                <div className="card" style={{ width: '450px', maxWidth: '90%', padding: '24px' }}>
                  <h3 style={{ marginTop: 0, marginBottom: '8px' }}>Compliance Review Note</h3>
                  <p style={{ fontSize: '0.8rem', color: 'var(--color-muted)', marginBottom: '14px' }}>
                    Document review findings for {selectedAttempt.person_name || selectedAttempt.person_email} regarding {selectedAttempt.attempt_count} attempts to send {selectedAttempt.data_type} to {selectedAttempt.destination}.
                  </p>
                  <form onSubmit={handleSubmitReview}>
                    <textarea
                      rows={4}
                      className="input"
                      style={{ width: '100%', marginBottom: '14px' }}
                      value={reviewNote}
                      onChange={(e) => setReviewNote(e.target.value)}
                      placeholder="e.g. Consulted employee; guided user to approved internal Llama workflow."
                      required
                    />
                    <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px' }}>
                      <button type="button" className="btn btn-secondary" onClick={() => setSelectedAttempt(null)}>
                        Cancel
                      </button>
                      <button type="submit" className="btn btn-primary" disabled={reviewSubmitting || !reviewNote.trim()}>
                        {reviewSubmitting ? 'Saving...' : 'Record Review'}
                      </button>
                    </div>
                  </form>
                </div>
              </div>
            )}
          </Section>
        </div>
      )}      {/* ──────────────────────────────────────────────────────────────────────────
          TAB 4: INSPECTION LOG
          ────────────────────────────────────────────────────────────────────────── */}
      {activeTab === 'history' && (
        <div className="animate-fade-in">
          <Section
            title="Inspection Audit History"
            description="Metadata-only record of all outbound and inbound inspections. Zero file content or secrets persisted."
          >
            <div className="card" style={{ overflowX: 'auto', padding: 0 }}>
              <table className="table" style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--color-border)', textAlign: 'left', fontSize: '0.8rem', color: 'var(--color-muted)' }}>
                    <th style={{ padding: '10px 14px' }}>Time</th>
                    <th style={{ padding: '10px 14px' }}>Filename & Size</th>
                    <th style={{ padding: '10px 14px' }}>Destination</th>
                    <th style={{ padding: '10px 14px' }}>Detected Types</th>
                    <th style={{ padding: '10px 14px' }}>Action</th>
                    <th style={{ padding: '10px 14px' }}>Risk</th>
                    <th style={{ padding: '10px 14px' }}>User / Actor</th>
                  </tr>
                </thead>
                <tbody>
                  {history.length === 0 ? (
                    <tr>
                      <td colSpan={7} style={{ padding: '24px', textAlign: 'center', color: 'var(--color-muted)' }}>
                        No inspections recorded yet.
                      </td>
                    </tr>
                  ) : (
                    history.map((row: InspectionHistoryRow) => (
                      <tr key={row.id} style={{ borderBottom: '1px solid var(--color-border)', fontSize: '0.82rem' }}>
                        <td style={{ padding: '10px 14px', whiteSpace: 'nowrap' }}>{row.created_at}</td>
                        <td style={{ padding: '10px 14px' }}>
                          <strong>{row.filename}</strong>
                          <div style={{ fontSize: '0.72rem', color: 'var(--color-muted)' }}>
                            {row.file_type} • {row.file_size_bytes} B
                          </div>
                        </td>
                        <td style={{ padding: '10px 14px' }}>{row.destination}</td>
                        <td style={{ padding: '10px 14px' }}>
                          <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                            {row.detected_types.map((dt: string, i: number) => (
                              <span key={i} className="badge badge-secondary" style={{ fontSize: '0.72rem' }}>
                                {dt}
                              </span>
                            ))}
                          </div>
                        </td>
                        <td style={{ padding: '10px 14px' }}>
                          <span className={`badge badge-${row.action_taken === 'blocked' ? 'critical' : row.action_taken === 'warned' ? 'high' : 'low'}`}>
                            {row.action_taken.toUpperCase()}
                          </span>
                        </td>
                        <td style={{ padding: '10px 14px' }}>
                          <RiskBadge level={row.risk_level as any} />
                        </td>
                        <td style={{ padding: '10px 14px' }}>{row.person_name || row.actor}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </Section>
        </div>
      )}
    </div>
  );
}
