// ─── Governance & Policy Controls Page ───────────────────────────────────────
// Comprehensive Governance section for AURA:
// - Policy thresholds (0-100, logically ordered)
// - Additive demo weights (0-50 bounds)
// - Transfer volume anomaly threshold (1-500 MB)
// - Severity response recommendations review
// - Service approval status controls (Approved, Needs review, Unapproved)
// - Tamper-evident SHA-256 audit history trail
// - In-app confirmation dialog before saving policy modifications
// - Architecture workflow, privacy boundaries, and Team Zero Limit card

import { useState, useEffect } from 'react';
import {
  api,
  type PolicyThresholds,
  type PolicyWeights,
  type PolicyRecommendations,
  type AuditEntryItem,
  type Service,
} from '../api/client';
import { INTEGRATION_TILES } from '../mockData';
import {
  StateBadge,
  WorkflowDiagram,
  DemoNotice,
  PageHeader,
  Section,
} from '../components/ui';

const TEAM_MEMBERS = [
  { initials: 'SR', name: 'Srujan', role: 'Team Leader' },
  { initials: 'SS', name: 'Sudeep Sr', role: '— role to be defined —' },
  { initials: 'TN', name: 'Thrishul N', role: '— role to be defined —' },
];

const PRIVACY_ITEMS = [
  {
    icon: '🚫',
    text: 'No live network connection, packet capture, or promiscuous sniffing is active in this prototype.',
  },
  {
    icon: '🚫',
    text: 'No network scanning, subnet probing, or HTTPS decryption is performed at any stage.',
  },
  {
    icon: '📋',
    text: 'Network records analyze privacy-safe metadata only. They never expose raw prompt text or file contents.',
  },
  {
    icon: '🔬',
    text: 'Prompt Lab evaluates text strictly in memory for privacy preview and never stores raw prompts in database records.',
  },
  {
    icon: '🔔',
    text: 'No real warning emails, browser alerts, or firewall block commands are dispatched. All actions are simulated.',
  },
  {
    icon: '🏷️',
    text: '"Would block" labels appear strictly as simulated policy recommendations, never as active connection blocks.',
  },
  {
    icon: '🔐',
    text: 'Audit trail uses a local tamper-evident SHA-256 hash chain without storing sensitive inputs or secrets.',
  },
];

export function Governance() {
  // Policy settings state
  const [thresholds, setThresholds] = useState<PolicyThresholds>({
    medium_threshold: 25,
    high_threshold: 50,
    critical_threshold: 75,
  });
  const [weights, setWeights] = useState<PolicyWeights>({
    sensitivity_restricted: 35,
    sensitivity_confidential: 25,
    sensitivity_internal: 10,
    service_unapproved: 20,
    service_under_review: 12,
    auth_denied_or_mismatch: 20,
    high_transfer_volume: 18,
    anomaly_signal_flagged: 10,
  });
  const [volumeThresholdMb, setVolumeThresholdMb] = useState<number>(5);
  const [recommendations, setRecommendations] = useState<PolicyRecommendations>({
    low: 'Allow or record for visibility',
    medium: 'Warn / review before sending',
    high: 'Review promptly',
    critical: 'Would block before transmission (simulation)',
  });
  const [fieldDescriptions, setFieldDescriptions] = useState<Record<string, string>>({});
  const [canEditPolicies, setCanEditPolicies] = useState(false);
  const [userRole, setUserRole] = useState('viewer');

  // Services registry
  const [services, setServices] = useState<Service[]>([]);
  const [servicesLoading, setServicesLoading] = useState(true);

  // Audit history
  const [auditEntries, setAuditEntries] = useState<AuditEntryItem[]>([]);
  const [isChainValid, setIsChainValid] = useState(true);
  const [chainStatus, setChainStatus] = useState('Verifying hash chain…');
  const [auditLoading, setAuditLoading] = useState(true);

  // UI status & feedback
  const [loadingPolicies, setLoadingPolicies] = useState(true);
  const [policyError, setPolicyError] = useState<string | null>(null);
  const [policySuccess, setPolicySuccess] = useState<string | null>(null);
  const [showConfirmModal, setShowConfirmModal] = useState(false);
  const [savingPolicies, setSavingPolicies] = useState(false);

  // Load policy settings
  const loadPolicies = async () => {
    try {
      setLoadingPolicies(true);
      const res = await api.policies();
      setThresholds(res.thresholds);
      setWeights(res.weights);
      setVolumeThresholdMb(res.volumeThresholdMb);
      setRecommendations(res.recommendations);
      setFieldDescriptions(res.fieldDescriptions || {});
      setCanEditPolicies(res.canEdit);
      setUserRole(res.userRole);
    } catch (err: unknown) {
      setPolicyError(err instanceof Error ? err.message : 'Failed to load policies.');
    } finally {
      setLoadingPolicies(false);
    }
  };

  // Load services for approval governance
  const loadServices = async () => {
    try {
      setServicesLoading(true);
      const res = await api.services();
      setServices(res.services);
    } catch {
      // ignore
    } finally {
      setServicesLoading(false);
    }
  };

  // Load audit history
  const loadAuditHistory = async () => {
    try {
      setAuditLoading(true);
      const res = await api.auditLog(25);
      setAuditEntries(res.entries);
      setIsChainValid(res.isChainValid);
      setChainStatus(res.chainStatus);
    } catch {
      setChainStatus('Failed to retrieve audit log');
    } finally {
      setAuditLoading(false);
    }
  };

  useEffect(() => {
    loadPolicies();
    loadServices();
    loadAuditHistory();
  }, []);

  // Validate policy form client-side before confirmation
  const validatePolicies = (): string | null => {
    if (
      thresholds.medium_threshold <= 0 ||
      thresholds.medium_threshold >= thresholds.high_threshold ||
      thresholds.high_threshold >= thresholds.critical_threshold ||
      thresholds.critical_threshold > 100
    ) {
      return 'Thresholds must be strictly ordered within 1–100: 0 < Medium < High < Critical ≤ 100.';
    }

    for (const [key, val] of Object.entries(weights)) {
      if (typeof val !== 'number' || val < 0 || val > 50) {
        return `Weight '${key}' must be between 0 and 50 points.`;
      }
    }

    if (volumeThresholdMb < 1 || volumeThresholdMb > 500) {
      return 'Transfer volume threshold must be between 1 and 500 MB.';
    }

    return null;
  };

  // Save policy settings
  const handleSavePolicies = async () => {
    const errorMsg = validatePolicies();
    if (errorMsg) {
      setPolicyError(errorMsg);
      setShowConfirmModal(false);
      return;
    }

    try {
      setSavingPolicies(true);
      setPolicyError(null);
      setPolicySuccess(null);

      const res = await api.updatePolicies({
        thresholds,
        weights,
        volumeThresholdMb,
      });

      if (res.success) {
        setPolicySuccess('Policy settings updated successfully! Changes apply to future demo events.');
        setShowConfirmModal(false);
        await loadAuditHistory(); // Refresh audit trail
      }
    } catch (err: unknown) {
      setPolicyError(err instanceof Error ? err.message : 'Failed to update policy settings.');
      setShowConfirmModal(false);
    } finally {
      setSavingPolicies(false);
    }
  };

  // Update service approval status (Admin only)
  const handleServiceApprovalChange = async (serviceId: number, newStatus: string) => {
    try {
      const res = await api.updateServiceApproval(serviceId, newStatus);
      if (res.success) {
        setServices((prev) =>
          prev.map((s) => (s.id === serviceId ? { ...s, approval_status: newStatus } : s))
        );
        await loadAuditHistory(); // Refresh audit trail
      }
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Failed to update service approval status.');
    }
  };

  return (
    <>
      <PageHeader
        title="Governance & Policy Controls"
        subtitle="Configurable risk policy rules, service approvals, tamper-evident audit history, and prototype boundaries."
      />

      <main className="page-body">
        <DemoNotice
          message={
            'LOCAL DEMO GOVERNANCE — Policies configured here govern future deterministic evaluations and simulations in AURA. Historical event scores and timestamps remain untouched. No external firewalls, devices, or APIs are modified.'
          }
        />

        {/* ── 1. Administrator Policy Controls ────────────────────────────── */}
        <Section title="Risk Thresholds & Additive Weights">
          <div className="card card-body">
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                marginBottom: '16px',
                flexWrap: 'wrap',
                gap: '12px',
              }}
            >
              <div>
                <h3 className="font-semibold text-md" style={{ color: 'var(--color-text)' }}>
                  Demo Policy Configuration
                </h3>
                <p className="text-xs text-muted mt-1">
                  Tune risk engine thresholds, data weights, and volume anomaly limits.
                </p>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span
                  style={{
                    fontSize: 'var(--text-xs)',
                    padding: '3px 10px',
                    borderRadius: 'var(--radius-full)',
                    background: canEditPolicies ? 'rgba(37, 168, 149, 0.15)' : 'rgba(107, 122, 148, 0.15)',
                    color: canEditPolicies ? 'var(--color-accent-dim)' : 'var(--color-text-muted)',
                    fontWeight: 'var(--weight-semibold)',
                  }}
                >
                  {canEditPolicies ? '⚡ Administrator Edit Access' : `🔒 Read-Only (${userRole})`}
                </span>
              </div>
            </div>

            {/* Error or Success Notice */}
            {policyError && (
              <div
                className="card card-body mb-4"
                style={{
                  background: 'rgba(217, 103, 97, 0.1)',
                  borderColor: 'rgba(217, 103, 97, 0.3)',
                  padding: '10px 14px',
                }}
              >
                <p className="text-sm font-semibold" style={{ color: 'var(--color-critical)' }}>
                  Validation Error: {policyError}
                </p>
              </div>
            )}

            {policySuccess && (
              <div
                className="card card-body mb-4"
                style={{
                  background: 'rgba(46, 157, 110, 0.1)',
                  borderColor: 'rgba(46, 157, 110, 0.3)',
                  padding: '10px 14px',
                }}
              >
                <p className="text-sm font-semibold" style={{ color: 'var(--risk-low)' }}>
                  ✓ {policySuccess}
                </p>
              </div>
            )}

            {loadingPolicies ? (
              <p className="text-sm text-muted">Loading policy configuration…</p>
            ) : (
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  const err = validatePolicies();
                  if (err) {
                    setPolicyError(err);
                  } else {
                    setPolicyError(null);
                    setShowConfirmModal(true);
                  }
                }}
              >
                {/* Score Cutoff Thresholds */}
                <div style={{ marginBottom: '24px' }}>
                  <span className="section-label">1. Severity Score Cutoff Thresholds (0–100 Scale)</span>
                  <p className="text-xs text-muted mb-3">
                    Defines the score brackets that categorize events. Must satisfy: 0 &lt; Medium &lt; High &lt; Critical ≤ 100.
                  </p>

                  <div
                    style={{
                      display: 'grid',
                      gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
                      gap: '16px',
                    }}
                  >
                    <div>
                      <label className="text-xs font-semibold" htmlFor="med-thresh">
                        Medium Severity Threshold
                      </label>
                      <input
                        id="med-thresh"
                        type="number"
                        className="input-text w-full mt-1"
                        min={1}
                        max={98}
                        disabled={!canEditPolicies}
                        value={thresholds.medium_threshold}
                        onChange={(e) =>
                          setThresholds({ ...thresholds, medium_threshold: parseInt(e.target.value, 10) || 0 })
                        }
                      />
                      <span className="text-xs text-muted mt-1 block">
                        Score ≥ {thresholds.medium_threshold} triggers Medium (warn/review).
                      </span>
                    </div>

                    <div>
                      <label className="text-xs font-semibold" htmlFor="high-thresh">
                        High Severity Threshold
                      </label>
                      <input
                        id="high-thresh"
                        type="number"
                        className="input-text w-full mt-1"
                        min={2}
                        max={99}
                        disabled={!canEditPolicies}
                        value={thresholds.high_threshold}
                        onChange={(e) =>
                          setThresholds({ ...thresholds, high_threshold: parseInt(e.target.value, 10) || 0 })
                        }
                      />
                      <span className="text-xs text-muted mt-1 block">
                        Score ≥ {thresholds.high_threshold} triggers High (prompt review).
                      </span>
                    </div>

                    <div>
                      <label className="text-xs font-semibold" htmlFor="crit-thresh">
                        Critical Severity Threshold
                      </label>
                      <input
                        id="crit-thresh"
                        type="number"
                        className="input-text w-full mt-1"
                        min={3}
                        max={100}
                        disabled={!canEditPolicies}
                        value={thresholds.critical_threshold}
                        onChange={(e) =>
                          setThresholds({ ...thresholds, critical_threshold: parseInt(e.target.value, 10) || 0 })
                        }
                      />
                      <span className="text-xs text-muted mt-1 block">
                        Score ≥ {thresholds.critical_threshold} triggers Critical (simulated block).
                      </span>
                    </div>
                  </div>
                </div>

                {/* Additive Weights Grid */}
                <div style={{ marginBottom: '24px' }}>
                  <span className="section-label">2. Additive Demo Weights (0–50 Points Each)</span>
                  <p className="text-xs text-muted mb-3">
                    Points contributed by individual findings. Total points are summed and clamped to 0–100.
                  </p>

                  <div
                    style={{
                      display: 'grid',
                      gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
                      gap: '16px',
                    }}
                  >
                    <div>
                      <label className="text-xs font-semibold" htmlFor="w-rest">
                        Restricted Data Sensitivity
                      </label>
                      <input
                        id="w-rest"
                        type="number"
                        className="input-text w-full mt-1"
                        min={0}
                        max={50}
                        disabled={!canEditPolicies}
                        value={weights.sensitivity_restricted}
                        onChange={(e) =>
                          setWeights({ ...weights, sensitivity_restricted: parseInt(e.target.value, 10) || 0 })
                        }
                      />
                      <span className="text-xs text-muted block mt-1">
                        {fieldDescriptions.sensitivity_restricted || 'Restricted data label points.'}
                      </span>
                    </div>

                    <div>
                      <label className="text-xs font-semibold" htmlFor="w-conf">
                        Confidential Data Sensitivity
                      </label>
                      <input
                        id="w-conf"
                        type="number"
                        className="input-text w-full mt-1"
                        min={0}
                        max={50}
                        disabled={!canEditPolicies}
                        value={weights.sensitivity_confidential}
                        onChange={(e) =>
                          setWeights({ ...weights, sensitivity_confidential: parseInt(e.target.value, 10) || 0 })
                        }
                      />
                      <span className="text-xs text-muted block mt-1">
                        {fieldDescriptions.sensitivity_confidential || 'Confidential data label points.'}
                      </span>
                    </div>

                    <div>
                      <label className="text-xs font-semibold" htmlFor="w-unapp">
                        Unapproved AI Destination
                      </label>
                      <input
                        id="w-unapp"
                        type="number"
                        className="input-text w-full mt-1"
                        min={0}
                        max={50}
                        disabled={!canEditPolicies}
                        value={weights.service_unapproved}
                        onChange={(e) =>
                          setWeights({ ...weights, service_unapproved: parseInt(e.target.value, 10) || 0 })
                        }
                      />
                      <span className="text-xs text-muted block mt-1">
                        {fieldDescriptions.service_unapproved || 'Unapproved destination penalty.'}
                      </span>
                    </div>

                    <div>
                      <label className="text-xs font-semibold" htmlFor="w-rev">
                        Needs Review / Unknown AI Destination
                      </label>
                      <input
                        id="w-rev"
                        type="number"
                        className="input-text w-full mt-1"
                        min={0}
                        max={50}
                        disabled={!canEditPolicies}
                        value={weights.service_under_review}
                        onChange={(e) =>
                          setWeights({ ...weights, service_under_review: parseInt(e.target.value, 10) || 0 })
                        }
                      />
                      <span className="text-xs text-muted block mt-1">
                        {fieldDescriptions.service_under_review || 'Unreviewed destination points.'}
                      </span>
                    </div>

                    <div>
                      <label className="text-xs font-semibold" htmlFor="w-auth">
                        Authorization Denial or Mismatch
                      </label>
                      <input
                        id="w-auth"
                        type="number"
                        className="input-text w-full mt-1"
                        min={0}
                        max={50}
                        disabled={!canEditPolicies}
                        value={weights.auth_denied_or_mismatch}
                        onChange={(e) =>
                          setWeights({ ...weights, auth_denied_or_mismatch: parseInt(e.target.value, 10) || 0 })
                        }
                      />
                      <span className="text-xs text-muted block mt-1">
                        {fieldDescriptions.auth_denied_or_mismatch || 'Identity authorization mismatch points.'}
                      </span>
                    </div>

                    <div>
                      <label className="text-xs font-semibold" htmlFor="w-anom">
                        Supplied Anomaly Flag
                      </label>
                      <input
                        id="w-anom"
                        type="number"
                        className="input-text w-full mt-1"
                        min={0}
                        max={50}
                        disabled={!canEditPolicies}
                        value={weights.anomaly_signal_flagged}
                        onChange={(e) =>
                          setWeights({ ...weights, anomaly_signal_flagged: parseInt(e.target.value, 10) || 0 })
                        }
                      />
                      <span className="text-xs text-muted block mt-1">
                        {fieldDescriptions.anomaly_signal_flagged || 'Explicit metadata anomaly signal.'}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Transfer Volume Anomaly Limit */}
                <div style={{ marginBottom: '24px' }}>
                  <span className="section-label">3. Transfer Volume Anomaly Threshold</span>
                  <div style={{ maxWidth: '300px', marginTop: '8px' }}>
                    <label className="text-xs font-semibold" htmlFor="vol-thresh">
                      Transfer Volume Threshold (MB)
                    </label>
                    <input
                      id="vol-thresh"
                      type="number"
                      className="input-text w-full mt-1"
                      min={1}
                      max={500}
                      disabled={!canEditPolicies}
                      value={volumeThresholdMb}
                      onChange={(e) => setVolumeThresholdMb(parseFloat(e.target.value) || 1)}
                    />
                    <span className="text-xs text-muted mt-1 block">
                      Transfers exceeding {volumeThresholdMb} MB add +{weights.high_transfer_volume} points.
                    </span>
                  </div>
                </div>

                {/* Severity Response Recommendations Review */}
                <div style={{ marginBottom: '24px' }}>
                  <span className="section-label">4. Current Severity Response Outcomes (Simulation Text)</span>
                  <div className="table-wrapper mt-2">
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th style={{ width: '120px' }}>Severity</th>
                          <th>Current Simulated Recommendation</th>
                        </tr>
                      </thead>
                      <tbody>
                        <tr>
                          <td><span className="badge badge-low">Low</span></td>
                          <td className="text-sm">{recommendations.low}</td>
                        </tr>
                        <tr>
                          <td><span className="badge badge-medium">Medium</span></td>
                          <td className="text-sm">{recommendations.medium}</td>
                        </tr>
                        <tr>
                          <td><span className="badge badge-high">High</span></td>
                          <td className="text-sm">{recommendations.high}</td>
                        </tr>
                        <tr>
                          <td><span className="badge badge-critical">Critical</span></td>
                          <td className="text-sm font-medium">{recommendations.critical}</td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* Form Actions */}
                {canEditPolicies ? (
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginTop: '16px' }}>
                    <button
                      type="submit"
                      className="btn btn-primary"
                      disabled={savingPolicies}
                    >
                      Save Policy Changes
                    </button>
                    <span className="text-xs text-muted">
                      Requires administrator confirmation dialog before writing to policy database.
                    </span>
                  </div>
                ) : (
                  <p className="text-xs text-muted mt-2">
                    Policy edits require administrator privileges. Sign in as <strong>demo-admin</strong> to modify thresholds.
                  </p>
                )}
              </form>
            )}
          </div>
        </Section>

        {/* ── 2. AI Service Approval Registry Governance ─────────────────── */}
        <Section title="AI Service Approval Governance">
          <div className="card card-body">
            <p className="text-xs text-muted mb-4">
              Administrators may update the organization's approval posture for discovered AI services.
              Services marked as <strong>Unapproved</strong> automatically incur elevated risk scores in subsequent analyses.
            </p>

            {servicesLoading ? (
              <p className="text-sm text-muted">Loading service registry…</p>
            ) : (
              <div className="table-wrapper">
                <table className="data-table" aria-label="AI Service Approval Governance Registry">
                  <thead>
                    <tr>
                      <th scope="col">Service Name</th>
                      <th scope="col">Provider</th>
                      <th scope="col">Type</th>
                      <th scope="col">Registered Endpoints</th>
                      <th scope="col" style={{ width: '180px' }}>Approval Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {services.map((svc) => (
                      <tr key={svc.id}>
                        <td>
                          <span className="font-semibold text-sm" style={{ color: 'var(--color-text)' }}>
                            {svc.name}
                          </span>
                        </td>
                        <td className="text-sm text-muted">{svc.provider}</td>
                        <td>
                          <span className="text-xs">{svc.service_type}</span>
                        </td>
                        <td>
                          <span className="cell-primary">
                            {svc.domains[0] || (svc.local_ports[0] ? `Port ${svc.local_ports[0]}` : '—')}
                          </span>
                        </td>
                        <td>
                          {canEditPolicies ? (
                            <select
                              className="select-input"
                              value={svc.approval_status}
                              onChange={(e) => handleServiceApprovalChange(svc.id, e.target.value)}
                              aria-label={`Approval status for ${svc.name}`}
                              style={{ width: '100%', fontSize: 'var(--text-xs)' }}
                            >
                              <option value="Approved">Approved</option>
                              <option value="Needs review">Needs review</option>
                              <option value="Unapproved">Unapproved</option>
                              <option value="Unknown">Unknown</option>
                            </select>
                          ) : (
                            <span className={`approval-${svc.approval_status.toLowerCase().replace(/\s+/g, '-')}`}>
                              {svc.approval_status}
                            </span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </Section>

        {/* ── 3. Tamper-Evident Audit History Panel ───────────────────────── */}
        <Section title="Tamper-Evident Audit History">
          <div className="card card-body">
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                marginBottom: '16px',
                flexWrap: 'wrap',
                gap: '12px',
              }}
            >
              <div>
                <p className="text-sm font-medium" style={{ color: 'var(--color-text)' }}>
                  Local Audit Log & Cryptographic Verification
                </p>
                <p className="text-xs text-muted mt-1">
                  Immutable audit records linked through a tamper-evident SHA-256 hash chain.
                </p>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span
                  style={{
                    fontSize: 'var(--text-xs)',
                    padding: '4px 10px',
                    borderRadius: 'var(--radius-full)',
                    background: isChainValid ? 'rgba(46, 157, 110, 0.15)' : 'rgba(217, 103, 97, 0.15)',
                    color: isChainValid ? 'var(--risk-low)' : 'var(--color-critical)',
                    fontWeight: 'var(--weight-semibold)',
                  }}
                >
                  {isChainValid ? `✓ ${chainStatus}` : `⚠️ ${chainStatus}`}
                </span>

                <button
                  className="btn btn-secondary"
                  style={{ fontSize: 'var(--text-xs)', padding: '4px 8px' }}
                  onClick={loadAuditHistory}
                >
                  Refresh
                </button>
              </div>
            </div>

            <div
              style={{
                padding: '8px 12px',
                background: '#F9FAFB',
                borderRadius: 'var(--radius-sm)',
                marginBottom: '16px',
                fontSize: 'var(--text-xs)',
                color: 'var(--color-text-muted)',
              }}
            >
              🔒 <strong>Audit Guarantee:</strong> Action logs record actor, timestamp, action type, and target identifiers. Prompt text, secrets, passwords, and full HTTP bodies are strictly excluded.
            </div>

            {auditLoading ? (
              <p className="text-sm text-muted">Loading audit entries…</p>
            ) : (
              <div className="table-wrapper">
                <table className="data-table" aria-label="Tamper-evident audit log">
                  <thead>
                    <tr>
                      <th scope="col" style={{ width: '130px' }}>Timestamp</th>
                      <th scope="col">Actor</th>
                      <th scope="col">Action</th>
                      <th scope="col">Detail Summary</th>
                      <th scope="col">Hash (SHA-256)</th>
                    </tr>
                  </thead>
                  <tbody>
                    {auditEntries.map((entry) => (
                      <tr key={entry.id}>
                        <td className="text-xs text-muted" style={{ whiteSpace: 'nowrap' }}>
                          {new Date(entry.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                        </td>
                        <td>
                          <span
                            style={{
                              fontSize: 'var(--text-xs)',
                              fontFamily: 'var(--font-mono)',
                              background: 'rgba(0,0,0,0.04)',
                              padding: '2px 6px',
                              borderRadius: '4px',
                            }}
                          >
                            {entry.actor}
                          </span>
                        </td>
                        <td>
                          <span className="font-semibold text-xs" style={{ color: 'var(--color-text)' }}>
                            {entry.action}
                          </span>
                        </td>
                        <td className="text-xs text-muted">
                          {JSON.stringify(entry.detail)}
                        </td>
                        <td>
                          <span
                            style={{
                              fontFamily: 'var(--font-mono)',
                              fontSize: '11px',
                              color: 'var(--color-text-muted)',
                            }}
                            title={entry.entryHash}
                          >
                            {entry.entryHash ? `${entry.entryHash.slice(0, 8)}…${entry.entryHash.slice(-6)}` : 'genesis'}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </Section>

        {/* ── 4. Workflow / Architecture Diagram (Preserved) ──────────────── */}
        <Section title="AURA Six-Stage Architecture">
          <WorkflowDiagram />
        </Section>

        {/* ── 5. Privacy & Prototype Boundaries (Preserved) ───────────────── */}
        <Section title="Privacy & Prototype Boundaries">
          <div className="card card-body">
            <p
              className="text-sm"
              style={{ color: 'var(--color-text-2)', marginBottom: 'var(--space-4)', lineHeight: 1.6 }}
            >
              AURA is a prototype built for the MITK AI VISION 24H hackathon (PS-01).
              The boundaries below are maintained across all application phases so users and evaluators are never misled about what the tool does.
            </p>
            <div className="privacy-list">
              {PRIVACY_ITEMS.map((item) => (
                <div key={item.text} className="privacy-item">
                  <span className="privacy-item-icon" aria-hidden="true">{item.icon}</span>
                  <span className="text-sm">{item.text}</span>
                </div>
              ))}
            </div>
          </div>
        </Section>

        {/* ── 6. Integration Tiles (Preserved) ────────────────────────────── */}
        <Section title="Integration Status">
          <div className="integration-grid">
            {INTEGRATION_TILES.map((tile) => (
              <div key={tile.id} className="integration-tile">
                <div className="integration-tile-header">
                  <span className="integration-tile-name">
                    <span aria-hidden="true">{tile.icon}</span>
                    {tile.name}
                  </span>
                  <StateBadge state={tile.state} />
                </div>
                <p className="integration-tile-desc">{tile.description}</p>
              </div>
            ))}
          </div>
        </Section>

        {/* ── 7. Team Zero Limit Card (Preserved) ─────────────────────────── */}
        <Section title="Team Zero Limit">
          <div className="team-card">
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 'var(--space-3)',
                marginBottom: 'var(--space-2)',
              }}
            >
              <div
                style={{
                  width: 40,
                  height: 40,
                  borderRadius: '50%',
                  background: 'rgba(37,168,149,.15)',
                  border: '1.5px solid rgba(37,168,149,.3)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontSize: 20,
                  flexShrink: 0,
                }}
                aria-hidden="true"
              >
                ⚡
              </div>
              <div>
                <p className="font-semibold">Team Zero Limit</p>
                <p className="text-sm text-muted">
                  MITK AI VISION 24H Hackathon · Problem Statement PS-01
                </p>
              </div>
            </div>

            <div className="team-members">
              {TEAM_MEMBERS.map((m) => (
                <div key={m.name} className="team-member">
                  <div className="member-avatar" aria-hidden="true">
                    {m.initials}
                  </div>
                  <div className="member-info">
                    <span className="member-name">{m.name}</span>
                    <span
                      className="member-role"
                      style={
                        m.role.startsWith('—')
                          ? { fontStyle: 'italic', color: 'var(--color-text-muted)' }
                          : {}
                      }
                    >
                      {m.role}
                    </span>
                  </div>
                </div>
              ))}
            </div>

            <p
              className="text-xs text-muted"
              style={{
                marginTop: 'var(--space-4)',
                paddingTop: 'var(--space-4)',
                borderTop: '1px solid var(--color-border-subtle)',
              }}
            >
              Member roles marked with dashes are intentionally left editable for the team to fill in.
            </p>
          </div>
        </Section>

        {/* ── Confirmation Dialog Modal ────────────────────────────────────── */}
        {showConfirmModal && (
          <div
            className="confirm-backdrop"
            role="dialog"
            aria-modal="true"
            aria-labelledby="confirm-policy-title"
          >
            <div className="confirm-dialog">
              <div className="confirm-header">
                <span aria-hidden="true">⚠️</span>
                <span id="confirm-policy-title">Confirm Policy Adjustments</span>
              </div>
              <div className="confirm-body">
                <p>
                  Are you sure you want to update the risk intelligence thresholds and demo weights?
                </p>
                <ul className="text-xs text-muted mt-2" style={{ paddingLeft: '16px' }}>
                  <li>Score Thresholds: Medium ≥ {thresholds.medium_threshold}, High ≥ {thresholds.high_threshold}, Critical ≥ {thresholds.critical_threshold}</li>
                  <li>Volume Threshold: &gt; {volumeThresholdMb} MB</li>
                  <li>Changes govern future demo evaluations. Historical event records remain unchanged.</li>
                </ul>
              </div>
              <div className="confirm-footer">
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => setShowConfirmModal(false)}
                  disabled={savingPolicies}
                >
                  Cancel
                </button>
                <button
                  type="button"
                  className="btn btn-primary"
                  onClick={handleSavePolicies}
                  disabled={savingPolicies}
                >
                  {savingPolicies ? 'Saving…' : 'Confirm & Apply'}
                </button>
              </div>
            </div>
          </div>
        )}
      </main>
    </>
  );
}
