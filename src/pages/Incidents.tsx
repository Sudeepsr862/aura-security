// ─── Incidents Page ─────────────────────────────────────────────────────────
// Comprehensive Incident Center for AURA:
// - Automatic queue for High/Critical & Would Block findings
// - Status workflow (Open, Investigating, Resolved, False Positive)
// - Drill-down drawer with evidence, contributing factors, synthetic context
// - In-app simulated response actions (warning preview, approval review, block preview, false positive)
// - Notes thread with 2,000 char validation and demo author attribution
// - Confirmation dialogs for Resolved and False Positive transitions
// - Strict role protection: Viewers are read-only; Analysts/Admins may update

import { useState, useEffect, useMemo } from 'react';
import { api, type IncidentItem } from '../api/client';
import { RiskBadge, DemoNotice, PageHeader, Section } from '../components/ui';

export function Incidents() {
  const [incidents, setIncidents] = useState<IncidentItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [canEdit, setCanEdit] = useState(false);
  const [userRole, setUserRole] = useState('viewer');

  // Filters
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');

  // Selected incident for drawer drilldown
  const [selectedIncident, setSelectedIncident] = useState<IncidentItem | null>(null);

  // Note authoring state
  const [noteText, setNoteText] = useState('');
  const [noteSubmitting, setNoteSubmitting] = useState(false);
  const [noteError, setNoteError] = useState<string | null>(null);

  // Status transition confirmation dialog
  const [pendingStatusChange, setPendingStatusChange] = useState<{
    targetStatus: string;
    incidentId: number;
    title: string;
    reason?: string;
  } | null>(null);
  const [statusSubmitting, setStatusSubmitting] = useState(false);

  // Simulated action feedback preview
  const [activeSimulationPreview, setActiveSimulationPreview] = useState<{
    actionType: string;
    detail: Record<string, unknown>;
  } | null>(null);
  const [simActionLoading, setSimActionLoading] = useState(false);

  // Load incidents from API
  const loadIncidents = async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await api.incidents();
      setIncidents(res.incidents);
      setCanEdit(res.canEdit);
      setUserRole(res.userRole);

      // Refresh selected incident if open
      if (selectedIncident) {
        const updated = res.incidents.find((i) => i.id === selectedIncident.id);
        if (updated) setSelectedIncident(updated);
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to load incidents.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadIncidents();
  }, []);

  // Filtered list
  const filteredIncidents = useMemo(() => {
    return incidents.filter((inc) => {
      if (severityFilter !== 'all' && inc.severity !== severityFilter) {
        return false;
      }
      if (statusFilter !== 'all' && inc.status !== statusFilter) {
        return false;
      }
      if (search.trim()) {
        const q = search.trim().toLowerCase();
        const matchTitle = inc.title.toLowerCase().includes(q);
        const matchDest = inc.destination.toLowerCase().includes(q);
        const matchUser = inc.user.name.toLowerCase().includes(q);
        const matchDevice = inc.device.label.toLowerCase().includes(q);
        const matchProvider = inc.service.provider.toLowerCase().includes(q);
        if (!matchTitle && !matchDest && !matchUser && !matchDevice && !matchProvider) {
          return false;
        }
      }
      return true;
    });
  }, [incidents, severityFilter, statusFilter, search]);

  // Request status change (prompts confirmation dialog for Resolved / False Positive)
  const handleRequestStatusChange = (newStatus: string) => {
    if (!selectedIncident) return;

    if (newStatus === 'Resolved' || newStatus === 'False Positive') {
      setPendingStatusChange({
        targetStatus: newStatus,
        incidentId: selectedIncident.id,
        title: selectedIncident.title,
      });
    } else {
      executeStatusChange(selectedIncident.id, newStatus);
    }
  };

  // Execute confirmed status change
  const executeStatusChange = async (incidentId: number, targetStatus: string, reason?: string) => {
    try {
      setStatusSubmitting(true);
      const res = await api.updateIncidentStatus(incidentId, targetStatus, reason);
      if (res.success) {
        await loadIncidents();
        setPendingStatusChange(null);
      }
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Failed to update incident status.');
    } finally {
      setStatusSubmitting(false);
    }
  };

  // Add analyst note
  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedIncident) return;
    if (!noteText.trim()) {
      setNoteError('Note text cannot be empty.');
      return;
    }
    if (noteText.length > 2000) {
      setNoteError('Note exceeds maximum length of 2,000 characters.');
      return;
    }

    try {
      setNoteSubmitting(true);
      setNoteError(null);
      const res = await api.addIncidentNote(selectedIncident.id, noteText);
      if (res.success) {
        setNoteText('');
        await loadIncidents();
      }
    } catch (err: unknown) {
      setNoteError(err instanceof Error ? err.message : 'Failed to add note.');
    } finally {
      setNoteSubmitting(false);
    }
  };

  // Trigger simulated response
  const handleSimulateAction = async (actionType: string) => {
    if (!selectedIncident) return;

    if (actionType === 'mark_false_positive') {
      // Prompt confirmation with reason
      const reason = window.prompt('Enter reason for marking this incident as a False Positive:');
      if (reason === null) return; // User cancelled
      executeSimulatedAction(actionType, reason || 'Analyst identified as false positive.');
    } else {
      executeSimulatedAction(actionType);
    }
  };

  const executeSimulatedAction = async (actionType: string, reason?: string) => {
    if (!selectedIncident) return;
    try {
      setSimActionLoading(true);
      const res = await api.simulateIncidentAction(selectedIncident.id, actionType, reason);
      if (res.success) {
        setActiveSimulationPreview({
          actionType: res.actionType,
          detail: res.simulationDetail,
        });
        await loadIncidents();
      }
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Simulated action failed.');
    } finally {
      setSimActionLoading(false);
    }
  };

  const formatStatusClass = (status: string) => {
    const s = status.toLowerCase().replace(/\s+/g, '-');
    return `status-badge status-${s}`;
  };

  return (
    <>
      <PageHeader
        title="Incident Center"
        subtitle="Review, investigate, and simulate local policy response workflows for elevated AI risks."
      />

      <main className="page-body">
        <DemoNotice
          message={
            'LOCAL DEMO SIMULATION — All response actions, employee warnings, approval flags, and block previews remain local simulations inside AURA. No traffic is blocked, no packets dropped, and no external emails or firewall rules are dispatched.'
          }
        />

        {/* Permission Banner for Viewer */}
        {!canEdit && (
          <div
            className="card card-body mb-4"
            style={{
              background: 'rgba(79, 135, 197, 0.08)',
              border: '1px solid rgba(79, 135, 197, 0.25)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '12px 16px',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span aria-hidden="true">👁️</span>
              <span className="text-sm" style={{ color: 'var(--color-text-2)' }}>
                You are currently viewing as <strong>{userRole}</strong> (read-only mode). Triage, status changes,
                and note authoring require <strong>Analyst</strong> or <strong>Administrator</strong> credentials.
              </span>
            </div>
            <span className="text-xs text-muted">Role: {userRole}</span>
          </div>
        )}

        {/* Filter and Search Bar */}
        <div className="filter-toolbar">
          <div className="filter-group">
            <input
              type="text"
              className="input-text"
              placeholder="Search destination, title, user, device..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              style={{ minWidth: 260 }}
              aria-label="Search incidents"
            />

            <select
              className="select-input"
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              aria-label="Filter by severity"
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>

            <select
              className="select-input"
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              aria-label="Filter by status"
            >
              <option value="all">All Statuses</option>
              <option value="Open">Open</option>
              <option value="Investigating">Investigating</option>
              <option value="Resolved">Resolved</option>
              <option value="False Positive">False Positive</option>
            </select>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span className="text-xs text-muted">
              Showing <strong>{filteredIncidents.length}</strong> of <strong>{incidents.length}</strong> incidents
            </span>
            {(search || severityFilter !== 'all' || statusFilter !== 'all') && (
              <button
                className="btn btn-secondary"
                style={{ fontSize: 'var(--text-xs)', padding: '4px 8px' }}
                onClick={() => {
                  setSearch('');
                  setSeverityFilter('all');
                  setStatusFilter('all');
                }}
              >
                Clear Filters
              </button>
            )}
          </div>
        </div>

        {/* Incident Queue Table */}
        <Section title="Incident Queue">
          {loading ? (
            <div className="card card-body text-center" style={{ padding: '40px' }}>
              <p className="text-sm text-muted">Loading incident queue from local database…</p>
            </div>
          ) : error ? (
            <div className="card card-body" style={{ borderColor: 'var(--color-danger)', color: 'var(--color-danger)' }}>
              <p className="font-semibold">Error loading incidents</p>
              <p className="text-sm">{error}</p>
              <button className="btn btn-secondary mt-3" onClick={loadIncidents}>
                Retry
              </button>
            </div>
          ) : filteredIncidents.length === 0 ? (
            <div className="card card-body text-center" style={{ padding: '48px 24px' }}>
              <div style={{ fontSize: '32px', marginBottom: '12px' }} aria-hidden="true">
                🛡️
              </div>
              <p className="font-semibold" style={{ fontSize: 'var(--text-md)', marginBottom: '4px' }}>
                No matching incidents
              </p>
              <p className="text-sm text-muted" style={{ maxWidth: 440, margin: '0 auto 16px auto' }}>
                {search || severityFilter !== 'all' || statusFilter !== 'all'
                  ? 'No review incidents match the active search criteria or filters. Try adjusting your parameters.'
                  : 'All analyzed events are currently within standard policy boundaries. New incidents are automatically raised for High/Critical risk findings or block recommendations.'}
              </p>
              {(search || severityFilter !== 'all' || statusFilter !== 'all') && (
                <button
                  className="btn btn-secondary"
                  onClick={() => {
                    setSearch('');
                    setSeverityFilter('all');
                    setStatusFilter('all');
                  }}
                >
                  Reset Filters
                </button>
              )}
            </div>
          ) : (
            <div className="table-wrapper">
              <table className="data-table" aria-label="Incident review queue">
                <thead>
                  <tr>
                    <th scope="col" style={{ width: '100px' }}>Severity</th>
                    <th scope="col">Title & Finding</th>
                    <th scope="col">Destination</th>
                    <th scope="col">Synthetic User</th>
                    <th scope="col">Device</th>
                    <th scope="col">Status</th>
                    <th scope="col">Last Updated</th>
                    <th scope="col" style={{ textAlign: 'right' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredIncidents.map((inc) => (
                    <tr
                      key={inc.id}
                      style={{
                        cursor: 'pointer',
                        background: selectedIncident?.id === inc.id ? 'rgba(37, 168, 149, 0.04)' : undefined,
                      }}
                      onClick={() => setSelectedIncident(inc)}
                    >
                      <td>
                        <RiskBadge level={inc.severity} />
                      </td>
                      <td>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
                          <span className="font-medium" style={{ color: 'var(--color-text)' }}>
                            {inc.title}
                          </span>
                          <span className="text-xs text-muted">
                            Incident #{inc.id} · Score: {inc.event.risk_score}/100 · {inc.event.source_label}
                          </span>
                        </div>
                      </td>
                      <td>
                        <div style={{ display: 'flex', flexDirection: 'column' }}>
                          <span className="cell-primary">{inc.destination}</span>
                          <span className="text-xs text-muted">{inc.service.provider}</span>
                        </div>
                      </td>
                      <td>
                        <div style={{ display: 'flex', flexDirection: 'column' }}>
                          <span className="font-medium" style={{ fontSize: 'var(--text-sm)' }}>
                            {inc.user.name}
                          </span>
                          <span className="text-xs text-muted">{inc.user.department || 'Unknown Dept'}</span>
                        </div>
                      </td>
                      <td>
                        <span className="text-sm text-muted" style={{ fontFamily: 'var(--font-mono)' }}>
                          {inc.device.label}
                        </span>
                      </td>
                      <td>
                        <span className={formatStatusClass(inc.status)}>{inc.status}</span>
                      </td>
                      <td className="text-xs text-muted" style={{ whiteSpace: 'nowrap' }}>
                        {new Date(inc.updated_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        <button
                          className="btn btn-secondary"
                          style={{ fontSize: 'var(--text-xs)', padding: '4px 10px' }}
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedIncident(inc);
                          }}
                          aria-label={`Review details for incident ${inc.id}`}
                        >
                          Investigate
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Section>

        {/* Legend */}
        <Section title="Incident Review Guidelines">
          <div
            className="card card-body"
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
              gap: 'var(--space-4)',
            }}
          >
            <div>
              <p className="font-semibold text-sm mb-1" style={{ color: 'var(--color-critical)' }}>
                🔴 Critical Severity
              </p>
              <p className="text-xs text-muted">
                Restricted data or unapproved endpoint access with synthetic authorization mismatch. Policy triggers simulated block recommendation.
              </p>
            </div>
            <div>
              <p className="font-semibold text-sm mb-1" style={{ color: 'var(--color-danger)' }}>
                🟠 High Severity
              </p>
              <p className="text-xs text-muted">
                Confidential data or unapproved local/cloud AI services requiring prompt analyst triage and user verification.
              </p>
            </div>
            <div>
              <p className="font-semibold text-sm mb-1" style={{ color: 'var(--color-warning)' }}>
                🟡 Status Workflow
              </p>
              <p className="text-xs text-muted">
                Open → Investigating → Resolved or False Positive. Changing status logs actor, timestamp, and audit trail.
              </p>
            </div>
            <div>
              <p className="font-semibold text-sm mb-1" style={{ color: 'var(--color-accent)' }}>
                🛡️ Simulation Guarantee
              </p>
              <p className="text-xs text-muted">
                Zero network interception. Simulated block recommendations and employee warning previews do not affect real devices.
              </p>
            </div>
          </div>
        </Section>

        {/* ── Drill-Down Drawer Modal ────────────────────────────────────────── */}
        {selectedIncident && (
          <div
            className="drawer-backdrop"
            onClick={() => setSelectedIncident(null)}
            role="dialog"
            aria-modal="true"
            aria-labelledby="drawer-title"
          >
            <div className="drawer-panel" onClick={(e) => e.stopPropagation()}>
              {/* Drawer Header */}
              <div className="drawer-header">
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                    <RiskBadge level={selectedIncident.severity} />
                    <span className={formatStatusClass(selectedIncident.status)}>
                      {selectedIncident.status}
                    </span>
                    <span className="text-xs text-muted">Incident #{selectedIncident.id}</span>
                  </div>
                  <h2 id="drawer-title" className="font-semibold" style={{ fontSize: 'var(--text-lg)', lineHeight: 1.3 }}>
                    {selectedIncident.title}
                  </h2>
                </div>
                <button
                  className="close-btn"
                  onClick={() => setSelectedIncident(null)}
                  aria-label="Close incident details"
                >
                  ✕
                </button>
              </div>

              {/* Drawer Scrollable Content */}
              <div className="drawer-content">
                {/* Status Triage Controls */}
                <div
                  className="card card-body"
                  style={{
                    background: '#F8F9FA',
                    border: '1px solid var(--color-border)',
                  }}
                >
                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      marginBottom: '10px',
                    }}
                  >
                    <span className="font-semibold text-sm">Incident Triage Workflow</span>
                    <span className="text-xs text-muted">Current status: <strong>{selectedIncident.status}</strong></span>
                  </div>

                  {canEdit ? (
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                      <button
                        className="btn btn-secondary"
                        style={{
                          fontSize: 'var(--text-xs)',
                          borderColor: selectedIncident.status === 'Open' ? 'var(--color-warning)' : undefined,
                        }}
                        disabled={selectedIncident.status === 'Open'}
                        onClick={() => handleRequestStatusChange('Open')}
                      >
                        Set Open
                      </button>
                      <button
                        className="btn btn-secondary"
                        style={{
                          fontSize: 'var(--text-xs)',
                          borderColor: selectedIncident.status === 'Investigating' ? '#4F87C5' : undefined,
                        }}
                        disabled={selectedIncident.status === 'Investigating'}
                        onClick={() => handleRequestStatusChange('Investigating')}
                      >
                        Mark Investigating
                      </button>
                      <button
                        className="btn btn-secondary"
                        style={{
                          fontSize: 'var(--text-xs)',
                          borderColor: selectedIncident.status === 'Resolved' ? 'var(--risk-low)' : undefined,
                        }}
                        disabled={selectedIncident.status === 'Resolved'}
                        onClick={() => handleRequestStatusChange('Resolved')}
                      >
                        Mark Resolved ✓
                      </button>
                      <button
                        className="btn btn-secondary"
                        style={{
                          fontSize: 'var(--text-xs)',
                          borderColor: selectedIncident.status === 'False Positive' ? 'var(--color-text-muted)' : undefined,
                        }}
                        disabled={selectedIncident.status === 'False Positive'}
                        onClick={() => handleRequestStatusChange('False Positive')}
                      >
                        Mark False Positive
                      </button>
                    </div>
                  ) : (
                    <p className="text-xs text-muted">
                      Status modifications are disabled in read-only viewer mode. Log in as an analyst or administrator to change status.
                    </p>
                  )}
                </div>

                {/* Evidence & Risk Scoring Summary */}
                <div className="card card-body">
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                    <span className="font-semibold text-sm">Risk Engine Intelligence</span>
                    <span className="font-semibold" style={{ fontSize: 'var(--text-md)', color: 'var(--color-text)' }}>
                      Risk Score: {selectedIncident.event.risk_score} / 100
                    </span>
                  </div>

                  {selectedIncident.event.risk_explanation && (
                    <p
                      className="text-sm mb-3"
                      style={{
                        padding: '10px 12px',
                        background: '#F9FAFB',
                        borderRadius: 'var(--radius-sm)',
                        borderLeft: '3px solid var(--color-accent)',
                      }}
                    >
                      {selectedIncident.event.risk_explanation}
                    </p>
                  )}

                  {/* Factor Breakdown */}
                  <span className="text-xs text-muted font-semibold uppercase" style={{ letterSpacing: '0.06em' }}>
                    Contributing Risk Factors ({selectedIncident.event.risk_factors.length})
                  </span>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '8px' }}>
                    {selectedIncident.event.risk_factors.map((f) => (
                      <div
                        key={f.id}
                        style={{
                          display: 'flex',
                          justifyContent: 'space-between',
                          alignItems: 'flex-start',
                          padding: '8px 10px',
                          background: '#FFFFFF',
                          border: '1px solid var(--color-border-subtle)',
                          borderRadius: 'var(--radius-sm)',
                        }}
                      >
                        <div style={{ maxWidth: '80%' }}>
                          <p className="font-medium text-sm">{f.name}</p>
                          <p className="text-xs text-muted">{f.evidence}</p>
                        </div>
                        <span
                          className="font-semibold text-xs"
                          style={{
                            color: f.points > 15 ? 'var(--color-critical)' : 'var(--color-warning)',
                            padding: '2px 6px',
                            background: 'rgba(0,0,0,0.03)',
                            borderRadius: '4px',
                          }}
                        >
                          +{f.points} pts
                        </span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Synthetic Context Grid */}
                <div
                  className="card card-body"
                  style={{
                    display: 'grid',
                    gridTemplateColumns: '1fr 1fr',
                    gap: '12px',
                  }}
                >
                  <div>
                    <span className="text-xs text-muted uppercase font-semibold">Destination Metadata</span>
                    <p className="font-mono text-sm mt-1">{selectedIncident.destination}</p>
                    <p className="text-xs text-muted">
                      Port: {selectedIncident.event.port || '443'} · Provider: {selectedIncident.service.provider}
                    </p>
                    <p className="text-xs text-muted">
                      Approval: <strong>{selectedIncident.event.approval_status}</strong>
                    </p>
                  </div>

                  <div>
                    <span className="text-xs text-muted uppercase font-semibold">Synthetic Identity</span>
                    <p className="font-medium text-sm mt-1">{selectedIncident.user.name}</p>
                    <p className="text-xs text-muted">{selectedIncident.user.email || 'No synthetic email'}</p>
                    <p className="text-xs text-muted">
                      Dept: {selectedIncident.user.department} · Device: {selectedIncident.device.label}
                    </p>
                  </div>
                </div>

                {/* Recommended Next Steps */}
                <div className="card card-body">
                  <span className="font-semibold text-sm mb-2 block">Recommended Next Steps</span>
                  <ul style={{ paddingLeft: '18px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
                    {selectedIncident.recommended_steps.map((step, idx) => (
                      <li key={idx} className="text-sm" style={{ color: 'var(--color-text-2)' }}>
                        {step}
                      </li>
                    ))}
                  </ul>
                </div>

                {/* ── In-App Simulated Response Actions ────────────────────────── */}
                <div
                  className="card card-body"
                  style={{
                    background: 'linear-gradient(180deg, #F9FBFA 0%, #FFFFFF 100%)',
                    border: '1px solid rgba(37, 168, 149, 0.3)',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '10px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <span className="sim-notice-tag">Simulation Mode</span>
                      <span className="font-semibold text-sm">Response Action Previews</span>
                    </div>
                    <span className="text-xs text-muted">Safe In-App Previews</span>
                  </div>

                  <p className="text-xs text-muted mb-3">
                    AURA never invokes external blocking commands or live email integrations. Select an action below to preview how policy responses would appear:
                  </p>

                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                    <button
                      className="btn btn-secondary"
                      style={{ fontSize: 'var(--text-xs)' }}
                      disabled={!canEdit || simActionLoading}
                      onClick={() => handleSimulateAction('preview_warning')}
                      title="Preview how an in-app employee notification would look"
                    >
                      ✉️ Preview Employee Warning
                    </button>

                    <button
                      className="btn btn-secondary"
                      style={{ fontSize: 'var(--text-xs)' }}
                      disabled={!canEdit || simActionLoading}
                      onClick={() => handleSimulateAction('mark_approval')}
                      title="Record a local approval review workflow tag"
                    >
                      📝 Mark for Approval Review
                    </button>

                    <button
                      className="btn btn-secondary"
                      style={{ fontSize: 'var(--text-xs)' }}
                      disabled={!canEdit || simActionLoading}
                      onClick={() => handleSimulateAction('simulate_block')}
                      title="Display policy block recommendation simulation and reasons"
                    >
                      🛡️ Simulate Block Recommendation
                    </button>

                    <button
                      className="btn btn-secondary"
                      style={{ fontSize: 'var(--text-xs)' }}
                      disabled={!canEdit || simActionLoading}
                      onClick={() => handleSimulateAction('mark_false_positive')}
                      title="Mark as false positive resolution"
                    >
                      🏷️ Mark as False Positive
                    </button>
                  </div>

                  {/* Active Simulation Preview Box */}
                  {activeSimulationPreview && (
                    <div className="sim-preview-box">
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                        <span className="font-semibold text-xs uppercase" style={{ color: 'var(--color-accent)' }}>
                          Preview: {activeSimulationPreview.actionType.replace('_', ' ')}
                        </span>
                        <button
                          className="close-btn"
                          style={{ fontSize: '14px' }}
                          onClick={() => setActiveSimulationPreview(null)}
                        >
                          ✕
                        </button>
                      </div>

                      {activeSimulationPreview.actionType === 'preview_warning' && (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                          <p className="font-semibold text-xs">Subject: {String(activeSimulationPreview.detail.title)}</p>
                          <p className="text-xs text-muted">To: {String(activeSimulationPreview.detail.recipient)}</p>
                          <pre
                            style={{
                              fontFamily: 'var(--font-body)',
                              whiteSpace: 'pre-wrap',
                              background: '#FFFFFF',
                              padding: '8px',
                              borderRadius: '4px',
                              border: '1px solid var(--color-border-subtle)',
                              fontSize: '12px',
                              marginTop: '6px',
                            }}
                          >
                            {String(activeSimulationPreview.detail.message)}
                          </pre>
                        </div>
                      )}

                      {activeSimulationPreview.actionType === 'simulate_block' && (
                        <div>
                          <p className="font-semibold text-sm" style={{ color: 'var(--color-critical)' }}>
                            Outcome: {String(activeSimulationPreview.detail.recommendation)}
                          </p>
                          <p className="text-xs text-muted mt-1">
                            Destination: {String(activeSimulationPreview.detail.destination)}
                          </p>
                          <p className="text-xs text-muted mt-2">
                            {String(activeSimulationPreview.detail.disclaimer)}
                          </p>
                        </div>
                      )}

                      {activeSimulationPreview.actionType === 'mark_approval' && (
                        <div>
                          <p className="font-semibold text-sm text-accent">
                            {String(activeSimulationPreview.detail.workflowNote)}
                          </p>
                          <p className="text-xs text-muted mt-1">
                            {String(activeSimulationPreview.detail.disclaimer)}
                          </p>
                        </div>
                      )}

                      {activeSimulationPreview.actionType === 'mark_false_positive' && (
                        <div>
                          <p className="font-semibold text-sm">
                            Resolution: Marked as False Positive
                          </p>
                          <p className="text-xs text-muted mt-1">
                            Reason: {String(activeSimulationPreview.detail.reason)}
                          </p>
                        </div>
                      )}
                    </div>
                  )}

                  {/* Past Simulated Actions on this Incident */}
                  {selectedIncident.simulated_actions.length > 0 && (
                    <div style={{ marginTop: '12px' }}>
                      <span className="text-xs text-muted font-semibold uppercase">Simulated History</span>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', marginTop: '6px' }}>
                        {selectedIncident.simulated_actions.map((act) => (
                          <div
                            key={act.id}
                            className="text-xs text-muted"
                            style={{
                              display: 'flex',
                              justifyContent: 'space-between',
                              padding: '4px 6px',
                              background: '#F9FAFB',
                              borderRadius: '4px',
                            }}
                          >
                            <span>⚡ {act.summary} (by {act.actor})</span>
                            <span>{new Date(act.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                {/* ── Analyst Notes Thread ────────────────────────────────────── */}
                <div className="card card-body">
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
                    <span className="font-semibold text-sm">Analyst Investigation Notes</span>
                    <span className="text-xs text-muted">{selectedIncident.notes.length} notes</span>
                  </div>

                  {selectedIncident.notes.length === 0 ? (
                    <p className="text-xs text-muted" style={{ fontStyle: 'italic', marginBottom: '12px' }}>
                      No notes recorded yet. Add initial triage observations or employee check notes below.
                    </p>
                  ) : (
                    <div className="notes-thread mb-4">
                      {selectedIncident.notes.map((n) => (
                        <div key={n.id} className="note-bubble">
                          <div className="note-header">
                            <span className="font-medium" style={{ color: 'var(--color-text)' }}>
                              {n.actor} <span style={{ opacity: 0.7 }}>({n.role})</span>
                            </span>
                            <span>{new Date(n.created_at).toLocaleString([], { dateStyle: 'short', timeStyle: 'short' })}</span>
                          </div>
                          <p className="note-text">{n.text}</p>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Add Note Form */}
                  {canEdit ? (
                    <form onSubmit={handleAddNote} style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                      <textarea
                        className="input-text"
                        rows={3}
                        placeholder="Add investigation notes, employee contact record, or resolution details (max 2,000 characters)..."
                        value={noteText}
                        onChange={(e) => setNoteText(e.target.value)}
                        maxLength={2000}
                        disabled={noteSubmitting}
                        aria-label="New analyst note text"
                      />
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span className="text-xs text-muted">
                          {noteText.length} / 2,000 characters
                        </span>
                        <button
                          type="submit"
                          className="btn btn-primary"
                          disabled={!noteText.trim() || noteSubmitting}
                          style={{ fontSize: 'var(--text-xs)', padding: '6px 14px' }}
                        >
                          {noteSubmitting ? 'Saving…' : 'Add Note'}
                        </button>
                      </div>
                      {noteError && (
                        <p className="text-xs" style={{ color: 'var(--color-danger)' }}>
                          {noteError}
                        </p>
                      )}
                    </form>
                  ) : (
                    <p className="text-xs text-muted">
                      Sign in as demo-analyst or demo-admin to append notes to this record.
                    </p>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ── Confirmation Dialog Modal ────────────────────────────────────── */}
        {pendingStatusChange && (
          <div
            className="confirm-backdrop"
            role="dialog"
            aria-modal="true"
            aria-labelledby="confirm-dialog-title"
          >
            <div className="confirm-dialog">
              <div className="confirm-header">
                <span aria-hidden="true">⚠️</span>
                <span id="confirm-dialog-title">Confirm Status Transition</span>
              </div>
              <div className="confirm-body">
                <p>
                  Are you sure you want to transition incident <strong>#{pendingStatusChange.incidentId}</strong> to{' '}
                  <strong style={{ color: 'var(--color-accent)' }}>{pendingStatusChange.targetStatus}</strong>?
                </p>
                <p className="text-xs text-muted mt-2">
                  This in-app review step will be attributed to <strong>{userRole}</strong> in the tamper-evident
                  audit log.
                </p>
              </div>
              <div className="confirm-footer">
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => setPendingStatusChange(null)}
                  disabled={statusSubmitting}
                >
                  Cancel
                </button>
                <button
                  type="button"
                  className="btn btn-primary"
                  onClick={() =>
                    executeStatusChange(
                      pendingStatusChange.incidentId,
                      pendingStatusChange.targetStatus,
                      `Confirmed ${pendingStatusChange.targetStatus} status update in AURA Incident Center.`
                    )
                  }
                  disabled={statusSubmitting}
                >
                  {statusSubmitting ? 'Updating…' : 'Confirm & Save'}
                </button>
              </div>
            </div>
          </div>
        )}
      </main>
    </>
  );
}
