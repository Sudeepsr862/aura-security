// ─── Data & Risk Page ───────────────────────────────────────────────────────
// Phase 5: Access context and explainable risk intelligence
// Transparent, deterministic demo scoring with full factor breakdown and synthetic identity correlation.

import { useState, useEffect } from 'react';
import {
  api,
  type RiskEventRow,
  type RiskOverviewResponse,
  type RiskFactor,
} from '../api/client';
import {
  DataLabelPill,
  RiskScoreBar,
  PageHeader,
  Section,
  ClassificationBadge,
  SourceBadge,
} from '../components/ui';
import type { DataLabel } from '../types';

const SENSITIVITY_LEVELS: {
  label: DataLabel;
  description: string;
  example: string;
  points: number;
}[] = [
  {
    label: 'Public',
    description: 'Freely shareable information. No special handling required.',
    example: 'Marketing copy, public documentation.',
    points: 0,
  },
  {
    label: 'Internal',
    description: 'For use within the organisation only. Not for external sharing.',
    example: 'Internal wikis, meeting summaries.',
    points: 10,
  },
  {
    label: 'Confidential',
    description: 'Sensitive business information. Share on a need-to-know basis.',
    example: 'Financial reports, strategy documents, customer lists.',
    points: 25,
  },
  {
    label: 'Restricted',
    description: 'Highest sensitivity. Strict access controls and audit trail required.',
    example: 'Personal data, credentials, payment cards, source code.',
    points: 35,
  },
];

export function DataRisk() {
  const [overview, setOverview] = useState<RiskOverviewResponse | null>(null);
  const [events, setEvents] = useState<RiskEventRow[]>([]);
  const [totalEvents, setTotalEvents] = useState(0);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [classificationFilter, setClassificationFilter] = useState<string>('all');
  const [sourceFilter, setSourceFilter] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Selected event for detail inspection modal/drawer
  const [selectedEvent, setSelectedEvent] = useState<RiskEventRow | null>(null);
  const [showWeightsDisclosure, setShowWeightsDisclosure] = useState(false);

  // Load overview data
  useEffect(() => {
    let mounted = true;
    async function loadOverview() {
      try {
        const res = await api.riskOverview();
        if (mounted) setOverview(res);
      } catch (err: unknown) {
        if (mounted) console.warn('Failed to load risk overview:', err);
      }
    }
    loadOverview();
    return () => { mounted = false; };
  }, []);

  // Load events with filters
  useEffect(() => {
    let mounted = true;
    async function loadEvents() {
      setIsLoading(true);
      setError(null);
      try {
        const res = await api.riskEvents({
          severity: severityFilter !== 'all' ? severityFilter : undefined,
          classification: classificationFilter !== 'all' ? classificationFilter : undefined,
          source: sourceFilter !== 'all' ? sourceFilter : undefined,
          search: searchQuery.trim() || undefined,
          limit: 50,
        });
        if (mounted) {
          setEvents(res.events);
          setTotalEvents(res.pagination.total);
        }
      } catch (err: unknown) {
        if (mounted) {
          setError(err instanceof Error ? err.message : 'Failed to load risk events.');
        }
      } finally {
        if (mounted) setIsLoading(false);
      }
    }

    const timer = setTimeout(loadEvents, 150); // small debounce for search
    return () => {
      clearTimeout(timer);
      mounted = false;
    };
  }, [severityFilter, classificationFilter, sourceFilter, searchQuery]);

  function getSeverityColor(severity: string) {
    switch (severity.toLowerCase()) {
      case 'critical': return 'var(--color-danger, #ef4444)';
      case 'high':     return '#f97316';
      case 'medium':   return 'var(--color-warning, #f59e0b)';
      default:         return 'var(--color-success, #10b981)';
    }
  }

  function getAuthStatusBadge(status?: string) {
    switch (status) {
      case 'authorized':
        return <span className="badge badge-success text-xs">✓ Authorized</span>;
      case 'mismatch':
        return <span className="badge badge-warning text-xs">⚠️ Auth Mismatch</span>;
      case 'denied':
        return <span className="badge badge-danger text-xs">⛔ Unauthorized</span>;
      default:
        return <span className="badge text-xs" style={{ background: 'rgba(148, 163, 184, 0.2)', color: 'var(--color-text-2)' }}>❓ Needs Review</span>;
    }
  }

  return (
    <>
      <PageHeader
        title="Data & Risk — Explainable Risk Intelligence"
        subtitle="Transparent, deterministic risk scores based on service approval, data sensitivity, synthetic identity, and transfer context."
      />

      <main className="page-body">
        {/* Transparent scoring disclaimer banner */}
        <div
          className="card"
          style={{
            background: 'rgba(59, 130, 246, 0.08)',
            borderColor: 'rgba(59, 130, 246, 0.3)',
            marginBottom: 'var(--space-6)',
          }}
        >
          <div className="card-body" style={{ display: 'flex', gap: 'var(--space-3)', alignItems: 'flex-start' }}>
            <span style={{ fontSize: '1.25rem' }}>ℹ️</span>
            <div>
              <strong style={{ color: 'var(--color-text-1)', fontSize: 'var(--text-sm)' }}>
                Deterministic Demo Scoring Engine
              </strong>
              <p className="text-xs text-muted mt-1" style={{ lineHeight: 1.5 }}>
                All risk scores in AURA are computed using <strong>transparent additive demo policy weights</strong> and
                correlated synthetic metadata. Scores range from 0 to 100.
                <strong> AURA does not use an opaque machine learning model or external AI for scoring</strong>,
                and recommendations such as <em>“Would block (simulation)”</em> do not perform live packet filtering.
              </p>
              <button
                type="button"
                className="btn btn-secondary text-xs mt-2"
                onClick={() => setShowWeightsDisclosure(!showWeightsDisclosure)}
                style={{ padding: '2px 8px' }}
              >
                {showWeightsDisclosure ? '▲ Hide Demo Policy Weights' : '▼ View Documented Demo Policy Weights'}
              </button>
            </div>
          </div>
        </div>

        {/* Collapsible Policy Weights Disclosure */}
        {showWeightsDisclosure && overview?.policyWeights && (
          <div className="card mb-6" style={{ background: 'var(--color-surface-2)', border: '1px solid var(--color-border-subtle)' }}>
            <div className="card-body">
              <h4 style={{ fontSize: 'var(--text-sm)', fontWeight: 'var(--weight-semibold)', marginBottom: 'var(--space-3)' }}>
                📋 Documented Demo Policy Weights (Additive Model, Clamped 0–100)
              </h4>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 'var(--space-4)', fontSize: 'var(--text-xs)' }}>
                <div className="card" style={{ padding: 'var(--space-3)' }}>
                  <strong>Data Sensitivity Signals:</strong>
                  <ul className="mt-1" style={{ listStyle: 'none', paddingLeft: 0 }}>
                    <li>· Public: +0 pts</li>
                    <li>· Internal: +10 pts</li>
                    <li>· Confidential: +25 pts</li>
                    <li>· Restricted: +35 pts</li>
                  </ul>
                </div>
                <div className="card" style={{ padding: 'var(--space-3)' }}>
                  <strong>Service Approval Signals:</strong>
                  <ul className="mt-1" style={{ listStyle: 'none', paddingLeft: 0 }}>
                    <li>· Approved service: +0 pts</li>
                    <li>· Unapproved service: +20 pts</li>
                    <li>· Under review / Unknown: +12 pts</li>
                  </ul>
                </div>
                <div className="card" style={{ padding: 'var(--space-3)' }}>
                  <strong>Identity & Authorization Signals:</strong>
                  <ul className="mt-1" style={{ listStyle: 'none', paddingLeft: 0 }}>
                    <li>· Authorized in synthetic directory: +0 pts</li>
                    <li>· Authorization mismatch / Denied: +20 pts</li>
                    <li>· Unknown authorization: +8 pts</li>
                    <li>· Unlisted user / Unmanaged device: +5 pts each</li>
                  </ul>
                </div>
                <div className="card" style={{ padding: 'var(--space-3)' }}>
                  <strong>Volume & Anomaly Signals:</strong>
                  <ul className="mt-1" style={{ listStyle: 'none', paddingLeft: 0 }}>
                    <li>· High transfer volume (&gt;5 MB): +18 pts</li>
                    <li>· Metadata anomaly flagged: +10 pts</li>
                    <li>· First-seen destination: +5 pts</li>
                    <li>· Repeated elevated events (3+): +8 pts</li>
                  </ul>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Severity Metrics Counters */}
        <Section title="Risk Severity Overview">
          <div className="stat-grid" role="list" aria-label="Risk severity metrics">
            <article className="stat-card" role="listitem" style={{ borderLeft: '4px solid var(--color-success, #10b981)' }}>
              <span className="stat-label">🟢 Low Risk (0–24)</span>
              <span className="stat-value">{overview ? overview.counts.low : '…'}</span>
              <span className="stat-note">Allow or record for visibility</span>
            </article>

            <article className="stat-card" role="listitem" style={{ borderLeft: '4px solid var(--color-warning, #f59e0b)' }}>
              <span className="stat-label">🟡 Medium Risk (25–49)</span>
              <span className="stat-value">{overview ? overview.counts.medium : '…'}</span>
              <span className="stat-note">Warn / review before sending</span>
            </article>

            <article className="stat-card" role="listitem" style={{ borderLeft: '4px solid #f97316' }}>
              <span className="stat-label">🟠 High Risk (50–74)</span>
              <span className="stat-value">{overview ? overview.counts.high : '…'}</span>
              <span className="stat-note">Review promptly</span>
            </article>

            <article className="stat-card" role="listitem" style={{ borderLeft: '4px solid var(--color-danger, #ef4444)' }}>
              <span className="stat-label">🔴 Critical Risk (75–100)</span>
              <span className="stat-value">{overview ? overview.counts.critical : '…'}</span>
              <span className="stat-note">Would block before transmission (simulation)</span>
            </article>
          </div>
        </Section>

        {/* Data Sensitivity Legend with weights */}
        <Section title="Data Sensitivity Framework">
          <div className="card mb-6">
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))',
                gap: 0,
              }}
            >
              {SENSITIVITY_LEVELS.map((level, i) => (
                <div
                  key={level.label}
                  style={{
                    padding: 'var(--space-4) var(--space-5)',
                    borderRight: i < 3 ? '1px solid var(--color-border-subtle)' : 'none',
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <DataLabelPill label={level.label} />
                    <span className="text-xs font-semibold text-muted">+{level.points} pts</span>
                  </div>
                  <p
                    className="text-xs mt-2"
                    style={{ color: 'var(--color-text-2)', lineHeight: 1.5 }}
                  >
                    {level.description}
                  </p>
                  <p className="text-xs text-muted mt-1">
                    <em>e.g.</em> {level.example}
                  </p>
                </div>
              ))}
            </div>
          </div>
        </Section>

        {/* Filter Controls */}
        <Section title={`Correlated Events & Risk Analysis (${totalEvents} events)`}>
          <div className="card mb-4" style={{ padding: 'var(--space-4)' }}>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--space-3)', alignItems: 'center' }}>
              {/* Search */}
              <div style={{ flex: '1 1 200px' }}>
                <input
                  type="text"
                  placeholder="Filter by destination, user, device, or service…"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="input-text text-xs"
                  style={{ width: '100%' }}
                />
              </div>

              {/* Severity filter */}
              <div>
                <select
                  value={severityFilter}
                  onChange={(e) => setSeverityFilter(e.target.value)}
                  className="input-select text-xs"
                  aria-label="Filter by Severity"
                >
                  <option value="all">All Severities</option>
                  <option value="critical">🔴 Critical (75–100)</option>
                  <option value="high">🟠 High (50–74)</option>
                  <option value="medium">🟡 Medium (25–49)</option>
                  <option value="low">🟢 Low (0–24)</option>
                </select>
              </div>

              {/* Classification filter */}
              <div>
                <select
                  value={classificationFilter}
                  onChange={(e) => setClassificationFilter(e.target.value)}
                  className="input-select text-xs"
                  aria-label="Filter by Classification"
                >
                  <option value="all">All Classifications</option>
                  <option value="Likely cloud AI">Likely cloud AI</option>
                  <option value="Possible local AI">Possible local AI</option>
                  <option value="Ordinary web">Ordinary web</option>
                  <option value="Uncertain">Uncertain</option>
                </select>
              </div>

              {/* Source filter */}
              <div>
                <select
                  value={sourceFilter}
                  onChange={(e) => setSourceFilter(e.target.value)}
                  className="input-select text-xs"
                  aria-label="Filter by Source"
                >
                  <option value="all">All Sources</option>
                  <option value="simulation">Built-in Simulation</option>
                  <option value="csv">CSV Import</option>
                </select>
              </div>

              {/* Clear filters button */}
              {(severityFilter !== 'all' || classificationFilter !== 'all' || sourceFilter !== 'all' || searchQuery) && (
                <button
                  type="button"
                  className="btn btn-secondary text-xs"
                  onClick={() => {
                    setSeverityFilter('all');
                    setClassificationFilter('all');
                    setSourceFilter('all');
                    setSearchQuery('');
                  }}
                >
                  Reset Filters
                </button>
              )}
            </div>
          </div>

          {/* Events Table */}
          {isLoading ? (
            <div className="card card-body text-center" style={{ padding: '3rem' }}>
              <span className="text-muted">Calculating explainable risk scores…</span>
            </div>
          ) : error ? (
            <div className="card card-body text-center" style={{ color: 'var(--color-danger)' }}>
              ⚠️ {error}
            </div>
          ) : events.length === 0 ? (
            <div className="card card-body text-center" style={{ padding: '3rem' }}>
              <span className="text-muted">No events match the selected risk criteria.</span>
            </div>
          ) : (
            <div className="table-wrapper">
              <table className="data-table" aria-label="Risk-analyzed events table">
                <thead>
                  <tr>
                    <th scope="col">Destination</th>
                    <th scope="col">Service / Provider</th>
                    <th scope="col">Risk Score & Severity</th>
                    <th scope="col">Sensitivity</th>
                    <th scope="col">Synthetic User & Auth</th>
                    <th scope="col">Policy Recommendation</th>
                    <th scope="col" style={{ textAlign: 'right' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {events.map((evt) => {
                    const isBlock = evt.action_recommendation.includes('simulation') || evt.action_recommendation.includes('sample');
                    const sevColor = getSeverityColor(evt.risk_level);

                    return (
                      <tr key={evt.id}>
                        {/* Destination */}
                        <td>
                          <div style={{ display: 'flex', flexDirection: 'column' }}>
                            <code className="text-xs font-semibold" style={{ color: 'var(--color-text-1)' }}>
                              {evt.destination}{evt.port ? `:${evt.port}` : ''}
                            </code>
                            <div style={{ display: 'flex', gap: 4, marginTop: 2 }}>
                              <ClassificationBadge classification={evt.classification} />
                              <SourceBadge source={evt.source_type} />
                            </div>
                          </div>
                        </td>

                        {/* Service / Provider */}
                        <td>
                          <div className="text-xs">
                            <span className="font-medium">{evt.service_name}</span>
                            <span className="text-muted" style={{ display: 'block' }}>
                              Status: <strong>{evt.approval_status}</strong>
                            </span>
                          </div>
                        </td>

                        {/* Risk Score & Severity */}
                        <td style={{ minWidth: 150 }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: 2 }}>
                            <span
                              className="font-bold text-xs"
                              style={{ color: sevColor, textTransform: 'capitalize' }}
                            >
                              {evt.risk_level} ({evt.risk_score}/100)
                            </span>
                            <span className="text-xs text-muted">
                              {evt.risk_factors.length} factors
                            </span>
                          </div>
                          <RiskScoreBar score={evt.risk_score} />
                        </td>

                        {/* Sensitivity */}
                        <td>
                          <DataLabelPill label={evt.sensitivity_label as DataLabel} />
                        </td>

                        {/* Synthetic User & Auth */}
                        <td>
                          <div className="text-xs">
                            <div style={{ color: 'var(--color-text-1)', fontWeight: 'var(--weight-medium)' }}>
                              👤 {evt.person_name}
                            </div>
                            <div style={{ display: 'flex', gap: 4, marginTop: 2, alignItems: 'center' }}>
                              {getAuthStatusBadge(evt.authorization_status || evt.identity_correlation?.authStatus)}
                              <span className="text-muted" style={{ fontSize: 10 }}>
                                💻 {evt.device_label}
                              </span>
                            </div>
                          </div>
                        </td>

                        {/* Recommendation */}
                        <td>
                          {isBlock ? (
                            <span
                              className="badge text-xs"
                              style={{
                                background: 'rgba(239, 68, 68, 0.15)',
                                color: '#f87171',
                                border: '1px solid rgba(239, 68, 68, 0.4)',
                                fontWeight: 'var(--weight-semibold)',
                              }}
                            >
                              🛡️ Would block (simulation)
                            </span>
                          ) : evt.risk_level === 'high' ? (
                            <span
                              className="badge text-xs"
                              style={{
                                background: 'rgba(249, 115, 22, 0.15)',
                                color: '#fb923c',
                                border: '1px solid rgba(249, 115, 22, 0.4)',
                              }}
                            >
                              ⚠️ Review promptly
                            </span>
                          ) : evt.risk_level === 'medium' ? (
                            <span
                              className="badge text-xs"
                              style={{
                                background: 'rgba(245, 158, 11, 0.15)',
                                color: '#fbbf24',
                                border: '1px solid rgba(245, 158, 11, 0.3)',
                              }}
                            >
                              ⚠️ Warn / review
                            </span>
                          ) : (
                            <span
                              className="badge text-xs"
                              style={{
                                background: 'rgba(16, 185, 129, 0.15)',
                                color: '#34d399',
                                border: '1px solid rgba(16, 185, 129, 0.3)',
                              }}
                            >
                              ✓ Allow
                            </span>
                          )}
                        </td>

                        {/* Actions */}
                        <td style={{ textAlign: 'right' }}>
                          <button
                            type="button"
                            className="btn btn-secondary text-xs"
                            onClick={() => setSelectedEvent(evt)}
                            style={{ padding: '3px 8px' }}
                          >
                            Inspect Factors
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </Section>

        {/* Event Detail Inspection Modal / Drawer */}
        {selectedEvent && (
          <div
            className="modal-backdrop"
            style={{
              position: 'fixed',
              top: 0,
              left: 0,
              width: '100%',
              height: '100%',
              backgroundColor: 'rgba(0, 0, 0, 0.75)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              zIndex: 1000,
              padding: 'var(--space-4)',
            }}
            onClick={() => setSelectedEvent(null)}
          >
            <div
              className="card"
              style={{
                maxWidth: 720,
                width: '100%',
                maxHeight: '90vh',
                overflowY: 'auto',
                boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.5)',
              }}
              onClick={(e) => e.stopPropagation()}
            >
              {/* Modal Header */}
              <div className="card-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <h3 style={{ fontSize: 'var(--text-md)', fontWeight: 'var(--weight-semibold)', margin: 0 }}>
                    🔍 Explainable Risk Assessment (Event #{selectedEvent.id})
                  </h3>
                  <span className="text-xs text-muted">
                    Observed: {new Date(selectedEvent.occurred_at).toLocaleString()} · Source: {selectedEvent.source_label}
                  </span>
                </div>
                <button
                  type="button"
                  className="btn btn-secondary text-xs"
                  onClick={() => setSelectedEvent(null)}
                >
                  ✕ Close
                </button>
              </div>

              <div className="card-body" style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
                {/* Score & Recommendation Banner */}
                <div
                  className="card"
                  style={{
                    padding: 'var(--space-4)',
                    background:
                      selectedEvent.risk_level === 'critical'
                        ? 'rgba(239, 68, 68, 0.1)'
                        : selectedEvent.risk_level === 'high'
                        ? 'rgba(249, 115, 22, 0.1)'
                        : 'var(--color-surface-2)',
                    borderColor: getSeverityColor(selectedEvent.risk_level),
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline' }}>
                    <div>
                      <span className="text-xs text-muted">Deterministic Score:</span>
                      <h2
                        style={{
                          fontSize: 'var(--text-xl)',
                          color: getSeverityColor(selectedEvent.risk_level),
                          margin: '2px 0',
                        }}
                      >
                        {selectedEvent.risk_score} / 100 — {selectedEvent.risk_level.toUpperCase()}
                      </h2>
                    </div>
                    <div>
                      <span className="text-xs text-muted" style={{ display: 'block', textAlign: 'right' }}>
                        Completeness / Confidence:
                      </span>
                      <span className="badge text-xs" style={{ background: 'var(--color-surface-3)' }}>
                        {selectedEvent.risk_confidence || 'Medium'} Confidence
                      </span>
                    </div>
                  </div>

                  <div className="mt-2">
                    <RiskScoreBar score={selectedEvent.risk_score} />
                  </div>

                  {/* Recommendation notice */}
                  <div className="mt-3" style={{ borderTop: '1px solid var(--color-border-subtle)', paddingTop: 'var(--space-2)' }}>
                    <span className="text-xs font-semibold" style={{ color: 'var(--color-text-1)' }}>
                      Policy Recommendation:
                    </span>
                    <p
                      className="text-xs font-medium mt-1"
                      style={{
                        color:
                          selectedEvent.isSimulatedAction
                            ? '#f87171'
                            : selectedEvent.risk_level === 'high'
                            ? '#fb923c'
                            : 'var(--color-text-1)',
                      }}
                    >
                      {selectedEvent.isSimulatedAction ? '🛡️ ' : 'ℹ️ '}
                      {selectedEvent.action_recommendation}
                    </p>
                    {selectedEvent.isSimulatedAction && (
                      <p className="text-xs text-muted mt-1" style={{ fontSize: 11 }}>
                        <em>*Note: This is a simulated prototype policy response. AURA does not perform live network blocking or firewall modifications.</em>
                      </p>
                    )}
                  </div>
                </div>

                {/* Plain-English Explanation */}
                <div>
                  <h4 className="section-label" style={{ marginBottom: 4 }}>
                    Plain-English Explanation
                  </h4>
                  <div
                    className="card"
                    style={{
                      padding: 'var(--space-3) var(--space-4)',
                      background: 'var(--color-surface-2)',
                      fontSize: 'var(--text-xs)',
                      lineHeight: 1.6,
                      color: 'var(--color-text-2)',
                    }}
                  >
                    “{selectedEvent.risk_explanation || selectedEvent.evidence || 'Standard risk assessment based on configured demo weights.'}”
                  </div>
                </div>

                {/* Contributing Risk Factors Breakdown */}
                <div>
                  <h4 className="section-label" style={{ marginBottom: 4 }}>
                    Contributing Risk Factors Breakdown ({selectedEvent.risk_factors.length} factors)
                  </h4>
                  <table className="data-table text-xs" aria-label="Risk factor breakdown">
                    <thead>
                      <tr>
                        <th scope="col">Factor Name</th>
                        <th scope="col" style={{ width: 80, textAlign: 'right' }}>Points</th>
                        <th scope="col">Evidence & Rationale</th>
                      </tr>
                    </thead>
                    <tbody>
                      {selectedEvent.risk_factors.map((f: RiskFactor) => (
                        <tr key={f.id}>
                          <td>
                            <strong>{f.name}</strong>
                            {f.isMissingContext && (
                              <span
                                className="badge text-xs ml-2"
                                style={{ background: 'rgba(245, 158, 11, 0.2)', color: '#fbbf24', fontSize: 10 }}
                              >
                                Missing Context
                              </span>
                            )}
                          </td>
                          <td style={{ textAlign: 'right', fontWeight: 'bold', color: f.points > 0 ? getSeverityColor(selectedEvent.risk_level) : 'var(--color-success)' }}>
                            +{f.points}
                          </td>
                          <td className="text-muted" style={{ lineHeight: 1.4 }}>
                            {f.evidence}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                    <tfoot>
                      <tr style={{ background: 'var(--color-surface-2)', fontWeight: 'bold' }}>
                        <td>Total Clamped Score</td>
                        <td style={{ textAlign: 'right', color: getSeverityColor(selectedEvent.risk_level) }}>
                          {selectedEvent.risk_score} / 100
                        </td>
                        <td className="text-muted" style={{ fontSize: 11 }}>
                          Demo policy weights sum clamped between 0 and 100.
                        </td>
                      </tr>
                    </tfoot>
                  </table>
                </div>

                {/* Synthetic Identity & Device Correlation */}
                <div>
                  <h4 className="section-label" style={{ marginBottom: 4 }}>
                    Synthetic Identity & Device Correlation (Demo Records Only)
                  </h4>
                  <div
                    className="card"
                    style={{
                      padding: 'var(--space-3)',
                      background: 'var(--color-surface-2)',
                      fontSize: 'var(--text-xs)',
                    }}
                  >
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-3)' }}>
                      <div>
                        <span className="text-muted">Synthetic Employee:</span>
                        <div style={{ fontWeight: 'var(--weight-semibold)', color: 'var(--color-text-1)' }}>
                          {selectedEvent.identity_correlation?.userName || selectedEvent.person_name}
                        </div>
                        <span className="text-muted" style={{ fontSize: 11 }}>
                          {selectedEvent.identity_correlation?.userEmail || selectedEvent.user_email || 'No email in event'}
                          {selectedEvent.identity_correlation?.userListed ? ' (Found in demo directory)' : ' (Unlisted)'}
                        </span>
                      </div>
                      <div>
                        <span className="text-muted">Synthetic Device:</span>
                        <div style={{ fontWeight: 'var(--weight-semibold)', color: 'var(--color-text-1)' }}>
                          {selectedEvent.identity_correlation?.deviceLabel || selectedEvent.device_label}
                        </div>
                        <span className="text-muted" style={{ fontSize: 11 }}>
                          {selectedEvent.identity_correlation?.deviceKnown ? 'Managed company device' : 'Unmanaged / Unknown asset'}
                        </span>
                      </div>
                    </div>

                    <div className="mt-3 pt-2" style={{ borderTop: '1px solid var(--color-border-subtle)' }}>
                      <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center' }}>
                        <span className="text-muted">Authorization Status:</span>
                        {getAuthStatusBadge(selectedEvent.authorization_status || selectedEvent.identity_correlation?.authStatus)}
                      </div>
                      <p className="text-muted mt-1" style={{ fontSize: 11 }}>
                        ℹ️ {selectedEvent.identity_correlation?.notes || 'Authorization verified against synthetic demo directory.'}
                      </p>
                    </div>
                  </div>
                </div>

                {/* Destination & Payload Details */}
                <div>
                  <h4 className="section-label" style={{ marginBottom: 4 }}>
                    Observed Destination & Traffic Details
                  </h4>
                  <div
                    className="card"
                    style={{
                      padding: 'var(--space-3)',
                      background: 'var(--color-surface-2)',
                      fontSize: 'var(--text-xs)',
                      display: 'grid',
                      gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))',
                      gap: 'var(--space-2)',
                    }}
                  >
                    <div>
                      <span className="text-muted">Target Destination:</span>
                      <div><code>{selectedEvent.destination}:{selectedEvent.port || 443}</code></div>
                    </div>
                    <div>
                      <span className="text-muted">Service Registry Status:</span>
                      <div><strong>{selectedEvent.approval_status}</strong></div>
                    </div>
                    <div>
                      <span className="text-muted">Data Volume (est.):</span>
                      <div>{(selectedEvent.byte_count / 1024).toFixed(1)} KB ({selectedEvent.byte_count.toLocaleString()} bytes)</div>
                    </div>
                    <div>
                      <span className="text-muted">Sensitivity Label:</span>
                      <div><DataLabelPill label={selectedEvent.sensitivity_label as DataLabel} /></div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
      </main>
    </>
  );
}
