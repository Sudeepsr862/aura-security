// ─── Overview Page ──────────────────────────────────────────────────────────
import { useState, useEffect } from 'react';
import {
  api,
  type DashboardBootstrap,
} from '../api/client';
import {
  RiskBadge,
  DataLabelPill,
  PageHeader,
  Section,
  WorkflowDiagram,
  ClassificationBadge,
  SourceBadge,
  PrivacyScopeNotice,
} from '../components/ui';
import type { NavPage, RiskLevel, DataLabel } from '../types';

interface OverviewProps {
  onNavigate: (page: NavPage) => void;
}

export function Overview({ onNavigate }: OverviewProps) {
  const [data, setData] = useState<DashboardBootstrap | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let mounted = true;
    async function fetchDashboard() {
      setIsLoading(true);
      setError(null);
      try {
        const res = await api.dashboard();
        if (mounted) {
          setData(res);
        }
      } catch (err: unknown) {
        if (mounted) {
          setError(err instanceof Error ? err.message : 'Failed to connect to local AURA database.');
        }
      } finally {
        if (mounted) {
          setIsLoading(false);
        }
      }
    }

    fetchDashboard();
    return () => {
      mounted = false;
    };
  }, []);

  return (
    <>
      <PageHeader
        title="Overview"
        subtitle="Understand your AI footprint. Aggregated metrics and activity derived from stored metadata."
      />

      <main className="page-body">
        {/* Section 6: Privacy and Scope Notice */}
        <PrivacyScopeNotice />

        {/* Welcome */}
        <div className="mb-6">
          <h2 style={{ fontSize: 'var(--text-xl)', fontWeight: 'var(--weight-semibold)', marginBottom: 'var(--space-1)' }}>
            Understand your AI footprint.
          </h2>
          <p className="text-muted text-sm">
            AURA provides comprehensive AI visibility and governance: protecting browser-based AI services,
            classifying cloud AI endpoints, enforcing data-sharing policies, and preventing sensitive credential leakage.
          </p>
        </div>

        {/* Loading state */}
        {isLoading && (
          <div className="card card-body text-center" style={{ padding: '3rem' }}>
            <span className="text-muted">Loading live dashboard metrics from database…</span>
          </div>
        )}

        {/* Error state */}
        {error && (
          <div
            className="card card-body text-center"
            style={{ padding: '2rem', border: '1px solid rgba(239, 68, 68, 0.4)', color: '#f87171' }}
          >
            <p className="font-semibold">⚠️ Database Connection Notice</p>
            <p className="text-sm text-muted mt-1">{error}</p>
            <button
              className="btn btn-secondary text-xs mt-3"
              onClick={() => window.location.reload()}
            >
              🔄 Retry Connection
            </button>
          </div>
        )}

        {/* Loaded dashboard content */}
        {!isLoading && !error && data && (
          <>
            {/* Summary stat cards */}
            <Section>
              <div className="stat-grid" role="list" aria-label="Summary metrics">
                <article className="stat-card accent" role="listitem">
                  <span className="stat-label">AI-like events</span>
                  <span className="stat-value" aria-label={`${data.summary.aiLikeEvents} AI-like events`}>
                    {data.summary.aiLikeEvents}
                  </span>
                  <span className="stat-note">
                    {data.summary.csvImportCount > 0
                      ? `${data.summary.csvImportCount} from CSV import`
                      : 'From simulated metadata'}
                  </span>
                </article>

                <article className="stat-card warning" role="listitem">
                  <span className="stat-label">Services needing review</span>
                  <span className="stat-value">{data.summary.servicesNeedingReview}</span>
                  <span className="stat-note">Unapproved or unreviewed</span>
                </article>

                <article
                  className="stat-card danger"
                  role="listitem"
                  onClick={() => onNavigate('data-risk')}
                  style={{ cursor: 'pointer' }}
                  title="Click to view explainable risk intelligence in Data & Risk"
                >
                  <span className="stat-label">High-risk events</span>
                  <span className="stat-value">{data.summary.highRiskEvents}</span>
                  <span className="stat-note">High or critical risk level →</span>
                </article>

                <article className="stat-card" role="listitem">
                  <span className="stat-label">Open sample incidents</span>
                  <span className="stat-value">{data.summary.openIncidents}</span>
                  <span className="stat-note">Investigation queue</span>
                </article>
              </div>
            </Section>

            {/* Recent activity table */}
            <Section title="Recent Activity — Stored Metadata Events">
              <p className="text-sm text-muted mb-4">
                Showing recent events from the database, labeled by source provenance (built-in simulation vs CSV import).
                All payload contents are excluded by design.
              </p>

              {data.recentActivity.length === 0 ? (
                <div className="card card-body text-center" style={{ padding: '2rem' }}>
                  <span className="text-muted">No recent events found. Import metadata via AI Inventory to populate events.</span>
                </div>
              ) : (
                <div className="table-wrapper">
                  <table className="data-table" aria-label="Recent activity events">
                    <thead>
                      <tr>
                        <th scope="col">Destination</th>
                        <th scope="col">Service / Provider</th>
                        <th scope="col">Classification</th>
                        <th scope="col">Risk</th>
                        <th scope="col">Sensitivity</th>
                        <th scope="col">Data Volume (est.)</th>
                        <th scope="col">Time</th>
                        <th scope="col">Source</th>
                      </tr>
                    </thead>
                    <tbody>
                      {data.recentActivity.map((row) => (
                        <tr key={row.id}>
                          <td className="cell-primary font-mono text-xs">
                            {row.destination}
                            {row.port && <span className="text-muted">:{row.port}</span>}
                          </td>
                          <td className="font-medium text-xs" style={{ color: 'var(--color-text)' }}>
                            {row.provider_name}
                          </td>
                          <td>
                            <ClassificationBadge classification={row.classification || 'Uncertain'} />
                          </td>
                          <td>
                            <RiskBadge level={row.risk_level as RiskLevel} />
                          </td>
                          <td>
                            <DataLabelPill label={row.sensitivity_label as DataLabel} />
                          </td>
                          <td className="text-xs text-muted">
                            {(row.byte_count / 1024).toFixed(1)} KB
                          </td>
                          <td className="text-muted text-xs font-mono">
                            {row.occurred_at.length > 16 ? row.occurred_at.slice(0, 16).replace('T', ' ') : row.occurred_at}
                          </td>
                          <td>
                            <SourceBadge source={row.source_type || 'simulation'} />
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </Section>
          </>
        )}

        {/* Workflow illustration */}
        <Section title="How AURA Works">
          <WorkflowDiagram />
        </Section>

        {/* CTA Banner */}
        <div
          className="card card-body flex items-center gap-4"
          style={{ justifyContent: 'space-between', flexWrap: 'wrap', marginTop: '1.5rem' }}
        >
          <div>
            <p className="font-semibold" style={{ marginBottom: 4 }}>
              Explore AI Service Inventory &amp; Import Metadata
            </p>
            <p className="text-sm text-muted">
              Inspect discovered AI endpoints, review detection confidence, and import custom CSV metadata files.
            </p>
          </div>
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => onNavigate('ai-inventory')}
          >
            Open AI Inventory →
          </button>
        </div>
      </main>
    </>
  );
}
