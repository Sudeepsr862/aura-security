// ─── Browser AI Guard & Extension Dashboard ────────────────────────────────
// Protects multiple configurable AI web tools (Cloud AI & Local models).
//
// Key Capabilities:
// 1. Configured AI Sites & Protection Status (Protected, Inactive, Unsupported/Changed)
// 2. Editable AI Service Catalog (Add / remove domains)
// 3. Live Extension Interceptions with Review Workflow (Expected, Investigate, Policy exception)
// 4. Sample Historical Activity from the 5 CSV datasets joined on employee_id
// 5. Strict visual separation between Live Extension Events and Historical Dataset Samples
// 6. Built-in Test Sandbox simulating ChatGPT and Claude layouts for direct testing
// 7. Zero secret exposure & privacy guarantees

import { useState, useEffect } from 'react';
import {
  api,
  type ExtensionSiteItem,
  type ExtensionEventItem,
  type ExtensionDashboardSummaryResponse,
  type DatasetHistoryRecord,
  type DatasetIncidentRecord,
} from '../api/client';
import { RiskBadge, DemoNotice, PageHeader, Section } from '../components/ui';

type ExtensionTab = 'live_events' | 'catalog' | 'dataset_history' | 'dataset_incidents' | 'test_sandbox';

export function ExtensionGuard() {
  const [activeTab, setActiveTab] = useState<ExtensionTab>('live_events');
  const [summary, setSummary] = useState<ExtensionDashboardSummaryResponse | null>(null);
  const [sites, setSites] = useState<ExtensionSiteItem[]>([]);
  const [liveEvents, setLiveEvents] = useState<ExtensionEventItem[]>([]);
  const [historicalLogs, setHistoricalLogs] = useState<DatasetHistoryRecord[]>([]);
  const [historicalIncidents, setHistoricalIncidents] = useState<DatasetIncidentRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters for Live Events
  const [riskFilter, setRiskFilter] = useState('all');
  const [serviceFilter, setServiceFilter] = useState('all');
  const [reviewFilter, setReviewFilter] = useState('all');

  // Review Dialog State
  const [selectedEvent, setSelectedEvent] = useState<ExtensionEventItem | null>(null);
  const [targetReviewStatus, setTargetReviewStatus] = useState<'Expected' | 'Investigate' | 'Policy exception'>('Expected');
  const [reviewerNote, setReviewerNote] = useState('');
  const [reviewSubmitting, setReviewSubmitting] = useState(false);

  // Catalog Add Form State
  const [newSiteName, setNewSiteName] = useState('');
  const [newSiteDomain, setNewSiteDomain] = useState('');
  const [newSiteCategory, setNewSiteCategory] = useState<'cloud' | 'local' | 'custom'>('cloud');
  const [newSiteAdapter, setNewSiteAdapter] = useState('generic');
  const [addingSite, setAddingSite] = useState(false);

  // Test Sandbox State (for in-browser demonstration)
  const [sandboxStyle, setSandboxStyle] = useState<'chatgpt' | 'claude'>('chatgpt');
  const [sandboxPrompt, setSandboxPrompt] = useState('');
  const [sandboxMessages, setSandboxMessages] = useState<Array<{ sender: 'user' | 'ai'; text: string }>>([
    { sender: 'ai', text: 'Hello! I am your AI assistant. How can I help you today?' },
  ]);

  useEffect(() => {
    loadData();
  }, [riskFilter, serviceFilter, reviewFilter]);

  async function loadData() {
    setLoading(true);
    setError(null);
    try {
      const [sum, st, ev, hist, inc] = await Promise.all([
        api.extensionSummary().catch(() => null),
        api.extensionSites().catch(() => null),
        api.extensionEvents({
          risk: riskFilter !== 'all' ? riskFilter : undefined,
          service: serviceFilter !== 'all' ? serviceFilter : undefined,
          review: reviewFilter !== 'all' ? reviewFilter : undefined,
        }).catch(() => null),
        api.datasetHistory().catch(() => null),
        api.datasetIncidents().catch(() => null),
      ]);

      if (sum) setSummary(sum);
      if (st) setSites(st.sites);
      if (ev) setLiveEvents(ev.events);
      if (hist) setHistoricalLogs(hist.records);
      if (inc) setHistoricalIncidents(inc.incidents);
    } catch (err: any) {
      setError(err?.message || 'Failed to load extension information.');
    } finally {
      setLoading(false);
    }
  }

  // Submit review action
  async function handleSubmitReview(e: React.FormEvent) {
    e.preventDefault();
    if (!selectedEvent) return;
    setReviewSubmitting(true);
    try {
      await api.reviewExtensionEvent(selectedEvent.id, targetReviewStatus, reviewerNote.trim());
      setSelectedEvent(null);
      setReviewerNote('');
      // Reload live events and summary
      const [ev, sum] = await Promise.all([
        api.extensionEvents(),
        api.extensionSummary(),
      ]);
      setLiveEvents(ev.events);
      setSummary(sum);
    } catch (err: any) {
      alert(err?.message || 'Failed to submit review.');
    } finally {
      setReviewSubmitting(false);
    }
  }

  // Add site to catalog
  async function handleAddSite(e: React.FormEvent) {
    e.preventDefault();
    if (!newSiteName.trim() || !newSiteDomain.trim()) return;
    setAddingSite(true);
    try {
      await api.addExtensionSite({
        name: newSiteName.trim(),
        domain: newSiteDomain.trim(),
        category: newSiteCategory,
        adapter: newSiteAdapter,
      });
      setNewSiteName('');
      setNewSiteDomain('');
      const [st, sum] = await Promise.all([
        api.extensionSites(),
        api.extensionSummary(),
      ]);
      setSites(st.sites);
      setSummary(sum);
    } catch (err: any) {
      alert(err?.message || 'Failed to add AI service.');
    } finally {
      setAddingSite(false);
    }
  }

  // Delete site from catalog
  async function handleDeleteSite(id: number) {
    if (!confirm('Remove this domain from the protected catalog?')) return;
    try {
      await api.deleteExtensionSite(id);
      const [st, sum] = await Promise.all([
        api.extensionSites(),
        api.extensionSummary(),
      ]);
      setSites(st.sites);
      setSummary(sum);
    } catch (err: any) {
      alert(err?.message || 'Failed to delete AI service.');
    }
  }

  // Sandbox send helper (simulates website submission)
  function handleSandboxSend() {
    if (!sandboxPrompt.trim()) return;

    // Simulate user message
    const msg = sandboxPrompt;
    setSandboxMessages((prev) => [...prev, { sender: 'user', text: msg }]);
    setSandboxPrompt('');

    // Simulate AI response
    setTimeout(() => {
      setSandboxMessages((prev) => [
        ...prev,
        { sender: 'ai', text: `Simulated response: Received clean query without policy violations (${msg.length} chars).` },
      ]);
    }, 600);
  }

  return (
    <div className="page-container animate-fade-in" id="main-content">
      <PageHeader
        title="Browser AI Guard & Extension Center"
        subtitle="In-browser Manifest V3 extension monitoring multiple AI websites and local models. Stops sensitive leaks before send."
      >
        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
          <span className="badge badge-success" style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span>🟢</span> Extension Active
          </span>
          <span className="badge badge-info" style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span>🔒</span> In-Memory Pre-Transfer Check
          </span>
        </div>
      </PageHeader>

      <DemoNotice message="Privacy Guarantee: The Chrome extension performs all regex detection locally in-memory inside the browser tab. Prompt texts, file contents, and secret values are never transmitted to the server or persisted to disk." />

      {error && (
        <div className="banner banner-error" style={{ marginBottom: '16px' }}>
          <span>⚠️ {error}</span>
        </div>
      )}

      {/* KPI Overview Strip */}
      {summary && (
        <div className="grid grid-4" style={{ marginBottom: '24px' }}>
          <div className="card stat-card">
            <span className="stat-label">Protected AI Sites</span>
            <span className="stat-value">{summary.catalog.protectedSites} <span style={{ fontSize: '1rem', color: 'var(--color-muted)' }}>/ {summary.catalog.totalSites}</span></span>
            <span className="stat-sub">{summary.catalog.unsupportedSites} unsupported or changed</span>
          </div>
          <div className="card stat-card">
            <span className="stat-label">Live Blocked Submissions</span>
            <span className="stat-value" style={{ color: 'var(--color-critical)' }}>{summary.liveEvents.blocked}</span>
            <span className="stat-sub">{summary.liveEvents.critical} critical severity stops</span>
          </div>
          <div className="card stat-card">
            <span className="stat-label">Pending Compliance Reviews</span>
            <span className="stat-value" style={{ color: 'var(--color-high)' }}>{summary.liveEvents.pendingReview}</span>
            <span className="stat-sub">Awaiting reviewer classification</span>
          </div>
          <div className="card stat-card">
            <span className="stat-label">Reference Datasets Loaded</span>
            <span className="stat-value" style={{ color: 'var(--color-accent)' }}>{summary.datasets.employees} <span style={{ fontSize: '0.9rem', color: 'var(--color-muted)' }}>Employees</span></span>
            <span className="stat-sub">{summary.datasets.aiLogs} historical AI logs</span>
          </div>
        </div>
      )}

      {/* Tab Navigation */}
      <div className="tabs-nav" style={{ display: 'flex', gap: '8px', borderBottom: '1px solid var(--color-border)', marginBottom: '24px', flexWrap: 'wrap' }}>
        <button
          type="button"
          className={`tab-btn ${activeTab === 'live_events' ? 'active' : ''}`}
          onClick={() => setActiveTab('live_events')}
        >
          ⚡ Live Extension Events ({liveEvents.length})
        </button>
        <button
          type="button"
          className={`tab-btn ${activeTab === 'catalog' ? 'active' : ''}`}
          onClick={() => setActiveTab('catalog')}
        >
          🌐 AI Service Catalog ({sites.length})
        </button>
        <button
          type="button"
          className={`tab-btn ${activeTab === 'dataset_history' ? 'active' : ''}`}
          onClick={() => setActiveTab('dataset_history')}
        >
          📜 Historical Sample Activity (CSV Datasets)
        </button>
        <button
          type="button"
          className={`tab-btn ${activeTab === 'dataset_incidents' ? 'active' : ''}`}
          onClick={() => setActiveTab('dataset_incidents')}
        >
          🚨 Historical Incidents ({historicalIncidents.length})
        </button>
        <button
          type="button"
          className={`tab-btn ${activeTab === 'test_sandbox' ? 'active' : ''}`}
          onClick={() => setActiveTab('test_sandbox')}
        >
          🧪 Local AI Test Sandbox
        </button>
      </div>

      {/* ──────────────────────────────────────────────────────────────────────────
          TAB 1: LIVE EXTENSION EVENTS
          ────────────────────────────────────────────────────────────────────────── */}
      {activeTab === 'live_events' && (
        <div className="animate-fade-in">
          <Section
            title="Live Extension Interception Events"
            description="Real-time events recorded by the Chrome extension when pre-transfer rules intercept sensitive messages or file uploads. Minimal metadata only — no raw secrets or prompt text stored."
          >
            {/* Filters Strip */}
            <div className="card" style={{ padding: '12px 16px', marginBottom: '16px', display: 'flex', gap: '16px', alignItems: 'center', flexWrap: 'wrap' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <label style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--color-muted)' }}>Risk Level:</label>
                <select className="input" value={riskFilter} onChange={(e) => setRiskFilter(e.target.value)} style={{ padding: '4px 8px', fontSize: '0.8rem' }}>
                  <option value="all">All Levels</option>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                </select>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <label style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--color-muted)' }}>AI Service:</label>
                <select className="input" value={serviceFilter} onChange={(e) => setServiceFilter(e.target.value)} style={{ padding: '4px 8px', fontSize: '0.8rem' }}>
                  <option value="all">All Services</option>
                  {Array.from(new Set(sites.map((s) => s.name))).sort().map((name) => (
                    <option key={name} value={name}>{name}</option>
                  ))}
                </select>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <label style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--color-muted)' }}>Review Status:</label>
                <select className="input" value={reviewFilter} onChange={(e) => setReviewFilter(e.target.value)} style={{ padding: '4px 8px', fontSize: '0.8rem' }}>
                  <option value="all">All Statuses</option>
                  <option value="Pending">Pending Review</option>
                  <option value="Expected">Expected</option>
                  <option value="Investigate">Investigate</option>
                  <option value="Policy exception">Policy Exception</option>
                </select>
              </div>

              <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: '8px' }}>
                {loading && (
                  <span style={{ fontSize: '0.78rem', color: 'var(--color-muted)' }}>
                    ⏳ Refreshing...
                  </span>
                )}
                <span className="badge badge-success" style={{ fontSize: '0.78rem' }}>
                  🟢 Live Extension Feed
                </span>
              </div>
            </div>

            {/* Live Events Table */}
            <div className="card" style={{ overflowX: 'auto', padding: 0 }}>
              <table className="table" style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--color-border)', textAlign: 'left', fontSize: '0.8rem', color: 'var(--color-muted)' }}>
                    <th style={{ padding: '12px 16px' }}>Source & Time</th>
                    <th style={{ padding: '12px 16px' }}>Employee ID</th>
                    <th style={{ padding: '12px 16px' }}>AI Service & Domain</th>
                    <th style={{ padding: '12px 16px' }}>Event Type</th>
                    <th style={{ padding: '12px 16px' }}>Detected Category</th>
                    <th style={{ padding: '12px 16px' }}>Action Taken</th>
                    <th style={{ padding: '12px 16px' }}>Risk</th>
                    <th style={{ padding: '12px 16px' }}>Review Status</th>
                    <th style={{ padding: '12px 16px' }}>Review Action</th>
                  </tr>
                </thead>
                <tbody>
                  {loading && liveEvents.length === 0 ? (
                    <tr>
                      <td colSpan={9} style={{ padding: '32px', textAlign: 'center', color: 'var(--color-muted)' }}>
                        ⏳ Loading extension interception feed...
                      </td>
                    </tr>
                  ) : liveEvents.length === 0 ? (
                    <tr>
                      <td colSpan={9} style={{ padding: '32px', textAlign: 'center', color: 'var(--color-muted)' }}>
                        No live extension events match the selected filters.
                      </td>
                    </tr>
                  ) : (
                    liveEvents.map((ev) => (
                      <tr key={ev.id} style={{ borderBottom: '1px solid var(--color-border)', fontSize: '0.85rem' }}>
                        <td style={{ padding: '12px 16px', whiteSpace: 'nowrap' }}>
                          <span className="badge badge-success" style={{ fontSize: '0.68rem', display: 'block', marginBottom: '2px', width: 'fit-content' }}>
                            LIVE EXTENSION
                          </span>
                          <span style={{ fontSize: '0.78rem', color: 'var(--color-muted)' }}>{ev.event_time}</span>
                        </td>
                        <td style={{ padding: '12px 16px' }}>
                          <strong>{ev.employee_id}</strong>
                          {ev.employee_name && (
                            <div style={{ fontSize: '0.72rem', color: 'var(--color-muted)' }}>{ev.employee_name} ({ev.department})</div>
                          )}
                        </td>
                        <td style={{ padding: '12px 16px' }}>
                          <strong>{ev.ai_service}</strong>
                          <div style={{ fontSize: '0.75rem', color: 'var(--color-muted)', fontFamily: 'monospace' }}>{ev.domain}</div>
                        </td>
                        <td style={{ padding: '12px 16px' }}>
                          <span style={{ fontSize: '0.8rem' }}>
                            {ev.event_type === 'file_upload' ? `📎 Upload: ${ev.file_name || 'file'}` : '💬 Message Send'}
                          </span>
                        </td>
                        <td style={{ padding: '12px 16px' }}>
                          <span className="badge badge-secondary" style={{ fontSize: '0.75rem' }}>
                            🏷️ {ev.detected_category}
                          </span>
                          <div style={{ fontSize: '0.72rem', color: 'var(--color-muted)', marginTop: '2px' }}>
                            Rule: {ev.matched_rule}
                          </div>
                        </td>
                        <td style={{ padding: '12px 16px' }}>
                          <span className={`badge badge-${ev.action_taken === 'blocked' ? 'critical' : ev.action_taken === 'warned' ? 'high' : 'low'}`}>
                            {ev.action_taken.toUpperCase()}
                          </span>
                        </td>
                        <td style={{ padding: '12px 16px' }}>
                          <RiskBadge level={ev.risk_level} />
                        </td>
                        <td style={{ padding: '12px 16px' }}>
                          <span
                            className={`badge ${
                              ev.review_status === 'Pending' ? 'badge-high' :
                              ev.review_status === 'Expected' ? 'badge-success' :
                              ev.review_status === 'Investigate' ? 'badge-critical' : 'badge-info'
                            }`}
                          >
                            {ev.review_status}
                          </span>
                          {ev.reviewer_note && (
                            <div style={{ fontSize: '0.72rem', color: 'var(--color-muted)', marginTop: '2px', maxWidth: '140px' }}>
                              "{ev.reviewer_note}"
                            </div>
                          )}
                        </td>
                        <td style={{ padding: '12px 16px' }}>
                          <button
                            type="button"
                            className="btn btn-secondary"
                            style={{ fontSize: '0.75rem', padding: '4px 8px' }}
                            onClick={() => {
                              setSelectedEvent(ev);
                              setTargetReviewStatus(ev.review_status === 'Pending' ? 'Expected' : ev.review_status);
                              setReviewerNote(ev.reviewer_note || '');
                            }}
                          >
                            Review
                          </button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>

            {/* Review Dialog */}
            {selectedEvent && (
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
                <div className="card" style={{ width: '480px', maxWidth: '90%', padding: '24px' }}>
                  <h3 style={{ marginTop: 0, marginBottom: '8px' }}>Review Live Extension Event</h3>
                  <p style={{ fontSize: '0.82rem', color: 'var(--color-muted)', marginBottom: '14px' }}>
                    Record authorized evaluation for <strong>{selectedEvent.employee_id}</strong> on <strong>{selectedEvent.ai_service}</strong> ({selectedEvent.detected_category}).
                  </p>

                  <form onSubmit={handleSubmitReview}>
                    <div style={{ marginBottom: '14px' }}>
                      <label style={{ display: 'block', fontSize: '0.85rem', marginBottom: '6px', fontWeight: 600 }}>
                        Review Outcome Status
                      </label>
                      <select
                        className="input"
                        style={{ width: '100%' }}
                        value={targetReviewStatus}
                        onChange={(e) => setTargetReviewStatus(e.target.value as any)}
                      >
                        <option value="Expected">Expected (Benign business activity or authorized routine)</option>
                        <option value="Investigate">Investigate (Requires follow-up compliance interview)</option>
                        <option value="Policy exception">Policy exception (Formal exception granted for approved role)</option>
                      </select>
                    </div>

                    <div style={{ marginBottom: '16px' }}>
                      <label style={{ display: 'block', fontSize: '0.85rem', marginBottom: '6px', fontWeight: 600 }}>
                        Reviewer Note / Rationale
                      </label>
                      <textarea
                        rows={3}
                        className="input"
                        style={{ width: '100%' }}
                        value={reviewerNote}
                        onChange={(e) => setReviewerNote(e.target.value)}
                        placeholder="e.g. Employee consulted; guided to approved internal model pipeline."
                      />
                    </div>

                    <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px' }}>
                      <button type="button" className="btn btn-secondary" onClick={() => setSelectedEvent(null)}>
                        Cancel
                      </button>
                      <button type="submit" className="btn btn-primary" disabled={reviewSubmitting}>
                        {reviewSubmitting ? 'Saving...' : 'Confirm Review'}
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
          TAB 2: AI SERVICE CATALOG
          ────────────────────────────────────────────────────────────────────────── */}
      {activeTab === 'catalog' && (
        <div className="animate-fade-in">
          <Section
            title="Configured AI Services & Protection Status"
            description="Manage browser-based AI websites and local model web interfaces. Extension requests permissions only for configured domains. Unsupported or changed sites visibly report their status."
          >
            {/* Add Site Form */}
            <div className="card" style={{ padding: '20px', marginBottom: '20px' }}>
              <h3 style={{ fontSize: '0.95rem', marginTop: 0, marginBottom: '14px' }}>+ Add New AI Service Domain</h3>
              <form onSubmit={handleAddSite} style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr)) auto', gap: '12px', alignItems: 'end' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '0.8rem', marginBottom: '4px' }}>Service Name</label>
                  <input
                    type="text"
                    className="input"
                    style={{ width: '100%' }}
                    placeholder="e.g. Perplexity AI"
                    value={newSiteName}
                    onChange={(e) => setNewSiteName(e.target.value)}
                    required
                  />
                </div>
                <div>
                  <label style={{ display: 'block', fontSize: '0.8rem', marginBottom: '4px' }}>Website Domain or Host</label>
                  <input
                    type="text"
                    className="input"
                    style={{ width: '100%' }}
                    placeholder="e.g. perplexity.ai or localhost:9000"
                    value={newSiteDomain}
                    onChange={(e) => setNewSiteDomain(e.target.value)}
                    required
                  />
                </div>
                <div>
                  <label style={{ display: 'block', fontSize: '0.8rem', marginBottom: '4px' }}>Category</label>
                  <select
                    className="input"
                    style={{ width: '100%' }}
                    value={newSiteCategory}
                    onChange={(e) => setNewSiteCategory(e.target.value as any)}
                  >
                    <option value="cloud">Cloud AI</option>
                    <option value="local">Local Model</option>
                    <option value="custom">Custom WebUI</option>
                  </select>
                </div>
                <div>
                  <label style={{ display: 'block', fontSize: '0.8rem', marginBottom: '4px' }}>Detector</label>
                  <select
                    className="input"
                    style={{ width: '100%' }}
                    value={newSiteAdapter}
                    onChange={(e) => setNewSiteAdapter(e.target.value)}
                  >
                    <option value="generic">Generic Detector</option>
                    <option value="chatgpt">ChatGPT Style</option>
                    <option value="claude">Claude Style</option>
                    <option value="local_webui">Local WebUI</option>
                  </select>
                </div>
                <button type="submit" className="btn btn-primary" disabled={addingSite} style={{ height: '38px' }}>
                  {addingSite ? 'Adding...' : 'Add Domain'}
                </button>
              </form>
            </div>

            {/* Catalog Table */}
            <div className="card" style={{ overflowX: 'auto', padding: 0 }}>
              <table className="table" style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--color-border)', textAlign: 'left', fontSize: '0.8rem', color: 'var(--color-muted)' }}>
                    <th style={{ padding: '12px 16px' }}>Service Name</th>
                    <th style={{ padding: '12px 16px' }}>Domain / Port</th>
                    <th style={{ padding: '12px 16px' }}>Category</th>
                    <th style={{ padding: '12px 16px' }}>Adapter</th>
                    <th style={{ padding: '12px 16px' }}>Protection Status</th>
                    <th style={{ padding: '12px 16px' }}>Last Active</th>
                    <th style={{ padding: '12px 16px' }}>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {sites.map((s) => (
                    <tr key={s.id} style={{ borderBottom: '1px solid var(--color-border)', fontSize: '0.85rem' }}>
                      <td style={{ padding: '12px 16px' }}>
                        <strong>{s.name}</strong>
                      </td>
                      <td style={{ padding: '12px 16px' }}>
                        <code style={{ fontSize: '0.8rem' }}>{s.domain}</code>
                      </td>
                      <td style={{ padding: '12px 16px' }}>
                        <span className={`badge ${s.category === 'cloud' ? 'badge-info' : s.category === 'local' ? 'badge-secondary' : 'badge-high'}`}>
                          {s.category.toUpperCase()}
                        </span>
                      </td>
                      <td style={{ padding: '12px 16px' }}>
                        <span style={{ fontSize: '0.78rem', color: 'var(--color-muted)' }}>{s.adapter}</span>
                      </td>
                      <td style={{ padding: '12px 16px' }}>
                        <span className={`badge ${s.status === 'protected' ? 'badge-success' : s.status === 'inactive' ? 'badge-secondary' : 'badge-critical'}`}>
                          {s.status === 'protected' ? 'Protected' : s.status === 'inactive' ? 'Inactive' : '⚠️ Changed / Unsupported'}
                        </span>
                      </td>
                      <td style={{ padding: '12px 16px', fontSize: '0.78rem', color: 'var(--color-muted)' }}>
                        {s.last_active_at || 'Never detected'}
                      </td>
                      <td style={{ padding: '12px 16px' }}>
                        <button
                          type="button"
                          className="btn btn-secondary"
                          style={{ fontSize: '0.75rem', padding: '4px 8px', color: 'var(--color-critical)' }}
                          onClick={() => handleDeleteSite(s.id)}
                        >
                          Remove
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div style={{ marginTop: '16px', fontSize: '0.8rem', color: 'var(--color-muted)' }}>
              <strong>Coverage Limitation:</strong> Each AI site has its own interface, and new or changed sites may require an adapter or updated configuration. This extension protects supported browser pages where permission has been granted; it does not cover desktop applications or every network connection.
            </div>
          </Section>
        </div>
      )}

      {/* ──────────────────────────────────────────────────────────────────────────
          TAB 3: HISTORICAL SAMPLE ACTIVITY (FROM CSV DATASETS)
          ────────────────────────────────────────────────────────────────────────── */}
      {activeTab === 'dataset_history' && (
        <div className="animate-fade-in">
          <Section
            title="Sample Historical Activity (Reference CSV Datasets)"
            description="Historical logs imported from dataset_b_ai_usage_logs.csv and dataset_d_network_logs.csv, joined on employee_id with dataset_a_employees.csv context. Clearly distinguished from live extension events."
          >
            <div className="banner banner-info" style={{ marginBottom: '16px', fontSize: '0.82rem' }}>
              <span>ℹ️ <strong>Sample Data Provenance:</strong> The records below represent historical synthetic datasets (500 AI usage records). They are read-only reference data and are visibly labeled as sample records.</span>
            </div>

            <div className="card" style={{ overflowX: 'auto', padding: 0 }}>
              <table className="table" style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--color-border)', textAlign: 'left', fontSize: '0.8rem', color: 'var(--color-muted)' }}>
                    <th style={{ padding: '12px 16px' }}>Data Provenance</th>
                    <th style={{ padding: '12px 16px' }}>Log ID & Time</th>
                    <th style={{ padding: '12px 16px' }}>Employee Context</th>
                    <th style={{ padding: '12px 16px' }}>AI Service & Domain</th>
                    <th style={{ padding: '12px 16px' }}>Inspection Result (Dataset)</th>
                    <th style={{ padding: '12px 16px' }}>Service Status</th>
                    <th style={{ padding: '12px 16px' }}>Transfer Size</th>
                  </tr>
                </thead>
                <tbody>
                  {historicalLogs.slice(0, 30).map((row) => (
                    <tr key={row.log_id} style={{ borderBottom: '1px solid var(--color-border)', fontSize: '0.85rem' }}>
                      <td style={{ padding: '12px 16px', whiteSpace: 'nowrap' }}>
                        <span className="badge badge-secondary" style={{ fontSize: '0.68rem', display: 'block', marginBottom: '2px', width: 'fit-content' }}>
                          HISTORICAL SAMPLE
                        </span>
                        <span style={{ fontSize: '0.72rem', color: 'var(--color-muted)' }}>dataset_b</span>
                      </td>
                      <td style={{ padding: '12px 16px' }}>
                        <strong>{row.log_id}</strong>
                        <div style={{ fontSize: '0.75rem', color: 'var(--color-muted)' }}>{row.timestamp}</div>
                      </td>
                      <td style={{ padding: '12px 16px' }}>
                        <strong>{row.employee_id}</strong> ({row.employee_name})
                        <div style={{ fontSize: '0.72rem', color: 'var(--color-muted)' }}>
                          {row.job_role} • {row.department}
                        </div>
                        <div style={{ fontSize: '0.7rem', color: 'var(--color-muted)' }}>
                          Trust: {row.device_trust_status}
                        </div>
                      </td>
                      <td style={{ padding: '12px 16px' }}>
                        <strong>{row.ai_service}</strong>
                        <div style={{ fontSize: '0.75rem', color: 'var(--color-muted)', fontFamily: 'monospace' }}>{row.destination_domain}</div>
                      </td>
                      <td style={{ padding: '12px 16px' }}>
                        <span style={{ fontSize: '0.8rem', color: row.inspection_result.includes('Detected') ? 'var(--color-critical)' : 'var(--color-text)' }}>
                          {row.inspection_result}
                        </span>
                      </td>
                      <td style={{ padding: '12px 16px' }}>
                        <span className={`badge ${row.service_status.includes('Approved') ? 'badge-success' : 'badge-high'}`}>
                          {row.service_status}
                        </span>
                      </td>
                      <td style={{ padding: '12px 16px', fontSize: '0.8rem' }}>
                        {row.request_size}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p style={{ fontSize: '0.78rem', color: 'var(--color-muted)', marginTop: '8px' }}>
              Showing 30 of {historicalLogs.length} historical sample records. Joined via <code>employee_id</code>.
            </p>
          </Section>
        </div>
      )}

      {/* ──────────────────────────────────────────────────────────────────────────
          TAB 4: HISTORICAL SECURITY INCIDENTS (DATASET E)
          ────────────────────────────────────────────────────────────────────────── */}
      {activeTab === 'dataset_incidents' && (
        <div className="animate-fade-in">
          <Section
            title="Sample Security Incidents (Dataset E)"
            description="Reference incident records from dataset_e_security_incidents.csv joined with employee context. Clearly distinguished from live extension events."
          >
            <div className="card" style={{ overflowX: 'auto', padding: 0 }}>
              <table className="table" style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--color-border)', textAlign: 'left', fontSize: '0.8rem', color: 'var(--color-muted)' }}>
                    <th style={{ padding: '12px 16px' }}>Incident ID & Time</th>
                    <th style={{ padding: '12px 16px' }}>Employee Context</th>
                    <th style={{ padding: '12px 16px' }}>Violation & Explanation</th>
                    <th style={{ padding: '12px 16px' }}>Severity & Score</th>
                    <th style={{ padding: '12px 16px' }}>Recommended Action</th>
                    <th style={{ padding: '12px 16px' }}>Resolution</th>
                  </tr>
                </thead>
                <tbody>
                  {historicalIncidents.slice(0, 20).map((inc) => (
                    <tr key={inc.incident_id} style={{ borderBottom: '1px solid var(--color-border)', fontSize: '0.85rem' }}>
                      <td style={{ padding: '12px 16px' }}>
                        <span className="badge badge-secondary" style={{ fontSize: '0.68rem', display: 'block', marginBottom: '2px', width: 'fit-content' }}>
                          DATASET INCIDENT
                        </span>
                        <strong>{inc.incident_id}</strong>
                        <div style={{ fontSize: '0.75rem', color: 'var(--color-muted)' }}>{inc.timestamp}</div>
                      </td>
                      <td style={{ padding: '12px 16px' }}>
                        <strong>{inc.employee_id}</strong>
                        {inc.employee_name && (
                          <div style={{ fontSize: '0.72rem', color: 'var(--color-muted)' }}>
                            {inc.employee_name} ({inc.department})
                          </div>
                        )}
                      </td>
                      <td style={{ padding: '12px 16px', maxWidth: '280px' }}>
                        <strong>{inc.policy_violation}</strong>
                        <p style={{ margin: '4px 0 0 0', fontSize: '0.78rem', color: 'var(--color-muted)' }}>
                          {inc.explanation}
                        </p>
                      </td>
                      <td style={{ padding: '12px 16px' }}>
                        <span className={`badge badge-${inc.severity.toLowerCase() === 'critical' ? 'critical' : inc.severity.toLowerCase() === 'high' ? 'high' : 'medium'}`}>
                          {inc.severity} ({inc.risk_score} pts)
                        </span>
                      </td>
                      <td style={{ padding: '12px 16px', fontSize: '0.78rem', color: 'var(--color-muted)', maxWidth: '200px' }}>
                        {inc.recommended_action}
                      </td>
                      <td style={{ padding: '12px 16px', fontSize: '0.78rem' }}>
                        <span className="badge badge-success">{inc.response_status}</span>
                        <div style={{ fontSize: '0.72rem', color: 'var(--color-muted)', marginTop: '2px' }}>
                          {inc.analyst_resolution}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Section>
        </div>
      )}

      {/* ──────────────────────────────────────────────────────────────────────────
          TAB 5: LOCAL AI TEST SANDBOX
          ────────────────────────────────────────────────────────────────────────── */}
      {activeTab === 'test_sandbox' && (
        <div className="animate-fade-in">
          <Section
            title="Local AI Test Sandbox"
            description="Simulates the exact DOM and layout of ChatGPT and Claude right here in the browser. Test typing synthetic secrets or uploading CSVs to observe live extension interception."
          >
            <div style={{ display: 'flex', gap: '8px', marginBottom: '16px' }}>
              <button
                type="button"
                className={`btn ${sandboxStyle === 'chatgpt' ? 'btn-primary' : 'btn-secondary'}`}
                onClick={() => setSandboxStyle('chatgpt')}
              >
                ChatGPT Web Layout (#prompt-textarea)
              </button>
              <button
                type="button"
                className={`btn ${sandboxStyle === 'claude' ? 'btn-primary' : 'btn-secondary'}`}
                onClick={() => setSandboxStyle('claude')}
              >
                Claude Web Layout (contenteditable ProseMirror)
              </button>
            </div>

            {/* Test Presets */}
            <div style={{ marginBottom: '16px' }}>
              <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--color-muted)', display: 'block', marginBottom: '6px' }}>
                Click to Insert a Test Scenario into the Message Composer:
              </span>
              <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                <button
                  type="button"
                  className="btn btn-secondary"
                  style={{ fontSize: '0.8rem', padding: '4px 10px' }}
                  onClick={() => setSandboxPrompt('Here is our OpenAI API key for testing: sk-proj-99887766554433221100aabbccddeeffgghhiijjkkllmmnnoopp')}
                >
                  🛑 Insert OpenAI API Key (Block)
                </button>
                <button
                  type="button"
                  className="btn btn-secondary"
                  style={{ fontSize: '0.8rem', padding: '4px 10px' }}
                  onClick={() => setSandboxPrompt('Connecting to postgres://admin:SuperSecret2026!@prod-db.internal:5432/main')}
                >
                  🛑 Insert Database Password (Block)
                </button>
                <button
                  type="button"
                  className="btn btn-secondary"
                  style={{ fontSize: '0.8rem', padding: '4px 10px' }}
                  onClick={() => setSandboxPrompt('CONFIDENTIAL PII: Monthly Compensation Sheet for Executive Team')}
                >
                  🛑 Insert Restricted Asset (Block)
                </button>
                <button
                  type="button"
                  className="btn btn-secondary"
                  style={{ fontSize: '0.8rem', padding: '4px 10px' }}
                  onClick={() => setSandboxPrompt('Please summarize our public technical documentation for the upcoming release.')}
                >
                  ✅ Insert Benign Message (Allowed)
                </button>
              </div>
            </div>

            {/* Simulated Chat Interface */}
            <div
              className="card"
              style={{
                background: sandboxStyle === 'chatgpt' ? '#202123' : '#1f1e1c',
                border: '1px solid #334155',
                borderRadius: '12px',
                padding: '20px',
                maxWidth: '750px',
              }}
            >
              <div style={{ borderBottom: '1px solid #334155', paddingBottom: '12px', marginBottom: '16px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span style={{ fontSize: '1.2rem' }}>{sandboxStyle === 'chatgpt' ? '🤖' : '🎭'}</span>
                  <strong>{sandboxStyle === 'chatgpt' ? 'ChatGPT (Simulated Web App)' : 'Claude (Simulated Web App)'}</strong>
                </div>
                <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>
                  AURA Guard Content Script Bound
                </span>
              </div>

              {/* Chat Messages Log */}
              <div style={{ minHeight: '160px', maxHeight: '250px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '10px', marginBottom: '16px' }}>
                {sandboxMessages.map((m, idx) => (
                  <div
                    key={idx}
                    style={{
                      alignSelf: m.sender === 'user' ? 'flex-end' : 'flex-start',
                      background: m.sender === 'user' ? '#2563eb' : '#334155',
                      color: '#ffffff',
                      padding: '8px 14px',
                      borderRadius: '8px',
                      maxWidth: '80%',
                      fontSize: '0.85rem',
                    }}
                  >
                    {m.text}
                  </div>
                ))}
              </div>

              {/* Message Composer & Controls */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {sandboxStyle === 'chatgpt' ? (
                  // ChatGPT layout uses #prompt-textarea
                  <textarea
                    id="prompt-textarea"
                    className="input"
                    rows={3}
                    style={{ width: '100%', resize: 'none', background: '#2a2b32', color: '#fff' }}
                    placeholder="Message ChatGPT… (Type secret or press Send)"
                    value={sandboxPrompt}
                    onChange={(e) => setSandboxPrompt(e.target.value)}
                  />
                ) : (
                  // Claude layout uses contenteditable
                  <div
                    contentEditable
                    role="textbox"
                    className="input ProseMirror"
                    style={{ minHeight: '60px', background: '#282724', color: '#fff', outline: 'none' }}
                    data-placeholder="Reply to Claude…"
                    onInput={(e) => setSandboxPrompt(e.currentTarget.innerText)}
                    dangerouslySetInnerHTML={{ __html: sandboxPrompt }}
                  />
                )}

                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <label style={{ fontSize: '0.75rem', color: '#94a3b8', cursor: 'pointer' }}>
                      📎 Upload Test File:
                      <input
                        type="file"
                        accept=".txt,.csv,.json,.env"
                        style={{ display: 'inline-block', marginLeft: '6px', fontSize: '0.75rem' }}
                      />
                    </label>
                  </div>

                  <button
                    type="button"
                    className="btn btn-primary send-button"
                    data-testid="send-button"
                    aria-label="Send Message"
                    onClick={handleSandboxSend}
                  >
                    Send ➔
                  </button>
                </div>
              </div>
            </div>
          </Section>
        </div>
      )}
    </div>
  );
}
