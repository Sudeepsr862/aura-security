// ─── AI Inventory Page (Phase 3: Metadata Ingestion & AI Discovery) ────────────
import { useState, useEffect, useId } from 'react';
import { api, type InventoryItem, type DatasetEvaluationReport, type CsvImportResponse } from '../api/client';
import { useAuth } from '../context/AuthContext';
import {
  ApprovalPill,
  PageHeader,
  Section,
  ClassificationBadge,
  SourceBadge,
  PrivacyScopeNotice,
} from '../components/ui';

export function AIInventory() {
  const { role } = useAuth();
  const searchInputId = useId();
  const classificationSelectId = useId();
  const approvalSelectId = useId();
  const sourceSelectId = useId();

  // Inventory & evaluation state
  const [inventory, setInventory] = useState<InventoryItem[]>([]);
  const [evalReport, setEvalReport] = useState<DatasetEvaluationReport | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Ingestion state
  const [csvText, setCsvText] = useState('');
  const [isImporting, setIsImporting] = useState(false);
  const [importResult, setImportResult] = useState<CsvImportResponse | null>(null);
  const [importError, setImportError] = useState<string | null>(null);
  const [showSkippedRows, setShowSkippedRows] = useState(false);
  const [showMetricDefinitions, setShowMetricDefinitions] = useState(false);
  const [isClearing, setIsClearing] = useState(false);

  // Search & Filter state
  const [searchTerm, setSearchTerm] = useState('');
  const [filterClassification, setFilterClassification] = useState('All');
  const [filterApproval, setFilterApproval] = useState('All');
  const [filterSource, setFilterSource] = useState('All');

  // Load inventory and evaluation metrics
  async function loadData() {
    setIsLoading(true);
    setError(null);
    try {
      const [invRes, evalRes] = await Promise.all([
        api.inventory(),
        api.evaluation(),
      ]);
      setInventory(invRes.inventory);
      setEvalReport(evalRes.report);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to load inventory data');
    } finally {
      setIsLoading(false);
    }
  }

  useEffect(() => {
    loadData();
  }, []);

  // Quick load sample CSV from backend
  async function handleLoadSampleCsv() {
    setImportError(null);
    try {
      const res = await api.sampleCsv();
      setCsvText(res.content);
    } catch (err: unknown) {
      setImportError(err instanceof Error ? err.message : 'Could not load sample CSV.');
    }
  }

  // Handle CSV file upload from disk
  function handleFileUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;

    if (file.size > 2 * 1024 * 1024) {
      setImportError('File exceeds 2 MB limit.');
      return;
    }

    const reader = new FileReader();
    reader.onload = (event) => {
      const text = event.target?.result as string;
      setCsvText(text || '');
      setImportError(null);
    };
    reader.onerror = () => {
      setImportError('Failed to read file from disk.');
    };
    reader.readAsText(file);
  }

  // Submit CSV metadata for ingestion
  async function handleImportSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!csvText.trim()) {
      setImportError('Please paste or upload CSV metadata.');
      return;
    }

    setIsImporting(true);
    setImportError(null);
    setImportResult(null);

    try {
      const res = await api.importCsv(csvText);
      setImportResult(res);
      await loadData();
    } catch (err: unknown) {
      setImportError(err instanceof Error ? err.message : 'Failed to import CSV metadata.');
    } finally {
      setIsImporting(false);
    }
  }

  // Clear imported CSV events
  async function handleClearCsv() {
    setIsClearing(true);
    setImportError(null);
    try {
      await api.clearCsv();
      setImportResult(null);
      await loadData();
    } catch (err: unknown) {
      setImportError(err instanceof Error ? err.message : 'Failed to clear CSV records.');
    } finally {
      setIsClearing(false);
    }
  }

  // Filter items
  const filteredInventory = inventory.filter((item) => {
    const matchesSearch =
      searchTerm === '' ||
      item.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      item.provider.toLowerCase().includes(searchTerm.toLowerCase()) ||
      item.endpoint.toLowerCase().includes(searchTerm.toLowerCase());

    const matchesClassification =
      filterClassification === 'All' || item.classification === filterClassification;

    const matchesApproval =
      filterApproval === 'All' || item.approval_status === filterApproval;

    const matchesSource =
      filterSource === 'All' ||
      (filterSource === 'CSV import' && item.source_types.includes('csv_import')) ||
      (filterSource === 'Simulation' && item.source_types.includes('simulation'));

    return matchesSearch && matchesClassification && matchesApproval && matchesSource;
  });

  const canImport = role === 'administrator' || role === 'analyst';

  return (
    <>
      <PageHeader
        title="AI Inventory & Discovery"
        subtitle="Discover cloud AI services, identify possible local runtimes, and analyze supplied network metadata."
      />

      <main className="page-body">
        {/* Section 6: Privacy and Scope Notice */}
        <PrivacyScopeNotice />

        {/* Section 2: Safe CSV Metadata Ingestion */}
        <Section title="Metadata Ingestion & CSV Import">
          <div className="card card-body" style={{ marginBottom: '1.5rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.75rem', marginBottom: '1rem' }}>
              <div>
                <h3 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--color-text)' }}>
                  Network Metadata CSV Ingest
                </h3>
                <p className="text-xs text-muted" style={{ marginTop: '2px' }}>
                  Supplied metadata only. Strictly ignores and discards unapproved payload columns (prompts, request bodies, tokens).
                </p>
              </div>

              {/* Role Indicator */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className="text-xs text-muted">Active Role:</span>
                <span
                  style={{
                    padding: '2px 8px',
                    borderRadius: '4px',
                    fontSize: '0.75rem',
                    fontWeight: 600,
                    background: canImport ? 'rgba(52, 211, 153, 0.15)' : 'rgba(239, 68, 68, 0.15)',
                    color: canImport ? '#34d399' : '#f87171',
                    border: `1px solid ${canImport ? 'rgba(52, 211, 153, 0.3)' : 'rgba(239, 68, 68, 0.3)'}`,
                  }}
                >
                  {role === 'administrator' ? '👑 Administrator' : role === 'analyst' ? '🔍 Analyst' : '👁️ Viewer (Read-only)'}
                </span>
              </div>
            </div>

            {!canImport && (
              <div
                style={{
                  padding: '10px 14px',
                  borderRadius: '6px',
                  background: 'rgba(239, 68, 68, 0.1)',
                  border: '1px solid rgba(239, 68, 68, 0.25)',
                  color: '#fca5a5',
                  fontSize: '0.8rem',
                  marginBottom: '1rem',
                }}
              >
                🔒 <strong>Import Restricted:</strong> Your active demo role is <strong>Viewer</strong>. To import CSV metadata, switch your role to <strong>Administrator</strong> or <strong>Analyst</strong> using the sidebar selector.
              </div>
            )}

            {/* Quick action buttons */}
            <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', marginBottom: '1rem' }}>
              <button
                type="button"
                className="btn btn-secondary text-xs"
                onClick={handleLoadSampleCsv}
                disabled={!canImport || isImporting}
              >
                📋 Load Sample CSV Dataset (18 rows)
              </button>
              <label
                className={`btn btn-secondary text-xs ${!canImport ? 'opacity-50 cursor-not-allowed' : ''}`}
                style={{ cursor: canImport ? 'pointer' : 'not-allowed', margin: 0 }}
              >
                📁 Choose .csv File
                <input
                  type="file"
                  accept=".csv"
                  onChange={handleFileUpload}
                  disabled={!canImport || isImporting}
                  style={{ display: 'none' }}
                />
              </label>
              <button
                type="button"
                className="btn btn-secondary text-xs"
                onClick={handleClearCsv}
                disabled={!canImport || isClearing}
                style={{ marginLeft: 'auto', color: '#f87171' }}
              >
                {isClearing ? 'Clearing…' : '🗑️ Reset CSV Imports'}
              </button>
            </div>

            {/* CSV Form */}
            <form onSubmit={handleImportSubmit}>
              <div style={{ marginBottom: '1rem' }}>
                <label
                  htmlFor="csv-textarea"
                  className="text-xs font-medium text-muted"
                  style={{ display: 'block', marginBottom: '4px' }}
                >
                  CSV Metadata Content (max 2 MB / 500 rows):
                </label>
                <textarea
                  id="csv-textarea"
                  value={csvText}
                  onChange={(e) => setCsvText(e.target.value)}
                  placeholder="timestamp,src_ip,device,user_email,domain_sni,dst_ip,dst_port,bytes_out,data_classification,authorization,anomaly,label,expected_provider..."
                  rows={5}
                  disabled={!canImport || isImporting}
                  style={{
                    width: '100%',
                    fontFamily: 'monospace',
                    fontSize: '0.75rem',
                    padding: '8px',
                    borderRadius: '6px',
                    background: 'var(--color-bg, #0f172a)',
                    color: 'var(--color-text, #f8fafc)',
                    border: '1px solid var(--color-border, #334155)',
                    resize: 'vertical',
                  }}
                />
              </div>

              {importError && (
                <div
                  style={{
                    padding: '8px 12px',
                    borderRadius: '6px',
                    background: 'rgba(239, 68, 68, 0.15)',
                    border: '1px solid rgba(239, 68, 68, 0.3)',
                    color: '#f87171',
                    fontSize: '0.8rem',
                    marginBottom: '1rem',
                  }}
                >
                  ⚠️ {importError}
                </div>
              )}

              {/* Import Results Banner */}
              {importResult && (
                <div
                  style={{
                    padding: '12px',
                    borderRadius: '6px',
                    background: 'rgba(52, 211, 153, 0.1)',
                    border: '1px solid rgba(52, 211, 153, 0.25)',
                    fontSize: '0.8rem',
                    marginBottom: '1rem',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', color: '#34d399', fontWeight: 600 }}>
                    <span>✅ {importResult.message}</span>
                    <span>
                      {importResult.summary.importedCount} imported / {importResult.summary.skippedCount} skipped
                    </span>
                  </div>

                  {/* Ignored columns privacy feedback */}
                  {importResult.summary.ignoredColumns.length > 0 && (
                    <div style={{ marginTop: '8px', color: '#94a3b8', fontSize: '0.75rem' }}>
                      🛡️ <strong>Privacy Protection Active:</strong> Discarded {importResult.summary.ignoredColumns.length} unapproved column(s):{' '}
                      <code>{importResult.summary.ignoredColumns.join(', ')}</code>. Prompt texts and request bodies were not saved or displayed.
                    </div>
                  )}

                  {/* Skipped rows expander */}
                  {importResult.skippedRows.length > 0 && (
                    <div style={{ marginTop: '8px' }}>
                      <button
                        type="button"
                        onClick={() => setShowSkippedRows(!showSkippedRows)}
                        style={{ background: 'none', border: 'none', color: '#fb923c', cursor: 'pointer', fontSize: '0.75rem', padding: 0 }}
                      >
                        {showSkippedRows ? '▼ Hide skipped row diagnostics' : `▶ View ${importResult.skippedRows.length} skipped row diagnostics`}
                      </button>

                      {showSkippedRows && (
                        <div style={{ marginTop: '6px', maxHeight: '140px', overflowY: 'auto' }}>
                          <table style={{ width: '100%', fontSize: '0.72rem', borderCollapse: 'collapse' }}>
                            <thead>
                              <tr style={{ color: '#94a3b8', textAlign: 'left' }}>
                                <th style={{ padding: '2px 4px' }}>Row</th>
                                <th style={{ padding: '2px 4px' }}>Destination Preview</th>
                                <th style={{ padding: '2px 4px' }}>Reason</th>
                              </tr>
                            </thead>
                            <tbody>
                              {importResult.skippedRows.map((sr, idx) => (
                                <tr key={idx} style={{ borderTop: '1px solid rgba(255,255,255,0.05)' }}>
                                  <td style={{ padding: '2px 4px' }}>#{sr.rowNumber}</td>
                                  <td style={{ padding: '2px 4px' }}>{sr.destinationPreview || '—'}</td>
                                  <td style={{ padding: '2px 4px', color: '#f87171' }}>{sr.reason}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}

              <button
                type="submit"
                className="btn btn-primary text-xs"
                disabled={!canImport || isImporting || !csvText.trim()}
              >
                {isImporting ? 'Ingesting & Classifying…' : '🚀 Ingest & Classify Metadata'}
              </button>
            </form>
          </div>
        </Section>

        {/* Section 5: Dataset Evaluation from Labels */}
        {evalReport && (
          <Section title="Detection Metrics & Dataset Evaluation">
            <div className="card card-body" style={{ marginBottom: '1.5rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.75rem', marginBottom: '1rem' }}>
                <div>
                  <h3 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--color-text)' }}>
                    Dataset Performance Evaluation
                  </h3>
                  <p className="text-xs text-muted" style={{ marginTop: '2px' }}>
                    Calculated only from records with explicit ground-truth labels ({evalReport.labeledRows} labeled / {evalReport.totalRows} total records).
                  </p>
                </div>
                <button
                  type="button"
                  className="btn btn-secondary text-xs"
                  onClick={() => setShowMetricDefinitions(!showMetricDefinitions)}
                >
                  ℹ️ {showMetricDefinitions ? 'Hide Metric Definitions' : 'Metric Definitions'}
                </button>
              </div>

              {showMetricDefinitions && (
                <div
                  style={{
                    padding: '10px 14px',
                    borderRadius: '6px',
                    background: 'rgba(30, 41, 59, 0.7)',
                    border: '1px solid rgba(56, 189, 248, 0.2)',
                    fontSize: '0.75rem',
                    lineHeight: 1.5,
                    marginBottom: '1rem',
                  }}
                >
                  <p><strong>Metric Definitions:</strong></p>
                  <ul style={{ paddingLeft: '1.25rem', marginTop: '4px' }}>
                    <li><strong>Precision:</strong> TP / (TP + FP) — Fraction of flagged AI events that are truly AI.</li>
                    <li><strong>Recall:</strong> TP / (TP + FN) — Fraction of actual AI events successfully identified.</li>
                    <li><strong>False Positive Rate (FPR):</strong> FP / (FP + TN) — Fraction of ordinary events incorrectly flagged as AI.</li>
                    <li><strong>Pending labels:</strong> Displayed whenever a denominator is zero or records lack labels, avoiding invented percentages.</li>
                  </ul>
                  <p className="text-muted" style={{ marginTop: '6px' }}>
                    ⚠️ <em>{evalReport.disclaimer}</em>
                  </p>
                </div>
              )}

              {/* Metric Stat Cards */}
              <div className="stat-grid" style={{ marginBottom: '1rem' }}>
                <article className="stat-card accent">
                  <span className="stat-label">Precision</span>
                  <span className="stat-value" style={{ fontSize: '1.5rem' }}>
                    {evalReport.metrics.precision.formatted}
                  </span>
                  <span className="stat-note">
                    {evalReport.metrics.precision.value != null
                      ? `${evalReport.confusionMatrix.truePositives} TP / ${evalReport.metrics.precision.denominator} flagged`
                      : 'Pending labeled negatives/positives'}
                  </span>
                </article>

                <article className="stat-card">
                  <span className="stat-label">Recall (Sensitivity)</span>
                  <span className="stat-value" style={{ fontSize: '1.5rem' }}>
                    {evalReport.metrics.recall.formatted}
                  </span>
                  <span className="stat-note">
                    {evalReport.metrics.recall.value != null
                      ? `${evalReport.confusionMatrix.truePositives} TP / ${evalReport.metrics.recall.denominator} true AI`
                      : 'Pending ground truth'}
                  </span>
                </article>

                <article className="stat-card warning">
                  <span className="stat-label">False Positive Rate</span>
                  <span className="stat-value" style={{ fontSize: '1.5rem' }}>
                    {evalReport.metrics.falsePositiveRate.formatted}
                  </span>
                  <span className="stat-note">
                    {evalReport.metrics.falsePositiveRate.value != null
                      ? `${evalReport.confusionMatrix.falsePositives} FP / ${evalReport.metrics.falsePositiveRate.denominator} non-AI`
                      : 'Pending non-AI labels'}
                  </span>
                </article>

                <article className="stat-card">
                  <span className="stat-label">Provider Match</span>
                  <span className="stat-value" style={{ fontSize: '1.5rem' }}>
                    {evalReport.providerEvaluation.accuracy.formatted}
                  </span>
                  <span className="stat-note">
                    {evalReport.providerEvaluation.totalWithExpected > 0
                      ? `${evalReport.providerEvaluation.matches} of ${evalReport.providerEvaluation.totalWithExpected} expected providers matched`
                      : 'No expected_provider specified'}
                  </span>
                </article>
              </div>

              {/* Confusion Matrix Breakdown */}
              <div
                style={{
                  display: 'flex',
                  gap: '12px',
                  flexWrap: 'wrap',
                  padding: '8px 12px',
                  borderRadius: '6px',
                  background: 'rgba(15, 23, 42, 0.4)',
                  fontSize: '0.75rem',
                  color: 'var(--color-text-muted)',
                }}
              >
                <span><strong>True Positives (TP):</strong> {evalReport.confusionMatrix.truePositives}</span>
                <span>•</span>
                <span><strong>False Positives (FP):</strong> {evalReport.confusionMatrix.falsePositives}</span>
                <span>•</span>
                <span><strong>True Negatives (TN):</strong> {evalReport.confusionMatrix.trueNegatives}</span>
                <span>•</span>
                <span><strong>False Negatives (FN):</strong> {evalReport.confusionMatrix.falseNegatives}</span>
                <span>•</span>
                <span><strong>Unlabeled Rows:</strong> {evalReport.unlabeledRows}</span>
              </div>
            </div>
          </Section>
        )}

        {/* Section 4: AI Service Inventory & Usage Summaries */}
        <Section title="AI Service Inventory & Usage Summaries">
          {/* Controls: Search & Filters */}
          <div
            style={{
              display: 'flex',
              gap: '12px',
              flexWrap: 'wrap',
              marginBottom: '1rem',
              alignItems: 'center',
            }}
          >
            {/* Search */}
            <div style={{ flex: '1 1 200px' }}>
              <label htmlFor={searchInputId} className="visually-hidden">
                Search inventory
              </label>
              <input
                id={searchInputId}
                type="text"
                placeholder="🔍 Search endpoint, provider, or name…"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                style={{
                  width: '100%',
                  padding: '6px 12px',
                  borderRadius: '6px',
                  background: 'var(--color-surface, #1e293b)',
                  color: 'var(--color-text, #f8fafc)',
                  border: '1px solid var(--color-border, #334155)',
                  fontSize: '0.8rem',
                }}
              />
            </div>

            {/* Classification Filter */}
            <div>
              <label htmlFor={classificationSelectId} className="visually-hidden">
                Filter by Classification
              </label>
              <select
                id={classificationSelectId}
                value={filterClassification}
                onChange={(e) => setFilterClassification(e.target.value)}
                style={{
                  padding: '6px 10px',
                  borderRadius: '6px',
                  background: 'var(--color-surface, #1e293b)',
                  color: 'var(--color-text, #f8fafc)',
                  border: '1px solid var(--color-border, #334155)',
                  fontSize: '0.8rem',
                }}
              >
                <option value="All">All Classifications</option>
                <option value="Likely cloud AI">Likely cloud AI</option>
                <option value="Possible local AI">Possible local AI</option>
                <option value="Ordinary web">Ordinary web</option>
                <option value="Uncertain">Uncertain</option>
              </select>
            </div>

            {/* Approval Filter */}
            <div>
              <label htmlFor={approvalSelectId} className="visually-hidden">
                Filter by Approval Status
              </label>
              <select
                id={approvalSelectId}
                value={filterApproval}
                onChange={(e) => setFilterApproval(e.target.value)}
                style={{
                  padding: '6px 10px',
                  borderRadius: '6px',
                  background: 'var(--color-surface, #1e293b)',
                  color: 'var(--color-text, #f8fafc)',
                  border: '1px solid var(--color-border, #334155)',
                  fontSize: '0.8rem',
                }}
              >
                <option value="All">All Approvals</option>
                <option value="Approved">Approved</option>
                <option value="Needs review">Needs review</option>
                <option value="Unapproved">Unapproved</option>
                <option value="Unknown">Unknown</option>
              </select>
            </div>

            {/* Source Filter */}
            <div>
              <label htmlFor={sourceSelectId} className="visually-hidden">
                Filter by Source
              </label>
              <select
                id={sourceSelectId}
                value={filterSource}
                onChange={(e) => setFilterSource(e.target.value)}
                style={{
                  padding: '6px 10px',
                  borderRadius: '6px',
                  background: 'var(--color-surface, #1e293b)',
                  color: 'var(--color-text, #f8fafc)',
                  border: '1px solid var(--color-border, #334155)',
                  fontSize: '0.8rem',
                }}
              >
                <option value="All">All Sources</option>
                <option value="CSV import">CSV import</option>
                <option value="Simulation">Simulation</option>
              </select>
            </div>
          </div>

          {/* Derived estimates disclosure */}
          <p className="text-xs text-muted mb-4">
            ℹ️ Event counts and byte totals are estimates derived from the supplied or simulated records. They do not imply continuous network capture.
          </p>

          {/* Table */}
          {isLoading ? (
            <div className="card card-body text-center" style={{ padding: '2rem' }}>
              <span className="text-muted">Loading AI service inventory…</span>
            </div>
          ) : error ? (
            <div className="card card-body text-center" style={{ padding: '2rem', color: '#f87171' }}>
              <span>⚠️ Error loading inventory: {error}</span>
            </div>
          ) : filteredInventory.length === 0 ? (
            <div className="card card-body text-center" style={{ padding: '2rem' }}>
              <span className="text-muted">No services found matching the active filters.</span>
            </div>
          ) : (
            <div className="table-wrapper">
              <table className="data-table" aria-label="AI Service Inventory">
                <thead>
                  <tr>
                    <th scope="col">Service / Provider</th>
                    <th scope="col">Destination Endpoint</th>
                    <th scope="col">Classification</th>
                    <th scope="col">Approval</th>
                    <th scope="col">First Seen</th>
                    <th scope="col">Estimated Usage</th>
                    <th scope="col">Evidence &amp; Confidence</th>
                    <th scope="col">Source</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredInventory.map((item) => (
                    <tr key={item.id}>
                      {/* Name / Provider */}
                      <td>
                        <div className="font-medium" style={{ color: 'var(--color-text)' }}>
                          {item.name}
                        </div>
                        <div className="text-xs text-muted">
                          {item.provider}
                        </div>
                      </td>

                      {/* Endpoint */}
                      <td className="cell-primary font-mono text-xs">
                        {item.endpoint}
                      </td>

                      {/* Classification */}
                      <td>
                        <ClassificationBadge classification={item.classification} />
                      </td>

                      {/* Approval */}
                      <td>
                        <ApprovalPill status={item.approval_status as any} />
                      </td>

                      {/* First Seen */}
                      <td className="text-xs text-muted font-mono">
                        {item.first_seen.length > 10 ? item.first_seen.slice(0, 10) : item.first_seen}
                      </td>

                      {/* Usage estimates */}
                      <td>
                        <div className="text-xs font-medium" style={{ color: 'var(--color-text)' }}>
                          {item.event_count} event{item.event_count !== 1 ? 's' : ''}
                        </div>
                        <div className="text-xs text-muted">
                          {(item.estimated_bytes / 1024).toFixed(1)} KB (est.)
                        </div>
                      </td>

                      {/* Evidence & Confidence */}
                      <td style={{ maxWidth: '280px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '2px' }}>
                          <span
                            style={{
                              fontSize: '0.7rem',
                              fontWeight: 700,
                              color: item.confidence > 0.8 ? '#34d399' : item.confidence > 0.4 ? '#fb923c' : '#94a3b8',
                            }}
                          >
                            {(item.confidence * 100).toFixed(0)}% conf.
                          </span>
                        </div>
                        <p className="text-xs text-muted" style={{ lineHeight: 1.3, margin: 0 }}>
                          {item.evidence}
                        </p>
                      </td>

                      {/* Source */}
                      <td>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                          {item.source_types.map((st, i) => (
                            <SourceBadge key={i} source={st} />
                          ))}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Section>
      </main>
    </>
  );
}
