// ─── Prompt Lab Page (Phase 4: Local In-Memory Scanner & Redaction) ───────────
import { useState, useEffect } from 'react';
import {
  api,
  type PromptDestination,
  type PromptScanResult,
  type PromptScanHistoryRow,
  type RiskFactor,
  type PromptScanResponse,
} from '../api/client';
import { useAuth } from '../context/AuthContext';
import {
  ApprovalPill,
  PageHeader,
  RiskBadge,
  DataLabelPill,
  RiskScoreBar,
  PrivacyScopeNotice,
} from '../components/ui';
import type { RiskLevel, DataLabel } from '../types';

const SYNTHETIC_EXAMPLES = [
  {
    label: '🟢 Benign Technical Query',
    destinationId: '1', // OpenAI API (Approved)
    text: 'Explain the core differences between PostgreSQL B-tree and GiST indexing algorithms for geospatial queries.',
  },
  {
    label: '🚨 API Key + Unapproved Destination',
    destinationId: 'unknown-dest', // Unapproved
    text: 'Please test this API request using authorization key: sk-proj-demo99887766554433221100aabbccddeeff and Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-ID198234871923847',
  },
  {
    label: '💳 Customer PII & Card (Luhn)',
    destinationId: 'unknown-dest',
    text: 'Customer refund record for Casey Quinn (casey.quinn@demo.aura, phone: (555) 234-5678). Card on file: 4012 8888 8888 1881. Total: $142.50.',
  },
  {
    label: '🔒 Credentials & Private Key',
    destinationId: 'unknown-dest',
    text: 'DB config: db_password="AdminSecurePassword2024!"\nHost: 192.168.1.100\nKey:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0fakeKeyDemoBytesHereForTestingOnly...\n-----END RSA PRIVATE KEY-----',
  },
];

export function PromptLab() {
  const { role } = useAuth();

  // Destination state
  const [destinations, setDestinations] = useState<PromptDestination[]>([]);
  const [selectedDestId, setSelectedDestId] = useState<string>('');
  const [isLoadingDest, setIsLoadingDest] = useState(true);

  // Prompt input state
  const [text, setText] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);

  // Scan result state
  const [result, setResult] = useState<PromptScanResult | null>(null);
  const [riskAssessment, setRiskAssessment] = useState<PromptScanResponse['riskAssessment'] | null>(null);
  const [copiedPreview, setCopiedPreview] = useState(false);

  // Audit history state
  const [history, setHistory] = useState<PromptScanHistoryRow[]>([]);
  const [showHistory, setShowHistory] = useState(false);

  // Load destinations
  useEffect(() => {
    let mounted = true;
    async function loadDestinations() {
      setIsLoadingDest(true);
      try {
        const res = await api.promptDestinations();
        if (mounted && res.destinations.length > 0) {
          setDestinations(res.destinations);
          setSelectedDestId(res.destinations[0].id);
        }
      } catch (err) {
        console.error('Failed to load Prompt Lab destinations:', err);
      } finally {
        if (mounted) setIsLoadingDest(false);
      }
    }

    loadDestinations();
    return () => {
      mounted = false;
    };
  }, []);

  // Load metadata history
  async function loadHistory() {
    try {
      const res = await api.promptHistory();
      setHistory(res.history);
    } catch (err) {
      console.error('Failed to load scan history:', err);
    }
  }

  const selectedDest =
    destinations.find((d) => d.id === selectedDestId) || destinations[0] || {
      name: 'Unknown destination',
      approvalStatus: 'Unknown',
    };

  const canScan = role === 'administrator' || role === 'analyst';

  // Handle Scan submission
  async function handleScanSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!text.trim()) {
      setScanError('Please enter synthetic prompt text to scan.');
      return;
    }

    setIsScanning(true);
    setScanError(null);

    try {
      const res = await api.scanPrompt({
        text,
        destination: selectedDest.name,
        destinationStatus: selectedDest.approvalStatus,
      });

      setResult(res.result);
      setRiskAssessment(res.riskAssessment || null);
      // STRICT PRIVACY REQUIREMENT: Clear the prompt input after successful scan!
      setText('');
      // Refresh metadata history
      loadHistory();
    } catch (err: unknown) {
      setScanError(err instanceof Error ? err.message : 'Prompt scan failed.');
    } finally {
      setIsScanning(false);
    }
  }

  function handleSelectExample(ex: (typeof SYNTHETIC_EXAMPLES)[0]) {
    setText(ex.text);
    if (destinations.some((d) => d.id === ex.destinationId)) {
      setSelectedDestId(ex.destinationId);
    }
    setScanError(null);
  }

  function handleClearAll() {
    setText('');
    setResult(null);
    setRiskAssessment(null);
    setScanError(null);
    setCopiedPreview(false);
  }

  function handleCopyPreview() {
    if (!result) return;
    navigator.clipboard.writeText(result.redactedPreview);
    setCopiedPreview(true);
    setTimeout(() => setCopiedPreview(false), 2000);
  }

  return (
    <>
      <PageHeader
        title="Prompt Lab"
        subtitle="In-memory sensitive data detection and policy recommendation for synthetic prompts. Never transmitted to external AI."
      />

      <main className="page-body">
        {/* Privacy & Scope Notice */}
        <PrivacyScopeNotice />

        <div className="prompt-lab-layout">
          {/* Left Column: Input Form & Result */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
            <div className="card">
              <div className="card-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '8px' }}>
                <span className="card-title">Synthetic Prompt Scanner</span>
                <span
                  style={{
                    fontSize: '0.72rem',
                    padding: '2px 8px',
                    borderRadius: '4px',
                    background: canScan ? 'rgba(52, 211, 153, 0.15)' : 'rgba(239, 68, 68, 0.15)',
                    color: canScan ? '#34d399' : '#f87171',
                    border: `1px solid ${canScan ? 'rgba(52, 211, 153, 0.3)' : 'rgba(239, 68, 68, 0.3)'}`,
                    fontWeight: 600,
                  }}
                >
                  {role === 'administrator' ? '👑 Administrator' : role === 'analyst' ? '🔍 Analyst' : '👁️ Viewer (Read-only)'}
                </span>
              </div>

              <div className="card-body" style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
                {/* Notice beside input */}
                <div
                  style={{
                    padding: '8px 12px',
                    borderRadius: '6px',
                    background: 'rgba(56, 189, 248, 0.1)',
                    border: '1px solid rgba(56, 189, 248, 0.25)',
                    fontSize: '0.8rem',
                    color: '#bae6fd',
                  }}
                >
                  🔒 <strong>Privacy Notice:</strong> Use synthetic examples only. AURA scans only text you enter here in-memory.
                  Raw prompt text is automatically cleared after scanning and is never written to disk or sent to an LLM.
                </div>

                {!canScan && (
                  <div
                    style={{
                      padding: '10px 14px',
                      borderRadius: '6px',
                      background: 'rgba(239, 68, 68, 0.1)',
                      border: '1px solid rgba(239, 68, 68, 0.25)',
                      color: '#fca5a5',
                      fontSize: '0.8rem',
                    }}
                  >
                    🔒 <strong>Scan Restricted:</strong> Your demo role is <strong>Viewer</strong>. Viewers cannot run prompt scans.
                    Switch your role to <strong>Administrator</strong> or <strong>Analyst</strong> in the sidebar to run scans.
                  </div>
                )}

                {/* Synthetic example shortcuts */}
                <div>
                  <span className="text-xs font-semibold text-muted" style={{ display: 'block', marginBottom: '6px' }}>
                    Load Safe Synthetic Examples:
                  </span>
                  <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                    {SYNTHETIC_EXAMPLES.map((ex, idx) => (
                      <button
                        key={idx}
                        type="button"
                        className="btn btn-secondary text-xs"
                        onClick={() => handleSelectExample(ex)}
                        disabled={!canScan || isScanning}
                      >
                        {ex.label}
                      </button>
                    ))}
                  </div>
                </div>

                {/* Scan Form */}
                <form onSubmit={handleScanSubmit}>
                  {/* Destination Selector */}
                  <div style={{ marginBottom: '1rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '4px' }}>
                      <label htmlFor="prompt-dest-select" className="section-label" style={{ margin: 0 }}>
                        Target Destination:
                      </label>
                      {selectedDest && (
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                          <span className="text-xs text-muted">Approval Status:</span>
                          <ApprovalPill status={selectedDest.approvalStatus as any} />
                        </div>
                      )}
                    </div>
                    <select
                      id="prompt-dest-select"
                      className="prompt-selector"
                      value={selectedDestId}
                      onChange={(e) => setSelectedDestId(e.target.value)}
                      disabled={!canScan || isScanning || isLoadingDest}
                      style={{ width: '100%' }}
                    >
                      {destinations.map((d) => (
                        <option key={d.id} value={d.id}>
                          {d.name} — [{d.approvalStatus}]
                        </option>
                      ))}
                    </select>
                  </div>

                  {/* Textarea */}
                  <div style={{ marginBottom: '1rem' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                      <label htmlFor="prompt-input" className="section-label" style={{ margin: 0 }}>
                        Synthetic Prompt Text:
                      </label>
                      <span className="text-xs text-muted font-mono">
                        {text.length.toLocaleString()} / 10,000 chars
                      </span>
                    </div>
                    <textarea
                      id="prompt-input"
                      className="prompt-textarea"
                      placeholder="Enter synthetic text to analyze (e.g. paste API key, credentials, or PII example)..."
                      value={text}
                      onChange={(e) => setText(e.target.value)}
                      disabled={!canScan || isScanning}
                      rows={6}
                      spellCheck={false}
                      autoComplete="off"
                      maxLength={10000}
                    />
                  </div>

                  {scanError && (
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
                      ⚠️ {scanError}
                    </div>
                  )}

                  {/* Buttons */}
                  <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                    <button
                      type="submit"
                      className="btn btn-primary"
                      disabled={!canScan || isScanning || !text.trim()}
                    >
                      {isScanning ? '🔬 Scanning in Memory…' : '🔬 Scan Prompt for Secrets'}
                    </button>
                    {(text || result) && (
                      <button
                        type="button"
                        className="btn btn-secondary text-xs"
                        onClick={handleClearAll}
                        disabled={isScanning}
                      >
                        Reset / Clear
                      </button>
                    )}
                  </div>
                </form>
              </div>
            </div>

            {/* Scan Results Card */}
            {result && (
              <div className="card" style={{ border: '1px solid var(--color-border)' }}>
                <div
                  className="card-header"
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    flexWrap: 'wrap',
                    gap: '8px',
                    borderBottom: '1px solid var(--color-border)',
                  }}
                >
                  <span className="card-title">Scan Results &amp; Policy Recommendation</span>
                  <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                    <span className="text-xs text-muted">Sensitivity:</span>
                    <DataLabelPill label={result.sensitivitySuggestion as DataLabel} />
                  </div>
                </div>

                <div className="card-body" style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
                  {/* Policy Recommendation Banner */}
                  <div
                    style={{
                      padding: '12px 16px',
                      borderRadius: '8px',
                      background:
                        result.policyOutcome === 'would_block'
                          ? 'rgba(239, 68, 68, 0.12)'
                          : result.policyOutcome === 'warn'
                          ? 'rgba(251, 146, 60, 0.12)'
                          : 'rgba(52, 211, 153, 0.12)',
                      border: `1px solid ${
                        result.policyOutcome === 'would_block'
                          ? 'rgba(239, 68, 68, 0.3)'
                          : result.policyOutcome === 'warn'
                          ? 'rgba(251, 146, 60, 0.3)'
                          : 'rgba(52, 211, 153, 0.3)'
                      }`,
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                      <span style={{ fontSize: '1.1rem' }}>
                        {result.policyOutcome === 'would_block' ? '🚫' : result.policyOutcome === 'warn' ? '⚠️' : 'ℹ️'}
                      </span>
                      <strong
                        style={{
                          fontSize: '0.95rem',
                          color:
                            result.policyOutcome === 'would_block'
                              ? '#f87171'
                              : result.policyOutcome === 'warn'
                              ? '#fb923c'
                              : '#34d399',
                        }}
                      >
                        {result.policyRecommendation}
                      </strong>
                    </div>
                    <p className="text-xs text-muted" style={{ margin: 0, lineHeight: 1.4 }}>
                      {result.policyExplanation}
                    </p>
                  </div>

                  {/* Categories Detected */}
                  <div>
                    <h4 style={{ fontSize: '0.85rem', fontWeight: 600, marginBottom: '6px', color: 'var(--color-text)' }}>
                      Detected Categories ({result.totalMatches} pattern match{result.totalMatches !== 1 ? 'es' : ''}):
                    </h4>
                    {result.matches.length === 0 ? (
                      <p className="text-xs text-muted">
                        No configured secrets, PII, or confidential business terms were detected.
                      </p>
                    ) : (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                        {result.matches.map((m, idx) => (
                          <div
                            key={idx}
                            style={{
                              display: 'flex',
                              alignItems: 'center',
                              justifyContent: 'space-between',
                              padding: '6px 10px',
                              borderRadius: '4px',
                              background: 'rgba(15, 23, 42, 0.4)',
                              border: '1px solid rgba(255, 255, 255, 0.05)',
                            }}
                          >
                            <div>
                              <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--color-text)' }}>
                                {m.category}
                              </span>
                              <span className="text-xs text-muted" style={{ marginLeft: '8px' }}>
                                ({m.count} occurrence{m.count !== 1 ? 's' : ''})
                              </span>
                              <p className="text-xs text-muted" style={{ margin: 0, marginTop: '2px' }}>
                                {m.explanation}
                              </p>
                            </div>
                            <RiskBadge level={m.riskLevel as RiskLevel} />
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* Redacted Preview */}
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
                      <h4 style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--color-text)', margin: 0 }}>
                        Redacted Preview (Session-only):
                      </h4>
                      <button
                        type="button"
                        className="btn btn-secondary text-xs"
                        onClick={handleCopyPreview}
                        style={{ padding: '2px 8px' }}
                      >
                        {copiedPreview ? '✓ Copied' : '📋 Copy Preview'}
                      </button>
                    </div>
                    <pre
                      style={{
                        padding: '10px 12px',
                        borderRadius: '6px',
                        background: 'var(--color-bg, #0f172a)',
                        color: 'var(--color-text, #f8fafc)',
                        border: '1px solid var(--color-border, #334155)',
                        fontSize: '0.78rem',
                        fontFamily: 'monospace',
                        whiteSpace: 'pre-wrap',
                        wordBreak: 'break-word',
                        margin: 0,
                        maxHeight: '200px',
                        overflowY: 'auto',
                      }}
                    >
                      {result.redactedPreview || '(Empty preview)'}
                    </pre>
                  </div>

                  {/* Explainable Risk Engine Correlation */}
                  {riskAssessment && (
                    <div
                      className="card"
                      style={{
                        padding: '12px 14px',
                        background: 'rgba(15, 23, 42, 0.5)',
                        border: '1px solid var(--color-border)',
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                        <div>
                          <span className="text-xs text-muted">Correlated Risk Engine Score:</span>
                          <div style={{ display: 'flex', alignItems: 'baseline', gap: '8px' }}>
                            <strong
                              style={{
                                fontSize: '1.1rem',
                                color:
                                  riskAssessment.severity === 'critical'
                                    ? '#ef4444'
                                    : riskAssessment.severity === 'high'
                                    ? '#f97316'
                                    : riskAssessment.severity === 'medium'
                                    ? '#f59e0b'
                                    : '#10b981',
                              }}
                            >
                              {riskAssessment.score} / 100
                            </strong>
                            <span className="text-xs font-semibold" style={{ textTransform: 'uppercase' }}>
                              ({riskAssessment.severity} risk)
                            </span>
                          </div>
                        </div>
                        <span className="badge text-xs" style={{ background: 'var(--color-surface-3)' }}>
                          {riskAssessment.confidence} Confidence
                        </span>
                      </div>

                      <RiskScoreBar score={riskAssessment.score} />

                      {/* Contributing Factors */}
                      <div className="mt-3">
                        <span className="text-xs font-semibold" style={{ color: 'var(--color-text-2)' }}>
                          Contributing Policy Factors:
                        </span>
                        <ul className="mt-1" style={{ listStyle: 'none', paddingLeft: 0, display: 'flex', flexDirection: 'column', gap: '4px' }}>
                          {riskAssessment.factors.map((f: RiskFactor) => (
                            <li key={f.id} className="text-xs" style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--color-text-2)' }}>
                              <span>· {f.name}: <em className="text-muted">{f.evidence}</em></span>
                              <strong style={{ marginLeft: 8, whiteSpace: 'nowrap' }}>+{f.points} pts</strong>
                            </li>
                          ))}
                        </ul>
                      </div>

                      <p className="text-xs text-muted mt-2" style={{ borderTop: '1px solid rgba(255, 255, 255, 0.05)', paddingTop: '6px', margin: 0 }}>
                        ℹ️ <em>Privacy guarantee:</em> Scored in-memory from detected category metadata and destination approval only. Raw prompt text is never passed to scoring logs or persistent storage.
                      </p>
                    </div>
                  )}

                  {/* Limitations Note */}
                  <div className="text-xs text-muted" style={{ borderTop: '1px solid var(--color-border-subtle)', paddingTop: '8px' }}>
                    ℹ️ <strong>Rule Engine Limitations:</strong> {result.confidenceNote}
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Right Column: Context, Prototype Boundaries & Audit Proof */}
          <aside aria-label="Prompt Lab information">
            <div className="card">
              <div className="card-header">
                <span className="card-title">About Prompt Lab</span>
              </div>
              <div className="card-body" style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
                <p className="text-sm" style={{ color: 'var(--color-text-2)', lineHeight: 1.6 }}>
                  The Prompt Lab processes text in memory on AURA's local server.
                  It detects credentials, PII, and sensitive business markers before prompts reach external AI destinations.
                </p>

                <div>
                  <p className="section-label">Supported Pattern Rules</p>
                  <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: '6px', padding: 0 }}>
                    {[
                      '🔑 API keys (OpenAI, GitHub, AWS, Bearer)',
                      '🔐 Password assignments (pwd=..., db_pass=...)',
                      '📜 Private keys (RSA/EC/DSA PEM headers)',
                      '💳 Payment cards (Luhn checksum validated)',
                      '📧 Email addresses & phone numbers',
                      '🌐 Internal IPv4 addresses (RFC 1918)',
                      '🏷️ Confidential & restricted business terms',
                      '🛡️ Heuristic prompt injection phrases',
                    ].map((item, i) => (
                      <li key={i} className="text-xs text-muted">
                        {item}
                      </li>
                    ))}
                  </ul>
                </div>

                <div style={{ borderTop: '1px solid var(--color-border-subtle)', paddingTop: 'var(--space-4)' }}>
                  <p className="section-label">Privacy Guarantees</p>
                  <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: '6px', padding: 0 }}>
                    {[
                      '✅ In-memory analysis only',
                      '✅ Raw prompt cleared after scan',
                      '✅ No prompts sent to external LLMs',
                      '✅ No raw prompts stored in database',
                      '✅ No content hashes stored',
                      '🚫 No clipboard or background app monitoring',
                    ].map((item, i) => (
                      <li key={i} className="text-xs" style={{ color: 'var(--color-text-2)' }}>
                        {item}
                      </li>
                    ))}
                  </ul>
                </div>

                {/* Audit verification button */}
                <div style={{ borderTop: '1px solid var(--color-border-subtle)', paddingTop: 'var(--space-4)' }}>
                  <button
                    type="button"
                    className="btn btn-secondary text-xs"
                    onClick={() => {
                      if (!showHistory) loadHistory();
                      setShowHistory(!showHistory);
                    }}
                    style={{ width: '100%' }}
                  >
                    {showHistory ? '▲ Hide Database Audit Proof' : '🔎 Verify Database Stored Metadata'}
                  </button>

                  {showHistory && (
                    <div style={{ marginTop: '8px', maxHeight: '160px', overflowY: 'auto' }}>
                      <p className="text-xs text-muted" style={{ marginBottom: '4px' }}>
                        Proof of privacy: Notice that only destination, category names, and character counts are persisted.
                      </p>
                      {history.length === 0 ? (
                        <p className="text-xs text-muted">No scan records in database yet.</p>
                      ) : (
                        <table style={{ width: '100%', fontSize: '0.7rem', borderCollapse: 'collapse' }}>
                          <thead>
                            <tr style={{ color: '#94a3b8', textAlign: 'left' }}>
                              <th>ID</th>
                              <th>Actor</th>
                              <th>Outcome</th>
                              <th>Chars</th>
                            </tr>
                          </thead>
                          <tbody>
                            {history.map((h) => (
                              <tr key={h.id} style={{ borderTop: '1px solid rgba(255,255,255,0.05)' }}>
                                <td>#{h.id}</td>
                                <td>{h.actor}</td>
                                <td style={{ color: h.policy_outcome === 'would_block' ? '#f87171' : '#34d399' }}>
                                  {h.policy_outcome}
                                </td>
                                <td>{h.char_count}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      )}
                    </div>
                  )}
                </div>
              </div>
            </div>
          </aside>
        </div>
      </main>
    </>
  );
}
