// ─── Shared UI helpers ──────────────────────────────────────────────────────
import type { RiskLevel, DataLabel, ApprovalStatus, IntegrationState } from '../types';

// ── Risk badge ────────────────────────────────────────────────────────────────
interface RiskBadgeProps {
  level: RiskLevel;
}

const RISK_LABELS: Record<RiskLevel, string> = {
  low:      'Low',
  medium:   'Medium',
  high:     'High',
  critical: 'Critical',
};

export function RiskBadge({ level }: RiskBadgeProps) {
  return (
    <span
      className={`badge badge-${level}`}
      aria-label={`Risk level: ${RISK_LABELS[level]}`}
    >
      {RISK_LABELS[level]}
    </span>
  );
}

// ── Data label pill ───────────────────────────────────────────────────────────
interface DataLabelPillProps {
  label: DataLabel;
}

export function DataLabelPill({ label }: DataLabelPillProps) {
  const cls = `label-pill label-${label.toLowerCase()}`;
  return <span className={cls}>{label}</span>;
}

// ── Approval status pill ──────────────────────────────────────────────────────
interface ApprovalPillProps {
  status: ApprovalStatus;
}

const APPROVAL_CLS: Record<ApprovalStatus, string> = {
  'Approved':       'approval-approved',
  'Needs review':   'approval-needs-review',
  'Unapproved':     'approval-unapproved',
  'Unknown':        'approval-unknown',
};

export function ApprovalPill({ status }: ApprovalPillProps) {
  return <span className={APPROVAL_CLS[status]}>{status}</span>;
}

// ── Integration state badge ───────────────────────────────────────────────────
interface StateBadgeProps {
  state: IntegrationState;
}

const STATE_CLS: Record<IntegrationState, string> = {
  'Simulated':     'state-badge state-simulated',
  'Not connected': 'state-badge state-not-connected',
  'Planned':       'state-badge state-planned',
};

export function StateBadge({ state }: StateBadgeProps) {
  return <span className={STATE_CLS[state]}>{state}</span>;
}

// ── Security notice banner ────────────────────────────────────────────────────
export interface SecurityNoticeProps {
  message: string;
  type?: 'info' | 'shield' | 'alert';
}

export function SecurityNotice({ message, type = 'shield' }: SecurityNoticeProps) {
  const icon = type === 'shield' ? '🛡️' : type === 'info' ? 'ℹ️' : '⚠️';
  return (
    <div className="security-notice" role="status" aria-label="Security status notice">
      <span className="security-notice-icon" aria-hidden="true">{icon}</span>
      <p className="security-notice-text">{message}</p>
    </div>
  );
}

export const DemoNotice = SecurityNotice;

// ── Risk score bar ────────────────────────────────────────────────────────────
interface RiskScoreBarProps {
  score: number; // 0–100
}

export function RiskScoreBar({ score }: RiskScoreBarProps) {
  const cls =
    score >= 70 ? 'risk-score-fill high' :
    score >= 40 ? 'risk-score-fill medium' :
    'risk-score-fill';

  return (
    <div
      className="risk-score-bar"
      role="meter"
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={score}
      aria-label={`Sample risk score: ${score} out of 100`}
    >
      <div className={cls} style={{ width: `${score}%` }} />
    </div>
  );
}

// ── Page header ───────────────────────────────────────────────────────────────
interface PageHeaderProps {
  title: string;
  subtitle: string;
  children?: React.ReactNode;
}

export function PageHeader({ title, subtitle, children }: PageHeaderProps) {
  return (
    <header className="page-header">
      <div className="page-header-left">
        <h1 className="page-title">{title}</h1>
        <p className="page-subtitle">{subtitle}</p>
      </div>
      {children && <div>{children}</div>}
    </header>
  );
}

// ── Section wrapper ───────────────────────────────────────────────────────────
interface SectionProps {
  title?: string;
  description?: string;
  children: React.ReactNode;
}

export function Section({ title, description, children }: SectionProps) {
  return (
    <section className="section">
      {title && <h2 className="section-title">{title}</h2>}
      {description && <p style={{ color: 'var(--color-muted)', fontSize: '0.88rem', marginTop: '-4px', marginBottom: '16px' }}>{description}</p>}
      {children}
    </section>
  );
}

// ── Workflow diagram ──────────────────────────────────────────────────────────
const WORKFLOW_STEPS = [
  { num: '1', label: 'Prompt Security' },
  { num: '2', label: 'AI-Service Discovery' },
  { num: '3', label: 'Data Sensitivity & DLP' },
  { num: '4', label: 'Device & Employee Auth' },
  { num: '5', label: 'Risk Scoring' },
  { num: '6', label: 'Alerts & Governance' },
];

export function WorkflowDiagram() {
  return (
    <div className="card">
      <div className="card-header">
        <span className="card-title">AURA Six-Stage Architecture</span>
        <span className="text-xs text-muted">Prototype — stages shown for illustration</span>
      </div>
      <nav
        className="workflow-diagram"
        aria-label="AURA six-stage workflow"
      >
        {WORKFLOW_STEPS.map((step) => (
          <div key={step.num} className="workflow-step">
            <div className="workflow-circle" aria-hidden="true">{step.num}</div>
            <span className="workflow-step-label">{step.label}</span>
          </div>
        ))}
      </nav>
    </div>
  );
}

// ── Classification badge ──────────────────────────────────────────────────────
interface ClassificationBadgeProps {
  classification: string;
}

export function ClassificationBadge({ classification }: ClassificationBadgeProps) {
  let icon = '❓';
  let style: React.CSSProperties = {
    background: 'rgba(148, 163, 184, 0.15)',
    color: '#94a3b8',
    borderColor: 'rgba(148, 163, 184, 0.3)',
  };

  if (classification === 'Likely cloud AI') {
    icon = '☁️';
    style = {
      background: 'rgba(56, 189, 248, 0.15)',
      color: '#38bdf8',
      borderColor: 'rgba(56, 189, 248, 0.3)',
    };
  } else if (classification === 'Possible local AI') {
    icon = '💻';
    style = {
      background: 'rgba(251, 146, 60, 0.15)',
      color: '#fb923c',
      borderColor: 'rgba(251, 146, 60, 0.3)',
    };
  } else if (classification === 'Ordinary web') {
    icon = '🌐';
    style = {
      background: 'rgba(52, 211, 153, 0.15)',
      color: '#34d399',
      borderColor: 'rgba(52, 211, 153, 0.3)',
    };
  }

  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '4px',
        padding: '2px 8px',
        borderRadius: '9999px',
        fontSize: '0.75rem',
        fontWeight: 600,
        border: '1px solid',
        ...style,
      }}
    >
      <span aria-hidden="true">{icon}</span>
      {classification}
    </span>
  );
}

// ── Source badge (CSV import vs built-in simulation) ───────────────────────────
interface SourceBadgeProps {
  source: string;
}

export function SourceBadge({ source }: SourceBadgeProps) {
  const isCsv = source === 'csv_import' || source.toLowerCase().includes('csv');
  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '4px',
        padding: '2px 8px',
        borderRadius: '4px',
        fontSize: '0.72rem',
        fontWeight: 600,
        background: isCsv ? 'rgba(168, 85, 247, 0.15)' : 'rgba(14, 165, 233, 0.15)',
        color: isCsv ? '#c084fc' : '#38bdf8',
        border: `1px solid ${isCsv ? 'rgba(168, 85, 247, 0.3)' : 'rgba(14, 165, 233, 0.3)'}`,
      }}
    >
      <span aria-hidden="true">{isCsv ? '📥' : '🧪'}</span>
      {isCsv ? 'CSV import' : 'Simulation'}
    </span>
  );
}

// ── Privacy & Scope Notice (Section 6 Requirement) ───────────────────────────
export function PrivacyScopeNotice() {
  return (
    <div
      role="note"
      aria-label="Privacy and Scope Notice"
      style={{
        display: 'flex',
        alignItems: 'flex-start',
        gap: '12px',
        padding: '12px 16px',
        borderRadius: '8px',
        background: 'rgba(15, 23, 42, 0.65)',
        border: '1px solid rgba(56, 189, 248, 0.25)',
        marginBottom: '1rem',
      }}
    >
      <span style={{ fontSize: '1.25rem', lineHeight: 1 }} aria-hidden="true">
        🛡️
      </span>
      <div style={{ fontSize: '0.825rem', lineHeight: 1.5, color: 'var(--color-text-muted, #94a3b8)' }}>
        <strong style={{ color: 'var(--color-text, #f8fafc)' }}>Privacy &amp; Scope Boundary: </strong>
        AURA analyzes supplied or simulated metadata only. It does not connect to devices, scan a network, capture
        packets, decrypt HTTPS, or inspect prompt contents in imported traffic.
      </div>
    </div>
  );
}
