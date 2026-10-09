import { SignalHalo } from './SignalHalo';
import type { NavPage } from '../types';
import { useAuth } from '../context/AuthContext';
import type { DemoUser } from '../api/client';

interface NavItem {
  id: NavPage;
  label: string;
  icon: string;
  description: string;
}

const NAV_ITEMS: NavItem[] = [
  { id: 'overview',        label: 'Overview',         icon: '◎', description: 'Summary and recent activity' },
  { id: 'ai-inventory',    label: 'AI Inventory',     icon: '🗂', description: 'Service inventory' },
  { id: 'prompt-lab',      label: 'Prompt Lab',       icon: '🔬', description: 'Synthetic prompt check' },
  { id: 'extension-guard', label: 'Browser AI Guard', icon: '🧩', description: 'Chrome extension & live events' },
  { id: 'data-guard',      label: 'Data Guard',       icon: '🛡️', description: 'File transfer & sharing rules' },
  { id: 'data-risk',       label: 'Data & Risk',      icon: '🏷', description: 'Sensitivity and risk signals' },
  { id: 'incidents',       label: 'Incidents',        icon: '🔔', description: 'Sample incident queue' },
  { id: 'governance',      label: 'Governance',       icon: '🏛️', description: 'Architecture and team info' },
];

interface SidebarProps {
  current: NavPage;
  onNavigate: (page: NavPage) => void;
  isOpen: boolean;
  onClose: () => void;
}

export function Sidebar({ current, onNavigate, isOpen, onClose }: SidebarProps) {
  const { user, role, switchRole, isLoading } = useAuth();

  function handleNav(page: NavPage) {
    onNavigate(page);
    onClose();
  }

  const roleEmoji: Record<DemoUser['role'], string> = {
    administrator: '👑',
    analyst: '🔍',
    viewer: '👁️',
  };

  return (
    <>
      {/* Mobile overlay */}
      <div
        className={`sidebar-overlay ${isOpen ? 'open' : ''}`}
        onClick={onClose}
        aria-hidden="true"
      />

      <nav
        className={`sidebar ${isOpen ? 'open' : ''}`}
        aria-label="Main navigation"
        id="main-sidebar"
      >
        {/* Brand */}
        <div className="sidebar-brand">
          <div className="brand-mark" aria-hidden="true">
            <SignalHalo size={36} className="brand-halo" />
            <div className="brand-text">
              <span className="brand-wordmark">AURA</span>
              <span className="brand-subtitle">AI Usage Risk &amp; Assurance</span>
            </div>
          </div>
          <div className="status-badge-active" role="status" aria-label="Active protection mode">
            <span className="status-badge-dot" aria-hidden="true" />
            ACTIVE PROTECTION
          </div>
        </div>

        {/* Navigation links */}
        <div className="sidebar-nav">
          <p className="nav-section-label" id="nav-section-label">Navigation</p>
          <ul
            role="list"
            aria-labelledby="nav-section-label"
            style={{ listStyle: 'none' }}
          >
            {NAV_ITEMS.map((item) => {
              const isActive = current === item.id;
              return (
                <li key={item.id} role="listitem">
                  <button
                    className={`nav-item ${isActive ? 'active' : ''}`}
                    onClick={() => handleNav(item.id)}
                    aria-current={isActive ? 'page' : undefined}
                    title={item.description}
                  >
                    <span className="nav-icon" aria-hidden="true">{item.icon}</span>
                    {item.label}
                  </button>
                </li>
              );
            })}
          </ul>
        </div>

        {/* Footer: user role switcher */}
        <div className="sidebar-footer">
          <div className="demo-user" aria-label="Active role profile">
            <div className="demo-avatar" aria-hidden="true">
              {roleEmoji[role] || '👤'}
            </div>
            <div className="demo-user-text" style={{ width: '100%' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <span className="demo-user-name" style={{ fontSize: '0.85rem' }}>
                  {user?.displayName ?? 'Security Officer'}
                </span>
                <span style={{ fontSize: '0.7rem', color: '#94a3b8', textTransform: 'capitalize' }}>
                  ({role})
                </span>
              </div>
              <div style={{ marginTop: '6px' }}>
                <label htmlFor="role-select" className="visually-hidden">
                  Switch Active Role
                </label>
                <select
                  id="role-select"
                  value={role}
                  disabled={isLoading}
                  onChange={(e) => switchRole(e.target.value as DemoUser['role'])}
                  style={{
                    width: '100%',
                    padding: '4px 6px',
                    borderRadius: '4px',
                    background: 'var(--color-surface, #1e293b)',
                    color: 'var(--color-text, #f8fafc)',
                    border: '1px solid var(--color-border, #334155)',
                    fontSize: '0.75rem',
                    cursor: 'pointer',
                  }}
                >
                  <option value="administrator">👑 Administrator (Full access)</option>
                  <option value="analyst">🔍 Security Analyst (Incidents & Review)</option>
                  <option value="viewer">👁️ Compliance Auditor (Read-only)</option>
                </select>
              </div>
            </div>
          </div>
        </div>
      </nav>
    </>
  );
}
