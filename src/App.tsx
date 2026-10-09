import { useState } from 'react';
import { AuthProvider } from './context/AuthContext';
import { Sidebar } from './components/Sidebar';
import { Overview }     from './pages/Overview';
import { AIInventory }  from './pages/AIInventory';
import { PromptLab }    from './pages/PromptLab';
import { DataRisk }     from './pages/DataRisk';
import { Incidents }    from './pages/Incidents';
import { Governance }   from './pages/Governance';
import { DataGuard }      from './pages/DataGuard';
import { ExtensionGuard }  from './pages/ExtensionGuard';
import type { NavPage } from './types';

const PAGE_LABELS: Record<NavPage, string> = {
  'overview':        'Overview',
  'ai-inventory':    'AI Inventory',
  'prompt-lab':      'Prompt Lab',
  'data-guard':      'Data Guard',
  'extension-guard': 'Browser AI Guard',
  'demo-ai-chat':    'Test Sandbox',
  'data-risk':       'Data & Risk',
  'incidents':       'Incidents',
  'governance':      'Governance',
};

export function App() {
  const [currentPage, setCurrentPage] = useState<NavPage>('overview');
  const [sidebarOpen, setSidebarOpen] = useState(false);

  function navigate(page: NavPage) {
    setCurrentPage(page);
    // Scroll main content to top on navigation
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  function renderPage() {
    switch (currentPage) {
      case 'overview':        return <Overview onNavigate={navigate} />;
      case 'ai-inventory':    return <AIInventory />;
      case 'prompt-lab':      return <PromptLab />;
      case 'data-guard':      return <DataGuard />;
      case 'extension-guard': return <ExtensionGuard />;
      case 'demo-ai-chat':    return <ExtensionGuard />;
      case 'data-risk':       return <DataRisk />;
      case 'incidents':       return <Incidents />;
      case 'governance':      return <Governance />;
    }
  }

  return (
    <AuthProvider>
      <div className="app-shell">
        {/* Skip-to-content link for keyboard users */}
        <a
          href="#main-content"
          className="visually-hidden"
          style={{ position: 'absolute', top: 4, left: 4, zIndex: 9999, background: 'white', padding: '4px 8px', borderRadius: 4 }}
          onFocus={(e) => (e.currentTarget.style.clip = 'auto')}
          onBlur={(e) => (e.currentTarget.style.clip = 'rect(0,0,0,0)')}
        >
          Skip to main content
        </a>

        <Sidebar
          current={currentPage}
          onNavigate={navigate}
          isOpen={sidebarOpen}
          onClose={() => setSidebarOpen(false)}
        />

        <div className="main-content" id="main-content">
          {/* Mobile top bar */}
          <div className="mobile-top-bar" role="banner">
            <div className="mobile-brand">
              <span aria-hidden="true">◎</span>
              AURA
            </div>
            <button
              className="hamburger-btn"
              onClick={() => setSidebarOpen(true)}
              aria-label="Open navigation menu"
              aria-controls="main-sidebar"
              aria-expanded={sidebarOpen}
            >
              ☰
            </button>
          </div>

          {/* Current page */}
          <div aria-live="polite" className="visually-hidden">
            Now viewing: {PAGE_LABELS[currentPage]}
          </div>

          {renderPage()}
        </div>
      </div>
    </AuthProvider>
  );
}
