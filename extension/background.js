// ─── AURA Browser AI Guard: Background Service Worker ───────────────────────
// Handles storage, heartbeat tracking, and telemetry dispatch to AURA dashboard.

const AURA_API_BASE = 'http://127.0.0.1:3001/api/extension';

// In-memory cache of domain protection status
const domainStatusCache = new Map();

/**
 * Sync active sites from AURA server into extension storage.
 */
async function syncCatalogWithServer() {
  try {
    const res = await fetch(`${AURA_API_BASE}/sites`, {
      headers: { 'Accept': 'application/json' },
    });
    if (res.ok) {
      const data = await res.json();
      if (Array.isArray(data.sites)) {
        await chrome.storage.local.set({ aura_sites: data.sites });
        console.log('[AURA Background] Synced', data.sites.length, 'sites from AURA API.');
      }
    }
  } catch (err) {
    console.log('[AURA Background] Note: AURA API server unreachable or offline:', err.message);
  }
}

// Initial sync on extension install/start
chrome.runtime.onInstalled.addListener(() => {
  console.log('[AURA Background] AURA AI Browser Guard installed.');
  syncCatalogWithServer();
});

// Message dispatcher
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'HEARTBEAT') {
    const { domain, serviceName, status } = message;
    domainStatusCache.set(domain, {
      serviceName,
      status: status || 'protected',
      lastActive: new Date().toISOString(),
    });

    // Notify server of active heartbeat
    fetch(`${AURA_API_BASE}/sites`, { method: 'GET' }).catch(() => {});
    sendResponse({ success: true });
    return true;
  }

  if (message.type === 'RECORD_EVENT') {
    const eventData = message.data;
    console.log('[AURA Background] Interception recorded:', eventData);

    // Persist locally in extension storage history
    chrome.storage.local.get(['aura_local_events'], (res) => {
      const list = res.aura_local_events || [];
      list.unshift({
        ...eventData,
        id: Date.now(),
        timestamp: new Date().toISOString(),
      });
      chrome.storage.local.set({ aura_local_events: list.slice(0, 50) });
    });

    // Forward to AURA Dashboard API
    fetch(`${AURA_API_BASE}/events`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(eventData),
    })
      .then((res) => res.json())
      .then((data) => {
        sendResponse({ success: true, serverResponse: data });
      })
      .catch((err) => {
        console.warn('[AURA Background] Could not forward event to AURA server:', err.message);
        sendResponse({ success: true, offline: true });
      });

    return true; // Keep message channel open for async response
  }

  if (message.type === 'GET_STATUS') {
    const domain = message.domain;
    const cached = domainStatusCache.get(domain) || {
      serviceName: 'Configured AI Tool',
      status: 'protected',
      lastActive: new Date().toISOString(),
    };
    sendResponse(cached);
    return true;
  }
});
