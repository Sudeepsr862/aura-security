// ─── AURA Browser AI Guard: Options Controller ──────────────────────────────
const AURA_API_BASE = 'http://127.0.0.1:3001/api/extension';

const DEFAULT_SITES = [
  { service_key: 'openai_chatgpt', name: 'OpenAI ChatGPT', domain: 'chatgpt.com', category: 'cloud', adapter: 'chatgpt', status: 'protected' },
  { service_key: 'anthropic_claude', name: 'Anthropic Claude', domain: 'claude.ai', category: 'cloud', adapter: 'claude', status: 'protected' },
  { service_key: 'google_gemini', name: 'Google Gemini', domain: 'gemini.google.com', category: 'cloud', adapter: 'generic', status: 'protected' },
  { service_key: 'microsoft_copilot', name: 'Microsoft Copilot', domain: 'copilot.microsoft.com', category: 'cloud', adapter: 'generic', status: 'protected' },
  { service_key: 'cohere_coral', name: 'Cohere Coral', domain: 'coral.cohere.com', category: 'cloud', adapter: 'generic', status: 'protected' },
  { service_key: 'groq_chat', name: 'Groq Cloud Console', domain: 'groq.com', category: 'cloud', adapter: 'generic', status: 'protected' },
  { service_key: 'mistral_lechat', name: 'Mistral Le Chat', domain: 'chat.mistral.ai', category: 'cloud', adapter: 'generic', status: 'protected' },
  { service_key: 'deepseek_chat', name: 'DeepSeek Chat', domain: 'chat.deepseek.com', category: 'cloud', adapter: 'generic', status: 'protected' },
  { service_key: 'huggingface_chat', name: 'Hugging Face Chat', domain: 'huggingface.co', category: 'cloud', adapter: 'generic', status: 'protected' },
  { service_key: 'ollama_local', name: 'Ollama Web API', domain: 'localhost:11434', category: 'local', adapter: 'local_webui', status: 'protected' },
  { service_key: 'lm_studio_local', name: 'LM Studio Local Server', domain: 'localhost:1234', category: 'local', adapter: 'local_webui', status: 'protected' },
  { service_key: 'vllm_local', name: 'vLLM Local OpenAI Server', domain: 'localhost:8000', category: 'local', adapter: 'local_webui', status: 'protected' },
  { service_key: 'textgen_webui', name: 'Text Generation WebUI', domain: 'localhost:7860', category: 'local', adapter: 'local_webui', status: 'protected' },
  { service_key: 'localai', name: 'LocalAI Server', domain: 'localhost:8080', category: 'local', adapter: 'local_webui', status: 'protected' },
  { service_key: 'aura_demo_sandbox', name: 'AURA AI Test Sandbox', domain: 'localhost:5174', category: 'custom', adapter: 'generic', status: 'protected' },
];

let catalog = [];

async function loadSites() {
  // Try loading from server first
  try {
    const res = await fetch(`${AURA_API_BASE}/sites`);
    if (res.ok) {
      const data = await res.json();
      if (Array.isArray(data.sites) && data.sites.length > 0) {
        catalog = data.sites;
        chrome.storage.local.set({ aura_sites: catalog });
        renderTable();
        return;
      }
    }
  } catch (_) {}

  // Fallback to storage or defaults
  chrome.storage.local.get(['aura_sites'], (res) => {
    catalog = res.aura_sites && res.aura_sites.length > 0 ? res.aura_sites : DEFAULT_SITES;
    renderTable();
  });
}

function renderTable() {
  const tbody = document.getElementById('catalog-tbody');
  const countEl = document.getElementById('site-count');
  countEl.textContent = catalog.length;
  tbody.innerHTML = '';

  catalog.forEach((site, index) => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><strong>${site.name}</strong></td>
      <td><code>${site.domain}</code></td>
      <td><span class="badge badge-${site.category}">${site.category.toUpperCase()}</span></td>
      <td><span style="font-size: 11px; color: #94a3b8;">${site.adapter}</span></td>
      <td><span class="badge badge-protected">${site.status || 'protected'}</span></td>
      <td>
        <button type="button" class="btn btn-danger" data-idx="${index}">Remove</button>
      </td>
    `;
    tbody.appendChild(tr);
  });

  // Attach delete handlers
  tbody.querySelectorAll('.btn-danger').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      const idx = parseInt(e.target.dataset.idx, 10);
      const site = catalog[idx];
      catalog.splice(idx, 1);
      chrome.storage.local.set({ aura_sites: catalog });
      renderTable();

      // Notify server if online
      if (site && site.id) {
        fetch(`${AURA_API_BASE}/sites/${site.id}`, { method: 'DELETE' }).catch(() => {});
      }
    });
  });
}

document.getElementById('add-site-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const name = document.getElementById('site-name').value.trim();
  const rawDomain = document.getElementById('site-domain').value.trim();
  const category = document.getElementById('site-category').value;
  const adapter = document.getElementById('site-adapter').value;

  const domain = rawDomain.toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  const newSite = {
    service_key: domain.replace(/[^a-z0-9]/g, '_'),
    name,
    domain,
    category,
    adapter,
    status: 'protected',
    is_enabled: 1,
  };

  catalog.push(newSite);
  chrome.storage.local.set({ aura_sites: catalog });
  renderTable();

  // Try saving to server
  try {
    await fetch(`${AURA_API_BASE}/sites`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, domain, category, adapter }),
    });
  } catch (_) {}

  // Request optional host permission dynamically
  if (chrome.permissions && chrome.permissions.request) {
    chrome.permissions.request({ origins: [`https://${domain}/*`, `http://${domain}/*`] }, (granted) => {
      console.log('Permission for domain', domain, granted ? 'granted' : 'skipped/denied');
    });
  }

  e.target.reset();
});

document.getElementById('btn-sync-server').addEventListener('click', () => {
  loadSites();
});

// Test Bench Helpers
window.setTestInput = function (text) {
  document.getElementById('test-input').value = text;
};

document.getElementById('btn-run-test').addEventListener('click', () => {
  const input = document.getElementById('test-input').value;
  const badge = document.getElementById('test-result-badge');
  const box = document.getElementById('test-result-box');

  if (!input.trim()) return;

  const result = window.AuraRules.inspectContent(input, 'Test Bench Sandbox', 'localhost');

  badge.innerHTML = `<span class="badge ${result.action === 'blocked' ? 'badge-danger' : result.action === 'warned' ? 'badge-custom' : 'badge-protected'}" style="font-size: 13px; padding: 4px 10px;">
    Action: ${result.action.toUpperCase()} (${result.riskLevel})
  </span>`;

  box.style.display = 'block';
  box.innerHTML = `
    <div style="font-weight: 600; color: ${result.action === 'blocked' ? '#fca5a5' : result.action === 'warned' ? '#fcd34d' : '#86efac'}; margin-bottom: 4px;">
      ${result.action === 'blocked' ? '🛑 Transfer Stopped by Policy' : result.action === 'warned' ? '⚠️ Warning Issued' : '✅ Allowed'}
    </div>
    <div style="font-size: 13px; margin-bottom: 6px;">${result.explanation}</div>
    <div style="font-size: 12px; color: #94a3b8;">
      Matched Rule: <strong style="color: #f1f5f9;">${result.matchedRule}</strong> | Category: <strong style="color: #f1f5f9;">${result.category}</strong>
    </div>
    <div style="font-size: 11px; color: #6ee7b7; margin-top: 6px;">
      🔒 Tested strictly in-memory. Zero secrets or raw texts persisted or transmitted.
    </div>
  `;
});

// Initialize on page load
loadSites();
