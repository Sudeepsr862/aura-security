// ─── AURA Browser AI Guard: Popup Script ─────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  const statusBadge = document.getElementById('popup-status-badge');
  const siteNameEl = document.getElementById('popup-site-name');
  const siteDomainEl = document.getElementById('popup-site-domain');
  const btnDashboard = document.getElementById('btn-open-dashboard');
  const btnOptions = document.getElementById('btn-open-options');
  const btnSandbox = document.getElementById('btn-open-sandbox');

  // Query current active tab
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (!tabs || tabs.length === 0 || !tabs[0].url) {
      siteNameEl.textContent = 'Browser Tab';
      siteDomainEl.textContent = 'No active URL';
      return;
    }

    try {
      const url = new URL(tabs[0].url);
      const host = url.port ? `${url.hostname}:${url.port}` : url.hostname;
      siteDomainEl.textContent = host;

      // Ask background worker for site status
      chrome.runtime.sendMessage({ type: 'GET_STATUS', domain: host }, (response) => {
        if (response && response.status === 'protected') {
          statusBadge.textContent = 'Protected';
          statusBadge.className = 'badge-status status-active';
          siteNameEl.textContent = response.serviceName || 'Configured AI Tool';
        } else {
          // Check common AI domains
          if (host.includes('chatgpt') || host.includes('claude') || host.includes('openai') || host.includes('copilot') || host.includes('5174')) {
            statusBadge.textContent = 'Protected';
            statusBadge.className = 'badge-status status-active';
            siteNameEl.textContent = host.includes('chatgpt') ? 'OpenAI ChatGPT' :
                                     host.includes('claude') ? 'Anthropic Claude' :
                                     host.includes('copilot') ? 'Microsoft Copilot' : 'AURA Sandbox';
          } else {
            statusBadge.textContent = 'Inactive';
            statusBadge.className = 'badge-status status-inactive';
            siteNameEl.textContent = 'Standard Web Page (Unmonitored)';
          }
        }
      });
    } catch (_) {
      siteNameEl.textContent = 'Special Page';
      siteDomainEl.textContent = tabs[0].url.substring(0, 30);
    }
  });

  btnDashboard.addEventListener('click', () => {
    chrome.tabs.create({ url: 'http://localhost:5174/' });
  });

  btnOptions.addEventListener('click', () => {
    chrome.runtime.openOptionsPage();
  });

  btnSandbox.addEventListener('click', () => {
    chrome.tabs.create({ url: 'http://localhost:5174/demo-ai-chat' });
  });
});
