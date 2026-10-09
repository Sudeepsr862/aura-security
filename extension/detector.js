// ─── AURA Browser AI Guard: Content Detector & Interceptor ──────────────────
// Runs inside the web page context of supported AI tools.
// Combines generic input detection with site-specific adapters for ChatGPT, Claude, and local models.

(function () {
  'use strict';

  const hostname = window.location.hostname.toLowerCase();
  const port = window.location.port;
  const hostWithPort = port ? `${hostname}:${port}` : hostname;

  // Identify matching AI service
  let serviceName = 'Configured AI Tool';
  let adapterType = 'generic';

  if (hostname.includes('chatgpt.com') || hostname.includes('openai.com')) {
    serviceName = 'OpenAI ChatGPT';
    adapterType = 'chatgpt';
  } else if (hostname.includes('claude.ai')) {
    serviceName = 'Anthropic Claude';
    adapterType = 'claude';
  } else if (hostname.includes('gemini.google.com') || hostname.includes('aistudio.google.com')) {
    serviceName = 'Google AI';
    adapterType = 'generic';
  } else if (hostname.includes('copilot.microsoft.com')) {
    serviceName = 'Microsoft Copilot';
    adapterType = 'generic';
  } else if (port === '11434') {
    serviceName = 'Ollama Local Model';
    adapterType = 'local_webui';
  } else if (port === '1234') {
    serviceName = 'LM Studio Local Server';
    adapterType = 'local_webui';
  } else if (port === '8000') {
    serviceName = 'vLLM Local Server';
    adapterType = 'local_webui';
  } else if (port === '7860') {
    serviceName = 'Text Generation WebUI';
    adapterType = 'local_webui';
  } else if (port === '5174') {
    serviceName = 'AURA AI Test Sandbox';
    adapterType = 'generic';
  }

  // Notify extension of active protection heartbeat
  try {
    if (chrome && chrome.runtime && chrome.runtime.sendMessage) {
      chrome.runtime.sendMessage({
        type: 'HEARTBEAT',
        domain: hostWithPort,
        serviceName,
        status: 'protected',
      });
    }
  } catch (_) {}

  /**
   * Helper: extract text from any composer element.
   */
  function extractComposerText(elem) {
    if (!elem) return '';
    if (elem instanceof HTMLTextAreaElement || elem instanceof HTMLInputElement) {
      return elem.value || '';
    }
    if (elem.isContentEditable) {
      return elem.innerText || elem.textContent || '';
    }
    return '';
  }

  /**
   * Helper: find the current composer on the page.
   */
  function findMessageComposer() {
    // 1. Site-specific adapters
    if (adapterType === 'chatgpt') {
      const gpt = document.querySelector('#prompt-textarea');
      if (gpt) return gpt;
    }
    if (adapterType === 'claude') {
      const claude = document.querySelector('div[contenteditable="true"].ProseMirror') ||
                     document.querySelector('div[contenteditable="true"]');
      if (claude) return claude;
    }

    // 2. Generic detector for AI chat inputs
    const selectors = [
      'textarea[placeholder*="message" i]',
      'textarea[placeholder*="ask" i]',
      'textarea[placeholder*="prompt" i]',
      'textarea[placeholder*="chat" i]',
      'div[contenteditable="true"][data-placeholder]',
      'div[contenteditable="true"][role="textbox"]',
      'div[contenteditable="true"]',
      'textarea',
    ];

    for (const sel of selectors) {
      const el = document.querySelector(sel);
      if (el && el.offsetParent !== null) return el;
    }

    return null;
  }

  /**
   * Dispatches event metadata to background worker and AURA dashboard.
   * STRICT PRIVACY: NEVER sends raw text or secret values.
   */
  function recordInterceptionEvent(result, eventType, fileName, employeeId = 'EMP_020') {
    try {
      if (chrome && chrome.runtime && chrome.runtime.sendMessage) {
        chrome.runtime.sendMessage({
          type: 'RECORD_EVENT',
          data: {
            employee_id: employeeId,
            ai_service: serviceName,
            domain: hostWithPort,
            event_type: eventType || 'message_send',
            file_name: fileName || null,
            detected_category: result.category,
            matched_rule: result.matchedRule,
            action_taken: result.action,
            risk_level: result.riskLevel,
          },
        });
      }
    } catch (err) {
      console.warn('[AURA Guard] Background dispatcher error:', err);
    }
  }

  /**
   * Inspects message content and stops transfer if sensitive data is detected.
   * Returns true if transfer is blocked, false if clean.
   */
  function evaluateAndIntercept(text, event) {
    if (!window.AuraRules || !window.AuraOverlay) return false;

    const result = window.AuraRules.inspectContent(text, serviceName, hostWithPort);

    if (result.isTriggered && (result.action === 'blocked' || result.action === 'warned')) {
      if (event) {
        event.preventDefault();
        event.stopPropagation();
        event.stopImmediatePropagation();
      }

      // Record metadata only in AURA backend
      recordInterceptionEvent(result, 'message_send');

      // Show in-page warning modal
      window.AuraOverlay.show(
        result,
        /* onCancel */ () => {
          console.log('[AURA Guard] Employee cancelled send.');
        },
        /* onRequestReview */ (userJustification) => {
          console.log('[AURA Guard] Review requested:', userJustification);
          try {
            chrome.runtime.sendMessage({
              type: 'REQUEST_EXCEPTION',
              data: {
                ai_service: serviceName,
                domain: hostWithPort,
                category: result.category,
                matchedRule: result.matchedRule,
                justification: userJustification,
              },
            });
          } catch (_) {}
        }
      );

      return true; // Blocked
    }

    return false; // Allowed
  }

  // ── Intercept Keyboard Submissions (Enter without Shift) ────────────────────
  document.addEventListener(
    'keydown',
    function (e) {
      if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) {
        const composer = findMessageComposer();
        if (composer && (composer === e.target || composer.contains(e.target))) {
          const text = extractComposerText(composer);
          if (text.trim().length > 0) {
            evaluateAndIntercept(text, e);
          }
        }
      }
    },
    true // Capture phase to intercept before site handler
  );

  // ── Intercept Click Submissions on Send Buttons ─────────────────────────────
  document.addEventListener(
    'click',
    function (e) {
      const target = e.target;
      if (!target) return;

      // Look for send button ancestors
      const btn = target.closest('button, [role="button"]');
      if (!btn) return;

      const isSendButton =
        btn.getAttribute('data-testid')?.includes('send') ||
        btn.getAttribute('aria-label')?.toLowerCase().includes('send') ||
        btn.classList.contains('send-button') ||
        btn.querySelector('svg') !== null && btn.closest('form');

      if (isSendButton) {
        const composer = findMessageComposer();
        if (composer) {
          const text = extractComposerText(composer);
          if (text.trim().length > 0) {
            evaluateAndIntercept(text, e);
          }
        }
      }
    },
    true // Capture phase
  );

  // ── Intercept File Uploads ──────────────────────────────────────────────────
  document.addEventListener(
    'change',
    function (e) {
      const input = e.target;
      if (!(input instanceof HTMLInputElement) || input.type !== 'file' || !input.files || input.files.length === 0) {
        return;
      }

      for (let i = 0; i < input.files.length; i++) {
        const file = input.files[i];
        const fname = file.name.toLowerCase();

        // Inspect readable text formats (TXT, CSV, JSON, ENV, PY, JS)
        if (
          fname.endsWith('.txt') ||
          fname.endsWith('.csv') ||
          fname.endsWith('.json') ||
          fname.endsWith('.env') ||
          fname.endsWith('.py') ||
          fname.endsWith('.js')
        ) {
          const reader = new FileReader();
          reader.onload = function () {
            const content = String(reader.result || '');
            if (window.AuraRules && window.AuraOverlay) {
              const result = window.AuraRules.inspectContent(content, serviceName, hostWithPort);
              if (result.isTriggered && (result.action === 'blocked' || result.action === 'warned')) {
                // Clear the file input to abort upload
                input.value = '';

                recordInterceptionEvent(result, 'file_upload', file.name);

                window.AuraOverlay.show(result, () => {
                  console.log('[AURA Guard] Upload cancelled.');
                });
              }
            }
          };
          reader.readAsText(file.slice(0, 500000)); // Read first 500KB locally
        }
      }
    },
    true
  );

  console.log(`[AURA Guard] Active protection initialized on ${serviceName} (${hostWithPort})`);
})();
