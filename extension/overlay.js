// ─── AURA Browser AI Guard: In-Page Overlay Manager ─────────────────────────
// Renders the modal dialog when a sensitive message or file transfer is stopped.

(function (global) {
  'use strict';

  function createOverlay(result, onCancel, onRequestReview) {
    // Remove any existing overlay
    const existing = document.getElementById('aura-modal-overlay');
    if (existing) existing.remove();

    const overlay = document.createElement('div');
    overlay.id = 'aura-modal-overlay';
    overlay.setAttribute('role', 'dialog');
    overlay.setAttribute('aria-modal', 'true');
    overlay.setAttribute('aria-labelledby', 'aura-title');

    const isBlock = result.action === 'blocked';
    const badgeClass = result.riskLevel === 'critical' ? 'aura-badge-critical' :
                       result.riskLevel === 'high' ? 'aura-badge-high' : 'aura-badge-medium';

    overlay.innerHTML = `
      <div id="aura-modal-card">
        <div class="aura-header">
          <div class="aura-header-title">
            <span style="font-size: 18px;">🛡️</span>
            <span id="aura-title">AURA Pre-Transfer Guard</span>
          </div>
          <span class="aura-header-badge ${badgeClass}">${result.action.toUpperCase()}</span>
        </div>

        <div class="aura-body">
          <div class="aura-site-banner">
            <span>Target AI Service: <strong class="aura-site-name">${result.serviceName}</strong></span>
            <span>Host: <code>${result.domain}</code></span>
          </div>

          <div class="aura-warning-box ${isBlock ? '' : 'aura-warn'}">
            <div class="aura-warning-headline">
              <span>${isBlock ? '🛑' : '⚠️'}</span>
              <span>${isBlock ? 'Transfer Stopped by Policy' : 'Policy Warning Issued'}</span>
            </div>
            <p class="aura-warning-desc">${result.explanation}</p>
          </div>

          <div>
            <div style="font-size: 11px; font-weight: 600; text-transform: uppercase; color: #94a3b8; margin-bottom: 5px;">
              Matched Policy Rule & Category:
            </div>
            <div style="display: flex; gap: 6px; flex-wrap: wrap;">
              <span class="aura-rule-pill">📋 ${result.matchedRule}</span>
              <span class="aura-rule-pill">🏷️ ${result.category}</span>
            </div>
          </div>

          <div class="aura-privacy-guarantee">
            <span style="font-size: 14px;">🔒</span>
            <span><strong>Privacy Guarantee:</strong> Secret values and prompt text are analyzed in-memory and discarded. Zero secrets or raw texts are transmitted to the dashboard.</span>
          </div>

          <div id="aura-exception-container" style="display: none;" class="aura-exception-form">
            <label for="aura-exception-input" style="font-size: 12px; color: #cbd5e1; font-weight: 500;">
              Business Justification for Policy Exception:
            </label>
            <textarea
              id="aura-exception-input"
              class="aura-exception-input"
              rows="3"
              placeholder="e.g. Necessary for approved enterprise internal testing."
            ></textarea>
          </div>
        </div>

        <div class="aura-footer">
          <button type="button" id="aura-btn-cancel" class="aura-btn aura-btn-secondary">
            ✕ Cancel Send
          </button>
          <button type="button" id="aura-btn-exception" class="aura-btn aura-btn-primary">
            Request Review / Exception
          </button>
        </div>
      </div>
    `;

    document.body.appendChild(overlay);

    const cancelBtn = overlay.querySelector('#aura-btn-cancel');
    const exceptionBtn = overlay.querySelector('#aura-btn-exception');
    const exceptionContainer = overlay.querySelector('#aura-exception-container');
    const exceptionInput = overlay.querySelector('#aura-exception-input');

    // Cancel action
    cancelBtn.addEventListener('click', () => {
      overlay.remove();
      if (typeof onCancel === 'function') onCancel();
    });

    // Exception / review action
    let exceptionMode = false;
    exceptionBtn.addEventListener('click', () => {
      if (!exceptionMode) {
        exceptionMode = true;
        exceptionContainer.style.display = 'flex';
        exceptionBtn.textContent = 'Submit Exception Request';
        exceptionBtn.className = 'aura-btn aura-btn-danger';
        exceptionInput.focus();
      } else {
        const note = exceptionInput.value.trim() || 'Employee requested policy review for business necessity.';
        overlay.remove();
        if (typeof onRequestReview === 'function') onRequestReview(note);
      }
    });

    // Close on Escape key
    const onKeyDown = (e) => {
      if (e.key === 'Escape') {
        overlay.remove();
        document.removeEventListener('keydown', onKeyDown);
        if (typeof onCancel === 'function') onCancel();
      }
    };
    document.addEventListener('keydown', onKeyDown);
  }

  global.AuraOverlay = {
    show: createOverlay,
  };
})(typeof window !== 'undefined' ? window : globalThis);
