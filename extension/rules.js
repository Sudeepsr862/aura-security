// ─── AURA Browser AI Guard: Local Rule Engine ────────────────────────────────
// In-memory detection module running inside browser content scripts.
//
// STRICT PRIVACY GUARANTEES:
// - Evaluates text in-memory. Discards scanned text immediately.
// - NEVER returns or leaks the raw secret or sensitive text.
// - Returns only classification category, matched policy rule, and risk level.

(function (global) {
  'use strict';

  /**
   * Luhn checksum algorithm for ISO/IEC 7812 payment card numbers.
   */
  function passesLuhn(numStr) {
    const digits = numStr.replace(/\D/g, '');
    if (digits.length < 13 || digits.length > 19) return false;
    let sum = 0;
    let alternate = false;
    for (let i = digits.length - 1; i >= 0; i--) {
      let d = parseInt(digits[i], 10);
      if (alternate) {
        d *= 2;
        if (d > 9) d -= 9;
      }
      sum += d;
      alternate = !alternate;
    }
    return sum % 10 === 0;
  }

  /**
   * Rule definitions with pattern checks and policy actions.
   */
  const DETECTION_RULES = [
    // 1. Private Cryptographic Keys
    {
      id: 'rule_private_keys',
      category: 'Private Cryptographic Keys',
      riskLevel: 'critical',
      action: 'blocked',
      ruleName: 'Prohibit Cryptographic Private Keys',
      explanation: 'Unencrypted PEM/SSH private key block detected. Never send private keys to external or local AI tools.',
      test: (text) => /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/i.test(text),
    },

    // 2. OpenAI and Personal Access API Tokens
    {
      id: 'rule_api_keys',
      category: 'API Keys & Access Tokens',
      riskLevel: 'critical',
      action: 'blocked',
      ruleName: 'Prohibit API Keys & Service Tokens',
      explanation: 'Production API key or token signature detected (e.g. OpenAI sk-, GitHub token, or AWS key).',
      test: (text) => {
        if (/\b(?:sk-(?:proj-)?[A-Za-z0-9_\-]{20,})\b/.test(text)) return true;
        if (/\b(?:gh[pousr]_[A-Za-z0-9_]{36,}|github_pat_[A-Za-z0-9_]{30,})\b/.test(text)) return true;
        if (/\b(?:AKIA[0-9A-Z]{16})\b/.test(text)) return true;
        if (/\bBearer\s+[A-Za-z0-9_\-\.]{25,}\b/i.test(text)) return true;
        if (/\b(?:api[_-]?key|access[_-]?token|secret[_-]?key)\s*[:=]\s*["']?[A-Za-z0-9_\-]{16,}["']?/i.test(text)) return true;
        return false;
      },
    },

    // 3. Database Passwords & Connection Strings
    {
      id: 'rule_credentials',
      category: 'Password / Database Credentials',
      riskLevel: 'critical',
      action: 'blocked',
      ruleName: 'Prohibit Credentials & Database URIs',
      explanation: 'Plaintext database connection string or password assignment detected.',
      test: (text) => {
        if (/postgres(?:ql)?:\/\/[^\s:]+:[^\s@]+@[^\s\/]+/i.test(text)) return true;
        if (/mysql:\/\/[^\s:]+:[^\s@]+@[^\s\/]+/i.test(text)) return true;
        if (/\b(?:password|passwd|db_pass|user_password|db_password)\s*[:=]\s*["']?[^\s"']{8,}["']?/i.test(text)) return true;
        return false;
      },
    },

    // 4. Payment Cards with Luhn validation
    {
      id: 'rule_payment_cards',
      category: 'Payment Card (PCI / Luhn)',
      riskLevel: 'critical',
      action: 'blocked',
      ruleName: 'Prohibit Payment Card Numbers',
      explanation: 'Valid payment card number satisfying ISO/IEC 7812 Luhn checksum detected.',
      test: (text) => {
        const matches = text.match(/\b(?:\d[ -]*?){13,19}\b/g);
        if (!matches) return false;
        return matches.some(m => passesLuhn(m));
      },
    },

    // 5. Confidential Company Assets & Business Records (from dataset c)
    {
      id: 'rule_confidential_assets',
      category: 'Confidential Business Records',
      riskLevel: 'high',
      action: 'blocked',
      ruleName: 'Prohibit Restricted Corporate Assets',
      explanation: 'Identified proprietary corporate document or compensation records matching internal data classification policy.',
      test: (text) => {
        const keywords = [
          'CONFIDENTIAL PII',
          'Monthly Compensation Sheet',
          'M&A Strategy Draft',
          'Merger & Acquisition Plan',
          'Executive Compensation Register',
          'Restricted Customer Database',
          'Enterprise Customer Leads',
          'Quarterly Earnings Embargo',
          'Employee SSN/Aadhaar Register',
        ];
        return keywords.some(k => text.toLowerCase().includes(k.toLowerCase()));
      },
    },

    // 6. Personal Identifiers (PII)
    {
      id: 'rule_pii',
      category: 'Personal Identifiers (PII)',
      riskLevel: 'medium',
      action: 'warned',
      ruleName: 'Warn on Personal Customer Identifiers',
      explanation: 'Multiple personal contact identifiers (emails, phone numbers) detected. Confirm necessity before sharing.',
      test: (text) => {
        const emails = text.match(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g) || [];
        const phones = text.match(/\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g) || [];
        return emails.length >= 2 || (emails.length >= 1 && phones.length >= 1);
      },
    },

    // 7. Dangerous Shell / Destructive Scripting
    {
      id: 'rule_dangerous_scripts',
      category: 'Infrastructure & Shell Command Risk',
      riskLevel: 'high',
      action: 'warned',
      ruleName: 'Review Remote Shell / System Execution Commands',
      explanation: 'Potentially risky remote script piping or destructive execution syntax detected.',
      test: (text) => {
        if (/\b(?:curl|wget)\s+.*\|\s*(?:bash|sh)\b/i.test(text)) return true;
        if (/\bpowershell\s+.*-enc\b/i.test(text)) return true;
        return false;
      },
    },
  ];

  /**
   * Main scan function for extension content script.
   * Returns inspection verdict without leaking secret values.
   */
  function inspectContent(rawText, serviceName, domain) {
    if (!rawText || typeof rawText !== 'string' || rawText.trim().length === 0) {
      return {
        isTriggered: false,
        action: 'allowed',
        category: 'Clean Content',
        matchedRule: 'None',
        riskLevel: 'low',
        explanation: 'No content to analyze.',
      };
    }

    for (const rule of DETECTION_RULES) {
      if (rule.test(rawText)) {
        return {
          isTriggered: true,
          action: rule.action,
          category: rule.category,
          matchedRule: rule.ruleName,
          riskLevel: rule.riskLevel,
          explanation: rule.explanation,
          serviceName: serviceName || 'Configured AI Service',
          domain: domain || window.location.hostname,
        };
      }
    }

    return {
      isTriggered: false,
      action: 'allowed',
      category: 'Clean Content',
      matchedRule: 'Baseline Allowed',
      riskLevel: 'low',
      explanation: 'No configured sensitive patterns detected.',
      serviceName: serviceName || 'Configured AI Service',
      domain: domain || window.location.hostname,
    };
  }

  // Export to global scope
  global.AuraRules = {
    inspectContent,
    passesLuhn,
    DETECTION_RULES,
  };
})(typeof window !== 'undefined' ? window : globalThis);
