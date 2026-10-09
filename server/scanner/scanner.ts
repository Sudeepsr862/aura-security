// ─── AURA Prompt Scanner Engine ───────────────────────────────────────────────
// In-memory pattern detection and redaction engine for synthetic prompt testing.
//
// STRICT PRIVACY GUARANTEE:
// - Operates in-memory only.
// - Never stores raw prompt text, redacted preview, or content digests.
// - Does not call external APIs, LLMs, or cloud analytics.
// - All secret matches are redacted in the preview returned to the browser session.

export interface PatternMatch {
  category: string;
  count: number;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  explanation: string;
}

export interface ScanResult {
  matches: PatternMatch[];
  totalMatches: number;
  redactedPreview: string;
  sensitivitySuggestion: 'Public' | 'Internal' | 'Confidential' | 'Restricted';
  policyOutcome: 'allow_caution' | 'warn' | 'would_block';
  policyRecommendation: string;
  policyExplanation: string;
  destinationStatus: string;
  confidenceNote: string;
}

/**
 * Standard Luhn checksum algorithm for payment card validation.
 * Verifies whether a 13-19 digit sequence satisfies the ISO/IEC 7812 checksum.
 */
export function passesLuhn(cardNumberStr: string): boolean {
  const digits = cardNumberStr.replace(/\D/g, '');
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
 * Analyzes text against documented pattern rules in memory.
 * Never persists or logs the raw text or the redacted output.
 */
export function scanPrompt(
  rawText: string,
  destination: string = 'Unknown destination',
  destinationStatus: string = 'Unknown',
): ScanResult {
  if (!rawText || rawText.trim() === '') {
    return {
      matches: [],
      totalMatches: 0,
      redactedPreview: '',
      sensitivitySuggestion: 'Public',
      policyOutcome: 'allow_caution',
      policyRecommendation: 'No configured pattern detected — this does not prove the prompt is safe.',
      policyExplanation: 'Empty or blank prompt entered.',
      destinationStatus,
      confidenceNote:
        'Pattern matching is a heuristic rule engine. It can miss obfuscated secrets and may produce false positives on formatted identifiers.',
    };
  }

  let textToRedact = rawText;
  const matchCounts: Record<string, number> = {};

  const recordMatch = (category: string, count = 1) => {
    matchCounts[category] = (matchCounts[category] || 0) + count;
  };

  // ── 1. Private Cryptographic Keys (Critical) ───────────────────────────────
  const privateKeyRegex = /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?(?:-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----|$)/gi;
  const privateKeyMatches = textToRedact.match(privateKeyRegex);
  if (privateKeyMatches && privateKeyMatches.length > 0) {
    recordMatch('Private Cryptographic Keys', privateKeyMatches.length);
    textToRedact = textToRedact.replace(privateKeyRegex, '[REDACTED: Private Key]');
  }

  // ── 2. Demo API Keys & Access Tokens (Critical) ────────────────────────────
  // OpenAI Keys (sk-..., sk-proj-...)
  const openAiRegex = /\b(sk-(?:proj-)?[A-Za-z0-9_\-]{20,})\b/g;
  const openAiMatches = textToRedact.match(openAiRegex);
  if (openAiMatches) {
    recordMatch('API Keys & Access Tokens', openAiMatches.length);
    textToRedact = textToRedact.replace(openAiRegex, '[REDACTED: API Key]');
  }

  // GitHub Personal Access Tokens (ghp_..., github_pat_...)
  const gitHubTokenRegex = /\b(?:gh[pousr]_[A-Za-z0-9_]{36,}|github_pat_[A-Za-z0-9_]{30,})\b/g;
  const gitHubMatches = textToRedact.match(gitHubTokenRegex);
  if (gitHubMatches) {
    recordMatch('API Keys & Access Tokens', gitHubMatches.length);
    textToRedact = textToRedact.replace(gitHubTokenRegex, '[REDACTED: API Key]');
  }

  // AWS Access Key ID
  const awsKeyRegex = /\b(AKIA[0-9A-Z]{16})\b/g;
  const awsMatches = textToRedact.match(awsKeyRegex);
  if (awsMatches) {
    recordMatch('API Keys & Access Tokens', awsMatches.length);
    textToRedact = textToRedact.replace(awsKeyRegex, '[REDACTED: API Key]');
  }

  // Generic Bearer Token
  const bearerRegex = /\bBearer\s+([A-Za-z0-9_\-\.]{20,})\b/g;
  let bearerCount = 0;
  textToRedact = textToRedact.replace(bearerRegex, (_match, token) => {
    if (token) bearerCount++;
    return 'Bearer [REDACTED: API Key]';
  });
  if (bearerCount > 0) {
    recordMatch('API Keys & Access Tokens', bearerCount);
  }

  // Generic API key assignments: api_key = "..." or api-key: ...
  const genericApiKeyRegex = /\b((?:api[_-]?key|access[_-]?token|auth[_-]?token|secret[_-]?key)\s*[:=]\s*["']?)([A-Za-z0-9_\-]{16,})(["']?)/gi;
  let genericKeyCount = 0;
  textToRedact = textToRedact.replace(genericApiKeyRegex, (_m, p1, _val, p3) => {
    genericKeyCount++;
    return `${p1}[REDACTED: API Key]${p3}`;
  });
  if (genericKeyCount > 0) {
    recordMatch('API Keys & Access Tokens', genericKeyCount);
  }

  // ── 3. Password-like Assignments (Critical) ────────────────────────────────
  const passwordAssignRegex = /\b((?:password|passwd|db_pass|user_password|secret_key|db_password)\s*[:=]\s*["']?)([^\s"']{6,})(["']?)/gi;
  let pwdCount = 0;
  textToRedact = textToRedact.replace(passwordAssignRegex, (_m, p1, _val, p3) => {
    pwdCount++;
    return `${p1}[REDACTED: Password]${p3}`;
  });
  if (pwdCount > 0) {
    recordMatch('Password / Secret Assignments', pwdCount);
  }

  // ── 4. Payment Card Numbers (Luhn Checksum Validated) (Critical) ───────────
  // Finds potential card sequences with digits, spaces, and dashes
  const cardCandidateRegex = /\b(?:\d[ -]*?){13,19}\b/g;
  let cardCount = 0;
  textToRedact = textToRedact.replace(cardCandidateRegex, (candidate) => {
    if (passesLuhn(candidate)) {
      cardCount++;
      return '[REDACTED: Card Number]';
    }
    return candidate; // Luhn check failed -> not a payment card
  });
  if (cardCount > 0) {
    recordMatch('Payment Card Numbers (Luhn Validated)', cardCount);
  }

  // ── 5. Email Addresses (Medium) ────────────────────────────────────────────
  const emailRegex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
  const emailMatches = textToRedact.match(emailRegex);
  if (emailMatches) {
    recordMatch('Email Addresses', emailMatches.length);
    textToRedact = textToRedact.replace(emailRegex, '[REDACTED: Email]');
  }

  // ── 6. Phone Numbers (Medium) ──────────────────────────────────────────────
  const phoneRegex = /(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g;
  const phoneMatches = textToRedact.match(phoneRegex);
  if (phoneMatches) {
    recordMatch('Phone Numbers', phoneMatches.length);
    textToRedact = textToRedact.replace(phoneRegex, '[REDACTED: Phone]');
  }

  // ── 7. Internal IPv4 Addresses (Medium) ────────────────────────────────────
  const internalIpRegex = /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g;
  const internalIpMatches = textToRedact.match(internalIpRegex);
  if (internalIpMatches) {
    recordMatch('Internal Network Addresses', internalIpMatches.length);
    textToRedact = textToRedact.replace(internalIpRegex, '[REDACTED: Internal IP]');
  }

  // ── 8. Sensitive Business Terms (Medium / Confidential) ────────────────────
  const sensitiveTermsRegex = /\b(confidential|restricted|internal only|customer database|source code|trade secret|proprietary|do not distribute)\b/gi;
  const termMatches = textToRedact.match(sensitiveTermsRegex);
  if (termMatches) {
    recordMatch('Sensitive Business Terms', termMatches.length);
    textToRedact = textToRedact.replace(sensitiveTermsRegex, '[REDACTED: Sensitive Term]');
  }

  // ── 9. Suspicious Request Phrases (Heuristic) ─────────────────────────────
  const suspiciousRegex = /\b(ignore previous instructions|bypass safety|jailbreak|reveal system prompt|exfiltrate)\b/gi;
  const suspiciousMatches = textToRedact.match(suspiciousRegex);
  if (suspiciousMatches) {
    recordMatch('Suspicious Prompt Phrases (Heuristic)', suspiciousMatches.length);
    textToRedact = textToRedact.replace(suspiciousRegex, '[FLAGGED: Heuristic Prompt Phrase]');
  }

  // Build match summary objects
  const CATEGORY_META: Record<
    string,
    { risk: 'low' | 'medium' | 'high' | 'critical'; explanation: string }
  > = {
    'API Keys & Access Tokens': {
      risk: 'critical',
      explanation: 'Credential pattern detected resembling an API key, access token, or authorization credential.',
    },
    'Password / Secret Assignments': {
      risk: 'critical',
      explanation: 'Assignment pattern resembling a plaintext password or secret key definition.',
    },
    'Private Cryptographic Keys': {
      risk: 'critical',
      explanation: 'Cryptographic private key header or PEM block detected.',
    },
    'Payment Card Numbers (Luhn Validated)': {
      risk: 'critical',
      explanation: 'Card sequence passed the standard Luhn checksum algorithm (PCI DSS sensitive).',
    },
    'Email Addresses': {
      risk: 'medium',
      explanation: 'Personal or enterprise email address pattern (possible PII).',
    },
    'Phone Numbers': {
      risk: 'medium',
      explanation: 'Telephone number format detected (possible PII).',
    },
    'Internal Network Addresses': {
      risk: 'medium',
      explanation: 'Private RFC 1918 / loopback IPv4 address indicating internal network topology.',
    },
    'Sensitive Business Terms': {
      risk: 'medium',
      explanation: 'Enterprise sensitivity or confidentiality markers detected in prompt text.',
    },
    'Suspicious Prompt Phrases (Heuristic)': {
      risk: 'medium',
      explanation: 'Heuristic prompt phrasing sometimes associated with safety bypass attempts. Flagged as an indicator only, not proof of malicious intent.',
    },
  };

  const matches: PatternMatch[] = Object.entries(matchCounts).map(([cat, count]) => ({
    category: cat,
    count,
    riskLevel: CATEGORY_META[cat]?.risk ?? 'medium',
    explanation: CATEGORY_META[cat]?.explanation ?? 'Pattern matched by rule engine.',
  }));

  const totalMatches = matches.reduce((sum, m) => sum + m.count, 0);

  // Determine Sensitivity Suggestion
  let sensitivitySuggestion: 'Public' | 'Internal' | 'Confidential' | 'Restricted' = 'Public';
  const hasCritical = matches.some((m) => m.riskLevel === 'critical');
  const hasMedium = matches.some((m) => m.riskLevel === 'medium');

  if (hasCritical) {
    sensitivitySuggestion = 'Restricted';
  } else if (hasMedium) {
    const hasPersonalOrBusiness =
      matchCounts['Email Addresses'] ||
      matchCounts['Phone Numbers'] ||
      matchCounts['Sensitive Business Terms'];
    sensitivitySuggestion = hasPersonalOrBusiness ? 'Confidential' : 'Internal';
  } else {
    sensitivitySuggestion = 'Public';
  }

  // Determine Policy Recommendation based on findings & destination approval
  let policyOutcome: 'allow_caution' | 'warn' | 'would_block' = 'allow_caution';
  let policyRecommendation = 'No configured pattern detected — this does not prove the prompt is safe.';
  let policyExplanation = 'No configured secret or sensitive patterns matched the rule engine. Note that regex rules cannot guarantee prompt safety.';

  const isApprovedDestination = destinationStatus === 'Approved';

  if (hasCritical) {
    if (!isApprovedDestination) {
      // Critical secret to unapproved or unknown destination -> Simulated Block
      policyOutcome = 'would_block';
      policyRecommendation = 'Would block before transmission (simulation).';
      policyExplanation = `High-risk credentials, private keys, or payment data detected destined for an unapproved or unknown endpoint (${destination}). Under enterprise policy, transmission would be blocked.`;
    } else {
      // Critical secret to approved destination -> Warn
      policyOutcome = 'warn';
      policyRecommendation = 'Warn / review before sending.';
      policyExplanation = `High-risk credentials detected. Although ${destination} is an approved enterprise service, transmitting raw credentials in prompt text is strongly discouraged.`;
    }
  } else if (hasMedium) {
    policyOutcome = 'warn';
    policyRecommendation = 'Warn / review before sending.';
    policyExplanation = `Sensitive personal data or internal business terminology detected. Review prompt text before transmitting to ${destination}.`;
  }

  return {
    matches,
    totalMatches,
    redactedPreview: textToRedact,
    sensitivitySuggestion,
    policyOutcome,
    policyRecommendation,
    policyExplanation,
    destinationStatus,
    confidenceNote:
      'Pattern matching is a heuristic rule engine. It can miss obfuscated secrets and may produce false positives on formatted identifiers.',
  };
}
