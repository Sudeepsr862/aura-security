// ─── AURA File Content Inspector ─────────────────────────────────────────────
// Analyzes synthetic file content for sensitive data patterns.
// STRICT PRIVACY GUARANTEE:
// - Operates in-memory only. Never stores raw file content or secrets.
// - Uses same proven pattern categories from the prompt scanner.
// - Detected secrets are used for detection only, then discarded immediately.
// - No secrets are written to logs, analytics, or review screens.

import { scanPrompt, type PatternMatch } from './scanner.js';

export interface FileInspectionResult {
  filename: string;
  fileType: string;
  fileSizeBytes: number;
  detectedTypes: PatternMatch[];
  totalFindings: number;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  matchedRules: string[];
  actionTaken: 'allowed' | 'warned' | 'blocked' | 'quarantined';
  actionReason: string;
  limitations: string[];
  redactedPreview: string;
  policyExplanation: string;
  confidenceNote: string;
}

export interface DataSharingRule {
  id: number;
  rule_name: string;
  data_types: string[];
  allowed_tools: string[];
  blocked_tools: string[];
  action: 'allow' | 'warn' | 'block';
  description: string;
  is_active: boolean;
}

export interface ProxyInspectionResult {
  canInspect: boolean;
  inspectionNote: string;
  detectedTypes: PatternMatch[];
  actionTaken: 'allowed' | 'warned' | 'blocked';
  limitation: string;
}

export interface IncomingInspectionResult {
  filename: string;
  fileSizeBytes: number;
  sourceOrigin: string;
  detectedRisks: string[];
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  actionTaken: 'allowed' | 'quarantined' | 'blocked';
  actionReason: string;
  malwareIndicators: string[];
  limitations: string[];
}

// ── Known file type detection (by extension) ─────────────────────────────────
const FILE_TYPE_MAP: Record<string, string> = {
  '.txt': 'text/plain',
  '.csv': 'text/csv',
  '.json': 'application/json',
  '.xml': 'application/xml',
  '.yaml': 'application/yaml',
  '.yml': 'application/yaml',
  '.md': 'text/markdown',
  '.py': 'text/x-python',
  '.js': 'text/javascript',
  '.ts': 'text/typescript',
  '.env': 'text/dotenv',
  '.pem': 'application/x-pem-file',
  '.key': 'application/x-pem-file',
  '.sql': 'application/sql',
  '.log': 'text/x-log',
  '.conf': 'text/x-config',
  '.ini': 'text/x-config',
  '.zip': 'application/zip',
  '.pdf': 'application/pdf',
  '.docx': 'application/vnd.openxmlformats',
  '.xlsx': 'application/vnd.openxmlformats',
  '.exe': 'application/x-executable',
  '.dll': 'application/x-sharedlib',
  '.sh': 'text/x-shellscript',
  '.bat': 'text/x-batch',
};

const BINARY_EXTENSIONS = new Set(['.zip', '.pdf', '.docx', '.xlsx', '.exe', '.dll', '.tar', '.gz', '.7z', '.rar']);

/**
 * Detect file type from filename extension.
 */
export function detectFileType(filename: string): string {
  const ext = filename.substring(filename.lastIndexOf('.')).toLowerCase();
  return FILE_TYPE_MAP[ext] ?? 'application/octet-stream';
}

/**
 * Check if a file extension is binary (cannot be text-scanned).
 */
export function isBinaryFile(filename: string): boolean {
  const ext = filename.substring(filename.lastIndexOf('.')).toLowerCase();
  return BINARY_EXTENSIONS.has(ext);
}

/**
 * Inspect file content against data-sharing policy rules.
 * Uses the existing prompt scanner engine for pattern detection.
 *
 * PRIVACY: Raw content is analyzed in memory, then discarded.
 * Only detection metadata and redacted previews are returned.
 * Secrets detected during scanning are NEVER persisted.
 */
export function inspectFileContent(
  filename: string,
  content: string,
  destination: string,
  rules: DataSharingRule[],
  destinationStatus: string = 'Unknown',
): FileInspectionResult {
  const fileType = detectFileType(filename);
  const fileSizeBytes = Buffer.byteLength(content, 'utf-8');
  const binary = isBinaryFile(filename);

  const limitations: string[] = [];

  // Binary files cannot be text-scanned
  if (binary) {
    limitations.push(
      `Binary file format (${fileType}) — content patterns cannot be detected via text regex. ` +
      'A production system would require format-specific parsers.'
    );

    return {
      filename,
      fileType,
      fileSizeBytes,
      detectedTypes: [],
      totalFindings: 0,
      riskLevel: 'medium',
      matchedRules: [],
      actionTaken: 'warned',
      actionReason: 'Binary file detected — content analysis not possible with text-based scanner.',
      limitations,
      redactedPreview: '[Binary file — content not displayed]',
      policyExplanation: 'Binary files cannot be fully inspected. Manual review recommended.',
      confidenceNote: 'Cannot inspect binary content with text-based pattern matching.',
    };
  }

  // Run the prompt scanner on the file content (in-memory only)
  const scanResult = scanPrompt(content, destination, destinationStatus);

  // Match against data-sharing policy rules
  const matchedRules: string[] = [];
  let strongestAction: 'allow' | 'warn' | 'block' = 'allow';
  const ruleReasons: string[] = [];

  for (const rule of rules) {
    if (!rule.is_active) continue;

    // Check if any detected category matches this rule's data_types
    const detectedCategories = scanResult.matches.map(m => m.category);
    const matchedTypes = rule.data_types.filter(dt => {
      const dtLower = dt.toLowerCase().trim();
      return detectedCategories.some(dc => {
        const dcLower = dc.toLowerCase().trim();
        if (dcLower.includes(dtLower) || dtLower.includes(dcLower)) return true;
        // Check significant words (>3 chars)
        const dtWords = dtLower.split(/[\/\&,\s\-]+/).filter(w => w.length >= 3);
        const dcWords = dcLower.split(/[\/\&,\s\-]+/).filter(w => w.length >= 3);
        return dtWords.some(w => dcWords.includes(w) || dcLower.includes(w));
      });
    });

    if (matchedTypes.length === 0) continue;

    // Check if destination is in blocked_tools
    const isBlocked = rule.blocked_tools.includes('*') ||
      rule.blocked_tools.some(t => destination.toLowerCase().includes(t.toLowerCase()));
    const isAllowed = rule.allowed_tools.includes('*') ||
      rule.allowed_tools.some(t => destination.toLowerCase().includes(t.toLowerCase()));

    if (isBlocked && !isAllowed) {
      matchedRules.push(rule.rule_name);
      ruleReasons.push(
        `Rule "${rule.rule_name}": ${matchedTypes.join(', ')} detected → ` +
        `destination "${destination}" is blocked by this policy. Action: ${rule.action.toUpperCase()}.`
      );

      if (rule.action === 'block' && strongestAction !== 'block') {
        strongestAction = 'block';
      } else if (rule.action === 'warn' && strongestAction === 'allow') {
        strongestAction = 'warn';
      }
    } else if (!isAllowed) {
      // Not explicitly allowed and data type matched — apply rule action
      matchedRules.push(rule.rule_name);
      ruleReasons.push(
        `Rule "${rule.rule_name}": ${matchedTypes.join(', ')} detected → ` +
        `destination "${destination}" is not in the allowed list. Action: ${rule.action.toUpperCase()}.`
      );

      if (rule.action === 'block' && strongestAction !== 'block') {
        strongestAction = 'block';
      } else if (rule.action === 'warn' && strongestAction === 'allow') {
        strongestAction = 'warn';
      }
    }
  }

  // Determine action taken
  let actionTaken: 'allowed' | 'warned' | 'blocked' = 'allowed';
  let actionReason = 'No policy rule violations detected. Transfer allowed.';

  if (strongestAction === 'block') {
    actionTaken = 'blocked';
    actionReason = `Transfer blocked by policy. ${ruleReasons.join(' ')}`;
  } else if (strongestAction === 'warn' || scanResult.policyOutcome === 'warn') {
    actionTaken = 'warned';
    actionReason = `Warning issued. ${ruleReasons.length > 0 ? ruleReasons.join(' ') : scanResult.policyExplanation}`;
  } else if (scanResult.policyOutcome === 'would_block') {
    actionTaken = 'blocked';
    actionReason = `Transfer would be blocked — critical sensitivity detected. ${scanResult.policyExplanation}`;
  }

  // Standard limitations for any text-based scan
  limitations.push(
    'Pattern matching is heuristic-based — can miss obfuscated, encoded, or steganographic content.',
  );
  if (fileSizeBytes > 1024 * 1024) {
    limitations.push('Large file scanned — analysis time may be higher in production environments.');
  }
  limitations.push(
    'This scanner cannot detect semantic meaning, context-dependent secrets, or intellectual property beyond pattern rules.',
  );

  return {
    filename,
    fileType,
    fileSizeBytes,
    detectedTypes: scanResult.matches,
    totalFindings: scanResult.totalMatches,
    riskLevel: scanResult.matches.some(m => m.riskLevel === 'critical')
      ? 'critical'
      : scanResult.matches.some(m => m.riskLevel === 'high')
        ? 'high'
        : scanResult.matches.some(m => m.riskLevel === 'medium')
          ? 'medium'
          : 'low',
    matchedRules,
    actionTaken,
    actionReason,
    limitations,
    redactedPreview: scanResult.redactedPreview.substring(0, 2000),
    policyExplanation: ruleReasons.length > 0
      ? ruleReasons.join('\n')
      : scanResult.policyExplanation,
    confidenceNote: scanResult.confidenceNote,
  };
}

/**
 * Simulated proxy / gateway inspection layer.
 * In a real deployment this would be an authorized network proxy
 * inspecting outbound traffic at the gateway. This prototype simulates
 * the concept, making clear what the proxy can and cannot inspect.
 */
export function proxyInspect(
  content: string,
  destination: string,
  isEncrypted: boolean = true,
): ProxyInspectionResult {
  // Simulated: encrypted HTTPS traffic cannot be fully inspected without
  // TLS interception (requires CA trust and endpoint configuration)
  if (isEncrypted) {
    return {
      canInspect: false,
      inspectionNote:
        'HTTPS / TLS encrypted transfer — proxy cannot inspect payload without authorized TLS interception ' +
        '(requires enterprise CA trust chain configured on endpoints). Metadata only: destination hostname and transfer size.',
      detectedTypes: [],
      actionTaken: 'allowed',
      limitation:
        'Encrypted payloads opaque to proxy. Only SNI hostname and connection metadata visible. ' +
        'Full content inspection requires authorized TLS decryption (MITM proxy with user consent).',
    };
  }

  // Unencrypted (HTTP) or decrypted traffic — run scanner
  const scanResult = scanPrompt(content, destination, 'Unknown');

  let actionTaken: 'allowed' | 'warned' | 'blocked' = 'allowed';
  if (scanResult.policyOutcome === 'would_block') {
    actionTaken = 'blocked';
  } else if (scanResult.policyOutcome === 'warn') {
    actionTaken = 'warned';
  }

  return {
    canInspect: true,
    inspectionNote:
      'Unencrypted or TLS-decrypted traffic — proxy performed full content inspection (simulation).',
    detectedTypes: scanResult.matches,
    actionTaken,
    limitation:
      'Proxy inspection only covers traffic routed through the gateway. ' +
      'Direct connections, VPN tunnels, or split-tunnel configurations bypass this layer.',
  };
}

// ── Simulated malware / inbound risk signatures ─────────────────────────────

const MALWARE_SIGNATURES = [
  { pattern: /\beicar\b/i, name: 'EICAR Test Signature', severity: 'high' as const },
  { pattern: /\bX5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}/, name: 'EICAR Standard Test String', severity: 'critical' as const },
  { pattern: /\bpowershell\s.*-enc/i, name: 'Encoded PowerShell Command', severity: 'high' as const },
  { pattern: /\bcmd\.exe\s*\/c/i, name: 'CMD Shell Execution', severity: 'medium' as const },
  { pattern: /\beval\s*\(\s*base64_decode/i, name: 'PHP Base64 Eval Pattern', severity: 'high' as const },
  { pattern: /\b(?:wget|curl)\s.*\|\s*(?:bash|sh)\b/i, name: 'Remote Script Execution (pipe to shell)', severity: 'critical' as const },
  { pattern: /\bCreateObject\s*\(\s*["']Wscript\.Shell["']\s*\)/i, name: 'VBScript Shell Object', severity: 'high' as const },
  { pattern: /\brm\s+-rf\s+\//i, name: 'Destructive File Deletion', severity: 'critical' as const },
];

const SUSPICIOUS_EXTENSIONS = new Set(['.exe', '.bat', '.cmd', '.ps1', '.vbs', '.scr', '.pif', '.com', '.msi']);

/**
 * Inspect incoming file/transfer for malware indicators and defined risks.
 * Returns a risk assessment with supporting reasons.
 *
 * This is a simulated prototype scanner — it uses basic signature matching
 * and does NOT replace a production antivirus or EDR solution.
 */
export function inspectIncoming(
  filename: string,
  content: string,
  sourceOrigin: string = 'unknown',
): IncomingInspectionResult {
  const fileSizeBytes = Buffer.byteLength(content, 'utf-8');
  const ext = filename.substring(filename.lastIndexOf('.')).toLowerCase();
  const detectedRisks: string[] = [];
  const malwareIndicators: string[] = [];
  const limitations: string[] = [];

  let maxSeverity: 'low' | 'medium' | 'high' | 'critical' = 'low';
  const severityOrder = { low: 0, medium: 1, high: 2, critical: 3 };

  // Check extension risk
  if (SUSPICIOUS_EXTENSIONS.has(ext)) {
    detectedRisks.push(`Suspicious file extension: ${ext} — executable or script file type.`);
    if (severityOrder[maxSeverity] < severityOrder['high']) maxSeverity = 'high';
    malwareIndicators.push(`Executable extension: ${ext}`);
  }

  // Check content for malware signatures (text files only)
  if (!isBinaryFile(filename)) {
    for (const sig of MALWARE_SIGNATURES) {
      if (sig.pattern.test(content)) {
        malwareIndicators.push(sig.name);
        detectedRisks.push(`Malware indicator: ${sig.name}`);
        if (severityOrder[maxSeverity] < severityOrder[sig.severity]) {
          maxSeverity = sig.severity;
        }
      }
    }

    // Also run the data scanner for sensitive incoming data
    const scanResult = scanPrompt(content, sourceOrigin, 'Unknown');
    if (scanResult.totalMatches > 0) {
      detectedRisks.push(
        `Incoming file contains ${scanResult.totalMatches} sensitive data pattern(s): ` +
        scanResult.matches.map(m => m.category).join(', '),
      );
    }
  } else {
    limitations.push('Binary file — text-based malware signature matching not performed.');
  }

  limitations.push(
    'This is a prototype signature scanner. It does not replace production antivirus, ' +
    'sandbox detonation, or behavior-based threat detection.',
  );
  limitations.push(
    'Obfuscated, packed, or polymorphic payloads may evade signature-based detection.',
  );

  // Determine action
  let actionTaken: 'allowed' | 'quarantined' | 'blocked' = 'allowed';
  let actionReason = 'No malware indicators or policy violations detected.';

  if (maxSeverity === 'critical') {
    actionTaken = 'blocked';
    actionReason = `Blocked: ${malwareIndicators.join(', ')} detected. File rejected per policy.`;
  } else if (maxSeverity === 'high') {
    actionTaken = 'quarantined';
    actionReason = `Quarantined for review: ${malwareIndicators.join(', ')} found. Awaiting analyst review.`;
  } else if (maxSeverity === 'medium') {
    actionTaken = 'quarantined';
    actionReason = `Quarantined: moderate risk indicators detected — ${detectedRisks.join('; ')}.`;
  }

  return {
    filename,
    fileSizeBytes,
    sourceOrigin,
    detectedRisks,
    riskLevel: maxSeverity,
    actionTaken,
    actionReason,
    malwareIndicators,
    limitations,
  };
}
