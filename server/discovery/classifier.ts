// ─── AURA Metadata Classifier ─────────────────────────────────────────────────
// Classifies network metadata events into:
// - 'Likely cloud AI'
// - 'Possible local AI'
// - 'Ordinary web'
// - 'Uncertain'
//
// Follows strict matching rules:
// - Exact hostname or valid subdomain matching (e.g. api.openai.com matches openai.com)
// - Rejection of lookalike domains (e.g. openai.com.attacker.com or not-openai.com)
// - Tenant-style Azure OpenAI matching (*.openai.azure.com)
// - Local port matching (11434 Ollama, 1234 LM Studio as high confidence; 8000/8080/5000 low confidence)
// - Port 443 alone NEVER causes an AI match
// - Clean evidence explanations & confidence scores (0.0 to 1.0)

export type ClassificationKind =
  | 'Likely cloud AI'
  | 'Possible local AI'
  | 'Ordinary web'
  | 'Uncertain';

export interface ServiceRegistryItem {
  id: number;
  name: string;
  provider: string;
  domains: string[];
  local_ports: number[];
  service_type: string;
  approval_status: string;
}

export interface ClassificationResult {
  classification: ClassificationKind;
  confidence: number;            // 0.0 to 1.0
  evidence: string;              // Human-readable explanation
  serviceId: number | null;
  provider: string;              // Provider name or 'Unknown'
  serviceName: string;
  approvalStatus: string;        // 'Approved' | 'Needs review' | 'Unapproved' | 'Unknown'
  matchedRule: string;
}

/**
 * Standard ordinary web domains recognized as benign enterprise/web traffic.
 */
export const ORDINARY_WEB_DOMAINS: string[] = [
  'github.com',
  'api.github.com',
  'microsoft.com',
  'office.com',
  'office365.com',
  'live.com',
  'windows.com',
  'google.com',
  'docs.google.com',
  'drive.google.com',
  'mail.google.com',
  'accounts.google.com',
  'stackoverflow.com',
  'wikipedia.org',
  'slack.com',
  'zoom.us',
  'salesforce.com',
  'jsdelivr.net',
  'cloudflare.com',
  'cdnjs.cloudflare.com',
  'apple.com',
  'icloud.com',
  'amazon.com',
  'aws.amazon.com',
  'linkedin.com',
  'atlassian.com',
  'jira.com',
  'bitbucket.org',
  'gitlab.com',
];

/**
 * Normalizes host/domain string:
 * - strips protocol (http://, https://)
 * - strips path and query
 * - strips port suffix if embedded in domain string (e.g., example.com:8080)
 * - converts to lowercase and trims
 */
export function normalizeHost(raw: string | null | undefined): { hostname: string; portFromHost: number | null } {
  if (!raw) return { hostname: '', portFromHost: null };

  let clean = raw.trim().toLowerCase();

  // Strip protocol
  clean = clean.replace(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, '');

  // Strip path & query
  const slashIdx = clean.indexOf('/');
  if (slashIdx !== -1) clean = clean.substring(0, slashIdx);
  const qIdx = clean.indexOf('?');
  if (qIdx !== -1) clean = clean.substring(0, qIdx);

  // Check for embedded port: host:port (handling IPv6 [::1]:port if any)
  let portFromHost: number | null = null;
  if (clean.includes(':')) {
    const parts = clean.split(':');
    if (parts.length === 2 && /^\d+$/.test(parts[1])) {
      clean = parts[0];
      const parsedPort = parseInt(parts[1], 10);
      if (parsedPort >= 1 && parsedPort <= 65535) {
        portFromHost = parsedPort;
      }
    }
  }

  // Strip trailing dot (FQDN representation)
  if (clean.endsWith('.')) clean = clean.slice(0, -1);

  return { hostname: clean, portFromHost };
}

/**
 * Safely checks if `hostname` matches a `registeredDomain` or is a valid subdomain.
 * Prevents lookalike domains:
 * - 'api.openai.com' matches 'openai.com' -> true (valid subdomain)
 * - 'openai.com' matches 'openai.com' -> true (exact)
 * - 'openai.com.attacker.com' matches 'openai.com' -> false (lookalike / suffix mismatch)
 * - 'evilopenai.com' matches 'openai.com' -> false (not subdomain)
 * - 'myorg.openai.azure.com' matches '*.openai.azure.com' -> true (wildcard pattern)
 */
export function isDomainMatch(hostname: string, registeredDomain: string): boolean {
  if (!hostname || !registeredDomain) return false;

  const h = hostname.toLowerCase();
  const r = registeredDomain.toLowerCase();

  // Wildcard match, e.g. *.openai.azure.com or *.ai.azure.com
  if (r.startsWith('*.')) {
    const base = r.slice(2); // e.g. 'openai.azure.com'
    if (h === base) return true;
    if (h.endsWith('.' + base)) return true;
    return false;
  }

  // Exact match
  if (h === r) return true;

  // Subdomain match: must end with '.<registeredDomain>'
  if (h.endsWith('.' + r)) {
    return true;
  }

  return false;
}

/**
 * Checks if IP or hostname refers to local host.
 */
export function isLocalHostOrIp(host: string): boolean {
  if (!host) return false;
  const h = host.toLowerCase();
  return (
    h === 'localhost' ||
    h === '127.0.0.1' ||
    h === '0.0.0.0' ||
    h === '::1' ||
    h.startsWith('127.') ||
    h.startsWith('192.168.') ||
    h.startsWith('10.') ||
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(h)
  );
}

/**
 * Evaluates a network event against the service registry and heuristic rules.
 */
export function classifyEvent(
  params: {
    destination: string;
    port?: number | null;
    rawHost?: string | null;
  },
  registry: ServiceRegistryItem[],
): ClassificationResult {
  const { hostname: hostNorm, portFromHost } = normalizeHost(params.rawHost || params.destination);
  const effectivePort = params.port ?? portFromHost;

  // 1. Check Cloud AI services from registry
  for (const svc of registry) {
    if (svc.service_type === 'Cloud AI') {
      for (const d of svc.domains) {
        if (isDomainMatch(hostNorm, d)) {
          return {
            classification: 'Likely cloud AI',
            confidence: 0.95,
            evidence: `Destination matches registered Cloud AI signature for ${svc.name} (${d}).`,
            serviceId: svc.id,
            provider: svc.provider,
            serviceName: svc.name,
            approvalStatus: svc.approval_status,
            matchedRule: `cloud_registry:${svc.provider}`,
          };
        }
      }
    }
  }

  // 2. Check Local AI endpoints from registry (explicit port list or local ports)
  for (const svc of registry) {
    if (svc.service_type === 'Possible local AI') {
      // Check explicit local ports registered
      if (effectivePort != null && svc.local_ports.includes(effectivePort)) {
        const isHighConfidencePort = effectivePort === 11434 || effectivePort === 1234;
        const conf = isHighConfidencePort ? 0.85 : 0.45;
        return {
          classification: 'Possible local AI',
          confidence: conf,
          evidence: `Port ${effectivePort} matches registered local AI service ${svc.name}. Note: port match is a clue, not proof of running model.`,
          serviceId: svc.id,
          provider: svc.provider,
          serviceName: svc.name,
          approvalStatus: svc.approval_status,
          matchedRule: `local_registry_port:${effectivePort}`,
        };
      }
      // Check domain match for local AI
      for (const d of svc.domains) {
        if (isDomainMatch(hostNorm, d) && effectivePort !== 443 && effectivePort !== 80) {
          return {
            classification: 'Possible local AI',
            confidence: 0.70,
            evidence: `Destination host matches registered local service ${svc.name}.`,
            serviceId: svc.id,
            provider: svc.provider,
            serviceName: svc.name,
            approvalStatus: svc.approval_status,
            matchedRule: `local_registry_domain:${d}`,
          };
        }
      }
    }
  }

  // 3. Check Local AI Heuristic Ports (even if not explicitly mapped to a service row)
  // Port 443 ALONE must NEVER be flagged as AI!
  if (effectivePort === 443 || effectivePort === 80) {
    // Port 443/80 alone without a cloud AI domain match is NOT local AI
    // Proceed to ordinary web check or uncertain
  } else if (effectivePort === 11434) {
    return {
      classification: 'Possible local AI',
      confidence: 0.85,
      evidence: 'Port 11434 is the default runtime port for Ollama local LLMs. Port match is a heuristic clue, not model proof.',
      serviceId: null,
      provider: 'Ollama / local',
      serviceName: 'Ollama Runtime (Heuristic)',
      approvalStatus: 'Needs review',
      matchedRule: 'heuristic_port:11434',
    };
  } else if (effectivePort === 1234) {
    return {
      classification: 'Possible local AI',
      confidence: 0.85,
      evidence: 'Port 1234 is the default API server port for LM Studio. Port match is a heuristic clue, not model proof.',
      serviceId: null,
      provider: 'LM Studio / local',
      serviceName: 'LM Studio Runtime (Heuristic)',
      approvalStatus: 'Needs review',
      matchedRule: 'heuristic_port:1234',
    };
  } else if (effectivePort === 8000 || effectivePort === 8080 || effectivePort === 5000) {
    // Only flag as possible local AI if destination appears local/internal
    const isLocal = isLocalHostOrIp(hostNorm);
    if (isLocal) {
      return {
        classification: 'Possible local AI',
        confidence: 0.40,
        evidence: `Generic developer/HTTP port ${effectivePort} on local address (${hostNorm}). Low-confidence clue only; commonly used for general dev servers as well.`,
        serviceId: null,
        provider: 'Unknown local',
        serviceName: `Local Service (port ${effectivePort})`,
        approvalStatus: 'Unknown',
        matchedRule: `generic_local_port:${effectivePort}`,
      };
    }
  }

  // 4. Check Ordinary Web from registry
  for (const svc of registry) {
    if (svc.service_type === 'Ordinary web') {
      for (const d of svc.domains) {
        if (isDomainMatch(hostNorm, d)) {
          return {
            classification: 'Ordinary web',
            confidence: 0.95,
            evidence: `Destination matches registered ordinary web service ${svc.name} (${d}).`,
            serviceId: svc.id,
            provider: svc.provider,
            serviceName: svc.name,
            approvalStatus: svc.approval_status,
            matchedRule: `ordinary_registry:${d}`,
          };
        }
      }
    }
  }

  // 5. Check Built-in Ordinary Web list
  for (const d of ORDINARY_WEB_DOMAINS) {
    if (isDomainMatch(hostNorm, d)) {
      return {
        classification: 'Ordinary web',
        confidence: 0.95,
        evidence: `Destination matches known ordinary business/web domain (${d}).`,
        serviceId: null,
        provider: 'General Web',
        serviceName: d,
        approvalStatus: 'Approved',
        matchedRule: `ordinary_builtin:${d}`,
      };
    }
  }

  // 6. Default to Uncertain
  return {
    classification: 'Uncertain',
    confidence: 0.20,
    evidence: hostNorm
      ? `Domain '${hostNorm}' is not recognized in AI service registry or ordinary web list.`
      : `Destination endpoint (port ${effectivePort ?? 'unknown'}) cannot be confidently classified from metadata alone.`,
    serviceId: null,
    provider: 'Unknown',
    serviceName: hostNorm || 'Uncertain Destination',
    approvalStatus: 'Unknown',
    matchedRule: 'unmatched',
  };
}
