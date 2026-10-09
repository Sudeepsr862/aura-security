// ─── AURA CSV Parser & Normalizer ─────────────────────────────────────────────
// Safe ingestion of network metadata CSV files.
//
// Privacy & Security Safeguards:
// - Ignores and strips all unknown/payload columns (prompts, bodies, passwords, tokens, files).
// - Enforces max 2 MB file size limit and max 500 rows limit.
// - Accurately parses booleans (e.g. "false", "0", "no" evaluate strictly to false).
// - Validates port (1-65535), byte counts (non-negative), and usable destination.
// - Returns skipped rows with non-sensitive diagnostic reasons (no raw payload leakage).

export interface NormalizedMetadataRow {
  rowNumber: number;
  timestamp: string;
  srcIp?: string;
  dstIp?: string;
  device?: string;
  userEmail?: string;
  domain?: string;
  destination: string;
  port: number | null;
  bytes: number;
  dataClassification: 'Public' | 'Internal' | 'Confidential' | 'Restricted';
  isAuthorized: boolean;
  explicitAuthorization?: 'authorized' | 'denied' | null;
  isAnomaly: boolean;
  groundTruthLabel?: string;
  expectedProvider?: string;
}

export interface SkippedRow {
  rowNumber: number;
  reason: string;
  destinationPreview?: string;
}

export interface CsvParseResult {
  success: boolean;
  totalRowsFound: number;
  importedRows: NormalizedMetadataRow[];
  skippedRows: SkippedRow[];
  ignoredColumnsDetected: string[];
  errorMessage?: string;
}

const MAX_CSV_SIZE_BYTES = 2 * 1024 * 1024; // 2 MB
const MAX_CSV_ROWS = 500;

// Column aliases for canonical mapping
const COLUMN_ALIASES: Record<string, string[]> = {
  timestamp:           ['timestamp', 'time', 'date', 'datetime', 'occurred_at'],
  src_ip:              ['src_ip', 'source_ip', 'srcip', 'source_address', 'src'],
  dst_ip:              ['dst_ip', 'destination_ip', 'dstip', 'dest_ip', 'target_ip'],
  device:              ['device', 'device_name', 'hostname', 'host_name', 'machine', 'device_id'],
  user_email:          ['user_email', 'user', 'email', 'username', 'user_id'],
  domain:              ['domain_sni', 'domain', 'host', 'sni', 'destination_domain', 'target_domain', 'fqdn'],
  dst_port:            ['dst_port', 'port', 'destination_port', 'dstport', 'target_port'],
  bytes:               ['bytes', 'bytes_out', 'data_volume', 'bytes_in', 'byte_count', 'size', 'volume', 'bytes_total'],
  data_classification: ['data_classification', 'classification', 'sensitivity', 'sensitivity_label', 'data_label'],
  authorization:       ['authorization', 'authorized', 'is_authorized', 'approval', 'approval_status', 'approved'],
  anomaly:             ['anomaly', 'is_anomaly', 'outlier'],
  label:               ['label', 'ground_truth', 'ground_truth_label', 'truth', 'expected_label'],
  expected_provider:   ['expected_provider', 'provider', 'target_provider', 'expected_vendor'],
};

/**
 * Parses raw CSV text into a 2D array of strings, respecting quotes and line breaks.
 */
export function parseCsvRaw(csvText: string): string[][] {
  // Strip UTF-8 BOM if present
  let text = csvText.startsWith('\uFEFF') ? csvText.slice(1) : csvText;
  text = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n');

  const rows: string[][] = [];
  let currentRow: string[] = [];
  let currentField = '';
  let insideQuotes = false;
  let i = 0;

  while (i < text.length) {
    const char = text[i];
    const nextChar = text[i + 1];

    if (char === '"') {
      if (insideQuotes && nextChar === '"') {
        // Escaped quote: "" -> "
        currentField += '"';
        i += 2;
        continue;
      }
      insideQuotes = !insideQuotes;
      i++;
      continue;
    }

    if (char === ',' && !insideQuotes) {
      currentRow.push(currentField);
      currentField = '';
      i++;
      continue;
    }

    if (char === '\n' && !insideQuotes) {
      currentRow.push(currentField);
      // Only push non-empty rows
      if (currentRow.some((f) => f.trim().length > 0)) {
        rows.push(currentRow);
      }
      currentRow = [];
      currentField = '';
      i++;
      continue;
    }

    currentField += char;
    i++;
  }

  // Push final field/row if text doesn't end with newline
  if (currentField.length > 0 || currentRow.length > 0) {
    currentRow.push(currentField);
    if (currentRow.some((f) => f.trim().length > 0)) {
      rows.push(currentRow);
    }
  }

  return rows;
}

/**
 * Normalizes boolean values strictly:
 * "false", "0", "no", "n", null, undefined -> false
 * "true", "1", "yes", "y" -> true
 */
export function parseBooleanStrict(val: unknown, defaultValue = false): boolean {
  if (val === null || val === undefined) return defaultValue;
  if (typeof val === 'boolean') return val;
  if (typeof val === 'number') return val !== 0;

  const s = String(val).trim().toLowerCase();
  if (s === 'false' || s === '0' || s === 'no' || s === 'n' || s === 'f' || s === '' || s === 'unauthorized') {
    return false;
  }
  if (s === 'true' || s === '1' || s === 'yes' || s === 'y' || s === 't' || s === 'authorized') {
    return true;
  }
  return defaultValue;
}

/**
 * Normalizes data sensitivity classification.
 */
export function parseClassification(raw: unknown): 'Public' | 'Internal' | 'Confidential' | 'Restricted' {
  if (!raw) return 'Internal';
  const s = String(raw).trim().toLowerCase();
  if (s.includes('pub')) return 'Public';
  if (s.includes('conf')) return 'Confidential';
  if (s.includes('rest')) return 'Restricted';
  return 'Internal';
}

/**
 * Normalizes date / timestamp string into valid ISO string.
 */
export function parseTimestamp(raw: unknown): string {
  if (!raw) return new Date().toISOString();
  const s = String(raw).trim();
  const d = new Date(s);
  if (!isNaN(d.getTime())) {
    return d.toISOString();
  }
  return new Date().toISOString();
}

/**
 * Parses and validates CSV content.
 */
export function parseAndValidateCsv(csvContent: string): CsvParseResult {
  // 1. Size limit check
  const byteLength = Buffer.byteLength(csvContent, 'utf-8');
  if (byteLength > MAX_CSV_SIZE_BYTES) {
    return {
      success: false,
      totalRowsFound: 0,
      importedRows: [],
      skippedRows: [],
      ignoredColumnsDetected: [],
      errorMessage: `File exceeds maximum allowed size of 2 MB (${(byteLength / (1024 * 1024)).toFixed(2)} MB uploaded).`,
    };
  }

  // 2. Parse raw rows
  const allRows = parseCsvRaw(csvContent);
  if (allRows.length === 0) {
    return {
      success: false,
      totalRowsFound: 0,
      importedRows: [],
      skippedRows: [],
      ignoredColumnsDetected: [],
      errorMessage: 'CSV file is empty or contains no readable lines.',
    };
  }

  // 3. Header mapping
  const rawHeaders = allRows[0].map((h) => h.trim());
  const headerMap = new Map<string, string>(); // canonicalName -> rawHeaderName
  const ignoredColumnsDetected: string[] = [];

  for (const h of rawHeaders) {
    const lower = h.toLowerCase().replace(/[\s_-]+/g, '_');
    let matchedCanonical: string | null = null;

    for (const [canonical, aliases] of Object.entries(COLUMN_ALIASES)) {
      if (aliases.includes(lower) || canonical === lower) {
        matchedCanonical = canonical;
        break;
      }
    }

    if (matchedCanonical) {
      if (!headerMap.has(matchedCanonical)) {
        headerMap.set(matchedCanonical, h);
      }
    } else {
      // Unknown column — record name only (NEVER values!)
      ignoredColumnsDetected.push(h);
    }
  }

  const dataRows = allRows.slice(1);
  const totalRowsFound = dataRows.length;

  // 4. Row limit check
  if (totalRowsFound > MAX_CSV_ROWS) {
    return {
      success: false,
      totalRowsFound,
      importedRows: [],
      skippedRows: [],
      ignoredColumnsDetected,
      errorMessage: `CSV exceeds maximum row limit of ${MAX_CSV_ROWS} rows (${totalRowsFound} rows found).`,
    };
  }

  // Fast header lookup index
  const headerIndexMap = new Map<string, number>();
  for (const [canonical, rawH] of headerMap.entries()) {
    const idx = rawHeaders.indexOf(rawH);
    if (idx !== -1) {
      headerIndexMap.set(canonical, idx);
    }
  }

  const importedRows: NormalizedMetadataRow[] = [];
  const skippedRows: SkippedRow[] = [];

  for (let r = 0; r < dataRows.length; r++) {
    const rowNum = r + 2; // 1-indexed, accounting for header row
    const row = dataRows[r];

    const getVal = (canonical: string): string => {
      const idx = headerIndexMap.get(canonical);
      return idx != null && idx < row.length ? row[idx].trim() : '';
    };

    const domainVal = getVal('domain');
    const dstIpVal  = getVal('dst_ip');
    const dstPortRaw = getVal('dst_port');
    const bytesRaw   = getVal('bytes');

    // Parse port
    let parsedPort: number | null = null;
    if (dstPortRaw !== '') {
      const n = parseInt(dstPortRaw, 10);
      if (isNaN(n) || n < 1 || n > 65535) {
        skippedRows.push({
          rowNumber: rowNum,
          reason: `Invalid port value '${dstPortRaw}' (must be 1–65535).`,
          destinationPreview: domainVal || dstIpVal || 'unknown',
        });
        continue;
      }
      parsedPort = n;
    }

    // Determine destination (domain, IP, or local endpoint)
    let destination = domainVal || dstIpVal;
    if (!destination && (parsedPort === 11434 || parsedPort === 1234 || parsedPort === 8000 || parsedPort === 8080)) {
      destination = `localhost:${parsedPort}`;
    }

    if (!destination) {
      skippedRows.push({
        rowNumber: rowNum,
        reason: 'Missing usable domain, destination IP, or recognized local-model port.',
      });
      continue;
    }

    // Parse bytes
    let byteCount = 0;
    if (bytesRaw !== '') {
      const b = parseInt(bytesRaw, 10);
      if (!isNaN(b) && b >= 0) {
        byteCount = b;
      }
    }

    // Parse booleans and explicit authorization
    const rawAuth = getVal('authorization');
    let explicitAuth: 'authorized' | 'denied' | null = null;
    if (rawAuth !== '') {
      const lowerAuth = rawAuth.toLowerCase().trim();
      if (lowerAuth === 'true' || lowerAuth === '1' || lowerAuth === 'yes' || lowerAuth === 'authorized' || lowerAuth === 'approved') {
        explicitAuth = 'authorized';
      } else if (lowerAuth === 'false' || lowerAuth === '0' || lowerAuth === 'no' || lowerAuth === 'denied' || lowerAuth === 'unauthorized' || lowerAuth === 'unapproved') {
        explicitAuth = 'denied';
      }
    }
    const isAuthorized = parseBooleanStrict(rawAuth, true);
    const isAnomaly    = parseBooleanStrict(getVal('anomaly'), false);

    // Build normalized row
    importedRows.push({
      rowNumber: rowNum,
      timestamp: parseTimestamp(getVal('timestamp')),
      srcIp: getVal('src_ip') || undefined,
      dstIp: dstIpVal || undefined,
      device: getVal('device') || undefined,
      userEmail: getVal('user_email') || undefined,
      domain: domainVal || undefined,
      destination,
      port: parsedPort,
      bytes: byteCount,
      dataClassification: parseClassification(getVal('data_classification')),
      isAuthorized,
      explicitAuthorization: explicitAuth,
      isAnomaly,
      groundTruthLabel: getVal('label') || undefined,
      expectedProvider: getVal('expected_provider') || undefined,
    });
  }

  return {
    success: true,
    totalRowsFound,
    importedRows,
    skippedRows,
    ignoredColumnsDetected,
  };
}
