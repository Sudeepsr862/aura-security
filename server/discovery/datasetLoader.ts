// ─── AURA Reference Dataset Loader ───────────────────────────────────────────
// Reads and imports the 5 reference CSV datasets:
// - dataset_a_employees.csv
// - dataset_b_ai_usage_logs.csv
// - dataset_c_company_assets.csv
// - dataset_d_network_logs.csv
// - dataset_e_security_incidents.csv
//
// STRICT PRIVACY & SAFETY:
// - Treats all files under sources/ as read-only. Never modifies or deletes originals.
// - Never exposes raw secrets, passwords, prompt text, or confidential file contents.
// - All records are joined primarily on employee_id.
// - Clearly distinguishes dataset sample records from live extension events.

import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import type Database from 'better-sqlite3';

const __dirname = dirname(fileURLToPath(import.meta.url));
const SOURCES_DIR = join(__dirname, '../../sources');

/**
 * Robust CSV line splitter that respects quoted commas and escapes.
 */
function parseCsvLine(text: string): string[] {
  const result: string[] = [];
  let cur = '';
  let inQuotes = false;

  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === '"') {
      if (inQuotes && text[i + 1] === '"') {
        cur += '"';
        i++;
      } else {
        inQuotes = !inQuotes;
      }
    } else if (ch === ',' && !inQuotes) {
      result.push(cur.trim());
      cur = '';
    } else {
      cur += ch;
    }
  }
  result.push(cur.trim());
  return result;
}

/**
 * Parse CSV file into rows of string arrays.
 */
function readCsvFile(filePath: string): string[][] {
  if (!existsSync(filePath)) return [];
  const content = readFileSync(filePath, 'utf-8');
  const lines = content.split(/\r?\n/).filter(l => l.trim().length > 0);
  return lines.map(parseCsvLine);
}

/**
 * Imports all 5 reference datasets into SQLite if they exist.
 */
export function importAllReferenceDatasets(db: Database.Database): {
  success: boolean;
  employeesCount: number;
  assetsCount: number;
  aiLogsCount: number;
  networkLogsCount: number;
  incidentsCount: number;
  note: string;
} {
  let empCount = 0;
  let astCount = 0;
  let aiCount = 0;
  let netCount = 0;
  let incCount = 0;

  // 1. Dataset A: Employees
  const empPath = join(SOURCES_DIR, 'dataset_a_employees.csv');
  if (existsSync(empPath)) {
    const rows = readCsvFile(empPath);
    if (rows.length > 1) {
      const insert = db.prepare(`
        INSERT OR REPLACE INTO dataset_employees (
          employee_id, full_name, department, job_role, device_id,
          device_trust_status, approved_ai_services, data_access_level, department_policy
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
      db.transaction(() => {
        for (let i = 1; i < rows.length; i++) {
          const r = rows[i];
          if (r.length >= 9 && r[0]) {
            insert.run(r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8]);
            empCount++;
          }
        }
      })();
    }
  }

  // 2. Dataset C: Company Assets
  const assetPath = join(SOURCES_DIR, 'dataset_c_company_assets.csv');
  if (existsSync(assetPath)) {
    const rows = readCsvFile(assetPath);
    if (rows.length > 1) {
      const insert = db.prepare(`
        INSERT OR REPLACE INTO dataset_assets (
          document_id, filename, owner_department, data_classification, data_category,
          authorized_roles, permitted_destinations, synthetic_fingerprint, fictional_snippet
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
      db.transaction(() => {
        for (let i = 1; i < rows.length; i++) {
          const r = rows[i];
          if (r.length >= 9 && r[0]) {
            insert.run(r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8]);
            astCount++;
          }
        }
      })();
    }
  }

  // 3. Dataset B: AI Usage Logs
  const aiPath = join(SOURCES_DIR, 'dataset_b_ai_usage_logs.csv');
  if (existsSync(aiPath)) {
    const rows = readCsvFile(aiPath);
    if (rows.length > 1) {
      const insert = db.prepare(`
        INSERT OR REPLACE INTO dataset_ai_logs (
          log_id, timestamp, employee_id, ai_service, destination_domain,
          dst_port, business_purpose, prompt_category, inspection_result,
          service_status, request_size, response_size
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
      db.transaction(() => {
        for (let i = 1; i < rows.length; i++) {
          const r = rows[i];
          if (r.length >= 12 && r[0]) {
            const port = parseInt(r[5], 10) || 443;
            insert.run(r[0], r[1], r[2], r[3], r[4], port, r[6], r[7], r[8], r[9], r[10], r[11]);
            aiCount++;
          }
        }
      })();
    }
  }

  // 4. Dataset D: Network Logs
  const netPath = join(SOURCES_DIR, 'dataset_d_network_logs.csv');
  if (existsSync(netPath)) {
    const rows = readCsvFile(netPath);
    if (rows.length > 1) {
      const insert = db.prepare(`
        INSERT OR REPLACE INTO dataset_network_logs (
          network_log_id, timestamp, employee_id, device_id, destination_domain,
          destination_ip, protocol, connection_status, bytes_sent, bytes_recv,
          transfer_duration_sec, request_frequency_min, trust_level, anomaly_indicator
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
      db.transaction(() => {
        for (let i = 1; i < rows.length; i++) {
          const r = rows[i];
          if (r.length >= 14 && r[0]) {
            const bytesSent = parseInt(r[8], 10) || 0;
            const bytesRecv = parseInt(r[9], 10) || 0;
            const duration = parseInt(r[10], 10) || 0;
            const freq = parseInt(r[11], 10) || 0;
            insert.run(r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], bytesSent, bytesRecv, duration, freq, r[12], r[13]);
            netCount++;
          }
        }
      })();
    }
  }

  // 5. Dataset E: Security Incidents
  const incPath = join(SOURCES_DIR, 'dataset_e_security_incidents.csv');
  if (existsSync(incPath)) {
    const rows = readCsvFile(incPath);
    if (rows.length > 1) {
      const insert = db.prepare(`
        INSERT OR REPLACE INTO dataset_incidents (
          incident_id, timestamp, employee_id, related_event_ids, detected_categories,
          policy_violation, risk_score, severity, explanation, recommended_action,
          response_status, analyst_resolution
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
      db.transaction(() => {
        for (let i = 1; i < rows.length; i++) {
          const r = rows[i];
          if (r.length >= 12 && r[0]) {
            const score = parseInt(r[6], 10) || 0;
            insert.run(r[0], r[1], r[2], r[3], r[4], r[5], score, r[7], r[8], r[9], r[10], r[11]);
            incCount++;
          }
        }
      })();
    }
  }

  return {
    success: empCount > 0,
    employeesCount: empCount,
    assetsCount: astCount,
    aiLogsCount: aiCount,
    networkLogsCount: netCount,
    incidentsCount: incCount,
    note: empCount > 0
      ? 'All 5 reference datasets loaded into read-only context successfully.'
      : 'Datasets not found in sources/. Place dataset_a..e.csv in sources/ directory.',
  };
}

/**
 * Returns joined historical logs with employee identity context.
 */
export function queryHistoricalLogs(
  db: Database.Database,
  limit = 100,
  filterService?: string,
  filterRisk?: string,
): any[] {
  let sql = `
    SELECT
      l.log_id, l.timestamp, l.employee_id, l.ai_service, l.destination_domain,
      l.prompt_category, l.inspection_result, l.service_status, l.request_size,
      e.full_name as employee_name, e.department, e.job_role,
      e.device_trust_status, e.approved_ai_services, e.data_access_level
    FROM dataset_ai_logs l
    LEFT JOIN dataset_employees e ON e.employee_id = l.employee_id
    WHERE 1=1
  `;
  const params: any[] = [];

  if (filterService && filterService !== 'all') {
    sql += ` AND l.ai_service LIKE ?`;
    params.push(`%${filterService}%`);
  }

  if (filterRisk && filterRisk !== 'all') {
    if (filterRisk.toLowerCase() === 'high' || filterRisk.toLowerCase() === 'critical') {
      sql += ` AND (l.inspection_result LIKE '%Credentials%' OR l.inspection_result LIKE '%Secrets%' OR l.service_status LIKE '%Unapproved%')`;
    }
  }

  sql += ` ORDER BY l.timestamp DESC LIMIT ?`;
  params.push(limit);

  return db.prepare(sql).all(...params);
}

/**
 * Returns joined sample incidents with employee context.
 */
export function queryHistoricalIncidents(db: Database.Database, limit = 50): any[] {
  const sql = `
    SELECT
      i.incident_id, i.timestamp, i.employee_id, i.related_event_ids,
      i.detected_categories, i.policy_violation, i.risk_score, i.severity,
      i.explanation, i.recommended_action, i.response_status, i.analyst_resolution,
      e.full_name as employee_name, e.department, e.job_role, e.device_trust_status
    FROM dataset_incidents i
    LEFT JOIN dataset_employees e ON e.employee_id = i.employee_id
    ORDER BY i.timestamp DESC LIMIT ?
  `;
  return db.prepare(sql).all(limit);
}
