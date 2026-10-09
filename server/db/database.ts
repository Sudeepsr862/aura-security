// ─── AURA Database Setup & Seed ──────────────────────────────────────────────
// Applies schema and seeds demo records on first run.
// All seeded records are synthetic / fictional.
// Re-running is safe — uses INSERT OR IGNORE.

import Database from 'better-sqlite3';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { assessRisk } from '../risk/riskEngine.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

// ── Open the database ─────────────────────────────────────────────────────────
const DB_PATH = join(__dirname, '../../data/aura.db');

export function openDb(): Database.Database {
  const db = new Database(DB_PATH);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  return db;
}

// ── Apply schema ──────────────────────────────────────────────────────────────
export function applySchema(db: Database.Database): void {
  const sql = readFileSync(join(__dirname, 'schema.sql'), 'utf-8');
  db.exec(sql);

  // Auto-migrate columns for existing database
  const columns = db.pragma('table_info(events)') as Array<{ name: string }>;
  const existingCols = new Set(columns.map((c) => c.name));
  const newCols: Array<{ name: string; type: string }> = [
    { name: 'source_type', type: "TEXT NOT NULL DEFAULT 'simulation'" },
    { name: 'device_name', type: 'TEXT' },
    { name: 'user_email', type: 'TEXT' },
    { name: 'src_ip', type: 'TEXT' },
    { name: 'dst_ip', type: 'TEXT' },
    { name: 'classification', type: "TEXT NOT NULL DEFAULT 'Uncertain'" },
    { name: 'confidence', type: 'REAL NOT NULL DEFAULT 0.0' },
    { name: 'evidence', type: 'TEXT' },
    { name: 'is_anomaly', type: 'INTEGER NOT NULL DEFAULT 0' },
    { name: 'is_authorized', type: 'INTEGER NOT NULL DEFAULT 0' },
    { name: 'expected_provider', type: 'TEXT' },
    { name: 'risk_factors', type: "TEXT NOT NULL DEFAULT '[]'" },
    { name: 'risk_explanation', type: 'TEXT' },
    { name: 'risk_confidence', type: "TEXT NOT NULL DEFAULT 'Medium'" },
    { name: 'authorization_status', type: "TEXT NOT NULL DEFAULT 'unknown'" },
    { name: 'identity_correlation', type: "TEXT NOT NULL DEFAULT '{}'" },
  ];

  for (const col of newCols) {
    if (!existingCols.has(col.name)) {
      db.exec(`ALTER TABLE events ADD COLUMN ${col.name} ${col.type}`);
    }
  }

  // Auto-migrate incidents table schema (ensure notes, simulated_actions, and extended statuses)
  const incMaster = db.prepare("SELECT sql FROM sqlite_master WHERE name = 'incidents'").get() as { sql: string } | undefined;
  if (incMaster && incMaster.sql) {
    const lacksStatuses = !incMaster.sql.includes('False Positive') || !incMaster.sql.includes('Investigating');
    const incCols = db.pragma('table_info(incidents)') as Array<{ name: string }>;
    const incColSet = new Set(incCols.map((c) => c.name));
    const lacksCols = !incColSet.has('notes') || !incColSet.has('simulated_actions');

    if (lacksStatuses || lacksCols) {
      db.exec(`
        PRAGMA foreign_keys=OFF;
        ALTER TABLE incidents RENAME TO incidents_old;

        CREATE TABLE incidents (
          id              INTEGER PRIMARY KEY AUTOINCREMENT,
          severity        TEXT    NOT NULL CHECK(severity IN ('low','medium','high','critical')),
          title           TEXT    NOT NULL,
          event_id        INTEGER REFERENCES events(id) ON DELETE SET NULL,
          destination     TEXT    NOT NULL,
          device_id       INTEGER REFERENCES synthetic_devices(id) ON DELETE SET NULL,
          person_id       INTEGER REFERENCES synthetic_people(id) ON DELETE SET NULL,
          status          TEXT    NOT NULL DEFAULT 'Open' CHECK(status IN ('Open','Investigating','Under review','Resolved','False Positive')),
          notes           TEXT    NOT NULL DEFAULT '[]',
          simulated_actions TEXT  NOT NULL DEFAULT '[]',
          is_demo         INTEGER NOT NULL DEFAULT 1,
          created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
          updated_at      TEXT    NOT NULL DEFAULT (datetime('now'))
        );

        INSERT INTO incidents (id, severity, title, event_id, destination, device_id, person_id, status, is_demo, created_at, updated_at)
        SELECT id, severity, title, event_id, destination, device_id, person_id, status, is_demo, created_at, updated_at
        FROM incidents_old;

        DROP TABLE incidents_old;
        PRAGMA foreign_keys=ON;
      `);
    }
  }

  // Auto-backfill existing events that lack explainable risk factors
  const unbackfilled = db.prepare(`
    SELECT e.id, e.destination, e.port, e.classification, e.confidence,
           e.sensitivity_label, e.approval_status, e.byte_count, e.is_anomaly,
           e.user_email, e.device_name, e.person_id, e.device_id, e.is_authorized
    FROM events e
    WHERE e.risk_factors = '[]' OR e.risk_factors IS NULL
  `).all() as Array<{
    id: number;
    destination: string;
    port: number | null;
    classification: string;
    confidence: number;
    sensitivity_label: string;
    approval_status: string;
    byte_count: number;
    is_anomaly: number;
    user_email: string | null;
    device_name: string | null;
    person_id: number | null;
    device_id: number | null;
    is_authorized: number;
  }>;

  if (unbackfilled.length > 0) {
    const updateRisk = db.prepare(`
      UPDATE events
      SET risk_factors = ?, risk_explanation = ?, risk_confidence = ?,
          risk_score = ?, risk_level = ?, action_recommendation = ?,
          authorization_status = ?, identity_correlation = ?
      WHERE id = ?
    `);

    for (const row of unbackfilled) {
      const risk = assessRisk({
        destination: row.destination,
        port: row.port,
        classification: row.classification,
        classificationConfidence: row.confidence,
        sensitivityLabel: row.sensitivity_label,
        serviceApproval: row.approval_status,
        byteCount: row.byte_count,
        isAnomalySignal: Boolean(row.is_anomaly),
        userEmail: row.user_email,
        deviceLabel: row.device_name,
        explicitAuth: row.is_authorized ? 'authorized' : 'denied',
      });

      updateRisk.run(
        JSON.stringify(risk.factors),
        risk.explanation,
        risk.confidence,
        risk.score,
        risk.severity,
        risk.recommendation,
        risk.identityCorrelation.authStatus,
        JSON.stringify(risk.identityCorrelation),
        row.id
      );
    }
  }
}

// ── Audit helper ──────────────────────────────────────────────────────────────
export function appendAudit(
  db: Database.Database,
  actor: string,
  action: string,
  detail: object = {},
): void {
  const last = db.prepare(
    `SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1`
  ).get() as { entry_hash: string } | undefined;

  const prevHash = last?.entry_hash ?? '';
  const ts = new Date().toISOString();
  const content = `${prevHash}|${actor}|${action}|${JSON.stringify(detail)}|${ts}`;
  const entryHash = createHash('sha256').update(content).digest('hex');

  db.prepare(
    `INSERT INTO audit_log (actor, action, detail, prev_hash, entry_hash, created_at)
     VALUES (?, ?, ?, ?, ?, ?)`
  ).run(actor, action, JSON.stringify(detail), prevHash, entryHash, ts);
}

// ── Seed demo data ────────────────────────────────────────────────────────────
export function seedDemo(db: Database.Database): void {
  // ── Demo users ──────────────────────────────────────────────────────────────
  const users = [
    { username: 'demo-admin',   display_name: 'Demo Administrator', role: 'administrator' },
    { username: 'demo-analyst', display_name: 'Demo Analyst',        role: 'analyst'       },
    { username: 'demo-viewer',  display_name: 'Demo Viewer',         role: 'viewer'        },
  ];
  const insertUser = db.prepare(
    `INSERT OR IGNORE INTO demo_users (username, display_name, role)
     VALUES (@username, @display_name, @role)`
  );
  for (const u of users) insertUser.run(u);

  // ── Services ────────────────────────────────────────────────────────────────
  const services = [
    {
      name: 'OpenAI API & ChatGPT',
      provider: 'OpenAI',
      domains: JSON.stringify(['api.openai.com', 'chatgpt.com', 'platform.openai.com']),
      local_ports: JSON.stringify([]),
      service_type: 'Cloud AI',
      approval_status: 'Approved',
      notes: 'Enterprise account — approved via IT-2024-081.',
    },
    {
      name: 'Google Gemini & AI Studio',
      provider: 'Google',
      domains: JSON.stringify(['bard.google.com', 'gemini.google.com', 'generativelanguage.googleapis.com', 'ai.google.dev']),
      local_ports: JSON.stringify([]),
      service_type: 'Cloud AI',
      approval_status: 'Needs review',
      notes: 'Personal Google account detected; enterprise account not confirmed.',
    },
    {
      name: 'Claude (Anthropic)',
      provider: 'Anthropic',
      domains: JSON.stringify(['api.anthropic.com', 'claude.ai']),
      local_ports: JSON.stringify([]),
      service_type: 'Cloud AI',
      approval_status: 'Needs review',
      notes: 'Developer testing via direct API token.',
    },
    {
      name: 'Hugging Face Hub & Inference',
      provider: 'Hugging Face',
      domains: JSON.stringify(['huggingface.co', 'api-inference.huggingface.co']),
      local_ports: JSON.stringify([]),
      service_type: 'Cloud AI',
      approval_status: 'Needs review',
      notes: 'Open model weights and hosted inference API.',
    },
    {
      name: 'Mistral AI',
      provider: 'Mistral',
      domains: JSON.stringify(['api.mistral.ai', 'console.mistral.ai']),
      local_ports: JSON.stringify([]),
      service_type: 'Cloud AI',
      approval_status: 'Needs review',
      notes: 'European frontier model API platform.',
    },
    {
      name: 'Cohere Platform',
      provider: 'Cohere',
      domains: JSON.stringify(['api.cohere.ai', 'api.cohere.com']),
      local_ports: JSON.stringify([]),
      service_type: 'Cloud AI',
      approval_status: 'Needs review',
      notes: 'Enterprise NLP and RAG embedding endpoints.',
    },
    {
      name: 'Perplexity AI',
      provider: 'Perplexity',
      domains: JSON.stringify(['api.perplexity.ai', 'perplexity.ai']),
      local_ports: JSON.stringify([]),
      service_type: 'Cloud AI',
      approval_status: 'Unapproved',
      notes: 'Conversational research engine; unapproved for company source code.',
    },
    {
      name: 'Azure OpenAI Service (Tenant)',
      provider: 'Microsoft / Azure OpenAI',
      domains: JSON.stringify(['*.openai.azure.com']),
      local_ports: JSON.stringify([]),
      service_type: 'Cloud AI',
      approval_status: 'Approved',
      notes: 'Enterprise Microsoft tenant deployment for internal tools.',
    },
    {
      name: 'Ollama (possible local)',
      provider: 'Ollama / local',
      domains: JSON.stringify(['localhost', '127.0.0.1']),
      local_ports: JSON.stringify([11434]),
      service_type: 'Possible local AI',
      approval_status: 'Unapproved',
      notes: 'Port 11434 is commonly used by Ollama. A port match is only a clue — it does not confirm a model is running.',
    },
    {
      name: 'LM Studio (possible local)',
      provider: 'LM Studio / local',
      domains: JSON.stringify(['localhost', '127.0.0.1']),
      local_ports: JSON.stringify([1234]),
      service_type: 'Possible local AI',
      approval_status: 'Needs review',
      notes: 'Port 1234 is the default local OpenAI-compatible server port for LM Studio.',
    },
    {
      name: 'GitHub',
      provider: 'GitHub / Microsoft',
      domains: JSON.stringify(['github.com', 'api.github.com']),
      local_ports: JSON.stringify([]),
      service_type: 'Ordinary web',
      approval_status: 'Approved',
      notes: 'Standard code repository; ordinary developer traffic.',
    },
    {
      name: 'Microsoft 365',
      provider: 'Microsoft',
      domains: JSON.stringify(['microsoft.com', 'office.com']),
      local_ports: JSON.stringify([]),
      service_type: 'Ordinary web',
      approval_status: 'Approved',
      notes: 'Corporate productivity suite.',
    },
    {
      name: 'Unknown internal host',
      provider: 'Unknown',
      domains: JSON.stringify(['192.168.1.55']),
      local_ports: JSON.stringify([8080]),
      service_type: 'Possible local AI',
      approval_status: 'Unknown',
      notes: 'Internal IP with unrecognised port. Classification uncertain.',
    },
  ];
  const insertSvc = db.prepare(
    `INSERT OR IGNORE INTO services
       (name, provider, domains, local_ports, service_type, approval_status, notes)
     VALUES
       (@name, @provider, @domains, @local_ports, @service_type, @approval_status, @notes)`
  );
  for (const s of services) insertSvc.run(s);

  // ── Synthetic people ────────────────────────────────────────────────────────
  const people = [
    { display_name: 'Alex Mercer',   demo_email: 'alex.mercer@demo.aura',   department: 'Engineering',  role_title: 'Senior Developer' },
    { display_name: 'Jordan Riley',  demo_email: 'jordan.riley@demo.aura',  department: 'Data Science',  role_title: 'ML Engineer' },
    { display_name: 'Sam Patel',     demo_email: 'sam.patel@demo.aura',     department: 'Finance',       role_title: 'Financial Analyst' },
    { display_name: 'Casey Quinn',   demo_email: 'casey.quinn@demo.aura',   department: 'Legal',         role_title: 'Compliance Officer' },
    { display_name: 'Morgan Hayes',  demo_email: 'morgan.hayes@demo.aura',  department: 'Engineering',  role_title: 'DevOps Engineer' },
  ];
  const insertPerson = db.prepare(
    `INSERT OR IGNORE INTO synthetic_people
       (display_name, demo_email, department, role_title)
     VALUES
       (@display_name, @demo_email, @department, @role_title)`
  );
  for (const p of people) insertPerson.run(p);

  // ── Synthetic devices ────────────────────────────────────────────────────────
  const devicesRaw = [
    { label: 'DEVICE-SYN-042', person_name: 'Alex Mercer',   os_label: 'macOS 14 (demo)' },
    { label: 'DEVICE-SYN-018', person_name: 'Jordan Riley',  os_label: 'Ubuntu 22 (demo)' },
    { label: 'DEVICE-SYN-091', person_name: 'Sam Patel',     os_label: 'Windows 11 (demo)' },
    { label: 'DEVICE-SYN-007', person_name: 'Casey Quinn',   os_label: 'macOS 13 (demo)' },
    { label: 'DEVICE-SYN-033', person_name: 'Morgan Hayes',  os_label: 'Windows 11 (demo)' },
  ];
  const getPerson = db.prepare(`SELECT id FROM synthetic_people WHERE display_name = ? LIMIT 1`);
  const insertDevice = db.prepare(
    `INSERT OR IGNORE INTO synthetic_devices (label, person_id, os_label)
     VALUES (?, ?, ?)`
  );
  for (const d of devicesRaw) {
    const person = getPerson.get(d.person_name) as { id: number } | undefined;
    insertDevice.run(d.label, person?.id ?? null, d.os_label);
  }

  // ── Permitted services per person ────────────────────────────────────────────
  const getSvc   = db.prepare(`SELECT id FROM services WHERE name = ? LIMIT 1`);
  const checkPPS = db.prepare(`SELECT 1 FROM person_permitted_services WHERE person_id=? AND service_id=? LIMIT 1`);
  const insertPPS = db.prepare(`INSERT OR IGNORE INTO person_permitted_services VALUES (?,?)`);

  const permissions: Record<string, string[]> = {
    'Alex Mercer':  ['OpenAI API', 'GitHub'],
    'Jordan Riley': ['OpenAI API', 'GitHub', 'Claude (Anthropic)'],
    'Sam Patel':    ['GitHub'],
    'Casey Quinn':  ['GitHub'],
    'Morgan Hayes': ['GitHub', 'OpenAI API'],
  };
  for (const [name, svcNames] of Object.entries(permissions)) {
    const person = getPerson.get(name) as { id: number } | undefined;
    if (!person) continue;
    for (const svcName of svcNames) {
      const svc = getSvc.get(svcName) as { id: number } | undefined;
      if (!svc) continue;
      if (!checkPPS.get(person.id, svc.id)) {
        insertPPS.run(person.id, svc.id);
      }
    }
  }

  // ── Events ───────────────────────────────────────────────────────────────────
  type EventSeed = {
    occurred_at: string; source_label: string; source_type: string;
    device_label: string; person_name: string; user_email: string;
    destination: string; port: number | null; service_name: string | null;
    classification: string; confidence: number; evidence: string;
    approval_status: string; risk_level: string; risk_score: number;
    action_recommendation: string; byte_count: number; sensitivity_label: string;
    evidence_tags: string[]; ground_truth_label: string | null; expected_provider: string | null;
  };

  const getDevice = db.prepare(`SELECT id FROM synthetic_devices WHERE label = ? LIMIT 1`);

  const eventSeeds: EventSeed[] = [
    {
      occurred_at: '2024-10-07T10:42:00Z', source_label: 'DNS-sim', source_type: 'simulation',
      device_label: 'DEVICE-SYN-042', person_name: 'Alex Mercer', user_email: 'alex.mercer@demo.aura',
      destination: 'api.openai.com', port: 443, service_name: 'OpenAI API & ChatGPT',
      classification: 'Likely cloud AI', confidence: 0.95,
      evidence: 'Destination matches registered Cloud AI signature for OpenAI API & ChatGPT (api.openai.com).',
      approval_status: 'Approved', risk_level: 'low', risk_score: 12,
      action_recommendation: 'Allow', byte_count: 8200, sensitivity_label: 'Internal',
      evidence_tags: ['approved-service','authorized-device'],
      ground_truth_label: 'ai', expected_provider: 'OpenAI',
    },
    {
      occurred_at: '2024-10-07T10:38:00Z', source_label: 'flow-sim', source_type: 'simulation',
      device_label: 'DEVICE-SYN-042', person_name: 'Alex Mercer', user_email: 'alex.mercer@demo.aura',
      destination: 'localhost', port: 11434, service_name: 'Ollama (possible local)',
      classification: 'Possible local AI', confidence: 0.85,
      evidence: 'Port 11434 is the default runtime port for Ollama local LLMs. Note: port match is a clue, not proof.',
      approval_status: 'Unapproved', risk_level: 'high', risk_score: 82,
      action_recommendation: 'Would block (sample)', byte_count: 45000, sensitivity_label: 'Confidential',
      evidence_tags: ['unapproved-service','high-data-volume','local-ai-port'],
      ground_truth_label: 'ai', expected_provider: 'Ollama',
    },
    {
      occurred_at: '2024-10-07T10:31:00Z', source_label: 'DNS-sim', source_type: 'simulation',
      device_label: 'DEVICE-SYN-018', person_name: 'Jordan Riley', user_email: 'jordan.riley@demo.aura',
      destination: 'github.com', port: 443, service_name: 'GitHub',
      classification: 'Ordinary web', confidence: 0.95,
      evidence: 'Destination matches registered ordinary web service GitHub (github.com).',
      approval_status: 'Approved', risk_level: 'low', risk_score: 5,
      action_recommendation: 'Allow', byte_count: 1500, sensitivity_label: 'Public',
      evidence_tags: ['approved-service'],
      ground_truth_label: 'benign', expected_provider: null,
    },
    {
      occurred_at: '2024-10-07T10:17:00Z', source_label: 'DNS-sim', source_type: 'simulation',
      device_label: 'DEVICE-SYN-018', person_name: 'Jordan Riley', user_email: 'jordan.riley@demo.aura',
      destination: 'bard.google.com', port: 443, service_name: 'Google Gemini & AI Studio',
      classification: 'Likely cloud AI', confidence: 0.95,
      evidence: 'Destination matches registered Cloud AI signature for Google Gemini & AI Studio (bard.google.com).',
      approval_status: 'Needs review', risk_level: 'medium', risk_score: 55,
      action_recommendation: 'Review', byte_count: 12400, sensitivity_label: 'Internal',
      evidence_tags: ['needs-review','possible-personal-account'],
      ground_truth_label: 'ai', expected_provider: 'Google',
    },
    {
      occurred_at: '2024-10-07T09:54:00Z', source_label: 'flow-sim', source_type: 'simulation',
      device_label: 'DEVICE-SYN-091', person_name: 'Sam Patel', user_email: 'sam.patel@demo.aura',
      destination: '192.168.1.55', port: 8080, service_name: 'Unknown internal host',
      classification: 'Possible local AI', confidence: 0.40,
      evidence: 'Generic developer/HTTP port 8080 on local address. Low-confidence clue only.',
      approval_status: 'Unknown', risk_level: 'critical', risk_score: 91,
      action_recommendation: 'Would block (sample)', byte_count: 98000, sensitivity_label: 'Restricted',
      evidence_tags: ['unknown-destination','restricted-data','unapproved-device'],
      ground_truth_label: null, expected_provider: null,
    },
    {
      occurred_at: '2024-10-05T16:10:00Z', source_label: 'DNS-sim', source_type: 'simulation',
      device_label: 'DEVICE-SYN-007', person_name: 'Casey Quinn', user_email: 'casey.quinn@demo.aura',
      destination: 'api.anthropic.com', port: 443, service_name: 'Claude (Anthropic)',
      classification: 'Likely cloud AI', confidence: 0.95,
      evidence: 'Destination matches registered Cloud AI signature for Claude (Anthropic) (api.anthropic.com).',
      approval_status: 'Needs review', risk_level: 'medium', risk_score: 48,
      action_recommendation: 'Review', byte_count: 5600, sensitivity_label: 'Internal',
      evidence_tags: ['needs-review'],
      ground_truth_label: 'ai', expected_provider: 'Anthropic',
    },
  ];

  const insertEvent = db.prepare(
    `INSERT OR IGNORE INTO events
       (occurred_at, source_label, source_type, device_id, person_id, device_name, user_email,
        destination, port, service_id, classification, confidence, evidence,
        approval_status, risk_level, risk_score, action_recommendation,
        byte_count, sensitivity_label, evidence_tags, ground_truth_label, expected_provider,
        risk_factors, risk_explanation, risk_confidence, authorization_status, identity_correlation)
     VALUES
       (@occurred_at, @source_label, @source_type, @device_id, @person_id, @device_name, @user_email,
        @destination, @port, @service_id, @classification, @confidence, @evidence,
        @approval_status, @risk_level, @risk_score, @action_recommendation,
        @byte_count, @sensitivity_label, @evidence_tags, @ground_truth_label, @expected_provider,
        @risk_factors, @risk_explanation, @risk_confidence, @authorization_status, @identity_correlation)`
  );

  for (const e of eventSeeds) {
    const device  = getDevice.get(e.device_label) as { id: number; label: string; person_id: number | null } | undefined;
    const person  = getPerson.get(e.person_name)  as { id: number; display_name: string; demo_email: string } | undefined;
    const service = e.service_name ? getSvc.get(e.service_name) as { id: number } | undefined : undefined;
    const isPermitted = person && service ? Boolean(checkPPS.get(person.id, service.id)) : false;

    const risk = assessRisk({
      destination: e.destination,
      port: e.port,
      classification: e.classification,
      classificationConfidence: e.confidence,
      sensitivityLabel: e.sensitivity_label,
      serviceApproval: e.approval_status,
      byteCount: e.byte_count,
      userEmail: e.user_email,
      userName: e.person_name,
      deviceLabel: e.device_label,
      syntheticUser: person ? { id: person.id, display_name: person.display_name, demo_email: person.demo_email } : null,
      syntheticDevice: device ? { id: device.id, label: device.label, person_id: device.person_id } : null,
      isServicePermittedForUser: isPermitted,
    });

    insertEvent.run({
      ...e,
      device_id:            device?.id  ?? null,
      person_id:            person?.id  ?? null,
      device_name:          e.device_label,
      service_id:           service?.id ?? null,
      evidence_tags:        JSON.stringify(e.evidence_tags),
      risk_level:           risk.severity,
      risk_score:           risk.score,
      action_recommendation: risk.recommendation,
      risk_factors:         JSON.stringify(risk.factors),
      risk_explanation:     risk.explanation,
      risk_confidence:      risk.confidence,
      authorization_status: risk.identityCorrelation.authStatus,
      identity_correlation: JSON.stringify(risk.identityCorrelation),
    });

    // Update existing rows with explainable risk fields
    db.prepare(`
      UPDATE events
      SET classification = ?, confidence = ?, evidence = ?, source_type = 'simulation', expected_provider = ?,
          risk_level = ?, risk_score = ?, action_recommendation = ?, risk_factors = ?,
          risk_explanation = ?, risk_confidence = ?, authorization_status = ?, identity_correlation = ?
      WHERE destination = ? AND (source_type = 'simulation' OR source_label LIKE '%sim%')
    `).run(
      e.classification, e.confidence, e.evidence, e.expected_provider,
      risk.severity, risk.score, risk.recommendation, JSON.stringify(risk.factors),
      risk.explanation, risk.confidence, risk.identityCorrelation.authStatus, JSON.stringify(risk.identityCorrelation),
      e.destination
    );
  }

  // ── Incidents ────────────────────────────────────────────────────────────────
  const getEventByDest = db.prepare(
    `SELECT id FROM events WHERE destination = ? AND port = ? ORDER BY id DESC LIMIT 1`
  );

  type IncidentSeed = {
    severity: string; title: string; destination: string; port: number | null;
    device_label: string; person_name: string; status: string;
  };

  const incidentSeeds: IncidentSeed[] = [
    {
      severity: 'high', status: 'Open',
      title: 'Confidential data sent to unapproved local AI endpoint',
      destination: 'localhost', port: 11434,
      device_label: 'DEVICE-SYN-042', person_name: 'Alex Mercer',
    },
    {
      severity: 'medium', status: 'Under review',
      title: 'Unreviewed cloud AI service detected on managed device',
      destination: 'bard.google.com', port: 443,
      device_label: 'DEVICE-SYN-018', person_name: 'Jordan Riley',
    },
    {
      severity: 'critical', status: 'Open',
      title: 'Restricted data label observed near unknown internal host',
      destination: '192.168.1.55', port: 8080,
      device_label: 'DEVICE-SYN-091', person_name: 'Sam Patel',
    },
    {
      severity: 'low', status: 'Resolved',
      title: 'New AI service observed — pending classification',
      destination: 'api.anthropic.com', port: 443,
      device_label: 'DEVICE-SYN-007', person_name: 'Casey Quinn',
    },
  ];

  const insertIncident = db.prepare(
    `INSERT OR IGNORE INTO incidents
       (severity, title, event_id, destination, device_id, person_id, status)
     VALUES
       (@severity, @title, @event_id, @destination, @device_id, @person_id, @status)`
  );

  for (const inc of incidentSeeds) {
    const event  = inc.port != null
      ? getEventByDest.get(inc.destination, inc.port) as { id: number } | undefined
      : undefined;
    const device = getDevice.get(inc.device_label) as { id: number } | undefined;
    const person = getPerson.get(inc.person_name)  as { id: number } | undefined;
    insertIncident.run({
      severity:    inc.severity,
      title:       inc.title,
      event_id:    event?.id  ?? null,
      destination: inc.destination,
      device_id:   device?.id ?? null,
      person_id:   person?.id ?? null,
      status:      inc.status,
    });
  }

  // ── Demo policies ─────────────────────────────────────────────────────────────
  const policySeeds = [
    {
      name: 'high_risk_threshold',
      description: 'Risk score at or above this value is treated as high risk.',
      value: '70',
    },
    {
      name: 'auto_block_unapproved',
      description: 'Whether to automatically recommend blocking unapproved services (sample outcome only).',
      value: 'false',
    },
    {
      name: 'alert_on_restricted_label',
      description: 'Raise an incident when a Restricted sensitivity label is observed.',
      value: 'true',
    },
    {
      name: 'risk_thresholds',
      description: 'Configurable score cutoff thresholds: Low < medium < high < critical <= 100.',
      value: JSON.stringify({
        medium_threshold: 25,
        high_threshold: 50,
        critical_threshold: 75,
      }),
    },
    {
      name: 'demo_weights',
      description: 'Documented additive weights per risk engine factor (0-50 points each).',
      value: JSON.stringify({
        sensitivity_restricted: 35,
        sensitivity_confidential: 25,
        sensitivity_internal: 10,
        service_unapproved: 20,
        service_under_review: 12,
        auth_denied_or_mismatch: 20,
        high_transfer_volume: 18,
        anomaly_signal_flagged: 10,
      }),
    },
    {
      name: 'volume_threshold_mb',
      description: 'Data transfer volume anomaly threshold in MB.',
      value: '5',
    },
    {
      name: 'severity_recommendations',
      description: 'Current response recommendation text mapped by risk severity level.',
      value: JSON.stringify({
        low: 'Allow or record for visibility',
        medium: 'Warn / review before sending',
        high: 'Review promptly',
        critical: 'Would block before transmission (simulation)',
      }),
    },
  ];
  const insertPolicy = db.prepare(
    `INSERT OR IGNORE INTO policies (name, description, value)
     VALUES (@name, @description, @value)`
  );
  for (const p of policySeeds) insertPolicy.run(p);

  // Sync automatic incidents from qualifying high/critical events
  syncIncidentsFromEvents(db, 'system');

  // ── Phase 7: Data-sharing policy rules ──────────────────────────────────────
  const sharingRules = [
    {
      rule_name: 'Block credentials to unapproved AI',
      data_types: JSON.stringify(['API Keys', 'Password', 'Private Cryptographic Keys']),
      allowed_tools: JSON.stringify(['OpenAI API & ChatGPT', 'Azure OpenAI Service (Tenant)']),
      blocked_tools: JSON.stringify(['*']),
      action: 'block',
      description: 'Prevents credentials, passwords, and private keys from being shared with unapproved AI services. Approved enterprise tools are exempt.',
    },
    {
      rule_name: 'Warn on PII to external services',
      data_types: JSON.stringify(['Email Addresses', 'Phone Numbers', 'Payment Card Numbers']),
      allowed_tools: JSON.stringify([]),
      blocked_tools: JSON.stringify(['*']),
      action: 'warn',
      description: 'Warns when personal identifiable information (PII) is detected in transfers to any external service.',
    },
    {
      rule_name: 'Block payment card data everywhere',
      data_types: JSON.stringify(['Payment Card Numbers']),
      allowed_tools: JSON.stringify([]),
      blocked_tools: JSON.stringify(['*']),
      action: 'block',
      description: 'Blocks any file transfer containing payment card numbers (PCI DSS compliance). No exceptions.',
    },
    {
      rule_name: 'Restrict source code sharing',
      data_types: JSON.stringify(['Sensitive Business Terms']),
      allowed_tools: JSON.stringify(['GitHub']),
      blocked_tools: JSON.stringify(['*']),
      action: 'warn',
      description: 'Warns when sensitive business terms or source code markers are shared with non-approved code hosting services.',
    },
    {
      rule_name: 'Allow internal data to approved tools',
      data_types: JSON.stringify(['Internal Network Addresses']),
      allowed_tools: JSON.stringify(['OpenAI API & ChatGPT', 'GitHub', 'Azure OpenAI Service (Tenant)']),
      blocked_tools: JSON.stringify([]),
      action: 'allow',
      description: 'Internal network address references are allowed to be shared with approved enterprise tools.',
    },
  ];

  const insertSharingRule = db.prepare(`
    INSERT OR IGNORE INTO data_sharing_rules
      (rule_name, data_types, allowed_tools, blocked_tools, action, description)
    VALUES (@rule_name, @data_types, @allowed_tools, @blocked_tools, @action, @description)
  `);
  for (const r of sharingRules) insertSharingRule.run(r);

  // ── Initial audit entry ───────────────────────────────────────────────────────
  const existingAudit = db.prepare(`SELECT COUNT(*) as cnt FROM audit_log`).get() as { cnt: number };
  if (existingAudit.cnt === 0) {
    appendAudit(db, 'system', 'db.seed', { note: 'Initial demo seed applied' });
  }
}

/**
 * Automatically creates review incidents from qualifying risk events.
 * RULES:
 * 1. High or Critical risk events create an incident.
 * 2. Events with a simulated "Would block" recommendation create an incident.
 * 3. Low-risk events do NOT create incidents.
 * 4. Deduplicates against existing incidents: if event_id already has an incident, skip.
 * 5. Strict privacy: only metadata and categories used; no prompts or secrets.
 */
export function syncIncidentsFromEvents(
  db: Database.Database,
  actor: string = 'system',
): { createdCount: number } {
  const candidates = db.prepare(`
    SELECT e.id, e.risk_level, e.action_recommendation, e.destination, e.port,
           e.device_id, e.person_id, e.device_name, e.user_email,
           e.sensitivity_label, e.approval_status, e.risk_score, e.risk_explanation,
           e.evidence, e.created_at, e.occurred_at
    FROM events e
    LEFT JOIN incidents i ON i.event_id = e.id
    WHERE i.id IS NULL
      AND (
        e.risk_level IN ('high', 'critical')
        OR e.action_recommendation LIKE '%Would block%'
      )
    ORDER BY e.id ASC
  `).all() as Array<{
    id: number;
    risk_level: string;
    action_recommendation: string;
    destination: string;
    port: number | null;
    device_id: number | null;
    person_id: number | null;
    device_name: string | null;
    user_email: string | null;
    sensitivity_label: string;
    approval_status: string;
    risk_score: number;
    risk_explanation: string | null;
    evidence: string | null;
    created_at: string;
    occurred_at: string;
  }>;

  if (candidates.length === 0) {
    return { createdCount: 0 };
  }

  const insertStmt = db.prepare(`
    INSERT INTO incidents (
      severity, title, event_id, destination, device_id, person_id,
      status, notes, simulated_actions, is_demo, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, 'Open', '[]', '[]', 1, datetime('now'), datetime('now'))
  `);

  let count = 0;
  for (const row of candidates) {
    const sev = row.risk_level === 'critical' ? 'critical' : 'high';
    const isWouldBlock = row.action_recommendation.includes('Would block');

    let title = '';
    if (row.risk_level === 'critical') {
      title = `${row.sensitivity_label} data observed near ${row.approval_status.toLowerCase()} destination (${row.destination})`;
    } else if (isWouldBlock) {
      title = `Simulated block recommendation for ${row.destination}`;
    } else {
      title = `Elevated ${row.risk_level} risk event observed: ${row.destination}`;
    }

    const info = insertStmt.run(
      sev,
      title,
      row.id,
      row.destination,
      row.device_id,
      row.person_id,
    );

    appendAudit(db, actor, 'incident.create', {
      incident_id: Number(info.lastInsertRowid),
      event_id: row.id,
      severity: sev,
      destination: row.destination,
    });
    count++;
  }

  return { createdCount: count };
}
