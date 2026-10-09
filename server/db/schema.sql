-- ─── AURA Database Schema ────────────────────────────────────────────────────
-- Prototype database for demo purposes only.
-- All seeded records are synthetic / fictional.
-- Run via: node server/db/migrate.js (auto-run on server start)

PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

-- ── Demo users ────────────────────────────────────────────────────────────────
-- Stores demo role accounts only. No real credentials.
CREATE TABLE IF NOT EXISTS demo_users (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  username    TEXT    NOT NULL UNIQUE,
  display_name TEXT   NOT NULL,
  role        TEXT    NOT NULL CHECK(role IN ('administrator','analyst','viewer')),
  is_demo     INTEGER NOT NULL DEFAULT 1,  -- always 1; remind future devs
  created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- ── Sessions ──────────────────────────────────────────────────────────────────
-- token_hash: SHA-256 hex of the raw session token (raw token never stored).
CREATE TABLE IF NOT EXISTS sessions (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id      INTEGER NOT NULL REFERENCES demo_users(id) ON DELETE CASCADE,
  token_hash   TEXT    NOT NULL UNIQUE,
  expires_at   TEXT    NOT NULL,
  created_at   TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- ── AI service registry ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS services (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  name            TEXT    NOT NULL,
  provider        TEXT    NOT NULL,
  domains         TEXT    NOT NULL,  -- JSON array of strings
  local_ports     TEXT    NOT NULL DEFAULT '[]',  -- JSON array of integers
  service_type    TEXT    NOT NULL CHECK(service_type IN ('Cloud AI','Possible local AI','Ordinary web')),
  approval_status TEXT    NOT NULL CHECK(approval_status IN ('Approved','Needs review','Unapproved','Unknown')),
  notes           TEXT,
  is_demo         INTEGER NOT NULL DEFAULT 1,
  updated_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- ── Synthetic people ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS synthetic_people (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  display_name    TEXT NOT NULL,
  demo_email      TEXT NOT NULL UNIQUE,
  department      TEXT NOT NULL,
  role_title      TEXT NOT NULL,
  is_demo         INTEGER NOT NULL DEFAULT 1
);

-- ── Synthetic devices ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS synthetic_devices (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  label           TEXT NOT NULL UNIQUE,
  person_id       INTEGER REFERENCES synthetic_people(id) ON DELETE SET NULL,
  os_label        TEXT NOT NULL,
  is_demo         INTEGER NOT NULL DEFAULT 1
);

-- ── Permitted services per person ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS person_permitted_services (
  person_id   INTEGER NOT NULL REFERENCES synthetic_people(id) ON DELETE CASCADE,
  service_id  INTEGER NOT NULL REFERENCES services(id) ON DELETE CASCADE,
  PRIMARY KEY (person_id, service_id)
);

-- ── Events ────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS events (
  id                  INTEGER PRIMARY KEY AUTOINCREMENT,
  occurred_at         TEXT    NOT NULL,
  source_label        TEXT    NOT NULL,   -- e.g. 'DNS-sim', 'flow-sim', 'CSV-import'
  source_type         TEXT    NOT NULL DEFAULT 'simulation' CHECK(source_type IN ('simulation','csv_import')),
  device_id           INTEGER REFERENCES synthetic_devices(id) ON DELETE SET NULL,
  person_id           INTEGER REFERENCES synthetic_people(id) ON DELETE SET NULL,
  device_name         TEXT,               -- from metadata / CSV
  user_email          TEXT,               -- from metadata / CSV
  src_ip              TEXT,
  dst_ip              TEXT,
  destination         TEXT    NOT NULL,   -- domain or IP:port
  port                INTEGER,
  service_id          INTEGER REFERENCES services(id) ON DELETE SET NULL,
  classification      TEXT    NOT NULL DEFAULT 'Uncertain' CHECK(classification IN ('Likely cloud AI','Possible local AI','Ordinary web','Uncertain')),
  confidence          REAL    NOT NULL DEFAULT 0.0 CHECK(confidence BETWEEN 0.0 AND 1.0),
  evidence            TEXT,               -- clear rationale string
  approval_status     TEXT    NOT NULL DEFAULT 'Unknown',
  risk_level          TEXT    NOT NULL DEFAULT 'low' CHECK(risk_level IN ('low','medium','high','critical')),
  risk_score          INTEGER NOT NULL DEFAULT 0 CHECK(risk_score BETWEEN 0 AND 100),
  action_recommendation TEXT  NOT NULL DEFAULT 'Review',
  byte_count          INTEGER NOT NULL DEFAULT 0,
  sensitivity_label   TEXT    NOT NULL DEFAULT 'Public' CHECK(sensitivity_label IN ('Public','Internal','Confidential','Restricted')),
  evidence_tags       TEXT    NOT NULL DEFAULT '[]',  -- JSON array
  is_anomaly          INTEGER NOT NULL DEFAULT 0,
  is_authorized       INTEGER NOT NULL DEFAULT 0,
  risk_factors        TEXT    NOT NULL DEFAULT '[]',  -- JSON array of RiskFactor objects
  risk_explanation    TEXT,                           -- Plain English explanation string
  risk_confidence     TEXT    NOT NULL DEFAULT 'Medium', -- 'High' | 'Medium' | 'Low'
  authorization_status TEXT   NOT NULL DEFAULT 'unknown', -- 'authorized' | 'denied' | 'unknown' | 'mismatch'
  identity_correlation TEXT   NOT NULL DEFAULT '{}',  -- JSON object of IdentityCorrelation
  ground_truth_label  TEXT,
  expected_provider   TEXT,
  is_demo             INTEGER NOT NULL DEFAULT 1,
  created_at          TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- ── Incidents ─────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS incidents (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  severity        TEXT    NOT NULL CHECK(severity IN ('low','medium','high','critical')),
  title           TEXT    NOT NULL,
  event_id        INTEGER REFERENCES events(id) ON DELETE SET NULL,
  destination     TEXT    NOT NULL,
  device_id       INTEGER REFERENCES synthetic_devices(id) ON DELETE SET NULL,
  person_id       INTEGER REFERENCES synthetic_people(id) ON DELETE SET NULL,
  status          TEXT    NOT NULL DEFAULT 'Open' CHECK(status IN ('Open','Investigating','Under review','Resolved','False Positive')),
  notes           TEXT    NOT NULL DEFAULT '[]', -- JSON array of note entries: { id, actor, text, timestamp }
  simulated_actions TEXT  NOT NULL DEFAULT '[]', -- JSON array of simulated responses
  is_demo         INTEGER NOT NULL DEFAULT 1,
  created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
  updated_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- ── Demo policies (editable in later phases) ──────────────────────────────────
CREATE TABLE IF NOT EXISTS policies (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  name        TEXT    NOT NULL UNIQUE,
  description TEXT    NOT NULL,
  value       TEXT    NOT NULL,  -- JSON value
  is_demo     INTEGER NOT NULL DEFAULT 1,
  updated_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- ── Audit history (append-only) ───────────────────────────────────────────────
-- tamper-evident (hash chain) — note: not tamper-proof; relies on DB integrity.
CREATE TABLE IF NOT EXISTS audit_log (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  actor       TEXT    NOT NULL,   -- demo username or 'system'
  action      TEXT    NOT NULL,   -- e.g. 'session.create', 'policy.update'
  detail      TEXT    NOT NULL DEFAULT '{}',  -- JSON, no sensitive content
  prev_hash   TEXT    NOT NULL DEFAULT '',
  entry_hash  TEXT    NOT NULL DEFAULT '',    -- SHA-256 of (prev_hash|actor|action|detail|ts)
  created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- ── Data-Sharing Policy Rules ────────────────────────────────────────────────
-- Configurable rules: which data types may/may not be shared with which tools.
-- Administrators create/edit rules; employees see applicable rules.
CREATE TABLE IF NOT EXISTS data_sharing_rules (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  rule_name       TEXT    NOT NULL UNIQUE,
  data_types      TEXT    NOT NULL DEFAULT '[]',  -- JSON array: e.g. ["API Keys","Email Addresses"]
  allowed_tools   TEXT    NOT NULL DEFAULT '[]',  -- JSON array of service names or '*'
  blocked_tools   TEXT    NOT NULL DEFAULT '[]',  -- JSON array of service names or '*'
  action          TEXT    NOT NULL CHECK(action IN ('allow','warn','block')) DEFAULT 'warn',
  description     TEXT    NOT NULL DEFAULT '',
  is_active       INTEGER NOT NULL DEFAULT 1,
  is_demo         INTEGER NOT NULL DEFAULT 1,
  created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
  updated_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- ── File Inspections (outbound) ──────────────────────────────────────────────
-- Records metadata from outbound file/data transfer scans.
-- STRICT PRIVACY: never stores raw file content, only detection metadata.
CREATE TABLE IF NOT EXISTS file_inspections (
  id                  INTEGER PRIMARY KEY AUTOINCREMENT,
  filename            TEXT    NOT NULL,
  file_size_bytes     INTEGER NOT NULL DEFAULT 0,
  file_type           TEXT    NOT NULL DEFAULT 'unknown',
  destination         TEXT    NOT NULL,
  direction           TEXT    NOT NULL DEFAULT 'outbound' CHECK(direction IN ('outbound','inbound')),
  detected_types      TEXT    NOT NULL DEFAULT '[]',  -- JSON array of matched data categories
  matched_rules       TEXT    NOT NULL DEFAULT '[]',  -- JSON array of rule_name strings
  risk_level          TEXT    NOT NULL DEFAULT 'low' CHECK(risk_level IN ('low','medium','high','critical')),
  action_taken        TEXT    NOT NULL DEFAULT 'allowed' CHECK(action_taken IN ('allowed','warned','blocked','quarantined')),
  action_reason       TEXT    NOT NULL DEFAULT '',
  limitations         TEXT    NOT NULL DEFAULT '',     -- what the system cannot determine
  inspector           TEXT    NOT NULL DEFAULT 'local' CHECK(inspector IN ('local','proxy')),
  actor               TEXT    NOT NULL DEFAULT 'system',
  person_id           INTEGER REFERENCES synthetic_people(id) ON DELETE SET NULL,
  is_demo             INTEGER NOT NULL DEFAULT 1,
  created_at          TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- ── Transfer Attempt Tracking ────────────────────────────────────────────────
-- Flags repeated attempts to send blocked/restricted data.
-- Groups by person + destination + data_type for repeat counting.
-- Does NOT automatically label anyone as malicious.
CREATE TABLE IF NOT EXISTS transfer_attempts (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  person_id       INTEGER REFERENCES synthetic_people(id) ON DELETE SET NULL,
  person_email    TEXT,
  destination     TEXT    NOT NULL,
  data_type       TEXT    NOT NULL,        -- e.g. 'API Keys & Access Tokens'
  matched_rule    TEXT    NOT NULL,        -- rule_name that was violated
  attempt_count   INTEGER NOT NULL DEFAULT 1,
  last_attempt_at TEXT    NOT NULL DEFAULT (datetime('now')),
  flagged_for_review INTEGER NOT NULL DEFAULT 0,
  review_note     TEXT,
  is_demo         INTEGER NOT NULL DEFAULT 1,
  created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- ── Proxy / Gateway Inspections ──────────────────────────────────────────────
-- Simulated second-layer outbound inspection via proxy/gateway.
-- Records what could and could not be inspected.
CREATE TABLE IF NOT EXISTS proxy_inspections (
  id                  INTEGER PRIMARY KEY AUTOINCREMENT,
  inspection_id       INTEGER REFERENCES file_inspections(id) ON DELETE SET NULL,
  proxy_layer         TEXT    NOT NULL DEFAULT 'simulated-gateway',
  can_inspect         INTEGER NOT NULL DEFAULT 1,  -- 1 = inspectable, 0 = encrypted/opaque
  inspection_note     TEXT    NOT NULL DEFAULT '',
  detected_types      TEXT    NOT NULL DEFAULT '[]',
  action_taken        TEXT    NOT NULL DEFAULT 'allowed' CHECK(action_taken IN ('allowed','warned','blocked')),
  limitation          TEXT    NOT NULL DEFAULT '',  -- what proxy cannot see
  is_demo             INTEGER NOT NULL DEFAULT 1,
  created_at          TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- ── Incoming Traffic Inspections ─────────────────────────────────────────────
-- Simulated inbound file/transfer malware and risk checks.
CREATE TABLE IF NOT EXISTS incoming_inspections (
  id                  INTEGER PRIMARY KEY AUTOINCREMENT,
  filename            TEXT    NOT NULL,
  file_size_bytes     INTEGER NOT NULL DEFAULT 0,
  source_origin       TEXT    NOT NULL DEFAULT 'unknown',
  detected_risks      TEXT    NOT NULL DEFAULT '[]',   -- JSON array of risk descriptions
  risk_level          TEXT    NOT NULL DEFAULT 'low' CHECK(risk_level IN ('low','medium','high','critical')),
  action_taken        TEXT    NOT NULL DEFAULT 'allowed' CHECK(action_taken IN ('allowed','quarantined','blocked')),
  action_reason       TEXT    NOT NULL DEFAULT '',
  malware_indicators  TEXT    NOT NULL DEFAULT '[]',   -- JSON array of indicator strings
  is_demo             INTEGER NOT NULL DEFAULT 1,
  created_at          TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- ── Prompt Lab Scan Records (Privacy-first metadata only) ──────────────────────
-- STRICT PRIVACY GUARANTEE:
-- Never stores raw prompt text, redacted previews, or content hashes.
-- Stores only high-level detection metadata and policy outcomes.
CREATE TABLE IF NOT EXISTS prompt_scans (
  id                      INTEGER PRIMARY KEY AUTOINCREMENT,
  scanned_at              TEXT    NOT NULL,
  actor                   TEXT    NOT NULL,
  destination             TEXT    NOT NULL,
  destination_status      TEXT    NOT NULL DEFAULT 'Unknown',
  categories              TEXT    NOT NULL DEFAULT '[]',  -- JSON array of category names
  sensitivity_suggestion  TEXT    NOT NULL DEFAULT 'Internal',
  policy_outcome          TEXT    NOT NULL CHECK(policy_outcome IN ('allow_caution','warn','would_block')),
  char_count              INTEGER NOT NULL DEFAULT 0,
  created_at              TEXT    NOT NULL DEFAULT (datetime('now'))
);
