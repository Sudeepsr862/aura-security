// ─── Incidents Routes ─────────────────────────────────────────────────────────
// Comprehensive incident review workflow, notes, and simulated responses.
// Enforces role-based permissions:
// - Administrators and Analysts may update status, add notes, and trigger simulated actions.
// - Viewers have read-only access (PATCH / POST return HTTP 403 Forbidden).
// - All response actions remain simulated inside AURA.

import { Router } from 'express';
import { requireAuth, requireRole } from '../middleware/auth.js';
import { appendAudit } from '../db/database.js';

export const incidentsRouter = Router();

export type IncidentStatus = 'Open' | 'Investigating' | 'Resolved' | 'False Positive' | 'Under review';
export const VALID_STATUSES: IncidentStatus[] = ['Open', 'Investigating', 'Resolved', 'False Positive', 'Under review'];

export interface IncidentNote {
  id: string;
  actor: string;
  role: string;
  text: string;
  created_at: string;
}

export interface SimulatedActionRecord {
  id: string;
  action_type: 'preview_warning' | 'mark_approval' | 'simulate_block' | 'mark_false_positive';
  actor: string;
  timestamp: string;
  summary: string;
  details?: Record<string, unknown>;
  is_simulation: true;
}

/**
 * Derives recommended next steps based on risk severity, approval status, and destination.
 */
function deriveRecommendedSteps(severity: string, approvalStatus: string, destination: string): string[] {
  const steps: string[] = [];
  if (severity === 'critical') {
    steps.push('Investigate potential data sensitivity and verify synthetic user identity authorization.');
    steps.push(`Evaluate whether access to unapproved endpoint '${destination}' violates internal policies.`);
    steps.push('Recommend redirecting user to an approved corporate alternative (e.g. OpenAI Enterprise).');
  } else if (severity === 'high') {
    steps.push(`Review unapproved or unreviewed service usage for destination '${destination}'.`);
    steps.push('Contact employee to verify business necessity and whether sensitive information was included.');
    steps.push('If legitimate, submit service for formal IT governance review.');
  } else if (severity === 'medium') {
    steps.push(`Confirm whether personal account or enterprise login was used for '${destination}'.`);
    steps.push('Remind user of data classification guidelines and acceptable AI usage.');
  } else {
    steps.push(`Destination '${destination}' meets standard policy criteria. Record for visibility.`);
  }
  return steps;
}

/**
 * GET /api/incidents
 * List incidents with optional filters: severity, status, provider, destination, search.
 */
incidentsRouter.get('/', requireAuth, (req, res) => {
  const db = req.db;
  const userRole = req.demoUser?.role ?? 'viewer';
  const { severity, status, provider, destination, search } = req.query;

  let query = `
    SELECT
      i.id,
      i.severity,
      i.title,
      i.destination,
      i.status,
      i.notes,
      i.simulated_actions,
      i.created_at,
      i.updated_at,
      i.event_id,
      e.occurred_at,
      e.source_label,
      e.source_type,
      e.port,
      e.classification,
      e.confidence,
      e.approval_status,
      e.risk_score,
      e.risk_factors,
      e.risk_explanation,
      e.action_recommendation,
      e.byte_count,
      e.sensitivity_label,
      e.evidence,
      COALESCE(p.display_name, 'Unknown') as person_name,
      p.demo_email as person_email,
      p.department as person_department,
      p.role_title as person_role,
      COALESCE(d.label, 'Unknown') as device_label,
      d.os_label as device_os,
      s.name as service_name,
      s.provider as service_provider
    FROM incidents i
    LEFT JOIN events e ON e.id = i.event_id
    LEFT JOIN synthetic_people p ON p.id = COALESCE(i.person_id, e.person_id)
    LEFT JOIN synthetic_devices d ON d.id = COALESCE(i.device_id, e.device_id)
    LEFT JOIN services s ON s.id = e.service_id
    WHERE i.is_demo = 1
  `;

  const params: unknown[] = [];

  if (typeof severity === 'string' && severity.trim()) {
    query += ` AND i.severity = ?`;
    params.push(severity.trim().toLowerCase());
  }

  if (typeof status === 'string' && status.trim()) {
    query += ` AND i.status = ?`;
    params.push(status.trim());
  }

  if (typeof destination === 'string' && destination.trim()) {
    query += ` AND i.destination LIKE ?`;
    params.push(`%${destination.trim()}%`);
  }

  if (typeof provider === 'string' && provider.trim()) {
    query += ` AND (s.provider LIKE ? OR s.name LIKE ?)`;
    params.push(`%${provider.trim()}%`, `%${provider.trim()}%`);
  }

  if (typeof search === 'string' && search.trim()) {
    const term = `%${search.trim()}%`;
    query += ` AND (
      i.title LIKE ?
      OR i.destination LIKE ?
      OR p.display_name LIKE ?
      OR d.label LIKE ?
      OR s.name LIKE ?
      OR s.provider LIKE ?
    )`;
    params.push(term, term, term, term, term, term);
  }

  query += `
    ORDER BY
      CASE i.severity
        WHEN 'critical' THEN 1
        WHEN 'high'     THEN 2
        WHEN 'medium'   THEN 3
        ELSE 4
      END,
      i.updated_at DESC
  `;

  const rows = db.prepare(query).all(...params) as Array<{
    id: number;
    severity: string;
    title: string;
    destination: string;
    status: string;
    notes: string;
    simulated_actions: string;
    created_at: string;
    updated_at: string;
    event_id: number | null;
    occurred_at: string | null;
    source_label: string | null;
    source_type: string | null;
    port: number | null;
    classification: string | null;
    confidence: number | null;
    approval_status: string | null;
    risk_score: number | null;
    risk_factors: string | null;
    risk_explanation: string | null;
    action_recommendation: string | null;
    byte_count: number | null;
    sensitivity_label: string | null;
    evidence: string | null;
    person_name: string;
    person_email: string | null;
    person_department: string | null;
    person_role: string | null;
    device_label: string;
    device_os: string | null;
    service_name: string | null;
    service_provider: string | null;
  }>;

  const incidents = rows.map((r) => {
    let parsedNotes: IncidentNote[] = [];
    try {
      parsedNotes = JSON.parse(r.notes || '[]');
    } catch {
      parsedNotes = [];
    }

    let parsedSimulatedActions: SimulatedActionRecord[] = [];
    try {
      parsedSimulatedActions = JSON.parse(r.simulated_actions || '[]');
    } catch {
      parsedSimulatedActions = [];
    }

    let parsedFactors = [];
    try {
      parsedFactors = JSON.parse(r.risk_factors || '[]');
    } catch {
      parsedFactors = [];
    }

    const recommendedSteps = deriveRecommendedSteps(
      r.severity,
      r.approval_status || 'Unknown',
      r.destination
    );

    return {
      id: r.id,
      severity: r.severity,
      title: r.title,
      destination: r.destination,
      status: r.status,
      created_at: r.created_at,
      updated_at: r.updated_at,
      notes: parsedNotes,
      simulated_actions: parsedSimulatedActions,
      recommended_steps: recommendedSteps,
      event: {
        id: r.event_id,
        occurred_at: r.occurred_at,
        source_label: r.source_label || 'simulation',
        source_type: r.source_type || 'simulation',
        port: r.port,
        classification: r.classification || 'Uncertain',
        confidence: r.confidence ?? 0,
        approval_status: r.approval_status || 'Unknown',
        risk_score: r.risk_score ?? 0,
        risk_explanation: r.risk_explanation,
        risk_factors: parsedFactors,
        action_recommendation: r.action_recommendation || 'Review',
        byte_count: r.byte_count ?? 0,
        sensitivity_label: r.sensitivity_label || 'Internal',
        evidence: r.evidence,
      },
      user: {
        name: r.person_name,
        email: r.person_email,
        department: r.person_department,
        role: r.person_role,
      },
      device: {
        label: r.device_label,
        os: r.device_os,
      },
      service: {
        name: r.service_name || r.destination,
        provider: r.service_provider || 'Unknown',
      },
    };
  });

  return res.json({
    incidents,
    canEdit: ['administrator', 'analyst'].includes(userRole),
    userRole,
    demoNotice:
      'All response actions are local simulations inside AURA. No traffic is blocked and no real notifications are sent.',
  });
});

/**
 * GET /api/incidents/:id
 * Retrieve full details for a single incident.
 */
incidentsRouter.get('/:id', requireAuth, (req, res) => {
  const db = req.db;
  const userRole = req.demoUser?.role ?? 'viewer';
  const id = parseInt(String(req.params.id), 10);

  if (isNaN(id)) {
    return res.status(400).json({ error: 'Invalid incident ID.' });
  }

  const row = db.prepare(`
    SELECT
      i.id, i.severity, i.title, i.destination, i.status, i.notes, i.simulated_actions,
      i.created_at, i.updated_at, i.event_id,
      e.occurred_at, e.source_label, e.source_type, e.port, e.classification,
      e.confidence, e.approval_status, e.risk_score, e.risk_factors, e.risk_explanation,
      e.action_recommendation, e.byte_count, e.sensitivity_label, e.evidence,
      COALESCE(p.display_name, 'Unknown') as person_name,
      p.demo_email as person_email,
      p.department as person_department,
      p.role_title as person_role,
      COALESCE(d.label, 'Unknown') as device_label,
      d.os_label as device_os,
      s.name as service_name,
      s.provider as service_provider
    FROM incidents i
    LEFT JOIN events e ON e.id = i.event_id
    LEFT JOIN synthetic_people p ON p.id = COALESCE(i.person_id, e.person_id)
    LEFT JOIN synthetic_devices d ON d.id = COALESCE(i.device_id, e.device_id)
    LEFT JOIN services s ON s.id = e.service_id
    WHERE i.id = ? AND i.is_demo = 1
  `).get(id) as any;

  if (!row) {
    return res.status(404).json({ error: 'Incident not found.' });
  }

  let parsedNotes: IncidentNote[] = [];
  try {
    parsedNotes = JSON.parse(row.notes || '[]');
  } catch {
    parsedNotes = [];
  }

  let parsedSimulatedActions: SimulatedActionRecord[] = [];
  try {
    parsedSimulatedActions = JSON.parse(row.simulated_actions || '[]');
  } catch {
    parsedSimulatedActions = [];
  }

  let parsedFactors = [];
  try {
    parsedFactors = JSON.parse(row.risk_factors || '[]');
  } catch {
    parsedFactors = [];
  }

  const recommendedSteps = deriveRecommendedSteps(
    row.severity,
    row.approval_status || 'Unknown',
    row.destination
  );

  return res.json({
    incident: {
      id: row.id,
      severity: row.severity,
      title: row.title,
      destination: row.destination,
      status: row.status,
      created_at: row.created_at,
      updated_at: row.updated_at,
      notes: parsedNotes,
      simulated_actions: parsedSimulatedActions,
      recommended_steps: recommendedSteps,
      event: {
        id: row.event_id,
        occurred_at: row.occurred_at,
        source_label: row.source_label || 'simulation',
        source_type: row.source_type || 'simulation',
        port: row.port,
        classification: row.classification || 'Uncertain',
        confidence: row.confidence ?? 0,
        approval_status: row.approval_status || 'Unknown',
        risk_score: row.risk_score ?? 0,
        risk_explanation: row.risk_explanation,
        risk_factors: parsedFactors,
        action_recommendation: row.action_recommendation || 'Review',
        byte_count: row.byte_count ?? 0,
        sensitivity_label: row.sensitivity_label || 'Internal',
        evidence: row.evidence,
      },
      user: {
        name: row.person_name,
        email: row.person_email,
        department: row.person_department,
        role: row.person_role,
      },
      device: {
        label: row.device_label,
        os: row.device_os,
      },
      service: {
        name: row.service_name || row.destination,
        provider: row.service_provider || 'Unknown',
      },
    },
    canEdit: ['administrator', 'analyst'].includes(userRole),
    userRole,
  });
});

/**
 * PATCH /api/incidents/:id/status
 * Update incident status (e.g. Open -> Investigating -> Resolved -> False Positive).
 * Enforces: Only administrator and analyst roles may update.
 */
incidentsRouter.patch(
  '/:id/status',
  requireAuth,
  requireRole('administrator', 'analyst'),
  (req, res) => {
    const db = req.db;
    const actor = req.demoUser?.username ?? 'demo-analyst';
    const actorRole = req.demoUser?.role ?? 'analyst';
    const id = parseInt(String(req.params.id), 10);

    if (isNaN(id)) {
      return res.status(400).json({ error: 'Invalid incident ID.' });
    }

    const { status, note } = req.body;

    if (!status || typeof status !== 'string') {
      return res.status(400).json({ error: 'Status is required.' });
    }

    if (!VALID_STATUSES.includes(status as IncidentStatus)) {
      return res.status(400).json({
        error: `Invalid status '${status}'. Must be one of: ${VALID_STATUSES.join(', ')}.`,
      });
    }

    const existing = db.prepare(`SELECT id, status, notes FROM incidents WHERE id = ?`).get(id) as {
      id: number;
      status: string;
      notes: string;
    } | undefined;

    if (!existing) {
      return res.status(404).json({ error: 'Incident not found.' });
    }

    let notesList: IncidentNote[] = [];
    try {
      notesList = JSON.parse(existing.notes || '[]');
    } catch {
      notesList = [];
    }

    // Optional status transition note
    if (typeof note === 'string' && note.trim().length > 0) {
      if (note.trim().length > 2000) {
        return res.status(400).json({ error: 'Note exceeds maximum limit of 2,000 characters.' });
      }
      notesList.push({
        id: `note-${Date.now()}`,
        actor,
        role: actorRole,
        text: `Status changed to ${status}: ${note.trim()}`,
        created_at: new Date().toISOString(),
      });
    }

    db.prepare(`
      UPDATE incidents
      SET status = ?, notes = ?, updated_at = datetime('now')
      WHERE id = ?
    `).run(status, JSON.stringify(notesList), id);

    appendAudit(db, actor, 'incident.update_status', {
      incident_id: id,
      new_status: status,
      prev_status: existing.status,
      has_note: Boolean(note),
    });

    return res.json({
      success: true,
      message: `Incident status updated to '${status}'.`,
      id,
      status,
      notes: notesList,
    });
  }
);

/**
 * POST /api/incidents/:id/notes
 * Append an analyst note to the incident with length validation and demo attribution.
 * Enforces: Only administrator and analyst roles may add notes.
 */
incidentsRouter.post(
  '/:id/notes',
  requireAuth,
  requireRole('administrator', 'analyst'),
  (req, res) => {
    const db = req.db;
    const actor = req.demoUser?.username ?? 'demo-analyst';
    const actorRole = req.demoUser?.role ?? 'analyst';
    const id = parseInt(String(req.params.id), 10);

    if (isNaN(id)) {
      return res.status(400).json({ error: 'Invalid incident ID.' });
    }

    const { text } = req.body;

    if (typeof text !== 'string' || text.trim().length === 0) {
      return res.status(400).json({ error: 'Note text cannot be empty.' });
    }

    if (text.length > 2000) {
      return res.status(400).json({
        error: 'Note exceeds maximum allowed length of 2,000 characters.',
        currentLength: text.length,
      });
    }

    const existing = db.prepare(`SELECT id, notes FROM incidents WHERE id = ?`).get(id) as {
      id: number;
      notes: string;
    } | undefined;

    if (!existing) {
      return res.status(404).json({ error: 'Incident not found.' });
    }

    let notesList: IncidentNote[] = [];
    try {
      notesList = JSON.parse(existing.notes || '[]');
    } catch {
      notesList = [];
    }

    const newNote: IncidentNote = {
      id: `note-${Date.now()}`,
      actor,
      role: actorRole,
      text: text.trim(),
      created_at: new Date().toISOString(),
    };

    notesList.push(newNote);

    db.prepare(`
      UPDATE incidents
      SET notes = ?, updated_at = datetime('now')
      WHERE id = ?
    `).run(JSON.stringify(notesList), id);

    appendAudit(db, actor, 'incident.add_note', {
      incident_id: id,
      note_id: newNote.id,
      char_count: text.trim().length,
    });

    return res.json({
      success: true,
      note: newNote,
      notes: notesList,
    });
  }
);

/**
 * POST /api/incidents/:id/simulate-action
 * Executes an in-app simulated response action:
 * - preview_warning: Show synthetic employee warning preview (no email/network alert sent)
 * - mark_approval: Record local pending-review status (no external ticketing)
 * - simulate_block: Display simulated block recommendation and contributing factors (no firewall change)
 * - mark_false_positive: Record false positive resolution with analyst attribution
 */
incidentsRouter.post(
  '/:id/simulate-action',
  requireAuth,
  requireRole('administrator', 'analyst'),
  (req, res) => {
    const db = req.db;
    const actor = req.demoUser?.username ?? 'demo-analyst';
    const actorRole = req.demoUser?.role ?? 'analyst';
    const id = parseInt(String(req.params.id), 10);

    if (isNaN(id)) {
      return res.status(400).json({ error: 'Invalid incident ID.' });
    }

    const { actionType, reason } = req.body;

    const ALLOWED_ACTIONS = ['preview_warning', 'mark_approval', 'simulate_block', 'mark_false_positive'];
    if (!actionType || !ALLOWED_ACTIONS.includes(actionType)) {
      return res.status(400).json({
        error: `Invalid actionType '${actionType}'. Must be one of: ${ALLOWED_ACTIONS.join(', ')}.`,
      });
    }

    const inc = db.prepare(`
      SELECT i.id, i.severity, i.title, i.destination, i.status, i.notes, i.simulated_actions,
             e.risk_factors, e.action_recommendation, e.sensitivity_label, e.approval_status,
             p.display_name as person_name, p.demo_email as person_email
      FROM incidents i
      LEFT JOIN events e ON e.id = i.event_id
      LEFT JOIN synthetic_people p ON p.id = i.person_id
      WHERE i.id = ?
    `).get(id) as any;

    if (!inc) {
      return res.status(404).json({ error: 'Incident not found.' });
    }

    let simulatedActions: SimulatedActionRecord[] = [];
    try {
      simulatedActions = JSON.parse(inc.simulated_actions || '[]');
    } catch {
      simulatedActions = [];
    }

    let notesList: IncidentNote[] = [];
    try {
      notesList = JSON.parse(inc.notes || '[]');
    } catch {
      notesList = [];
    }

    let simulationDetail: Record<string, unknown> = {};
    const timestamp = new Date().toISOString();

    if (actionType === 'preview_warning') {
      const recipient = inc.person_email || inc.person_name || 'employee@demo.aura';
      simulationDetail = {
        title: `[SIMULATION] Policy Reminder: Usage of ${inc.destination}`,
        recipient,
        template: 'Standard Employee AI Safety Notice (Demo)',
        message: `Hello ${inc.person_name || 'Team Member'},\n\nAURA observed network traffic to '${inc.destination}' with ${inc.sensitivity_label || 'Internal'} data. This destination is currently marked as ${inc.approval_status || 'Unapproved'} in company policy.\n\nPlease route production AI workloads through approved enterprise gateways.\n\n— IT Security & Governance (Simulated)`,
        disclaimer: 'SIMULATION ONLY: No email, chat alert, or browser notification was sent.',
      };

      simulatedActions.push({
        id: `sim-${Date.now()}`,
        action_type: 'preview_warning',
        actor,
        timestamp,
        summary: `Previewed employee warning notification for ${recipient}`,
        details: simulationDetail,
        is_simulation: true,
      });

      appendAudit(db, actor, 'incident.simulated_warning_preview', {
        incident_id: id,
        recipient,
      });
    } else if (actionType === 'mark_approval') {
      simulationDetail = {
        previousStatus: inc.status,
        newStatus: 'Investigating',
        workflowNote: 'Incident marked for internal approval review in AURA queue.',
        disclaimer: 'SIMULATION ONLY: Local pending-review flag recorded in AURA. No external approver or ticketing system contacted.',
      };

      simulatedActions.push({
        id: `sim-${Date.now()}`,
        action_type: 'mark_approval',
        actor,
        timestamp,
        summary: 'Marked for approval review in AURA demo workflow',
        details: simulationDetail,
        is_simulation: true,
      });

      notesList.push({
        id: `note-${Date.now()}`,
        actor,
        role: actorRole,
        text: `[Workflow] Marked for approval review: ${reason || 'Awaiting formal governance sign-off.'}`,
        created_at: timestamp,
      });

      db.prepare(`
        UPDATE incidents
        SET status = 'Investigating', notes = ?, simulated_actions = ?, updated_at = datetime('now')
        WHERE id = ?
      `).run(JSON.stringify(notesList), JSON.stringify(simulatedActions), id);

      appendAudit(db, actor, 'incident.simulated_approval_review', {
        incident_id: id,
      });
    } else if (actionType === 'simulate_block') {
      let factors = [];
      try {
        factors = JSON.parse(inc.risk_factors || '[]');
      } catch {
        factors = [];
      }

      simulationDetail = {
        destination: inc.destination,
        recommendation: 'Would block (sample outcome)',
        contributingFactors: factors,
        policyTrigger: inc.action_recommendation || 'Would block before transmission (simulation)',
        disclaimer: 'SIMULATION ONLY: AURA does not perform live network blocking, packet dropping, or firewall modifications.',
      };

      simulatedActions.push({
        id: `sim-${Date.now()}`,
        action_type: 'simulate_block',
        actor,
        timestamp,
        summary: `Simulated block recommendation previewed for ${inc.destination}`,
        details: simulationDetail,
        is_simulation: true,
      });

      appendAudit(db, actor, 'incident.simulated_block_recommendation', {
        incident_id: id,
        destination: inc.destination,
      });
    } else if (actionType === 'mark_false_positive') {
      const reasonText = (typeof reason === 'string' && reason.trim()) ? reason.trim() : 'Marked as false positive by analyst review.';
      
      simulationDetail = {
        previousStatus: inc.status,
        newStatus: 'False Positive',
        reason: reasonText,
        disclaimer: 'SIMULATION ONLY: Updated local demo incident record to False Positive.',
      };

      simulatedActions.push({
        id: `sim-${Date.now()}`,
        action_type: 'mark_false_positive',
        actor,
        timestamp,
        summary: `Marked as False Positive: ${reasonText}`,
        details: simulationDetail,
        is_simulation: true,
      });

      notesList.push({
        id: `note-${Date.now()}`,
        actor,
        role: actorRole,
        text: `[Resolution - False Positive]: ${reasonText}`,
        created_at: timestamp,
      });

      db.prepare(`
        UPDATE incidents
        SET status = 'False Positive', notes = ?, simulated_actions = ?, updated_at = datetime('now')
        WHERE id = ?
      `).run(JSON.stringify(notesList), JSON.stringify(simulatedActions), id);

      appendAudit(db, actor, 'incident.mark_false_positive', {
        incident_id: id,
        reason_length: reasonText.length,
      });
    }

    // Persist updated simulated_actions if not already updated in specific branch
    if (actionType === 'preview_warning' || actionType === 'simulate_block') {
      db.prepare(`
        UPDATE incidents
        SET simulated_actions = ?, updated_at = datetime('now')
        WHERE id = ?
      `).run(JSON.stringify(simulatedActions), id);
    }

    return res.json({
      success: true,
      actionType,
      simulationDetail,
      simulatedActions,
      notes: notesList,
    });
  }
);
