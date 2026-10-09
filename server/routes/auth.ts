// ─── Auth Routes ─────────────────────────────────────────────────────────────
// POST /api/auth/signin   — demo role selector sign-in
// GET  /api/auth/me       — current session user
// POST /api/auth/signout  — invalidate session

import { Router } from 'express';
import { randomBytes } from 'node:crypto';
import { hashToken, requireAuth } from '../middleware/auth.js';
import { appendAudit } from '../db/database.js';

export const authRouter = Router();

const SESSION_TTL_HOURS = 8;
const DEMO_ROLES = ['administrator', 'analyst', 'viewer'] as const;

/**
 * POST /api/auth/signin
 * Body: { role: 'administrator' | 'analyst' | 'viewer' }
 *
 * Issues a random session token (raw returned as HttpOnly cookie,
 * hash stored in DB). This is demo-only — not production authentication.
 */
authRouter.post('/signin', (req, res) => {
  const { role } = req.body as { role?: string };

  if (!role || !DEMO_ROLES.includes(role as typeof DEMO_ROLES[number])) {
    return res.status(400).json({
      error: `role must be one of: ${DEMO_ROLES.join(', ')}`,
    });
  }

  const db = req.db;
  const user = db.prepare(
    `SELECT id, username, display_name, role FROM demo_users WHERE role = ? LIMIT 1`
  ).get(role) as { id: number; username: string; display_name: string; role: string } | undefined;

  if (!user) {
    return res.status(500).json({ error: 'Demo user not found. Run seed first.' });
  }

  // Expire any existing sessions for this user
  db.prepare(`DELETE FROM sessions WHERE user_id = ?`).run(user.id);

  // Create new session
  const rawToken = randomBytes(32).toString('hex');
  const hash     = hashToken(rawToken);
  const expires  = new Date(Date.now() + SESSION_TTL_HOURS * 3600 * 1000).toISOString();

  db.prepare(
    `INSERT INTO sessions (user_id, token_hash, expires_at) VALUES (?, ?, ?)`
  ).run(user.id, hash, expires);

  appendAudit(db, user.username, 'session.create', { role });

  // Set HttpOnly SameSite=Lax cookie (compatible with reverse proxies and modern browser security)
  const isHttps = req.secure || req.headers['x-forwarded-proto'] === 'https';
  res.cookie('aura_session', rawToken, {
    httpOnly:  true,
    sameSite:  'lax',
    secure:    Boolean(isHttps),
    maxAge:    SESSION_TTL_HOURS * 3600 * 1000,
    path:      '/',
  });

  return res.json({
    token: rawToken,
    user: {
      username:    user.username,
      displayName: user.display_name,
      role:        user.role,
    },
    expiresAt: expires,
    sessionStatus: 'active',
  });
});

/**
 * GET /api/auth/me
 * Returns the current demo user if the session is valid.
 */
authRouter.get('/me', requireAuth, (req, res) => {
  return res.json({ user: req.demoUser });
});

/**
 * POST /api/auth/signout
 * Deletes the session from the database and clears the cookie.
 */
authRouter.post('/signout', requireAuth, (req, res) => {
  const { username } = req.demoUser!;
  const rawToken = req.cookies?.aura_session as string;

  req.db
    .prepare(`DELETE FROM sessions WHERE token_hash = ?`)
    .run(hashToken(rawToken));

  appendAudit(req.db, username, 'session.destroy', {});

  res.clearCookie('aura_session', { path: '/' });
  return res.json({ message: 'Signed out.' });
});
