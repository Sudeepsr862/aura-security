// ─── AURA Auth Middleware ─────────────────────────────────────────────────────
// Demo session validation — not production authentication.
// Reads HttpOnly SameSite cookie, validates hash against DB.

import type { Request, Response, NextFunction } from 'express';
import { createHash } from 'node:crypto';
import type Database from 'better-sqlite3';

export type DemoRole = 'administrator' | 'analyst' | 'viewer';

export interface AuthedUser {
  id: number;
  username: string;
  displayName: string;
  role: DemoRole;
}

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      db: Database.Database;
      demoUser?: AuthedUser;
    }
  }
}

/** Hash a raw token for storage / lookup. */
export function hashToken(raw: string): string {
  return createHash('sha256').update(raw).digest('hex');
}

/** Inject db instance onto every request. */
export function injectDb(db: Database.Database) {
  return (_req: Request, _res: Response, next: NextFunction) => {
    _req.db = db;
    next();
  };
}

/** Require a valid demo session. Attaches demoUser to req. */
export function requireAuth(req: Request, res: Response, next: NextFunction) {
  const raw = req.cookies?.aura_session as string | undefined;
  if (!raw) {
    return res.status(401).json({ error: 'No session. Please sign in via the demo selector.' });
  }

  const hash = hashToken(raw);
  const now  = new Date().toISOString();

  const row = req.db.prepare(
    `SELECT s.id, s.expires_at,
            u.id as uid, u.username, u.display_name, u.role
     FROM sessions s
     JOIN demo_users u ON u.id = s.user_id
     WHERE s.token_hash = ? AND s.expires_at > ?
     LIMIT 1`
  ).get(hash, now) as {
    id: number; expires_at: string;
    uid: number; username: string; display_name: string; role: DemoRole;
  } | undefined;

  if (!row) {
    res.clearCookie('aura_session');
    return res.status(401).json({ error: 'Session expired or invalid. Please sign in again.' });
  }

  req.demoUser = {
    id:          row.uid,
    username:    row.username,
    displayName: row.display_name,
    role:        row.role,
  };
  next();
}

/** Require a minimum role. Call after requireAuth. */
export function requireRole(...allowed: DemoRole[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.demoUser) {
      return res.status(401).json({ error: 'Unauthenticated.' });
    }
    if (!allowed.includes(req.demoUser.role)) {
      return res.status(403).json({
        error: `Your demo role (${req.demoUser.role}) cannot perform this action.`,
      });
    }
    next();
  };
}
