// ─── AURA API Server ──────────────────────────────────────────────────────────
// Local-only Express server for the AURA prototype.
// Binds to 127.0.0.1 only — not exposed to the local network.
// All data is synthetic demo data; no live network monitoring.

import express from 'express';
import cookieParser from 'cookie-parser';
import { mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { openDb, applySchema, seedDemo } from './db/database.js';
import { injectDb } from './middleware/auth.js';
import { authRouter }      from './routes/auth.js';
import { dashboardRouter } from './routes/dashboard.js';
import { servicesRouter }  from './routes/services.js';
import { eventsRouter }    from './routes/events.js';
import { incidentsRouter } from './routes/incidents.js';
import { peopleRouter }    from './routes/people.js';
import { policiesRouter }  from './routes/policies.js';
import { ingestRouter }    from './routes/ingest.js';
import { promptLabRouter }  from './routes/promptLab.js';
import { riskRouter }       from './routes/risk.js';
import { auditRouter }      from './routes/audit.js';
import { dataGuardRouter }  from './routes/dataGuard.js';
import { extensionRouter }  from './routes/extension.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORT = parseInt(process.env.AURA_PORT ?? '3001', 10);
const HOST = '127.0.0.1';  // local-only

// ── Ensure data directory exists ──────────────────────────────────────────────
const dataDir = join(__dirname, '../data');
mkdirSync(dataDir, { recursive: true });

// ── Init database ─────────────────────────────────────────────────────────────
console.log('📦  Opening database …');
const db = openDb();
applySchema(db);
seedDemo(db);
console.log('✅  Database ready.');

// ── Express app ───────────────────────────────────────────────────────────────
const app = express();

// Proxy compatibility: trust upstream reverse proxies (Nginx, Caddy, Cloudflare, ALB, Traefik)
app.set('trust proxy', true);

// Security: strict size limit (4mb for CSV payload), no x-powered-by header
app.disable('x-powered-by');
app.use(express.json({ limit: '4mb' }));
app.use(cookieParser());

// Proxy & Extension CORS Configuration
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  } else {
    res.setHeader('Access-Control-Allow-Origin', '*');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, Cookie, X-Forwarded-For, X-Forwarded-Proto, X-Forwarded-Host');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(204);
  }
  next();
});

// Inject db instance on every request
app.use(injectDb(db));

// ── Health check ──────────────────────────────────────────────────────────────
/**
 * GET /api/health
 * Returns server status. No auth required.
 */
app.get('/api/health', (req, res) => {
  res.json({
    status:  'ok',
    service: 'AURA AI Security Platform',
    version: '1.0.0',
    proxyCompatible: true,
    clientIp: req.ip,
    protocol: req.protocol,
    time:    new Date().toISOString(),
  });
});

// ── Routes ────────────────────────────────────────────────────────────────────
app.use('/api/auth',      authRouter);
app.use('/api/dashboard', dashboardRouter);
app.use('/api/services',  servicesRouter);
app.use('/api/events',    eventsRouter);
app.use('/api/incidents', incidentsRouter);
app.use('/api/people',    peopleRouter);
app.use('/api/policies',   policiesRouter);
app.use('/api/ingest',     ingestRouter);
app.use('/api/prompt-lab', promptLabRouter);
app.use('/api/risk',       riskRouter);
app.use('/api/audit',      auditRouter);
app.use('/api/data-guard', dataGuardRouter);
app.use('/api/extension',  extensionRouter);

// ── Error handler ─────────────────────────────────────────────────────────────
// Never expose stack traces or request bodies in the response.
app.use(
  (err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    console.error('[AURA API error]', err.message);
    res.status(500).json({ error: 'An internal error occurred.' });
  }
);

// ── 404 catch-all ─────────────────────────────────────────────────────────────
app.use((_req, res) => {
  res.status(404).json({ error: 'API endpoint not found.' });
});

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, HOST, () => {
  console.log(`🚀  AURA AI Security API active on http://${HOST}:${PORT}`);
  console.log('    ✓ Reverse proxy & forwarded headers enabled.');
  console.log('    ✓ Browser extension CORS & authorization ready.');
});
