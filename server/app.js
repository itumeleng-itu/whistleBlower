import { createHash, randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize, sep } from 'node:path';

export const SESSION_TTL_MS = 30 * 60 * 1000;
export const MAX_REPORTS_PER_SESSION = 5;
const MAX_BODY_BYTES = 32 * 1024;
const MAX_NEW_SESSIONS_PER_MINUTE = 120;

export const CATEGORIES = [
  'fraud',
  'corruption-bribery',
  'health-safety',
  'environmental',
  'labour-violations',
  'harassment-discrimination',
  'data-privacy',
  'other',
];

const LIMITS = { company: 200, location: 200, description: 10000 };

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.webmanifest': 'application/manifest+json',
  '.svg': 'image/svg+xml',
};

const SECURITY_HEADERS = {
  'Content-Security-Policy':
    "default-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), interest-cohort=()',
};

const hashToken = (token) => createHash('sha256').update(token).digest('hex');

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

export function createApp({ db, publicDir, now = () => Date.now() }) {
  const stmts = {
    insertSession: db.prepare('INSERT INTO sessions (token_hash, expires_at) VALUES (?, ?)'),
    getSession: db.prepare('SELECT report_count FROM sessions WHERE token_hash = ? AND expires_at > ?'),
    deleteSession: db.prepare('DELETE FROM sessions WHERE token_hash = ?'),
    purgeSessions: db.prepare('DELETE FROM sessions WHERE expires_at <= ?'),
    countReport: db.prepare('UPDATE sessions SET report_count = report_count + 1 WHERE token_hash = ?'),
    insertReport: db.prepare(`
      INSERT INTO reports (reference, company, category, description, location, incident_date, submitted_on)
      VALUES (?, ?, ?, ?, ?, ?, ?)`),
  };

  // In-memory only; never persisted and not keyed by IP address.
  let windowStart = 0;
  let sessionsThisWindow = 0;

  function createSession() {
    const t = now();
    if (t - windowStart >= 60_000) {
      windowStart = t;
      sessionsThisWindow = 0;
    }
    if (++sessionsThisWindow > MAX_NEW_SESSIONS_PER_MINUTE) {
      throw new HttpError(429, 'Too many requests, try again shortly');
    }
    stmts.purgeSessions.run(t);
    const sessionId = randomBytes(32).toString('base64url');
    const expiresAt = t + SESSION_TTL_MS;
    stmts.insertSession.run(hashToken(sessionId), expiresAt);
    return { sessionId, expiresAt };
  }

  function requireSession(req) {
    const match = /^Bearer ([A-Za-z0-9_-]{43})$/.exec(req.headers.authorization ?? '');
    if (!match) throw new HttpError(401, 'Missing or malformed session');
    const tokenHash = hashToken(match[1]);
    const row = stmts.getSession.get(tokenHash, now());
    if (!row) throw new HttpError(401, 'Session expired, please log in again');
    return { tokenHash, reportCount: row.report_count };
  }

  function validateReport(body) {
    const str = (v) => (typeof v === 'string' ? v.trim() : '');
    const report = {
      company: str(body.company),
      category: str(body.category),
      description: str(body.description),
      location: str(body.location) || null,
      incidentDate: str(body.incidentDate) || null,
    };
    if (!report.company) throw new HttpError(400, 'Company is required');
    if (!CATEGORIES.includes(report.category)) throw new HttpError(400, 'Invalid category');
    if (report.description.length < 20) {
      throw new HttpError(400, 'Description must be at least 20 characters');
    }
    for (const [field, max] of Object.entries(LIMITS)) {
      if ((report[field] ?? '').length > max) {
        throw new HttpError(400, `${field} must be at most ${max} characters`);
      }
    }
    if (report.incidentDate) {
      const d = /^\d{4}-\d{2}-\d{2}$/.test(report.incidentDate) && new Date(report.incidentDate);
      if (!d || Number.isNaN(d.getTime()) || d.getTime() > now()) {
        throw new HttpError(400, 'Invalid incident date');
      }
    }
    return report;
  }

  function submitReport(req, body) {
    const session = requireSession(req);
    if (session.reportCount >= MAX_REPORTS_PER_SESSION) {
      throw new HttpError(429, 'Report limit reached for this session');
    }
    const r = validateReport(body);
    const reference = 'WB-' + randomBytes(6).toString('hex').toUpperCase();
    const submittedOn = new Date(now()).toISOString().slice(0, 10);
    db.exec('BEGIN');
    try {
      stmts.insertReport.run(reference, r.company, r.category, r.description, r.location, r.incidentDate, submittedOn);
      stmts.countReport.run(session.tokenHash);
      db.exec('COMMIT');
    } catch (err) {
      db.exec('ROLLBACK');
      throw err;
    }
    return { reference };
  }

  async function readJson(req) {
    if (!(req.headers['content-type'] ?? '').startsWith('application/json')) {
      throw new HttpError(415, 'Expected application/json');
    }
    let size = 0;
    const chunks = [];
    for await (const chunk of req) {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) throw new HttpError(413, 'Request too large');
      chunks.push(chunk);
    }
    try {
      const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      if (parsed === null || typeof parsed !== 'object') throw new Error();
      return parsed;
    } catch {
      throw new HttpError(400, 'Invalid JSON');
    }
  }

  async function handleApi(req, res, path) {
    res.setHeader('Cache-Control', 'no-store');
    if (path === '/api/session' && req.method === 'POST') {
      // Called only after the access key was validated on the device.
      // The request carries no body: the server never learns the key.
      return sendJson(res, 201, createSession());
    }
    if (path === '/api/session' && req.method === 'DELETE') {
      const { tokenHash } = requireSession(req);
      stmts.deleteSession.run(tokenHash);
      res.writeHead(204).end();
      return;
    }
    if (path === '/api/categories' && req.method === 'GET') {
      return sendJson(res, 200, { categories: CATEGORIES });
    }
    if (path === '/api/reports' && req.method === 'POST') {
      return sendJson(res, 201, submitReport(req, await readJson(req)));
    }
    throw new HttpError(404, 'Not found');
  }

  async function serveStatic(req, res, path) {
    if (req.method !== 'GET' && req.method !== 'HEAD') throw new HttpError(405, 'Method not allowed');
    const rel = path === '/' ? 'index.html' : decodeURIComponent(path).replace(/^\/+/, '');
    const file = normalize(join(publicDir, rel));
    if (!file.startsWith(publicDir + sep)) throw new HttpError(404, 'Not found');
    let data;
    try {
      data = await readFile(file);
    } catch {
      throw new HttpError(404, 'Not found');
    }
    res.writeHead(200, {
      'Content-Type': MIME[extname(file)] ?? 'application/octet-stream',
      // The service worker must always be revalidated so updates roll out.
      'Cache-Control': rel === 'sw.js' ? 'no-cache' : 'public, max-age=300',
    });
    res.end(req.method === 'HEAD' ? undefined : data);
  }

  // Note: no request logging anywhere, and client IPs are never read.
  return async function handler(req, res) {
    for (const [k, v] of Object.entries(SECURITY_HEADERS)) res.setHeader(k, v);
    const path = new URL(req.url, 'http://localhost').pathname;
    try {
      if (path.startsWith('/api/')) await handleApi(req, res, path);
      else await serveStatic(req, res, path);
    } catch (err) {
      const status = err instanceof HttpError ? err.status : 500;
      if (status === 500) console.error('Internal error:', err.message);
      if (!res.headersSent) sendJson(res, status, { error: status === 500 ? 'Internal error' : err.message });
      else res.end();
    }
  };
}

function sendJson(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(body));
}
