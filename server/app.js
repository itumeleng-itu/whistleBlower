import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize, sep } from 'node:path';

export const SESSION_TTL_MS = 30 * 60 * 1000;
export const MAX_MESSAGES_PER_SESSION = 20;
export const STATUSES = ['received', 'in-review', 'needs-info', 'closed'];
const MAX_BODY_BYTES = 64 * 1024;
const MAX_NEW_SESSIONS_PER_MINUTE = 120;
const MAX_NEW_CASES_PER_MINUTE = 30;

// Ciphertexts are base64url. Limits leave room for the encryption overhead.
const B64U = /^[A-Za-z0-9_-]+$/;
const LIMITS = { auth: 43, wrappedKey: 1024, report: 30_000, message: 12_000 };

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

const sha256 = (value) => createHash('sha256').update(value).digest();

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

// Fixed-window counter held in memory only; never persisted, not keyed by IP.
function createLimiter(maxPerMinute, now) {
  let windowStart = 0;
  let count = 0;
  return () => {
    const t = now();
    if (t - windowStart >= 60_000) {
      windowStart = t;
      count = 0;
    }
    if (++count > maxPerMinute) throw new HttpError(429, 'Too many requests, try again shortly');
  };
}

function requireCiphertext(value, field, maxLength, exactLength) {
  const ok = typeof value === 'string' && B64U.test(value) &&
    (exactLength ? value.length === exactLength : value.length <= maxLength);
  if (!ok) throw new HttpError(400, `Invalid ${field}`);
  return value;
}

export function createApp({ db, publicDir, investigatorPublicKey, investigatorToken, now = () => Date.now() }) {
  const today = () => new Date(now()).toISOString().slice(0, 10);
  const investigatorTokenHash = investigatorToken ? sha256(investigatorToken) : null;
  const limitSessions = createLimiter(MAX_NEW_SESSIONS_PER_MINUTE, now);
  const limitCases = createLimiter(MAX_NEW_CASES_PER_MINUTE, now);

  const stmts = {
    insertCase: db.prepare(
      'INSERT INTO cases (auth_hash, wrapped_key, report, created_on, updated_on) VALUES (?, ?, ?, ?, ?)'),
    findCaseByAuth: db.prepare('SELECT id FROM cases WHERE auth_hash = ?'),
    getCase: db.prepare('SELECT * FROM cases WHERE id = ?'),
    listCases: db.prepare(`
      SELECT c.id, c.status, c.created_on, c.updated_on, c.wrapped_key, c.report,
        (SELECT sender FROM messages m WHERE m.case_id = c.id ORDER BY m.id DESC LIMIT 1) AS last_sender
      FROM cases c ORDER BY c.id DESC`),
    setStatus: db.prepare('UPDATE cases SET status = ?, updated_on = ? WHERE id = ?'),
    touchCase: db.prepare('UPDATE cases SET updated_on = ? WHERE id = ?'),
    listMessages: db.prepare('SELECT sender, body, created_on FROM messages WHERE case_id = ? ORDER BY id'),
    insertMessage: db.prepare('INSERT INTO messages (case_id, sender, body, created_on) VALUES (?, ?, ?, ?)'),
    insertSession: db.prepare('INSERT INTO sessions (token_hash, role, case_id, expires_at) VALUES (?, ?, ?, ?)'),
    getSession: db.prepare('SELECT role, case_id, action_count FROM sessions WHERE token_hash = ? AND expires_at > ?'),
    countAction: db.prepare('UPDATE sessions SET action_count = action_count + 1 WHERE token_hash = ?'),
    deleteSession: db.prepare('DELETE FROM sessions WHERE token_hash = ?'),
    purgeSessions: db.prepare('DELETE FROM sessions WHERE expires_at <= ?'),
  };

  function transaction(fn) {
    db.exec('BEGIN');
    try {
      const result = fn();
      db.exec('COMMIT');
      return result;
    } catch (err) {
      db.exec('ROLLBACK');
      throw err;
    }
  }

  function createSession(role, caseId = null) {
    limitSessions();
    stmts.purgeSessions.run(now());
    const sessionId = randomBytes(32).toString('base64url');
    const expiresAt = now() + SESSION_TTL_MS;
    stmts.insertSession.run(sha256(sessionId).toString('hex'), role, caseId, expiresAt);
    return { sessionId, expiresAt };
  }

  function requireSession(req, role) {
    const match = /^Bearer ([A-Za-z0-9_-]{43})$/.exec(req.headers.authorization ?? '');
    if (!match) throw new HttpError(401, 'Missing or malformed session');
    const tokenHash = sha256(match[1]).toString('hex');
    const row = stmts.getSession.get(tokenHash, now());
    if (!row) throw new HttpError(401, 'Session expired, please log in again');
    if (role && row.role !== role) throw new HttpError(403, 'Not allowed');
    return { tokenHash, role: row.role, caseId: row.case_id, actionCount: row.action_count };
  }

  function caseView(caseId, { includeKey }) {
    const c = stmts.getCase.get(caseId);
    if (!c) throw new HttpError(404, 'Case not found');
    return {
      id: c.id,
      status: c.status,
      createdOn: c.created_on,
      updatedOn: c.updated_on,
      report: c.report,
      ...(includeKey && { wrappedKey: c.wrapped_key }),
      messages: stmts.listMessages.all(caseId).map((m) => ({ sender: m.sender, body: m.body, createdOn: m.created_on })),
    };
  }

  function addMessage(caseId, sender, body) {
    const message = requireCiphertext(body.message, 'message', LIMITS.message);
    const c = stmts.getCase.get(caseId);
    if (!c) throw new HttpError(404, 'Case not found');
    if (c.status === 'closed') throw new HttpError(409, 'This case is closed');
    transaction(() => {
      stmts.insertMessage.run(caseId, sender, message, today());
      stmts.touchCase.run(today(), caseId);
    });
  }

  // --- Route handlers ------------------------------------------------------

  function createCase(body) {
    limitCases();
    const auth = requireCiphertext(body.auth, 'auth', 0, LIMITS.auth);
    const wrappedKey = requireCiphertext(body.wrappedKey, 'wrappedKey', LIMITS.wrappedKey);
    const report = requireCiphertext(body.report, 'report', LIMITS.report);
    const authHash = sha256(auth).toString('hex');
    if (stmts.findCaseByAuth.get(authHash)) throw new HttpError(409, 'Case already exists');
    stmts.insertCase.run(authHash, wrappedKey, report, today(), today());
  }

  function reporterLogin(body) {
    const auth = requireCiphertext(body.auth, 'case code', 0, LIMITS.auth);
    const c = stmts.findCaseByAuth.get(sha256(auth).toString('hex'));
    if (!c) {
      limitSessions(); // failed attempts count against the same budget
      throw new HttpError(401, 'Case code not recognised');
    }
    return createSession('reporter', c.id);
  }

  function investigatorLogin(body) {
    if (!investigatorTokenHash) throw new HttpError(503, 'Investigator access is not configured');
    limitSessions();
    const ok = typeof body.token === 'string' && timingSafeEqual(sha256(body.token), investigatorTokenHash);
    if (!ok) throw new HttpError(401, 'Invalid investigator token');
    return createSession('investigator');
  }

  function reporterMessage(req, body) {
    const session = requireSession(req, 'reporter');
    if (session.actionCount >= MAX_MESSAGES_PER_SESSION) {
      throw new HttpError(429, 'Message limit reached for this session');
    }
    addMessage(session.caseId, 'reporter', body);
    stmts.countAction.run(session.tokenHash);
  }

  function parseCaseId(raw) {
    const id = Number(raw);
    if (!Number.isSafeInteger(id) || id < 1) throw new HttpError(404, 'Case not found');
    return id;
  }

  async function handleApi(req, res, path) {
    res.setHeader('Cache-Control', 'no-store');
    const route = `${req.method} ${path.replace(/\/\d+(?=\/|$)/, '/:id')}`;
    const caseId = /\/(\d+)(?:\/|$)/.exec(path)?.[1];

    switch (route) {
      case 'GET /api/config':
        if (!investigatorPublicKey) throw new HttpError(503, 'Reporting is not configured yet');
        return sendJson(res, 200, { investigatorPublicKey });
      case 'POST /api/cases':
        createCase(await readJson(req));
        return sendJson(res, 201, {});
      case 'POST /api/session':
        return sendJson(res, 201, reporterLogin(await readJson(req)));
      case 'POST /api/investigator/session':
        return sendJson(res, 201, investigatorLogin(await readJson(req)));
      case 'DELETE /api/session': {
        stmts.deleteSession.run(requireSession(req).tokenHash);
        res.writeHead(204).end();
        return;
      }
      case 'GET /api/case':
        return sendJson(res, 200, caseView(requireSession(req, 'reporter').caseId, { includeKey: false }));
      case 'POST /api/case/messages':
        reporterMessage(req, await readJson(req));
        return sendJson(res, 201, {});
      case 'GET /api/investigator/cases':
        requireSession(req, 'investigator');
        return sendJson(res, 200, {
          cases: stmts.listCases.all().map((c) => ({
            id: c.id,
            status: c.status,
            createdOn: c.created_on,
            updatedOn: c.updated_on,
            wrappedKey: c.wrapped_key,
            report: c.report,
            awaitingReply: c.last_sender === 'reporter',
          })),
        });
      case 'GET /api/investigator/cases/:id':
        requireSession(req, 'investigator');
        return sendJson(res, 200, caseView(parseCaseId(caseId), { includeKey: true }));
      case 'POST /api/investigator/cases/:id/messages':
        requireSession(req, 'investigator');
        addMessage(parseCaseId(caseId), 'investigator', await readJson(req));
        return sendJson(res, 201, {});
      case 'PATCH /api/investigator/cases/:id': {
        requireSession(req, 'investigator');
        const { status } = await readJson(req);
        if (!STATUSES.includes(status)) throw new HttpError(400, 'Invalid status');
        const id = parseCaseId(caseId);
        if (stmts.setStatus.run(status, today(), id).changes === 0) throw new HttpError(404, 'Case not found');
        return sendJson(res, 200, { status });
      }
      default:
        throw new HttpError(404, 'Not found');
    }
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
