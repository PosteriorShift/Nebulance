import pg from 'pg';
import crypto from 'crypto';

const { Pool } = pg;

/* =========================================================
   DB — reuse pool across warm invocations
   ========================================================= */
let pool;
function getPool() {
  if (!pool) {
    pool = new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: { rejectUnauthorized: false },
      max: 3,
    });
  }
  return pool;
}

/* =========================================================
   TABLE — auto-create on first request
   ========================================================= */
let tableReady = false;
async function ensureTable() {
  if (tableReady) return;
  await getPool().query(`
    CREATE TABLE IF NOT EXISTS site_content (
      id          INTEGER PRIMARY KEY DEFAULT 1,
      data        JSONB NOT NULL,
      updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_by  TEXT,
      CONSTRAINT single_row CHECK (id = 1)
    );
  `);
  await getPool().query(`
    INSERT INTO site_content (id, data) VALUES (1, '{}'::jsonb)
    ON CONFLICT (id) DO NOTHING;
  `);
  tableReady = true;
}

/* =========================================================
   AUTH — signed cookie, stateless
   ========================================================= */
const SESSION_SECRET = process.env.SESSION_SECRET || 'dev-secret-change-me';
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'admin';

function signSession() {
  const payload = `admin.${Date.now()}`;
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('hex');
  return `${payload}.${sig}`;
}

function verifySession(token) {
  if (!token || typeof token !== 'string') return false;
  const parts = token.split('.');
  if (parts.length !== 3) return false;
  const [user, ts, sig] = parts;
  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(`${user}.${ts}`).digest('hex');
  if (sig !== expected) return false;
  if (Date.now() - Number(ts) > 7 * 24 * 60 * 60 * 1000) return false;
  return user === 'admin';
}

function parseCookies(req) {
  const header = req.headers.cookie || '';
  const out = {};
  header.split(';').forEach(pair => {
    const idx = pair.indexOf('=');
    if (idx < 0) return;
    out[pair.slice(0, idx).trim()] = decodeURIComponent(pair.slice(idx + 1).trim());
  });
  return out;
}

function isAuthed(req) {
  return verifySession(parseCookies(req).nebulance_session);
}

/* =========================================================
   BODY READER (Vercel sometimes doesn't parse JSON automatically)
   ========================================================= */
async function readBody(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  return new Promise((resolve) => {
    let raw = '';
    req.on('data', chunk => { raw += chunk; });
    req.on('end', () => {
      try { resolve(JSON.parse(raw || '{}')); }
      catch { resolve({}); }
    });
  });
}

/* =========================================================
   RESPONSE HELPERS
   ========================================================= */
function setCookie(res, name, value, opts = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`];
  parts.push(`Path=${opts.path || '/'}`);
  if (opts.maxAge) parts.push(`Max-Age=${opts.maxAge}`);
  parts.push(`SameSite=${opts.sameSite || 'Lax'}`);
  if (opts.httpOnly !== false) parts.push('HttpOnly');
  if (opts.secure) parts.push('Secure');
  const existing = res.getHeader('Set-Cookie');
  const cookies = existing ? [].concat(existing, parts.join('; ')) : [parts.join('; ')];
  res.setHeader('Set-Cookie', cookies);
}

const ok = (res, body) => res.status(200).json(body);
const err = (res, code, message) => res.status(code).json({ error: message });

/* =========================================================
   HANDLER
   ========================================================= */
export default async function handler(req, res) {
  // CORS for local dev
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();

  const url = new URL(req.url, `http://${req.headers.host}`);
  const action = url.searchParams.get('action') || '';

  try {
    await ensureTable();
  } catch (e) {
    console.error('DB init failed:', e);
    return err(res, 500, 'Database connection failed');
  }

  /* ---------- AUTH ---------- */
  if (action === 'login' && req.method === 'POST') {
    const body = await readBody(req);
    if (body.username === ADMIN_USER && body.password === ADMIN_PASS) {
      setCookie(res, 'nebulance_session', signSession(), {
        maxAge: 7 * 24 * 60 * 60,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'Lax',
        httpOnly: true,
      });
      return ok(res, { ok: true });
    }
    return err(res, 401, 'Invalid credentials');
  }

  if (action === 'logout' && req.method === 'POST') {
    setCookie(res, 'nebulance_session', '', { maxAge: 0 });
    return ok(res, { ok: true });
  }

  if (action === 'me' && req.method === 'GET') {
    return ok(res, { authenticated: isAuthed(req) });
  }

  /* ---------- CONTENT (public read) ---------- */
  if (action === 'content' && req.method === 'GET') {
    const r = await getPool().query('SELECT data, updated_at FROM site_content WHERE id = 1');
    if (!r.rows.length) return ok(res, { data: {}, updated_at: null });
    return ok(res, { data: r.rows[0].data, updated_at: r.rows[0].updated_at });
  }

  /* ---------- CONTENT (protected write) ---------- */
  if (action === 'content' && req.method === 'PUT') {
    if (!isAuthed(req)) return err(res, 401, 'Unauthorized');
    const body = await readBody(req);
    if (!body || typeof body.data !== 'object') return err(res, 400, 'Invalid payload');

    await getPool().query(`
      INSERT INTO site_content (id, data, updated_at, updated_by)
      VALUES (1, $1::jsonb, NOW(), $2)
      ON CONFLICT (id) DO UPDATE
      SET data = EXCLUDED.data,
          updated_at = NOW(),
          updated_by = EXCLUDED.updated_by
    `, [JSON.stringify(body.data), ADMIN_USER]);

    return ok(res, { ok: true, saved_at: new Date().toISOString() });
  }

  /* ---------- HEALTH ---------- */
  if (action === 'health') {
    try {
      await getPool().query('SELECT 1');
      return ok(res, { ok: true, db: 'connected' });
    } catch (e) {
      return err(res, 500, 'DB error');
    }
  }

  return err(res, 404, 'Not found');
}
