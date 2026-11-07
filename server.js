import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import helmet from 'helmet';
import pg from 'pg';
import { z } from 'zod';

const { Pool } = pg;
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const port = Number(process.env.PORT || 10000);
const isProduction = process.env.NODE_ENV === 'production';
const sessionTtlDays = Number(process.env.SESSION_TTL_DAYS || 30);

if (!process.env.DATABASE_URL) {
  throw new Error('DATABASE_URL is required');
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: isProduction ? { rejectUnauthorized: false } : undefined,
  max: 10,
});

const app = express();
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '1mb' }));


const authSchema = z.object({
  phone: z.string().min(10).max(20),
  pin: z.string().regex(/^\d{4,}$/, 'PIN must contain at least four digits'),
});

const registerSchema = authSchema.extend({
  name: z.string().trim().min(1).max(100),
});

const stateSchema = z.object({
  objects: z.array(z.unknown()).default([]),
  employees: z.array(z.unknown()).default([]),
  jobs: z.array(z.unknown()).default([]),
  shifts: z.array(z.unknown()).default([]),
  rates: z.record(z.string(), z.number().finite().nonnegative()).default({}),
  meta: z.record(z.string(), z.unknown()).default({}),
});

function normalizePhone(value) {
  const digits = String(value || '').replace(/\D/g, '');
  if (digits.length === 11 && digits.startsWith('8')) return `+7${digits.slice(1)}`;
  if (digits.length === 11 && digits.startsWith('7')) return `+${digits}`;
  if (digits.length === 10) return `+7${digits}`;
  return null;
}

function hashPin(pin) {
  return new Promise((resolve, reject) => {
    const salt = crypto.randomBytes(16);
    crypto.scrypt(pin, salt, 64, (error, derivedKey) => {
      if (error) reject(error);
      else resolve(`scrypt:${salt.toString('hex')}:${derivedKey.toString('hex')}`);
    });
  });
}

function verifyPin(pin, encoded) {
  return new Promise((resolve, reject) => {
    const [, saltHex, hashHex] = String(encoded).split(':');
    if (!saltHex || !hashHex) return resolve(false);
    crypto.scrypt(pin, Buffer.from(saltHex, 'hex'), 64, (error, derivedKey) => {
      if (error) reject(error);
      else {
        const expected = Buffer.from(hashHex, 'hex');
        resolve(expected.length === derivedKey.length && crypto.timingSafeEqual(expected, derivedKey));
      }
    });
  });
}

function newId() {
  return crypto.randomUUID();
}

function newSessionId() {
  return crypto.randomBytes(32).toString('base64url');
}

function sessionCookie(value, maxAge) {
  const flags = [
    `session=${value}`,
    'HttpOnly',
    'SameSite=Lax',
    'Path=/',
    `Max-Age=${maxAge}`,
  ];
  if (isProduction) flags.push('Secure');
  return flags.join('; ');
}

function clearSessionCookie() {
  return 'session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0';
}

function getSessionId(req) {
  const raw = req.headers.cookie || '';
  return raw.split(';').map((part) => part.trim()).find((part) => part.startsWith('session='))?.slice(8) || null;
}

async function getUser(req) {
  const sessionId = getSessionId(req);
  if (!sessionId) return null;
  const result = await pool.query(
    `SELECT u.id, u.phone, u.name, u.role, u.status
       FROM sessions s
       JOIN users u ON u.id = s.user_id
      WHERE s.id = $1 AND s.expires_at > now()`,
    [sessionId],
  );
  const user = result.rows[0] || null;
  return user?.status === 'active' ? user : null;
}

function requireAuth(req, res, next) {
  getUser(req).then((user) => {
    if (!user) return res.status(401).json({ error: 'Требуется авторизация' });
    req.user = user;
    next();
  }).catch(next);
}

function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Недостаточно прав' });
    }
    next();
  };
}

function sameJson(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function canUpdateState(user, previous, next) {
  if (['admin', 'manager'].includes(user.role)) return true;
  if (user.role === 'workshopChief') {
    if (!sameJson(previous.objects, next.objects)
      || !sameJson(previous.employees, next.employees)
      || !sameJson(previous.jobs, next.jobs)
      || !sameJson(previous.rates, next.rates)
      || !sameJson(previous.meta, next.meta)
      || previous.shifts.length !== next.shifts.length) return false;
    const employee = previous.employees.find((item) => item.phone === user.phone);
    if (!employee) return false;
    const previousById = new Map(previous.shifts.map((shift) => [shift.id, shift]));
    const editableShiftKeys = new Set(['completed', 'completedAt', 'completedById']);
    for (const shift of next.shifts) {
      const oldShift = previousById.get(shift.id);
      if (!oldShift) return false;
      if (sameJson(oldShift, shift)) continue;
      for (const key of new Set([...Object.keys(oldShift), ...Object.keys(shift)])) {
        if (editableShiftKeys.has(key)) continue;
        if (!sameJson(oldShift[key], shift[key])) return false;
      }
      if (shift.completed && shift.completedById !== employee.id) return false;
      if (!shift.completed && shift.completedById !== null && shift.completedById !== undefined) return false;
    }
    return true;
  }
  if (user.role !== 'field') return false;
  if (!sameJson(previous.objects, next.objects)
    || !sameJson(previous.employees, next.employees)
    || !sameJson(previous.shifts, next.shifts)
    || !sameJson(previous.rates, next.rates)
    || !sameJson(previous.meta, next.meta)
    || previous.jobs.length !== next.jobs.length) return false;

  const employee = previous.employees.find((item) => item.phone === user.phone || item.name === user.name);
  if (!employee) return false;
  const previousById = new Map(previous.jobs.map((job) => [job.id, job]));
  for (const job of next.jobs) {
    const oldJob = previousById.get(job.id);
    if (!oldJob) return false;
    if (sameJson(oldJob, job)) continue;
    if (!Array.isArray(oldJob.assignees) || !oldJob.assignees.includes(employee.id)) return false;
    const allowed = new Set(['checkin', 'checkout', 'photos', 'expenses']);
    for (const key of Object.keys(oldJob)) {
      if (!allowed.includes(key) && !sameJson(oldJob[key], job[key])) return false;
    }
  }
  return true;
}

async function initializeDatabase() {
  const schema = `
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY, phone TEXT NOT NULL UNIQUE, name TEXT NOT NULL,
      pin_hash TEXT NOT NULL, role TEXT NOT NULL CHECK (role IN ('admin','accountant','manager','workshopChief','field','workshop')),
      status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','blocked')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY, user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      expires_at TIMESTAMPTZ NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS sessions_expires_at_idx ON sessions (expires_at);
    CREATE TABLE IF NOT EXISTS app_state (
      id BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
      state JSONB NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `;
  await pool.query(schema);
  await pool.query('ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check');
  await pool.query("ALTER TABLE users ADD CONSTRAINT users_role_check CHECK (role IN ('admin','accountant','manager','workshopChief','field','workshop'))");
}

app.get('/health', async (_req, res, next) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true });
  } catch (error) {
    next(error);
  }
});

app.post('/api/auth/register', async (req, res, next) => {
  try {
    const input = registerSchema.parse(req.body);
    const phone = normalizePhone(input.phone);
    if (!phone) return res.status(400).json({ error: 'Некорректный телефон' });
    const existing = await pool.query('SELECT 1 FROM users WHERE phone = $1', [phone]);
    if (existing.rowCount) return res.status(409).json({ error: 'Пользователь уже зарегистрирован' });
    const count = await pool.query('SELECT count(*)::int AS count FROM users');
    const user = {
      id: newId(),
      phone,
      name: input.name,
      pinHash: await hashPin(input.pin),
      role: Number(count.rows[0].count) === 0 ? 'admin' : 'field',
    };
    const sessionId = newSessionId();
    const expiresAt = new Date(Date.now() + sessionTtlDays * 86400000);
    await pool.query(
      'INSERT INTO users (id, phone, name, pin_hash, role) VALUES ($1, $2, $3, $4, $5)',
      [user.id, user.phone, user.name, user.pinHash, user.role],
    );
    const defaultState = {
      objects: [], employees: [], jobs: [], shifts: [],
      rates: { visit: 4000, resp: 5000, service: 3000, shopShift: 4000, manager: 0 },
      meta: { createdAt: Date.now() },
    };
    const stateResult = await pool.query('SELECT state FROM app_state WHERE id = TRUE');
    const state = stateResult.rows[0]?.state || defaultState;
    state.employees = Array.isArray(state.employees) ? state.employees : [];
    state.employees.push({
      id: newId(),
      name: user.name,
      role: user.role === 'admin' ? 'manager' : user.role,
      phone: user.phone,
      email: '',
      salary: 0,
      hireDate: new Date().toISOString().slice(0, 10),
      active: true,
    });
    await pool.query(
      `INSERT INTO app_state (id, state, updated_at) VALUES (TRUE, $1, now())
       ON CONFLICT (id) DO UPDATE SET state = EXCLUDED.state, updated_at = now()`,
      [JSON.stringify(state)],
    );
    await pool.query('INSERT INTO sessions (id, user_id, expires_at) VALUES ($1, $2, $3)', [sessionId, user.id, expiresAt]);
    res.setHeader('Set-Cookie', sessionCookie(sessionId, sessionTtlDays * 86400));
    res.status(201).json({ user: { id: user.id, phone: user.phone, name: user.name, role: user.role } });
  } catch (error) {
    if (error?.name === 'ZodError') return res.status(400).json({ error: 'Проверьте введённые данные' });
    next(error);
  }
});

app.post('/api/auth/login', async (req, res, next) => {
  try {
    const input = authSchema.parse(req.body);
    const phone = normalizePhone(input.phone);
    if (!phone) return res.status(400).json({ error: 'Некорректный телефон' });
    const result = await pool.query(
      'SELECT id, phone, name, role, status, pin_hash FROM users WHERE phone = $1',
      [phone],
    );
    const user = result.rows[0];
    if (!user || user.status !== 'active' || !(await verifyPin(input.pin, user.pin_hash))) {
      return res.status(401).json({ error: 'Неверный телефон или PIN' });
    }
    const sessionId = newSessionId();
    const expiresAt = new Date(Date.now() + sessionTtlDays * 86400000);
    await pool.query('INSERT INTO sessions (id, user_id, expires_at) VALUES ($1, $2, $3)', [sessionId, user.id, expiresAt]);
    res.setHeader('Set-Cookie', sessionCookie(sessionId, sessionTtlDays * 86400));
    res.json({ user: { id: user.id, phone: user.phone, name: user.name, role: user.role } });
  } catch (error) {
    if (error?.name === 'ZodError') return res.status(400).json({ error: 'Проверьте введённые данные' });
    next(error);
  }
});

app.post('/api/auth/logout', async (req, res, next) => {
  try {
    const sessionId = getSessionId(req);
    if (sessionId) await pool.query('DELETE FROM sessions WHERE id = $1', [sessionId]);
    res.setHeader('Set-Cookie', clearSessionCookie());
    res.status(204).end();
  } catch (error) {
    next(error);
  }
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  res.json({ user: req.user });
});

app.get('/api/users', requireAuth, requireRole('admin'), async (_req, res, next) => {
  try {
    const result = await pool.query(
      'SELECT id, phone, name, role, status, created_at FROM users ORDER BY created_at ASC',
    );
    res.json({ users: result.rows });
  } catch (error) {
    next(error);
  }
});

app.patch('/api/users/:id', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    const input = z.object({
      role: z.enum(['admin', 'accountant', 'manager', 'workshopChief', 'field', 'workshop']).optional(),
      status: z.enum(['active', 'blocked']).optional(),
    }).refine((value) => value.role || value.status, 'No changes supplied').parse(req.body);
    if (req.params.id === req.user.id && input.status === 'blocked') {
      return res.status(400).json({ error: 'Нельзя заблокировать текущего пользователя' });
    }
    const result = await pool.query(
      `UPDATE users
          SET role = COALESCE($2, role), status = COALESCE($3, status)
        WHERE id = $1
      RETURNING id, phone, name, role, status`,
      [req.params.id, input.role || null, input.status || null],
    );
    if (!result.rowCount) return res.status(404).json({ error: 'Пользователь не найден' });
    res.json({ user: result.rows[0] });
  } catch (error) {
    if (error?.name === 'ZodError') return res.status(400).json({ error: 'Некорректное изменение пользователя' });
    next(error);
  }
});

app.post('/api/users/:id/reset-pin', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    const { pin } = z.object({ pin: z.string().regex(/^\d{4,}$/) }).parse(req.body);
    const result = await pool.query(
      'UPDATE users SET pin_hash = $2 WHERE id = $1 RETURNING id',
      [req.params.id, await hashPin(pin)],
    );
    if (!result.rowCount) return res.status(404).json({ error: 'Пользователь не найден' });
    res.status(204).end();
  } catch (error) {
    if (error?.name === 'ZodError') return res.status(400).json({ error: 'PIN должен содержать минимум четыре цифры' });
    next(error);
  }
});

app.get('/api/state', requireAuth, async (_req, res, next) => {
  try {
    const result = await pool.query('SELECT state FROM app_state WHERE id = TRUE');
    const state = result.rows[0]?.state || {
      objects: [], employees: [], jobs: [], shifts: [],
      rates: { visit: 4000, resp: 5000, service: 3000, shopShift: 4000, manager: 0 },
      meta: { createdAt: Date.now(), managerRateVersion: 1 },
    };
    if (!state.meta?.managerRateVersion) {
      state.rates = { ...(state.rates || {}), manager: 0 };
      state.meta = { ...(state.meta || {}), managerRateVersion: 1 };
      await pool.query(
        `INSERT INTO app_state (id, state, updated_at) VALUES (TRUE, $1, now())
         ON CONFLICT (id) DO UPDATE SET state = EXCLUDED.state, updated_at = now()`,
        [JSON.stringify(state)],
      );
    }
    res.json(state);
  } catch (error) {
    next(error);
  }
});

app.put('/api/state', requireAuth, async (req, res, next) => {
  try {
    const state = stateSchema.parse(req.body);
    const currentResult = await pool.query('SELECT state FROM app_state WHERE id = TRUE');
    const current = currentResult.rows[0]?.state || {
      objects: [], employees: [], jobs: [], shifts: [], rates: {}, meta: {},
    };
    if (!canUpdateState(req.user, current, state)) {
      return res.status(403).json({ error: 'Недостаточно прав для изменения этих данных' });
    }
    await pool.query(
      `INSERT INTO app_state (id, state, updated_at) VALUES (TRUE, $1, now())
       ON CONFLICT (id) DO UPDATE SET state = EXCLUDED.state, updated_at = now()`,
      [JSON.stringify(state)],
    );
    res.status(204).end();
  } catch (error) {
    if (error?.name === 'ZodError') return res.status(400).json({ error: 'Некорректное состояние приложения' });
    next(error);
  }
});

app.use(express.static(path.join(__dirname, 'public'), {
  extensions: ['html'],
  index: 'index.html',
}));

app.use((error, _req, res, _next) => {
  console.error(error);
  if (error instanceof SyntaxError && error.status === 400 && 'body' in error) {
    return res.status(400).json({ error: 'Некорректный JSON' });
  }
  res.status(500).json({ error: 'Внутренняя ошибка сервера' });
});

initializeDatabase()
  .then(() => app.listen(port, () => console.log(`Object Uchet listening on port ${port}`)))
  .catch((error) => {
    console.error('Database initialization failed', error);
    process.exitCode = 1;
  });
