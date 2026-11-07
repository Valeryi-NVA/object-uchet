import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import helmet from 'helmet';
import pg from 'pg';
import QRCode from 'qrcode';
import { z } from 'zod';

const { Pool } = pg;
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const port = Number(process.env.PORT || 10000);
const isProduction = process.env.NODE_ENV === 'production';
const sessionTtlDays = Number(process.env.SESSION_TTL_DAYS || 30);
const SYSTEM_ROLES = ['admin', 'accountant', 'employee', 'workshopChief', 'manager'];
const adminSessionTtlDays = 3650;

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
  password: z.string().min(4).max(200),
});

const registerSchema = authSchema.extend({
  name: z.string().trim().min(1).max(100),
});

const stateSchema = z.object({
  objects: z.array(z.unknown()).default([]),
  employees: z.array(z.unknown()).default([]),
  jobs: z.array(z.unknown()).default([]),
  shifts: z.array(z.unknown()).default([]),
  attendance: z.array(z.unknown()).default([]),
  audit: z.array(z.unknown()).default([]),
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

function normalizeRoles(roles, legacyRole) {
  const values = Array.isArray(roles) ? roles : [legacyRole];
  const mapped = values.map((value) => value === 'field' || value === 'workshop' ? 'employee' : value);
  return [...new Set(mapped.filter((value) => SYSTEM_ROLES.includes(value)))];
}

function sessionTtlForRoles(roles) {
  return roles.includes('admin') ? adminSessionTtlDays : sessionTtlDays;
}

async function getUser(req) {
  const sessionId = getSessionId(req);
  if (!sessionId) return null;
  const result = await pool.query(
    `SELECT u.id, u.phone, u.name, u.role, u.roles, u.status
       FROM sessions s
       JOIN users u ON u.id = s.user_id
      WHERE s.id = $1 AND s.expires_at > now()`,
    [sessionId],
  );
  const user = result.rows[0] || null;
  if (user) user.roles = normalizeRoles(user.roles, user.role);
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
    if (!allowedRoles.some((role) => req.user.roles.includes(role))) {
      return res.status(403).json({ error: 'Недостаточно прав' });
    }
    next();
  };
}

function sameJson(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function canUpdateAttendance(employee, previous, next) {
  const previousAttendance = Array.isArray(previous.attendance) ? previous.attendance : [];
  const nextAttendance = Array.isArray(next.attendance) ? next.attendance : [];
  const nextById = new Map(nextAttendance.map((item) => [item.id, item]));
  if (nextAttendance.length < previousAttendance.length) return false;
  for (const oldItem of previousAttendance) {
    const item = nextById.get(oldItem.id);
    if (!item) return false;
    if (sameJson(oldItem, item)) continue;
    if (item.employeeId !== employee.id) return false;
    for (const key of new Set([...Object.keys(oldItem), ...Object.keys(item)])) {
      if (key !== 'endedAt' || !sameJson(oldItem.employeeId, item.employeeId)) {
        if (!sameJson(oldItem[key], item[key])) return false;
      }
    }
  }
  for (const item of nextAttendance) {
    if (previousAttendance.some((oldItem) => oldItem.id === item.id)) continue;
    if (item.employeeId !== employee.id || item.endedAt) return false;
  }
  return true;
}

function canUpdateWorkerStatuses(previous, next) {
  if (previous.employees.length !== next.employees.length) return false;
  const nextById = new Map(next.employees.map((employee) => [employee.id, employee]));
  for (const oldEmployee of previous.employees) {
    const employee = nextById.get(oldEmployee.id);
    if (!employee) return false;
    for (const key of new Set([...Object.keys(oldEmployee), ...Object.keys(employee)])) {
      if (key === 'workerStatus') continue;
      if (!sameJson(oldEmployee[key], employee[key])) return false;
    }
  }
  return true;
}

function canUpdateState(user, previous, next) {
  if (user.roles.includes('admin')) return true;
  if (user.roles.includes('manager')) {
    return sameJson(previous.employees, next.employees)
      && sameJson(previous.jobs, next.jobs)
      && sameJson(previous.shifts, next.shifts)
      && sameJson(previous.attendance, next.attendance)
      && sameJson(previous.rates, next.rates)
      && sameJson(previous.meta, next.meta);
  }
  if (user.roles.includes('workshopChief')) {
    if (!sameJson(previous.objects, next.objects)
      || !canUpdateWorkerStatuses(previous, next)
      || !sameJson(previous.jobs, next.jobs)
      || !sameJson(previous.rates, next.rates)
      || !sameJson(previous.meta, next.meta)
      || previous.shifts.length !== next.shifts.length) return false;
    const employee = previous.employees.find((item) => item.phone === user.phone);
    if (!employee) return false;
    if (!canUpdateAttendance(employee, previous, next)) return false;
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
  if (!user.roles.includes('employee')) return false;
  if (!sameJson(previous.objects, next.objects)
    || !sameJson(previous.employees, next.employees)
    || !sameJson(previous.shifts, next.shifts)
    || !sameJson(previous.jobs, next.jobs)
    || !sameJson(previous.rates, next.rates)
    || !sameJson(previous.meta, next.meta)
    || previous.jobs.length !== next.jobs.length) return false;

  const employee = previous.employees.find((item) => item.phone === user.phone || item.name === user.name);
  if (!employee) return false;
  if (!canUpdateAttendance(employee, previous, next)) return false;
  if (user.roles.includes('employee')) return true;
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
      pin_hash TEXT NOT NULL, role TEXT NOT NULL CHECK (role IN ('admin','accountant','employee','workshopChief','manager','field','workshop')),
      roles TEXT[] NOT NULL DEFAULT ARRAY['employee'],
      qr_token TEXT UNIQUE,
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
    CREATE TABLE IF NOT EXISTS audit_log (
      id UUID PRIMARY KEY,
      actor_id UUID REFERENCES users(id) ON DELETE SET NULL,
      action TEXT NOT NULL,
      target_id UUID,
      details JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS audit_log_created_at_idx ON audit_log (created_at DESC);
  `;
  await pool.query(schema);
  await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS roles TEXT[]');
  await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS qr_token TEXT');
  const usersWithoutQr = await pool.query('SELECT id FROM users WHERE qr_token IS NULL');
  for (const user of usersWithoutQr.rows) {
    await pool.query('UPDATE users SET qr_token = $2 WHERE id = $1', [user.id, newSessionId()]);
  }
  await pool.query("UPDATE users SET roles = ARRAY[CASE WHEN role IN ('field','workshop') THEN 'employee' ELSE role END] WHERE roles IS NULL OR cardinality(roles) = 0");
  await pool.query('ALTER TABLE users ALTER COLUMN roles SET DEFAULT ARRAY[\'employee\']');
  await pool.query('ALTER TABLE users ALTER COLUMN roles SET NOT NULL');
  await pool.query('ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check');
  await pool.query("ALTER TABLE users ADD CONSTRAINT users_role_check CHECK (role IN ('admin','accountant','employee','workshopChief','manager','field','workshop'))");
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
      pinHash: await hashPin(input.password),
      role: Number(count.rows[0].count) === 0 ? 'admin' : 'employee',
      roles: Number(count.rows[0].count) === 0 ? ['admin'] : ['employee'],
    };
    const sessionId = newSessionId();
    const userSessionTtlDays = sessionTtlForRoles(user.roles);
    const expiresAt = new Date(Date.now() + userSessionTtlDays * 86400000);
    await pool.query(
      'INSERT INTO users (id, phone, name, pin_hash, role, roles, qr_token) VALUES ($1, $2, $3, $4, $5, $6, $7)',
      [user.id, user.phone, user.name, user.pinHash, user.role, user.roles, newSessionId()],
    );
    const defaultState = {
      objects: [], employees: [], jobs: [], shifts: [], attendance: [], audit: [],
      rates: { visit: 4000, resp: 5000, service: 3000, shopShift: 4000, manager: 0 },
      meta: { createdAt: Date.now(), managerRateVersion: 1, workflowVersion: 2 },
    };
    const stateResult = await pool.query('SELECT state FROM app_state WHERE id = TRUE');
    const state = stateResult.rows[0]?.state || defaultState;
    state.employees = Array.isArray(state.employees) ? state.employees : [];
    state.employees.push({
      id: newId(),
      name: user.name,
      role: user.role === 'admin' ? 'manager' : 'employee',
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
    res.setHeader('Set-Cookie', sessionCookie(sessionId, userSessionTtlDays * 86400));
    res.status(201).json({ user: { id: user.id, phone: user.phone, name: user.name, role: user.role, roles: user.roles } });
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
      'SELECT id, phone, name, role, roles, status, pin_hash FROM users WHERE phone = $1',
      [phone],
    );
    const user = result.rows[0];
    if (!user || user.status !== 'active' || !(await verifyPin(input.password, user.pin_hash))) {
      return res.status(401).json({ error: 'Неверный телефон или PIN' });
    }
    const sessionId = newSessionId();
    const userRoles = normalizeRoles(user.roles, user.role);
    const userSessionTtlDays = sessionTtlForRoles(userRoles);
    const expiresAt = new Date(Date.now() + userSessionTtlDays * 86400000);
    await pool.query('INSERT INTO sessions (id, user_id, expires_at) VALUES ($1, $2, $3)', [sessionId, user.id, expiresAt]);
    res.setHeader('Set-Cookie', sessionCookie(sessionId, userSessionTtlDays * 86400));
    res.json({ user: { id: user.id, phone: user.phone, name: user.name, role: user.role, roles: normalizeRoles(user.roles, user.role) } });
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

app.get('/api/auth/attendance-token', requireAuth, async (req, res, next) => {
  try {
    const result = await pool.query('SELECT qr_token FROM users WHERE id = $1', [req.user.id]);
    res.json({ token: result.rows[0]?.qr_token || null });
  } catch (error) {
    next(error);
  }
});

app.get('/api/auth/attendance-qr', requireAuth, async (req, res, next) => {
  try {
    const result = await pool.query('SELECT qr_token FROM users WHERE id = $1', [req.user.id]);
    const token = result.rows[0]?.qr_token;
    if (!token) return res.status(404).json({ error: 'QR-код не найден' });
    const link = `${req.protocol}://${req.get('host')}/?mode=attendance&qr=${encodeURIComponent(token)}`;
    res.json({ link, image: await QRCode.toDataURL(link, { width: 320, margin: 2 }) });
  } catch (error) {
    next(error);
  }
});

app.post('/api/auth/attendance-token/verify', requireAuth, async (req, res, next) => {
  try {
    const token = z.object({ token: z.string().min(20).max(200) }).parse(req.body).token;
    const result = await pool.query(
      'SELECT id FROM users WHERE id = $1 AND qr_token = $2 AND status = $3',
      [req.user.id, token, 'active'],
    );
    if (!result.rowCount) return res.status(403).json({ error: 'QR-код не принадлежит этому пользователю' });
    res.json({ valid: true });
  } catch (error) {
    if (error?.name === 'ZodError') return res.status(400).json({ error: 'Некорректный QR-код' });
    next(error);
  }
});

app.get('/api/users', requireAuth, requireRole('admin'), async (_req, res, next) => {
  try {
    const result = await pool.query(
      'SELECT id, phone, name, roles, status, created_at FROM users ORDER BY created_at ASC',
    );
    res.json({ users: result.rows });
  } catch (error) {
    next(error);
  }
});

app.patch('/api/users/:id', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    const input = z.object({
      roles: z.array(z.enum(SYSTEM_ROLES)).min(1).optional(),
      status: z.enum(['active', 'blocked']).optional(),
    }).refine((value) => value.roles || value.status, 'No changes supplied').parse(req.body);
    const firstUser = await pool.query('SELECT id FROM users ORDER BY created_at ASC LIMIT 1');
    if (firstUser.rows[0]?.id === req.params.id) {
      return res.status(400).json({ error: 'Первого администратора нельзя изменять' });
    }
    if (req.params.id === req.user.id && (input.status === 'blocked' || input.roles)) {
      return res.status(400).json({ error: 'Учётную запись главного администратора нельзя изменять' });
    }
    const result = await pool.query(
      `UPDATE users
          SET roles = COALESCE($2, roles),
              role = COALESCE($3, role),
              status = COALESCE($4, status)
        WHERE id = $1
      RETURNING id, phone, name, roles, status`,
      [req.params.id, input.roles || null, input.roles?.[0] || null, input.status || null],
    );
    if (!result.rowCount) return res.status(404).json({ error: 'Пользователь не найден' });
    await pool.query(
      'INSERT INTO audit_log (id, actor_id, action, target_id, details) VALUES ($1, $2, $3, $4, $5)',
      [newId(), req.user.id, input.roles ? 'user.roles.changed' : 'user.status.changed', req.params.id, JSON.stringify(input)],
    );
    res.json({ user: result.rows[0] });
  } catch (error) {
    if (error?.name === 'ZodError') return res.status(400).json({ error: 'Некорректное изменение пользователя' });
    next(error);
  }
});

app.get('/api/audit', requireAuth, requireRole('admin', 'accountant', 'workshopChief'), async (_req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT a.id, a.action, a.target_id, a.details, a.created_at,
              actor.name AS actor_name, target.name AS target_name
         FROM audit_log a
         LEFT JOIN users actor ON actor.id = a.actor_id
         LEFT JOIN users target ON target.id = a.target_id
        ORDER BY a.created_at DESC
        LIMIT 500`,
    );
    res.json({ audit: result.rows });
  } catch (error) {
    next(error);
  }
});

app.post('/api/users/:id/reset-pin', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    const { password } = z.object({ password: z.string().min(4).max(200) }).parse(req.body);
    const result = await pool.query(
      'UPDATE users SET pin_hash = $2 WHERE id = $1 RETURNING id',
      [req.params.id, await hashPin(password)],
    );
    if (!result.rowCount) return res.status(404).json({ error: 'Пользователь не найден' });
    res.status(204).end();
  } catch (error) {
    if (error?.name === 'ZodError') return res.status(400).json({ error: 'Пароль должен содержать минимум четыре символа' });
    next(error);
  }
});

app.post('/api/users/:id/regenerate-qr', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    const token = newSessionId();
    const result = await pool.query(
      'UPDATE users SET qr_token = $2 WHERE id = $1 RETURNING id, qr_token',
      [req.params.id, token],
    );
    if (!result.rowCount) return res.status(404).json({ error: 'Пользователь не найден' });
    await pool.query(
      'INSERT INTO audit_log (id, actor_id, action, target_id, details) VALUES ($1, $2, $3, $4, $5)',
      [newId(), req.user.id, 'user.qr.regenerated', req.params.id, JSON.stringify({})],
    );
    res.json({ token: result.rows[0].qr_token });
  } catch (error) {
    next(error);
  }
});

app.get('/api/state', requireAuth, async (_req, res, next) => {
  try {
    const result = await pool.query('SELECT state FROM app_state WHERE id = TRUE');
    const state = result.rows[0]?.state || {
      objects: [], employees: [], jobs: [], shifts: [], attendance: [], audit: [],
      rates: { visit: 4000, resp: 5000, service: 3000, shopShift: 4000, manager: 0 },
      meta: { createdAt: Date.now(), managerRateVersion: 1, workflowVersion: 2 },
    };
    if (!state.meta?.workflowVersion) {
      state.employees = (state.employees || []).map((employee) => ({
        ...employee,
        type: employee.type || (employee.role === 'workshop' ? 'workshop' : 'field'),
        workerStatus: employee.workerStatus || 'worker',
      }));
      state.attendance = Array.isArray(state.attendance) ? state.attendance : [];
      state.audit = Array.isArray(state.audit) ? state.audit : [];
      state.meta = { ...(state.meta || {}), workflowVersion: 2 };
      await pool.query(
        `INSERT INTO app_state (id, state, updated_at) VALUES (TRUE, $1, now())
         ON CONFLICT (id) DO UPDATE SET state = EXCLUDED.state, updated_at = now()`,
        [JSON.stringify(state)],
      );
    }
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
      objects: [], employees: [], jobs: [], shifts: [], attendance: [], audit: [], rates: {}, meta: {},
    };
    if (!canUpdateState(req.user, current, state)) {
      return res.status(403).json({ error: 'Недостаточно прав для изменения этих данных' });
    }
    await pool.query(
      `INSERT INTO app_state (id, state, updated_at) VALUES (TRUE, $1, now())
       ON CONFLICT (id) DO UPDATE SET state = EXCLUDED.state, updated_at = now()`,
      [JSON.stringify(state)],
    );
    const changedSections = ['objects', 'jobs', 'shifts', 'attendance', 'employees']
      .filter((section) => !sameJson(current[section], state[section]));
    if (changedSections.length) {
      await pool.query(
        'INSERT INTO audit_log (id, actor_id, action, details) VALUES ($1, $2, $3, $4)',
        [newId(), req.user.id, 'state.changed', JSON.stringify({ sections: changedSections })],
      );
    }
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
