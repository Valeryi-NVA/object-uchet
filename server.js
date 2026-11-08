import { createServer } from 'node:http';
import { createHash, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';

const root = dirname(fileURLToPath(import.meta.url));
const dataDir = join(root, 'data');
const dbFile = join(dataDir, 'db.json');
const port = Number(process.env.PORT || 10000);
const secret = process.env.AUTH_SECRET || 'change-this-secret-in-render';
const sessions = new Map();
const pool = process.env.DATABASE_URL
  ? new pg.Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } })
  : null;

function hashPassword(password) {
  const salt = randomBytes(16).toString('hex');
  const key = scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${key}`;
}
function verifyPassword(password, stored) {
  const [salt, key] = String(stored || '').split(':');
  if (!salt || !key) return false;
  const actual = scryptSync(password, salt, 64);
  const expected = Buffer.from(key, 'hex');
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}
function tokenFor(user) {
  const payload = `${user.id}.${Date.now()}`;
  const signature = createHash('sha256').update(`${payload}.${secret}`).digest('hex');
  const token = `${payload}.${signature}`;
  sessions.set(token, user.id);
  return token;
}
async function readDb() {
  if (!existsSync(dbFile)) {
    await mkdir(dataDir, { recursive: true });
    const db = { employees: [], vehicles: [], works: [], objects: [], timesheet: [], trips: [], output: [], costs: [], payments: [], users: [{ id: 'u-admin', phone: '+79000000000', name: 'Администратор', passHash: hashPassword('admin'), role: 'admin', createdAt: new Date().toISOString() }], settings: {}, session: null };
    await writeFile(dbFile, JSON.stringify(db, null, 2), 'utf8');
  }
  return JSON.parse(await readFile(dbFile, 'utf8'));
}
async function writeDb(db) {
  await mkdir(dataDir, { recursive: true });
  await writeFile(dbFile, JSON.stringify(db, null, 2), 'utf8');
}
function send(response, status, body, headers = {}) {
  response.writeHead(status, { 'content-type': 'application/json; charset=utf-8', ...headers });
  response.end(JSON.stringify(body));
}
async function body(request) {
  let raw = '';
  for await (const chunk of request) raw += chunk;
  return raw ? JSON.parse(raw) : {};
}
function currentUser(request, db) {
  const token = request.headers.authorization?.startsWith('Bearer ') ? request.headers.authorization.slice(7) : '';
  const userId = sessions.get(token);
  return userId ? db.users.find((user) => user.id === userId) : null;
}
function publicUser(user) {
  return { id: user.id, phone: user.phone, name: user.name, role: user.role, createdAt: user.createdAt };
}
function publicDb(db) {
  return { ...db, users: db.users.map(publicUser), session: null };
}
async function authenticatedUser(request, db) {
  const token = request.headers.authorization?.startsWith('Bearer ') ? request.headers.authorization.slice(7) : '';
  if (!token) return null;
  if (pool) {
    const [userId, issuedAt, signature] = token.split('.');
    const payload = `${userId}.${issuedAt}`;
    const expected = createHash('sha256').update(`${payload}.${secret}`).digest('hex');
    if (!userId || !issuedAt || !signature || signature !== expected) return null;
    const result = await pool.query('SELECT id, phone, name, role, created_at FROM app_users WHERE id = $1', [userId]);
    return result.rows[0] ? {
      id: result.rows[0].id,
      phone: result.rows[0].phone,
      name: result.rows[0].name,
      role: result.rows[0].role,
      createdAt: result.rows[0].created_at
    } : null;
  }
  return currentUser(request, db);
}
function canManage(user) {
  return ['admin', 'OWNER', 'MANAGER', 'ACCOUNTANT'].includes(user.role);
}
async function audit(userId, action, entity, entityId, payload = {}) {
  if (pool) await pool.query(
    'INSERT INTO audit_logs (user_id, action, entity, entity_id, payload) VALUES ($1, $2, $3, $4, $5)',
    [userId, action, entity, entityId, JSON.stringify(payload)]
  );
}
async function postgresState() {
  const [users, objects, expenses, timeEntries] = await Promise.all([
    pool.query('SELECT id, phone, name, role, created_at FROM app_users ORDER BY created_at'),
    pool.query('SELECT id, client_id, name, address, status, start_date, end_date, note, created_at FROM objects ORDER BY created_at DESC'),
    pool.query('SELECT id, object_id, category, amount, currency, rate_to_base, expense_date, receipt_url, note, created_by_id FROM expenses ORDER BY expense_date DESC'),
    pool.query('SELECT id, employee_id, object_id, entry_date, hours, status, note FROM time_entries ORDER BY entry_date DESC')
  ]);
  return {
    users: users.rows.map((row) => ({ id: row.id, phone: row.phone, name: row.name, role: row.role, createdAt: row.created_at })),
    objects: objects.rows,
    costs: expenses.rows,
    timesheet: timeEntries.rows
  };
}

const server = createServer(async (request, response) => {
  try {
    const url = new URL(request.url || '/', `http://${request.headers.host || 'localhost'}`);
    const db = pool ? null : await readDb();
    if (url.pathname === '/health') { send(response, 200, { ok: true }); return; }
    if (url.pathname === '/api/auth/register' && request.method === 'POST') {
      const input = await body(request);
      const phone = String(input.phone || '').replace(/\D/g, '');
      const name = String(input.name || '').trim();
      const password = String(input.password || '');
      if (phone.length < 10 || name.length < 2 || password.length < 6) { send(response, 400, { error: 'Проверьте телефон, ФИО и пароль' }); return; }
      if (pool) {
        const normalizedPhone = `+7${phone.slice(-10)}`;
        const exists = await pool.query('SELECT 1 FROM app_users WHERE phone = $1', [normalizedPhone]);
        if (exists.rowCount) { send(response, 409, { error: 'Пользователь уже зарегистрирован' }); return; }
        const count = await pool.query('SELECT COUNT(*)::int AS count FROM app_users');
        const user = { id: `u-${randomBytes(8).toString('hex')}`, phone: normalizedPhone, name, passHash: hashPassword(password), role: count.rows[0].count ? 'EMPLOYEE' : 'OWNER', createdAt: new Date().toISOString() };
        await pool.query('INSERT INTO app_users (id, phone, name, password_hash, role, created_at) VALUES ($1, $2, $3, $4, $5, $6)', [user.id, user.phone, user.name, user.passHash, user.role, user.createdAt]);
        send(response, 201, { user: publicUser(user), token: tokenFor(user) }); return;
      }
      if (db.users.some((user) => user.phone.replace(/\D/g, '') === phone)) { send(response, 409, { error: 'Пользователь уже зарегистрирован' }); return; }
      const user = { id: `u-${randomBytes(8).toString('hex')}`, phone: `+7${phone.slice(-10)}`, name, passHash: hashPassword(password), role: db.users.length ? 'worker' : 'admin', createdAt: new Date().toISOString() };
      db.users.push(user); await writeDb(db);
      send(response, 201, { user: publicUser(user), token: tokenFor(user) }); return;
    }
    if (url.pathname === '/api/auth/login' && request.method === 'POST') {
      const input = await body(request);
      const phone = String(input.phone || '').replace(/\D/g, '');
      if (pool) {
        const result = await pool.query("SELECT id, phone, name, password_hash, role, created_at FROM app_users WHERE regexp_replace(phone, '\\D', '', 'g') = $1", [phone]);
        const row = result.rows[0];
        if (!row || !verifyPassword(String(input.password || ''), row.password_hash)) { send(response, 401, { error: 'Неверный телефон или пароль' }); return; }
        const user = { id: row.id, phone: row.phone, name: row.name, role: row.role, createdAt: row.created_at };
        send(response, 200, { user: publicUser(user), token: tokenFor(user) }); return;
      }
      const user = db.users.find((candidate) => candidate.phone.replace(/\D/g, '') === phone);
      if (!user || !verifyPassword(String(input.password || ''), user.passHash)) { send(response, 401, { error: 'Неверный телефон или пароль' }); return; }
      send(response, 200, { user: publicUser(user), token: tokenFor(user) }); return;
    }
    if (url.pathname === '/api/state' && request.method === 'GET') {
      const user = await authenticatedUser(request, db);
      if (!user) { send(response, 401, { error: 'Требуется вход' }); return; }
      if (pool) { send(response, 200, { db: await postgresState(), user: publicUser(user) }); return; }
      send(response, 200, { db: publicDb(db), user: publicUser(user) }); return;
    }
    if (url.pathname === '/api/state' && request.method === 'PUT') {
      const user = await authenticatedUser(request, db);
      if (!user) { send(response, 401, { error: 'Требуется вход' }); return; }
      if (pool) { send(response, 409, { error: 'Используйте ресурсные API PostgreSQL' }); return; }
      const incoming = await body(request);
      if (!incoming || typeof incoming !== 'object' || !Array.isArray(incoming.objects)) { send(response, 400, { error: 'Некорректное состояние приложения' }); return; }
      await writeDb({ ...incoming, users: db.users, session: null }); send(response, 200, { ok: true }); return;
    }
    if (pool && url.pathname === '/api/clients' && request.method === 'GET') {
      const user = await authenticatedUser(request, db);
      if (!user) { send(response, 401, { error: 'Требуется вход' }); return; }
      const result = await pool.query('SELECT id, name, contact, created_at FROM clients ORDER BY created_at DESC');
      send(response, 200, { items: result.rows }); return;
    }
    if (pool && url.pathname === '/api/clients' && request.method === 'POST') {
      const user = await authenticatedUser(request, db);
      if (!user || !canManage(user)) { send(response, 403, { error: 'Недостаточно прав' }); return; }
      const input = await body(request);
      const name = String(input.name || '').trim();
      if (name.length < 2) { send(response, 400, { error: 'Название клиента обязательно' }); return; }
      const id = `c-${randomBytes(8).toString('hex')}`;
      const result = await pool.query('INSERT INTO clients (id, name, contact) VALUES ($1, $2, $3) RETURNING id, name, contact, created_at', [id, name, String(input.contact || '').trim()]);
      await audit(user.id, 'CREATE', 'Client', id, result.rows[0]);
      send(response, 201, { item: result.rows[0] }); return;
    }
    const objectMatch = url.pathname.match(/^\/api\/objects\/([^/]+)$/);
    const objectCostsMatch = url.pathname.match(/^\/api\/objects\/([^/]+)\/costs$/);
    if (pool && url.pathname === '/api/objects' && request.method === 'GET') {
      const user = await authenticatedUser(request, db);
      if (!user) { send(response, 401, { error: 'Требуется вход' }); return; }
      const result = await pool.query('SELECT id, client_id, name, address, status, start_date, end_date, note, created_at FROM objects ORDER BY created_at DESC');
      send(response, 200, { items: result.rows }); return;
    }
    if (pool && url.pathname === '/api/objects' && request.method === 'POST') {
      const user = await authenticatedUser(request, db);
      if (!user || !canManage(user)) { send(response, 403, { error: 'Недостаточно прав' }); return; }
      const input = await body(request);
      const name = String(input.name || '').trim();
      if (name.length < 2) { send(response, 400, { error: 'Название объекта обязательно' }); return; }
      const id = `o-${randomBytes(8).toString('hex')}`;
      const result = await pool.query('INSERT INTO objects (id, client_id, name, address, status, note) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *', [id, input.clientId || null, name, String(input.address || '').trim(), String(input.status || 'PLANNING'), input.note || null]);
      await audit(user.id, 'CREATE', 'Object', id, result.rows[0]);
      send(response, 201, { item: result.rows[0] }); return;
    }
    if (pool && objectCostsMatch && request.method === 'GET') {
      const user = await authenticatedUser(request, db);
      if (!user) { send(response, 401, { error: 'Требуется вход' }); return; }
      const objectId = objectCostsMatch[1];
      const from = url.searchParams.get('from') || '1900-01-01';
      const to = url.searchParams.get('to') || '2999-12-31';
      const result = await pool.query('SELECT category, COALESCE(SUM(amount * rate_to_base), 0)::numeric AS total FROM expenses WHERE object_id = $1 AND expense_date BETWEEN $2 AND $3 GROUP BY category ORDER BY category', [objectId, from, to]);
      const byCategory = Object.fromEntries(result.rows.map((row) => [row.category, Number(row.total)]));
      send(response, 200, { byCategory, total: Object.values(byCategory).reduce((sum, value) => sum + value, 0) }); return;
    }
    if (pool && url.pathname === '/api/expenses' && request.method === 'POST') {
      const user = await authenticatedUser(request, db);
      if (!user || !canManage(user)) { send(response, 403, { error: 'Недостаточно прав' }); return; }
      const input = await body(request);
      const amount = Number(input.amount);
      if (!input.objectId || !Number.isFinite(amount) || amount < 0 || !input.category || !input.date) { send(response, 400, { error: 'Объект, категория, сумма и дата обязательны' }); return; }
      const id = `e-${randomBytes(8).toString('hex')}`;
      const result = await pool.query('INSERT INTO expenses (id, object_id, category, amount, currency, rate_to_base, expense_date, receipt_url, note, created_by_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING *', [id, input.objectId, input.category, amount, input.currency || 'RUB', Number(input.rateToBase || 1), input.date, input.receiptUrl || null, input.note || null, user.id]);
      await audit(user.id, 'CREATE', 'Expense', id, result.rows[0]);
      send(response, 201, { item: result.rows[0] }); return;
    }
    if (pool && url.pathname === '/api/expenses' && request.method === 'GET') {
      const user = await authenticatedUser(request, db);
      if (!user) { send(response, 401, { error: 'Требуется вход' }); return; }
      const result = await pool.query('SELECT id, object_id, category, amount, currency, rate_to_base, expense_date, receipt_url, note, created_by_id FROM expenses ORDER BY expense_date DESC');
      send(response, 200, { items: result.rows }); return;
    }
    if (pool && url.pathname === '/api/time-entries' && request.method === 'POST') {
      const user = await authenticatedUser(request, db);
      if (!user) { send(response, 401, { error: 'Требуется вход' }); return; }
      const input = await body(request);
      const entryDate = String(input.date || '');
      const hours = Number(input.hours);
      if (!input.objectId || !entryDate || !Number.isFinite(hours) || hours <= 0 || entryDate > new Date().toISOString().slice(0, 10)) {
        send(response, 400, { error: 'Объект, дата и положительное количество часов обязательны; дата не может быть будущей' }); return;
      }
      const employeeId = user.role === 'EMPLOYEE' ? user.id : String(input.employeeId || user.id);
      const id = `t-${randomBytes(8).toString('hex')}`;
      const result = await pool.query('INSERT INTO time_entries (id, employee_id, object_id, entry_date, hours, status, note) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *', [id, employeeId, input.objectId, entryDate, hours, 'DRAFT', input.note || null]);
      await audit(user.id, 'CREATE', 'TimeEntry', id, result.rows[0]);
      send(response, 201, { item: result.rows[0] }); return;
    }
    if (pool && url.pathname === '/api/time-entries' && request.method === 'GET') {
      const user = await authenticatedUser(request, db);
      if (!user) { send(response, 401, { error: 'Требуется вход' }); return; }
      const query = user.role === 'EMPLOYEE'
        ? pool.query('SELECT id, employee_id, object_id, entry_date, hours, status, note FROM time_entries WHERE employee_id = $1 ORDER BY entry_date DESC', [user.id])
        : pool.query('SELECT id, employee_id, object_id, entry_date, hours, status, note FROM time_entries ORDER BY entry_date DESC');
      const result = await query;
      send(response, 200, { items: result.rows }); return;
    }
    if (url.pathname === '/' || url.pathname === '/index.html') {
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      response.end(await readFile(join(root, 'index.html'))); return;
    }
    response.writeHead(404); response.end('Not found');
  } catch (error) {
    console.error(error);
    send(response, 500, { error: 'Внутренняя ошибка сервера' });
  }
});
async function initializePostgres() {
  if (!pool) return;
  await pool.query(await readFile(join(root, 'schema.sql'), 'utf8'));
  const count = await pool.query('SELECT COUNT(*)::int AS count FROM app_users');
  if (!count.rows[0].count) {
    const user = { id: 'u-admin', phone: '+79000000000', name: 'Администратор', passHash: hashPassword('admin'), role: 'OWNER', createdAt: new Date().toISOString() };
    await pool.query('INSERT INTO app_users (id, phone, name, password_hash, role, created_at) VALUES ($1, $2, $3, $4, $5, $6)', [user.id, user.phone, user.name, user.passHash, user.role, user.createdAt]);
    console.log('Created initial OWNER account: +79000000000');
  }
}
await initializePostgres();
server.listen(port, '0.0.0.0', () => console.log(`StroyGroup listening on ${port}`));
