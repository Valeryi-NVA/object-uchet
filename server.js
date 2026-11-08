import { createServer } from 'node:http';
import { createHash, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(fileURLToPath(import.meta.url));
const dataDir = join(root, 'data');
const dbFile = join(dataDir, 'db.json');
const port = Number(process.env.PORT || 10000);
const secret = process.env.AUTH_SECRET || 'change-this-secret-in-render';
const sessions = new Map();

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

const server = createServer(async (request, response) => {
  try {
    const url = new URL(request.url || '/', `http://${request.headers.host || 'localhost'}`);
    const db = await readDb();
    if (url.pathname === '/health') { send(response, 200, { ok: true }); return; }
    if (url.pathname === '/api/auth/register' && request.method === 'POST') {
      const input = await body(request);
      const phone = String(input.phone || '').replace(/\D/g, '');
      const name = String(input.name || '').trim();
      const password = String(input.password || '');
      if (phone.length < 10 || name.length < 2 || password.length < 6) { send(response, 400, { error: 'Проверьте телефон, ФИО и пароль' }); return; }
      if (db.users.some((user) => user.phone.replace(/\D/g, '') === phone)) { send(response, 409, { error: 'Пользователь уже зарегистрирован' }); return; }
      const user = { id: `u-${randomBytes(8).toString('hex')}`, phone: `+7${phone.slice(-10)}`, name, passHash: hashPassword(password), role: db.users.length ? 'worker' : 'admin', createdAt: new Date().toISOString() };
      db.users.push(user); await writeDb(db);
      send(response, 201, { user: publicUser(user), token: tokenFor(user) }); return;
    }
    if (url.pathname === '/api/auth/login' && request.method === 'POST') {
      const input = await body(request);
      const phone = String(input.phone || '').replace(/\D/g, '');
      const user = db.users.find((candidate) => candidate.phone.replace(/\D/g, '') === phone);
      if (!user || !verifyPassword(String(input.password || ''), user.passHash)) { send(response, 401, { error: 'Неверный телефон или пароль' }); return; }
      send(response, 200, { user: publicUser(user), token: tokenFor(user) }); return;
    }
    if (url.pathname === '/api/state' && request.method === 'GET') {
      if (!currentUser(request, db)) { send(response, 401, { error: 'Требуется вход' }); return; }
      const user = currentUser(request, db);
      send(response, 200, { db, user }); return;
    }
    if (url.pathname === '/api/state' && request.method === 'PUT') {
      const user = currentUser(request, db);
      if (!user) { send(response, 401, { error: 'Требуется вход' }); return; }
      const incoming = await body(request);
      if (!incoming || typeof incoming !== 'object' || !Array.isArray(incoming.users) || !Array.isArray(incoming.objects)) { send(response, 400, { error: 'Некорректное состояние приложения' }); return; }
      await writeDb({ ...incoming, session: null }); send(response, 200, { ok: true }); return;
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
server.listen(port, '0.0.0.0', () => console.log(`StroyGroup listening on ${port}`));
