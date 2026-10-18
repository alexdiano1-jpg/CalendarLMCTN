// Hub per amici — backend unico per Vercel (Express 5 + Neon Postgres + Google API)
try { process.loadEnvFile(); } catch {}
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const helmet = require('helmet');
const cookieSession = require('cookie-session');
const { Pool } = require('pg');
const { google } = require('googleapis');

/* ================= DATABASE (Neon Postgres) ================= */
const pool = new Pool({ connectionString: process.env.DATABASE_URL || process.env.POSTGRES_URL, max: 1 });
const query = async (text, params = []) => (await pool.query(text, params)).rows;
const one = async (text, params) => (await query(text, params))[0];
async function tx(fn) {
  const c = await pool.connect();
  try { await c.query('BEGIN'); await fn((t, p) => c.query(t, p)); await c.query('COMMIT'); }
  catch (e) { await c.query('ROLLBACK'); throw e; }
  finally { c.release(); }
}
let ready;
const init = () => (ready ??= pool.query(`
CREATE TABLE IF NOT EXISTS users(
  id SERIAL PRIMARY KEY, google_sub TEXT UNIQUE, email TEXT UNIQUE NOT NULL, name TEXT, picture TEXT,
  role TEXT NOT NULL DEFAULT 'viewer' CHECK(role IN ('admin','member','viewer')),
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','blocked')),
  created_at TIMESTAMPTZ DEFAULT now());
CREATE TABLE IF NOT EXISTS chats(id SERIAL PRIMARY KEY, name TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS messages(
  id SERIAL PRIMARY KEY, chat_id INT NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
  user_id INT NOT NULL REFERENCES users(id), body TEXT NOT NULL, created_at TIMESTAMPTZ DEFAULT now());
CREATE TABLE IF NOT EXISTS access(
  resource_type TEXT CHECK(resource_type IN ('chat','folder')), resource_id TEXT,
  subject_type TEXT CHECK(subject_type IN ('user','role')), subject_id TEXT,
  PRIMARY KEY(resource_type, resource_id, subject_type, subject_id));
`).catch((e) => { ready = null; throw e; }));

/* ================= GOOGLE (account master) ================= */
const oauthClient = () => new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT_ID, process.env.GOOGLE_CLIENT_SECRET, `${process.env.BASE_URL}/auth/callback`);
const master = oauthClient();
master.setCredentials({ refresh_token: process.env.MASTER_REFRESH_TOKEN });
const calendar = google.calendar({ version: 'v3', auth: master });
const drive = google.drive({ version: 'v3', auth: master });
const CAL_ID = process.env.MASTER_CALENDAR_ID || 'primary';
const ROOT_ID = process.env.NOTES_ROOT_FOLDER_ID;

/* ================= RBAC ================= */
const PERMS = {
  admin: ['*'],
  member: ['calendar:read', 'calendar:write', 'notes:read', 'notes:write', 'chat:read', 'chat:post'],
  viewer: ['calendar:read', 'notes:read', 'chat:read'],
};
const can = (u, perm) => !!u && u.status === 'approved' && (PERMS[u.role]?.includes('*') || PERMS[u.role]?.includes(perm));
const SUBJECT = `((subject_type='user' AND subject_id=$3) OR (subject_type='role' AND subject_id=$4))`;
async function hasAccess(u, type, id) {
  if (u.role === 'admin') return true;
  return !!(await one(`SELECT 1 FROM access WHERE resource_type=$1 AND resource_id=$2 AND ${SUBJECT}`,
    [type, String(id), String(u.id), u.role]));
}
async function visibleIds(u, type) { // null = tutto (admin)
  if (u.role === 'admin') return null;
  const rows = await query(`SELECT resource_id FROM access WHERE resource_type=$1 AND ((subject_type='user' AND subject_id=$2) OR (subject_type='role' AND subject_id=$3))`,
    [type, String(u.id), u.role]);
  return new Set(rows.map((r) => r.resource_id));
}
const requirePerm = (perm) => (req, res, next) =>
  can(req.user, perm) ? next() : res.status(403).json({ error: 'permesso negato' });
const requireResource = (type, perm, idFn) => async (req, res, next) => {
  if (!can(req.user, perm)) return res.status(403).json({ error: 'permesso negato' });
  if (!(await hasAccess(req.user, type, idFn(req)))) return res.status(403).json({ error: 'risorsa non abilitata' });
  next();
};
const onlyAdmin = (req, res, next) => (req.user.role === 'admin' ? next() : res.status(403).json({ error: 'solo admin' }));

/* ================= APP ================= */
const app = express();
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json());
app.use(cookieSession({
  name: 'hub', keys: [process.env.SESSION_SECRET], maxAge: 30 * 864e5,
  httpOnly: true, sameSite: 'lax', secure: process.env.BASE_URL?.startsWith('https'),
}));
app.use(async (_req, _res, next) => { await init(); next(); });
app.use(async (req, _res, next) => {
  req.user = req.session?.uid ? await one('SELECT * FROM users WHERE id=$1', [req.session.uid]) : null;
  next();
});
app.use(express.static(path.join(__dirname, '..', 'public'))); // in locale; su Vercel serve public/ da solo

/* ---------- Login Google (solo identità) ---------- */
app.get('/auth/login', (req, res) => {
  req.session.state = crypto.randomBytes(16).toString('hex');
  res.redirect(oauthClient().generateAuthUrl({
    scope: ['openid', 'email', 'profile'], state: req.session.state, prompt: 'select_account' }));
});
app.get('/auth/callback', async (req, res) => {
  if (!req.query.state || req.query.state !== req.session?.state) return res.status(400).send('state non valido');
  const c = oauthClient();
  const { tokens } = await c.getToken(req.query.code);
  const p = (await c.verifyIdToken({ idToken: tokens.id_token, audience: process.env.GOOGLE_CLIENT_ID })).getPayload();
  if (!p.email_verified) return res.status(403).send('email non verificata');
  const email = p.email.toLowerCase();
  const isAdmin = email === process.env.ADMIN_EMAIL.toLowerCase();
  let u = await one('SELECT * FROM users WHERE google_sub=$1 OR email=$2', [p.sub, email]);
  if (!u) {
    u = await one('INSERT INTO users(google_sub,email,name,picture,role,status) VALUES($1,$2,$3,$4,$5,$6) RETURNING id',
      [p.sub, email, p.name, p.picture, isAdmin ? 'admin' : 'viewer', isAdmin ? 'approved' : 'pending']);
  } else {
    await query('UPDATE users SET google_sub=$1, name=$2, picture=$3 WHERE id=$4', [p.sub, p.name, p.picture, u.id]);
    if (isAdmin) await query(`UPDATE users SET role='admin', status='approved' WHERE id=$1`, [u.id]);
  }
  req.session = { uid: u.id };
  res.redirect('/');
});
app.post('/auth/logout', (req, res) => { req.session = null; res.json({ ok: true }); });
app.get('/api/me', (req, res) => res.json(req.user && { id: req.user.id, name: req.user.name, role: req.user.role, status: req.user.status }));

const api = express.Router();
api.use((req, res, next) => (req.user?.status === 'approved' ? next() : res.status(401).json({ error: 'non autorizzato' })));

/* ---------- Calendario ---------- */
api.get('/calendar/events', requirePerm('calendar:read'), async (req, res) => {
  const r = await calendar.events.list({ calendarId: CAL_ID, singleEvents: true, orderBy: 'startTime', maxResults: 250,
    timeMin: req.query.from || new Date().toISOString(), timeMax: req.query.to });
  res.json(r.data.items);
});
api.post('/calendar/events', requirePerm('calendar:write'), async (req, res) => {
  const { title, description, start, end } = req.body;
  const r = await calendar.events.insert({ calendarId: CAL_ID,
    requestBody: { summary: title, description: `${description || ''}\n— creato da ${req.user.name}`, start, end } });
  res.json(r.data);
});
api.delete('/calendar/events/:id', requirePerm('calendar:write'), async (req, res) => {
  await calendar.events.delete({ calendarId: CAL_ID, eventId: req.params.id });
  res.json({ ok: true });
});

/* ---------- Note (cartelle Drive del master) ---------- */
const notes = express.Router();
const safeId = (req, res, next, v) => (/^[\w-]+$/.test(v) ? next() : res.status(400).json({ error: 'id non valido' }));
notes.param('folderId', safeId); notes.param('fileId', safeId);
notes.get('/folders', requirePerm('notes:read'), async (req, res) => {
  const r = await drive.files.list({ q: `'${ROOT_ID}' in parents and mimeType='application/vnd.google-apps.folder' and trashed=false`, fields: 'files(id,name)' });
  const ids = await visibleIds(req.user, 'folder');
  res.json(r.data.files.filter((f) => !ids || ids.has(f.id)));
});
async function guardFile(req, res, perm) {
  if (!can(req.user, perm)) { res.status(403).json({ error: 'permesso negato' }); return null; }
  const f = await drive.files.get({ fileId: req.params.fileId, fields: 'id,name,parents' });
  const parent = f.data.parents?.[0];
  if (!parent || !(await hasAccess(req.user, 'folder', parent))) { res.status(403).json({ error: 'cartella non abilitata' }); return null; }
  return f.data;
}
notes.get('/folders/:folderId/files', requireResource('folder', 'notes:read', (r) => r.params.folderId), async (req, res) => {
  const r = await drive.files.list({ q: `'${req.params.folderId}' in parents and trashed=false and mimeType='text/plain'`, fields: 'files(id,name,modifiedTime)' });
  res.json(r.data.files);
});
notes.get('/files/:fileId', async (req, res) => {
  if (!(await guardFile(req, res, 'notes:read'))) return;
  const r = await drive.files.get({ fileId: req.params.fileId, alt: 'media' }, { responseType: 'text' });
  res.json({ content: r.data });
});
notes.post('/folders/:folderId/files', requireResource('folder', 'notes:write', (r) => r.params.folderId), async (req, res) => {
  const r = await drive.files.create({
    requestBody: { name: req.body.name, parents: [req.params.folderId], mimeType: 'text/plain' },
    media: { mimeType: 'text/plain', body: req.body.content || '' }, fields: 'id,name' });
  res.json(r.data);
});
notes.put('/files/:fileId', async (req, res) => {
  if (!(await guardFile(req, res, 'notes:write'))) return;
  await drive.files.update({ fileId: req.params.fileId, media: { mimeType: 'text/plain', body: req.body.content } });
  res.json({ ok: true });
});
api.use('/notes', notes);

/* ---------- Chat (aggiornamento periodico, niente WebSocket) ---------- */
const chats = express.Router();
chats.param('id', (req, res, next, v) => (Number.isInteger(Number(v)) ? next() : res.status(400).json({ error: 'id non valido' })));
chats.get('/', requirePerm('chat:read'), async (req, res) => {
  const ids = await visibleIds(req.user, 'chat');
  const all = await query('SELECT id, name FROM chats ORDER BY id');
  res.json(all.filter((c) => !ids || ids.has(String(c.id))));
});
// ?after=<id ultimo messaggio visto> per ricevere solo i nuovi
chats.get('/:id/messages', requireResource('chat', 'chat:read', (r) => r.params.id), async (req, res) => {
  const after = Number(req.query.after) || 0;
  res.json(after
    ? await query(`SELECT m.id, m.body, m.created_at, u.name FROM messages m JOIN users u ON u.id=m.user_id
        WHERE m.chat_id=$1 AND m.id>$2 ORDER BY m.id LIMIT 100`, [req.params.id, after])
    : await query(`SELECT * FROM (SELECT m.id, m.body, m.created_at, u.name FROM messages m JOIN users u ON u.id=m.user_id
        WHERE m.chat_id=$1 ORDER BY m.id DESC LIMIT 100) t ORDER BY id`, [req.params.id]));
});
chats.post('/:id/messages', requireResource('chat', 'chat:post', (r) => r.params.id), async (req, res) => {
  const body = String(req.body?.body || '').trim();
  if (!body || body.length > 2000) return res.status(400).json({ error: 'messaggio non valido' });
  res.json(await one('INSERT INTO messages(chat_id,user_id,body) VALUES($1,$2,$3) RETURNING id', [req.params.id, req.user.id, body]));
});
api.use('/chats', chats);

/* ---------- Admin ---------- */
const admin = express.Router();
admin.use(onlyAdmin);
admin.get('/users', async (_req, res) => res.json(await query('SELECT id,email,name,role,status,created_at FROM users ORDER BY id')));
admin.patch('/users/:id', async (req, res) => {
  const { role, status } = req.body;
  if (role && !['admin', 'member', 'viewer'].includes(role)) return res.status(400).json({ error: 'ruolo non valido' });
  if (status && !['pending', 'approved', 'blocked'].includes(status)) return res.status(400).json({ error: 'stato non valido' });
  if (Number(req.params.id) === req.user.id && ((role && role !== 'admin') || (status && status !== 'approved')))
    return res.status(400).json({ error: 'non puoi declassare te stesso' });
  await query('UPDATE users SET role=COALESCE($1,role), status=COALESCE($2,status) WHERE id=$3', [role ?? null, status ?? null, req.params.id]);
  res.json({ ok: true });
});
admin.post('/chats', async (req, res) => {
  const name = String(req.body?.name || '').trim();
  if (!name) return res.status(400).json({ error: 'nome mancante' });
  res.json(await one('INSERT INTO chats(name) VALUES($1) RETURNING id', [name]));
});
admin.delete('/chats/:id', async (req, res) => { await query('DELETE FROM chats WHERE id=$1', [req.params.id]); res.json({ ok: true }); });
admin.get('/access', async (req, res) => res.json(await query(
  'SELECT subject_type, subject_id FROM access WHERE resource_type=$1 AND resource_id=$2', [req.query.resourceType, String(req.query.resourceId)])));
admin.put('/access', async (req, res) => {
  const { resourceType, resourceId, subjects } = req.body;
  if (!['chat', 'folder'].includes(resourceType) || !Array.isArray(subjects)) return res.status(400).json({ error: 'richiesta non valida' });
  await tx(async (run) => {
    await run('DELETE FROM access WHERE resource_type=$1 AND resource_id=$2', [resourceType, String(resourceId)]);
    for (const s of subjects) await run('INSERT INTO access VALUES($1,$2,$3,$4)', [resourceType, String(resourceId), s.type, String(s.id)]);
  });
  res.json({ ok: true });
});
admin.post('/calendar/purge', async (req, res) => {
  const { year, month } = req.body;
  const from = new Date(Date.UTC(year, month - 1, 1)), to = new Date(Date.UTC(year, month, 1));
  if (!(to <= new Date())) return res.status(400).json({ error: 'il mese deve essere interamente nel passato' });
  let deleted = 0, pageToken;
  do {
    const r = await calendar.events.list({ calendarId: CAL_ID, timeMin: from.toISOString(), timeMax: to.toISOString(), singleEvents: false, maxResults: 250, pageToken });
    for (const ev of r.data.items) { if (ev.recurrence) continue; await calendar.events.delete({ calendarId: CAL_ID, eventId: ev.id }); deleted++; }
    pageToken = r.data.nextPageToken;
  } while (pageToken);
  res.json({ deleted });
});
api.use('/admin', admin);

app.use('/api', api);
app.use((err, _req, res, _next) => { console.error(err); res.status(500).json({ error: 'errore interno' }); });

if (require.main === module) app.listen(process.env.PORT || 3000, () => console.log('Hub avviato'));
module.exports = app;
