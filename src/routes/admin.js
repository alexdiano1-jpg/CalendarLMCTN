const router = require('express').Router();
const db = require('../db');
const { calendar, CAL_ID } = require('../google');
const { requirePerm } = require('../rbac');

router.use((req, res, next) => (req.user.role === 'admin' ? next() : res.status(403).json({ error: 'solo admin' })));

// --- utenti ---
router.get('/users', (_req, res) => res.json(db.prepare('SELECT id,email,name,role,status,created_at FROM users').all()));

router.patch('/users/:id', (req, res) => {
  const { role, status } = req.body;
  if (role && !['admin', 'member', 'viewer'].includes(role)) return res.status(400).json({ error: 'ruolo non valido' });
  if (status && !['pending', 'approved', 'blocked'].includes(status)) return res.status(400).json({ error: 'stato non valido' });
  if (Number(req.params.id) === req.user.id && (role !== undefined && role !== 'admin' || status && status !== 'approved'))
    return res.status(400).json({ error: 'non puoi declassare te stesso' });
  db.prepare('UPDATE users SET role=COALESCE(?,role), status=COALESCE(?,status) WHERE id=?').run(role, status, req.params.id);
  res.json({ ok: true });
});

// --- chat ---
router.post('/chats', (req, res) =>
  res.json({ id: db.prepare('INSERT INTO chats(name) VALUES(?)').run(req.body.name).lastInsertRowid }));
router.delete('/chats/:id', (req, res) => { db.prepare('DELETE FROM chats WHERE id=?').run(req.params.id); res.json({ ok: true }); });

// --- accessi: sostituisce l'intera lista di soggetti di una risorsa ---
// body: { resourceType:'chat'|'folder', resourceId, subjects:[{type:'user'|'role', id}] }
router.put('/access', (req, res) => {
  const { resourceType, resourceId, subjects } = req.body;
  db.transaction(() => {
    db.prepare('DELETE FROM access WHERE resource_type=? AND resource_id=?').run(resourceType, String(resourceId));
    const ins = db.prepare('INSERT INTO access VALUES(?,?,?,?)');
    for (const s of subjects) ins.run(resourceType, String(resourceId), s.type, String(s.id));
  })();
  res.json({ ok: true });
});

// lettura accessi correnti di una risorsa
router.get('/access', (req, res) => res.json(db.prepare(
  'SELECT subject_type, subject_id FROM access WHERE resource_type=? AND resource_id=?')
  .all(req.query.resourceType, String(req.query.resourceId))));

// --- pulizia calendario: un mese intero, solo se interamente nel passato ---
router.post('/calendar/purge', async (req, res) => {
  const { year, month } = req.body; // month 1-12
  const from = new Date(Date.UTC(year, month - 1, 1));
  const to = new Date(Date.UTC(year, month, 1));
  if (!(to <= new Date())) return res.status(400).json({ error: 'il mese deve essere interamente nel passato' });
  let deleted = 0, pageToken;
  do {
    const r = await calendar.events.list({ calendarId: CAL_ID, timeMin: from.toISOString(), timeMax: to.toISOString(),
      singleEvents: false, maxResults: 250, pageToken });
    for (const ev of r.data.items) {
      // evita di cancellare serie ricorrenti ancora attive
      if (ev.recurrence) continue;
      await calendar.events.delete({ calendarId: CAL_ID, eventId: ev.id }); deleted++;
    }
    pageToken = r.data.nextPageToken;
  } while (pageToken);
  res.json({ deleted });
});

module.exports = router;
