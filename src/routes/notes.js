const router = require('express').Router();
const { drive, ROOT_ID } = require('../google');
const db = require('../db');
const { requirePerm, hasAccess, can } = require('../rbac');

const isFolder = "mimeType='application/vnd.google-apps.folder'";

// elenco cartelle (sottocartelle della root) filtrate per accesso
router.get('/folders', requirePerm('notes:read'), async (req, res) => {
  const r = await drive.files.list({ q: `'${ROOT_ID}' in parents and ${isFolder} and trashed=false`, fields: 'files(id,name)' });
  res.json(r.data.files.filter((f) => hasAccess(req.user, 'folder', f.id)));
});

// verifica server-side che il file stia dentro una cartella abilitata
async function guardFile(req, res, perm) {
  if (!can(req.user, perm)) { res.status(403).json({ error: 'permesso negato' }); return null; }
  const f = await drive.files.get({ fileId: req.params.fileId, fields: 'id,name,parents' });
  const parent = f.data.parents?.[0];
  if (!parent || !hasAccess(req.user, 'folder', parent)) { res.status(403).json({ error: 'cartella non abilitata' }); return null; }
  return f.data;
}

router.get('/folders/:folderId/files', requirePerm('notes:read'), async (req, res) => {
  if (!hasAccess(req.user, 'folder', req.params.folderId)) return res.status(403).json({ error: 'cartella non abilitata' });
  const r = await drive.files.list({ q: `'${req.params.folderId}' in parents and trashed=false and mimeType='text/plain'`, fields: 'files(id,name,modifiedTime)' });
  res.json(r.data.files);
});

router.get('/files/:fileId', async (req, res) => {
  if (!(await guardFile(req, res, 'notes:read'))) return;
  const r = await drive.files.get({ fileId: req.params.fileId, alt: 'media' }, { responseType: 'text' });
  res.json({ content: r.data });
});

router.post('/folders/:folderId/files', requirePerm('notes:write'), async (req, res) => {
  if (!hasAccess(req.user, 'folder', req.params.folderId)) return res.status(403).json({ error: 'cartella non abilitata' });
  const r = await drive.files.create({
    requestBody: { name: req.body.name, parents: [req.params.folderId], mimeType: 'text/plain' },
    media: { mimeType: 'text/plain', body: req.body.content || '' }, fields: 'id,name',
  });
  res.json(r.data);
});

router.put('/files/:fileId', async (req, res) => {
  if (!(await guardFile(req, res, 'notes:write'))) return;
  await drive.files.update({ fileId: req.params.fileId, media: { mimeType: 'text/plain', body: req.body.content } });
  res.json({ ok: true });
});

module.exports = router;
