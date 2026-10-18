const db = require('./db');

// Permessi globali per ruolo
const PERMS = {
  admin: ['*'],
  member: ['calendar:read', 'calendar:write', 'notes:read', 'notes:write', 'chat:read', 'chat:post'],
  viewer: ['calendar:read', 'notes:read', 'chat:read'],
};

const can = (user, perm) =>
  !!user && user.status === 'approved' &&
  (PERMS[user.role]?.includes('*') || PERMS[user.role]?.includes(perm));

// Accesso a una singola risorsa (chat / cartella): l'admin vede tutto,
// gli altri solo se esiste una regola per il loro id o per il loro ruolo.
function hasAccess(user, type, id) {
  if (user.role === 'admin') return true;
  return !!db.prepare(`SELECT 1 FROM access WHERE resource_type=? AND resource_id=? AND
    ((subject_type='user' AND subject_id=?) OR (subject_type='role' AND subject_id=?))`)
    .get(type, String(id), String(user.id), user.role);
}

const loadUser = (req, _res, next) => {
  req.user = req.session.uid ? db.prepare('SELECT * FROM users WHERE id=?').get(req.session.uid) : null;
  next();
};
const requireApproved = (req, res, next) =>
  req.user?.status === 'approved' ? next() : res.status(401).json({ error: 'non autorizzato' });

const requirePerm = (perm) => (req, res, next) =>
  can(req.user, perm) ? next() : res.status(403).json({ error: 'permesso negato' });

// perm globale + accesso alla risorsa; idFn estrae l'id dalla richiesta
const requireResource = (type, perm, idFn) => (req, res, next) => {
  if (!can(req.user, perm)) return res.status(403).json({ error: 'permesso negato' });
  if (!hasAccess(req.user, type, idFn(req))) return res.status(403).json({ error: 'risorsa non abilitata' });
  next();
};

module.exports = { PERMS, can, hasAccess, loadUser, requireApproved, requirePerm, requireResource };
