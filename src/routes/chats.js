const router = require('express').Router();
const db = require('../db');
const { requirePerm, requireResource, hasAccess } = require('../rbac');

router.get('/', requirePerm('chat:read'), (req, res) => {
  res.json(db.prepare('SELECT * FROM chats').all().filter((c) => hasAccess(req.user, 'chat', c.id)));
});

router.get('/:id/messages', requireResource('chat', 'chat:read', (r) => r.params.id), (req, res) => {
  res.json(db.prepare(`SELECT m.id,m.body,m.created_at,u.name FROM messages m JOIN users u ON u.id=m.user_id
    WHERE chat_id=? ORDER BY m.id DESC LIMIT 100`).all(req.params.id).reverse());
});

module.exports = router;
