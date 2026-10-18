const router = require('express').Router();
const crypto = require('crypto');
const db = require('../db');
const { newClient } = require('../google');

router.get('/login', (req, res) => {
  req.session.state = crypto.randomBytes(16).toString('hex');
  res.redirect(newClient().generateAuthUrl({
    scope: ['openid', 'email', 'profile'], // solo identità: nessun accesso ai dati Google dell'utente
    state: req.session.state, prompt: 'select_account',
  }));
});

router.get('/callback', async (req, res) => {
  try {
    if (!req.query.state || req.query.state !== req.session.state) return res.status(400).send('state non valido');
    const c = newClient();
    const { tokens } = await c.getToken(req.query.code);
    const t = await c.verifyIdToken({ idToken: tokens.id_token, audience: process.env.GOOGLE_CLIENT_ID });
    const p = t.getPayload();
    if (!p.email_verified) return res.status(403).send('email non verificata');

    const isAdmin = p.email.toLowerCase() === process.env.ADMIN_EMAIL.toLowerCase();
    let u = db.prepare('SELECT * FROM users WHERE google_sub=? OR email=?').get(p.sub, p.email);
    if (!u) {
      const id = db.prepare(`INSERT INTO users(google_sub,email,name,picture,role,status) VALUES(?,?,?,?,?,?)`)
        .run(p.sub, p.email, p.name, p.picture, isAdmin ? 'admin' : 'viewer', isAdmin ? 'approved' : 'pending')
        .lastInsertRowid;
      u = { id };
    } else {
      db.prepare('UPDATE users SET google_sub=?, name=?, picture=? WHERE id=?').run(p.sub, p.name, p.picture, u.id);
    }
    req.session.regenerate(() => { req.session.uid = u.id; res.redirect('/'); });
  } catch (e) { console.error(e); res.status(500).send('login fallito'); }
});

router.post('/logout', (req, res) => req.session.destroy(() => res.json({ ok: true })));
module.exports = router;
