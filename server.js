process.loadEnvFile?.();
const http = require('http');
const express = require('express');
const helmet = require('helmet');
const session = require('express-session');
const { Server } = require('socket.io');
const db = require('./db');
const rbac = require('./rbac');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const sess = session({
  secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.BASE_URL?.startsWith('https'), maxAge: 30 * 864e5 },
  // in produzione: usa uno store persistente (es. better-sqlite3-session-store)
});
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json());
app.use(sess);
app.use(rbac.loadUser);
app.use(express.static('public'));

app.use('/auth', require('./routes/auth'));
app.get('/api/me', (req, res) => res.json(req.user && { id: req.user.id, name: req.user.name, role: req.user.role, status: req.user.status }));

const api = express.Router();
api.use(rbac.requireApproved);
api.use('/calendar', require('./routes/calendar'));
api.use('/notes', require('./routes/notes'));
api.use('/chats', require('./routes/chats'));
api.use('/admin', require('./routes/admin'));
app.use('/api', api);
app.use((err, _req, res, _next) => { console.error(err); res.status(500).json({ error: 'errore interno' }); });

// --- chat in tempo reale: stessi controlli RBAC dell'HTTP ---
io.engine.use(sess);
io.use((socket, next) => {
  const uid = socket.request.session?.uid;
  const u = uid && db.prepare('SELECT * FROM users WHERE id=?').get(uid);
  if (!u || u.status !== 'approved') return next(new Error('non autorizzato'));
  socket.user = u; next();
});
io.on('connection', (socket) => {
  socket.on('join', (chatId) => {
    const u = db.prepare('SELECT * FROM users WHERE id=?').get(socket.user.id); // ruolo sempre aggiornato
    if (rbac.can(u, 'chat:read') && rbac.hasAccess(u, 'chat', chatId)) socket.join(`chat:${chatId}`);
  });
  socket.on('message', ({ chatId, body }) => {
    const u = db.prepare('SELECT * FROM users WHERE id=?').get(socket.user.id);
    if (!body?.trim() || body.length > 2000) return;
    if (!rbac.can(u, 'chat:post') || !rbac.hasAccess(u, 'chat', chatId)) return;
    const id = db.prepare('INSERT INTO messages(chat_id,user_id,body) VALUES(?,?,?)').run(chatId, u.id, body.trim()).lastInsertRowid;
    io.to(`chat:${chatId}`).emit('message', { id, chatId, name: u.name, body: body.trim() });
  });
});

server.listen(process.env.PORT || 3000, () => console.log('Hub avviato'));
