const Database = require('better-sqlite3');
const db = new Database(process.env.DB_PATH || 'hub.db');
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, google_sub TEXT UNIQUE, email TEXT UNIQUE NOT NULL,
  name TEXT, picture TEXT,
  role TEXT NOT NULL DEFAULT 'viewer' CHECK(role IN ('admin','member','viewer')),
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','blocked')),
  created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS chats(id INTEGER PRIMARY KEY, name TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS messages(
  id INTEGER PRIMARY KEY, chat_id INTEGER NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id), body TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP);
-- chi può vedere cosa: per singolo utente o per ruolo
CREATE TABLE IF NOT EXISTS access(
  resource_type TEXT CHECK(resource_type IN ('chat','folder')),
  resource_id TEXT, subject_type TEXT CHECK(subject_type IN ('user','role')),
  subject_id TEXT, PRIMARY KEY(resource_type, resource_id, subject_type, subject_id));
`);
module.exports = db;
