'use strict';

const express = require('express');
const session = require('express-session');
const Database = require('better-sqlite3');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const DATA_DIR = process.env.DATA_DIR || (process.platform === 'win32' ? path.join(__dirname, '../../data') : '/data');
const UPLOADS_DIR = path.join(DATA_DIR, 'uploads');
const DB_PATH = path.join(DATA_DIR, 'wardrobe.db');
const PORT = parseInt(process.env.PORT || '8098', 10);

fs.mkdirSync(UPLOADS_DIR, { recursive: true });

const db = new Database(DB_PATH);
db.pragma('foreign_keys = ON');
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS sessions (
    sid TEXT PRIMARY KEY,
    data TEXT NOT NULL,
    expires INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS bags (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    location TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS images (
    id TEXT PRIMARY KEY,
    bag_id TEXT NOT NULL REFERENCES bags(id) ON DELETE CASCADE,
    filename TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS items (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    category TEXT NOT NULL CHECK(category IN ('top','bottom','shoes','jacket')),
    seasons TEXT NOT NULL DEFAULT '',
    rating INTEGER CHECK(rating BETWEEN 1 AND 5),
    filename TEXT,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS outfits (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL DEFAULT '',
    top_id    TEXT REFERENCES items(id) ON DELETE SET NULL,
    bottom_id TEXT REFERENCES items(id) ON DELETE SET NULL,
    shoes_id  TEXT REFERENCES items(id) ON DELETE SET NULL,
    jacket_id TEXT REFERENCES items(id) ON DELETE SET NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
  );
`);

// Migration: add user_id to bags if not present (handles existing installs)
try { db.exec('ALTER TABLE bags ADD COLUMN user_id TEXT REFERENCES users(id) ON DELETE SET NULL'); } catch (_) {}

// Purge expired sessions every 15 min
setInterval(() => db.prepare('DELETE FROM sessions WHERE expires < ?').run(Date.now()), 15 * 60 * 1000);

// --- SQLite-backed session store ---
class SQLiteStore extends session.Store {
  get(sid, cb) {
    try {
      const row = db.prepare('SELECT data, expires FROM sessions WHERE sid = ?').get(sid);
      if (!row || row.expires < Date.now()) return cb(null, null);
      cb(null, JSON.parse(row.data));
    } catch (e) { cb(e); }
  }
  set(sid, sess, cb) {
    try {
      const expires = sess.cookie?.expires
        ? new Date(sess.cookie.expires).getTime()
        : Date.now() + 30 * 24 * 60 * 60 * 1000;
      db.prepare('INSERT OR REPLACE INTO sessions (sid, data, expires) VALUES (?, ?, ?)').run(sid, JSON.stringify(sess), expires);
      cb(null);
    } catch (e) { cb(e); }
  }
  destroy(sid, cb) {
    try { db.prepare('DELETE FROM sessions WHERE sid = ?').run(sid); cb(null); } catch (e) { cb(e); }
  }
}

// Persist session secret across restarts
const secretFile = path.join(DATA_DIR, '.session_secret');
let sessionSecret;
try { sessionSecret = fs.readFileSync(secretFile, 'utf8').trim(); } catch (_) {
  sessionSecret = crypto.randomBytes(32).toString('hex');
  fs.writeFileSync(secretFile, sessionSecret);
}

// --- App setup ---
const app = express();
app.use(express.json());
app.use(session({
  store: new SQLiteStore(),
  secret: sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', maxAge: 30 * 24 * 60 * 60 * 1000 },
}));
app.use(express.static(path.join(__dirname, '../public')));
app.use('/uploads', express.static(UPLOADS_DIR));

const upload = multer({
  storage: multer.diskStorage({
    destination: UPLOADS_DIR,
    filename: (_req, file, cb) => cb(null, `${uuidv4()}${path.extname(file.originalname).toLowerCase()}`),
  }),
  limits: { fileSize: 20 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => cb(null, file.mimetype.startsWith('image/')),
});

// --- Auth middleware ---
function requireAuth(req, res, next) {
  if (req.session.userId) return next();
  res.status(401).json({ error: 'Unauthorized' });
}

function requireAdmin(req, res, next) {
  if (req.session.isAdmin) return next();
  res.status(403).json({ error: 'Admin required' });
}

function ownsBag(userId, bagId) {
  const bag = db.prepare('SELECT user_id FROM bags WHERE id = ?').get(bagId);
  return bag && bag.user_id === userId;
}

// --- Setup ---
app.get('/api/setup/needed', (_req, res) => {
  res.json({ needed: db.prepare('SELECT COUNT(*) as n FROM users').get().n === 0 });
});

app.post('/api/setup', (req, res) => {
  if (db.prepare('SELECT COUNT(*) as n FROM users').get().n > 0) {
    return res.status(403).json({ error: 'Setup already complete' });
  }
  const { username, password } = req.body;
  if (!username?.trim() || !password || password.length < 4) {
    return res.status(400).json({ error: 'Username and password (min 4 characters) required' });
  }
  const id = uuidv4();
  db.prepare('INSERT INTO users (id, username, password_hash, is_admin) VALUES (?, ?, ?, 1)')
    .run(id, username.trim(), bcrypt.hashSync(password, 10));
  req.session.userId = id;
  req.session.username = username.trim();
  req.session.isAdmin = true;
  res.status(201).json({ ok: true });
});

// --- Auth ---
app.get('/api/auth/me', (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Not logged in' });
  res.json({ id: req.session.userId, username: req.session.username, isAdmin: req.session.isAdmin });
});

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  const user = db.prepare('SELECT * FROM users WHERE username = ? COLLATE NOCASE').get(username.trim());
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }
  req.session.userId = user.id;
  req.session.username = user.username;
  req.session.isAdmin = user.is_admin === 1;
  res.json({ ok: true, username: user.username, isAdmin: user.is_admin === 1 });
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

// --- Users (admin) ---
app.get('/api/users', requireAuth, requireAdmin, (_req, res) => {
  res.json(db.prepare('SELECT id, username, is_admin, created_at FROM users ORDER BY created_at ASC').all());
});

app.post('/api/users', requireAuth, requireAdmin, (req, res) => {
  const { username, password, isAdmin = false } = req.body;
  if (!username?.trim() || !password || password.length < 4) {
    return res.status(400).json({ error: 'Username and password (min 4 characters) required' });
  }
  const id = uuidv4();
  try {
    db.prepare('INSERT INTO users (id, username, password_hash, is_admin) VALUES (?, ?, ?, ?)')
      .run(id, username.trim(), bcrypt.hashSync(password, 10), isAdmin ? 1 : 0);
    res.status(201).json({ id });
  } catch (e) {
    if (e.message.includes('UNIQUE')) return res.status(409).json({ error: 'Username already taken' });
    throw e;
  }
});

app.delete('/api/users/:id', requireAuth, requireAdmin, (req, res) => {
  if (req.params.id === req.session.userId) return res.status(400).json({ error: 'Cannot delete your own account' });
  const result = db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
  if (!result.changes) return res.status(404).json({ error: 'User not found' });
  res.json({ ok: true });
});

app.put('/api/users/:id/password', requireAuth, (req, res) => {
  if (req.params.id !== req.session.userId && !req.session.isAdmin) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const { password } = req.body;
  if (!password || password.length < 4) return res.status(400).json({ error: 'Password must be at least 4 characters' });
  const result = db.prepare('UPDATE users SET password_hash = ? WHERE id = ?')
    .run(bcrypt.hashSync(password, 10), req.params.id);
  if (!result.changes) return res.status(404).json({ error: 'User not found' });
  res.json({ ok: true });
});

// --- Bags ---
app.get('/api/bags', requireAuth, (req, res) => {
  const bags = db.prepare(`
    SELECT b.*,
      (SELECT filename FROM images WHERE bag_id = b.id ORDER BY created_at LIMIT 1) AS cover,
      (SELECT COUNT(*) FROM images WHERE bag_id = b.id) AS image_count
    FROM bags b
    WHERE b.user_id = ?
    ORDER BY b.created_at DESC
  `).all(req.session.userId);
  res.json(bags);
});

// Public — NFC tap lands here, no login required
app.get('/api/bags/:id', (req, res) => {
  const bag = db.prepare('SELECT * FROM bags WHERE id = ?').get(req.params.id);
  if (!bag) return res.status(404).json({ error: 'Not found' });
  const images = db.prepare('SELECT id, filename FROM images WHERE bag_id = ? ORDER BY created_at').all(req.params.id);
  res.json({ ...bag, images });
});

app.post('/api/bags', requireAuth, (req, res) => {
  const { name, description = '', location = '' } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: 'Name is required' });
  const id = uuidv4();
  db.prepare('INSERT INTO bags (id, user_id, name, description, location) VALUES (?, ?, ?, ?, ?)')
    .run(id, req.session.userId, name.trim(), description.trim(), location.trim());
  res.status(201).json({ id });
});

app.put('/api/bags/:id', requireAuth, (req, res) => {
  if (!ownsBag(req.session.userId, req.params.id)) return res.status(404).json({ error: 'Not found' });
  const { name, description = '', location = '' } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: 'Name is required' });
  db.prepare('UPDATE bags SET name = ?, description = ?, location = ? WHERE id = ?')
    .run(name.trim(), description.trim(), location.trim(), req.params.id);
  res.json({ ok: true });
});

app.delete('/api/bags/:id', requireAuth, (req, res) => {
  if (!ownsBag(req.session.userId, req.params.id)) return res.status(404).json({ error: 'Not found' });
  const images = db.prepare('SELECT filename FROM images WHERE bag_id = ?').all(req.params.id);
  db.prepare('DELETE FROM bags WHERE id = ?').run(req.params.id);
  for (const img of images) fs.unlink(path.join(UPLOADS_DIR, img.filename), () => {});
  res.json({ ok: true });
});

app.post('/api/bags/:id/images', requireAuth, upload.array('images', 30), (req, res) => {
  if (!ownsBag(req.session.userId, req.params.id)) return res.status(404).json({ error: 'Bag not found' });
  const stmt = db.prepare('INSERT INTO images (id, bag_id, filename) VALUES (?, ?, ?)');
  const result = (req.files || []).map(f => {
    const id = uuidv4();
    stmt.run(id, req.params.id, f.filename);
    return { id, filename: f.filename };
  });
  res.status(201).json(result);
});

app.delete('/api/images/:id', requireAuth, (req, res) => {
  const img = db.prepare(`
    SELECT i.filename FROM images i
    JOIN bags b ON b.id = i.bag_id
    WHERE i.id = ? AND b.user_id = ?
  `).get(req.params.id, req.session.userId);
  if (!img) return res.status(404).json({ error: 'Not found' });
  db.prepare('DELETE FROM images WHERE id = ?').run(req.params.id);
  fs.unlink(path.join(UPLOADS_DIR, img.filename), () => {});
  res.json({ ok: true });
});

// --- Items ---
app.get('/api/items', requireAuth, (req, res) => {
  const { category, season } = req.query;
  let sql = 'SELECT * FROM items WHERE user_id = ?';
  const params = [req.session.userId];
  if (category) { sql += ' AND category = ?'; params.push(category); }
  if (season) { sql += " AND (',' || seasons || ',' LIKE ?)"; params.push(`%,${season},%`); }
  sql += ' ORDER BY created_at DESC';
  res.json(db.prepare(sql).all(...params));
});

app.get('/api/items/:id', requireAuth, (req, res) => {
  const item = db.prepare('SELECT * FROM items WHERE id = ? AND user_id = ?').get(req.params.id, req.session.userId);
  if (!item) return res.status(404).json({ error: 'Not found' });
  res.json(item);
});

app.post('/api/items', requireAuth, upload.single('image'), (req, res) => {
  const { name, category, seasons = '', rating } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: 'Name is required' });
  if (!['top','bottom','shoes','jacket'].includes(category)) return res.status(400).json({ error: 'Invalid category' });
  const id = uuidv4();
  const ratingVal = rating ? parseInt(rating, 10) : null;
  db.prepare('INSERT INTO items (id, user_id, name, category, seasons, rating, filename) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .run(id, req.session.userId, name.trim(), category, seasons, ratingVal, req.file?.filename || null);
  res.status(201).json({ id });
});

app.put('/api/items/:id', requireAuth, (req, res) => {
  const item = db.prepare('SELECT id FROM items WHERE id = ? AND user_id = ?').get(req.params.id, req.session.userId);
  if (!item) return res.status(404).json({ error: 'Not found' });
  const { name, category, seasons = '', rating } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: 'Name is required' });
  if (!['top','bottom','shoes','jacket'].includes(category)) return res.status(400).json({ error: 'Invalid category' });
  const ratingVal = rating ? parseInt(rating, 10) : null;
  db.prepare('UPDATE items SET name = ?, category = ?, seasons = ?, rating = ? WHERE id = ?')
    .run(name.trim(), category, seasons, ratingVal, req.params.id);
  res.json({ ok: true });
});

app.delete('/api/items/:id', requireAuth, (req, res) => {
  const item = db.prepare('SELECT filename FROM items WHERE id = ? AND user_id = ?').get(req.params.id, req.session.userId);
  if (!item) return res.status(404).json({ error: 'Not found' });
  db.prepare('DELETE FROM items WHERE id = ?').run(req.params.id);
  if (item.filename) fs.unlink(path.join(UPLOADS_DIR, item.filename), () => {});
  res.json({ ok: true });
});

// --- Outfits ---
app.get('/api/outfits', requireAuth, (req, res) => {
  const outfits = db.prepare(`
    SELECT o.*,
      ti.filename AS top_filename, ti.name AS top_name,
      bi.filename AS bottom_filename, bi.name AS bottom_name,
      si.filename AS shoes_filename, si.name AS shoes_name,
      ji.filename AS jacket_filename, ji.name AS jacket_name
    FROM outfits o
    LEFT JOIN items ti ON ti.id = o.top_id
    LEFT JOIN items bi ON bi.id = o.bottom_id
    LEFT JOIN items si ON si.id = o.shoes_id
    LEFT JOIN items ji ON ji.id = o.jacket_id
    WHERE o.user_id = ?
    ORDER BY o.created_at DESC
  `).all(req.session.userId);
  res.json(outfits);
});

app.post('/api/outfits', requireAuth, (req, res) => {
  const { name = '', top_id = null, bottom_id = null, shoes_id = null, jacket_id = null } = req.body;
  const id = uuidv4();
  db.prepare('INSERT INTO outfits (id, user_id, name, top_id, bottom_id, shoes_id, jacket_id) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .run(id, req.session.userId, name, top_id, bottom_id, shoes_id, jacket_id);
  res.status(201).json({ id });
});

app.delete('/api/outfits/:id', requireAuth, (req, res) => {
  const result = db.prepare('DELETE FROM outfits WHERE id = ? AND user_id = ?').run(req.params.id, req.session.userId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});

app.listen(PORT, '0.0.0.0', () => console.log(`Wardrobe tracker on :${PORT}`));
