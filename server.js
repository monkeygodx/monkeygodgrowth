'use strict';

const express = require('express');
const path    = require('path');
const fs      = require('fs');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Set JWT_SECRET in Railway env vars ──────────────────────────────────────
const JWT_SECRET = process.env.JWT_SECRET || 'monkeygod-dev-secret-CHANGE-IN-RAILWAY';

// ── User persistence ─────────────────────────────────────────────────────────
// On Railway: add a Volume mounted at /data for persistence across deploys.
// Without a volume, users reset on redeploy (they just re-register).
const DATA_DIR   = process.env.DATA_DIR || path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');

function ensureStore() {
  if (!fs.existsSync(DATA_DIR))   fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, '[]');
}

function loadUsers() {
  try { return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); }
  catch { return []; }
}

function saveUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

ensureStore();

// ── PDF delivery ──────────────────────────────────────────────────────────────
// Guides live in /private and are only ever reachable through the authenticated
// /api/download route below — never through express.static.
const PDF_DIR = process.env.PDF_DIR || path.join(__dirname, 'private');
const TIER_FILES = {
  basic:     { file: 'basic.pdf',     label: 'MonkeyGod-Basic-Guide.pdf' },
  premium:   { file: 'premium.pdf',   label: 'MonkeyGod-Premium-Guide.pdf' },
  exclusive: { file: 'exclusive.pdf', label: 'MonkeyGod-Exclusive-Guide.pdf' },
};

// ── Middleware ────────────────────────────────────────────────────────────────
app.set('trust proxy', 1);
app.use(express.json());
// Block direct/static access to /private before the static file server ever sees it.
app.use('/private', (_req, res) => res.status(404).end());
app.use(express.static(__dirname));

// ── Auth guard (used by protected routes) ────────────────────────────────────
function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  if (!header.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  try {
    req.user = jwt.verify(header.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Session expired — please log in again' });
  }
}

// ── POST /api/signup ──────────────────────────────────────────────────────────
app.post('/api/signup', async (req, res) => {
  const { email, password } = req.body || {};

  if (!email || !password)
    return res.status(400).json({ error: 'Email and password are required' });

  const em = email.trim().toLowerCase();

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(em))
    return res.status(400).json({ error: 'Enter a valid email address' });

  if (password.length < 8)
    return res.status(400).json({ error: 'Password must be at least 8 characters' });

  const users = loadUsers();

  if (users.find(u => u.email === em))
    return res.status(409).json({ error: 'An account with this email already exists' });

  const hash = await bcrypt.hash(password, 10);
  const user = {
    id: Date.now().toString(),
    email: em,
    hash,
    createdAt: new Date().toISOString(),
  };
  users.push(user);
  saveUsers(users);

  const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, email: user.email });
});

// ── POST /api/login ───────────────────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body || {};

  if (!email || !password)
    return res.status(400).json({ error: 'Email and password are required' });

  const em = email.trim().toLowerCase();
  const users = loadUsers();
  const user  = users.find(u => u.email === em);

  if (!user) return res.status(401).json({ error: 'Invalid email or password' });

  const match = await bcrypt.compare(password, user.hash);
  if (!match)  return res.status(401).json({ error: 'Invalid email or password' });

  const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, email: user.email });
});

// ── GET /api/me ───────────────────────────────────────────────────────────────
app.get('/api/me', requireAuth, (req, res) => {
  res.json({ email: req.user.email });
});

// ── POST /api/logout (client clears token; server confirms) ──────────────────
app.post('/api/logout', (_req, res) => res.json({ ok: true }));

// ── GET /api/download/:tier ───────────────────────────────────────────────────
// The one real gate on the PDFs: you must be logged in. mycheckout.live redirects
// back to /success.html with the purchased tier in the URL, but does not (yet) call
// a server-side webhook here — so this route trusts the tier the client asks for
// rather than checking it against a stored order. If mycheckout.live adds webhook
// support later, verify req.user.id against a recorded purchase for `tier` before
// streaming the file, instead of trusting the param.
app.get('/api/download/:tier', requireAuth, (req, res) => {
  const tier = TIER_FILES[req.params.tier];
  if (!tier) return res.status(404).json({ error: 'Unknown tier' });

  const filePath = path.join(PDF_DIR, tier.file);
  if (!fs.existsSync(filePath))
    return res.status(404).json({ error: 'Guide not available yet — email monkeygodus@gmail.com' });

  res.download(filePath, tier.label, err => {
    if (err && !res.headersSent) res.status(500).json({ error: 'Download failed — try again' });
  });
});

// ── SPA fallback ──────────────────────────────────────────────────────────────
app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`MonkeyGod Growth running on port ${PORT}`);
  if (JWT_SECRET.includes('CHANGE-IN-RAILWAY'))
    console.warn('⚠  JWT_SECRET is using the dev default — set it in Railway env vars');
});
