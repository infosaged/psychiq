require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');
const { db, stmtInsertScore, getBestScores, publicUser } = require('./db');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-in-production';
if (!process.env.JWT_SECRET) console.warn('WARNING: JWT_SECRET env var not set — using insecure default. Set it in Railway variables.');
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '*';

app.use(cors({ origin: ALLOWED_ORIGIN, credentials: true }));
app.use(express.json({ limit: '2mb' })); // allow avatar_data base64
app.use(express.static(path.join(__dirname, '..')));

// ── Middleware ────────────────────────────────────────────────────────────────

function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing token' });
  }
  try {
    req.user = jwt.verify(header.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function signToken(userId) {
  return jwt.sign({ sub: userId }, JWT_SECRET, { expiresIn: '90d' });
}

const VALID_TOPICS = ['cards', 'colors', 'animals', 'zodiac', 'celebrities', 'brands'];

// ── Auth ──────────────────────────────────────────────────────────────────────

// POST /api/auth/register
app.post('/api/auth/register', (req, res) => {
  const { email, password, displayName, username, dob, zodiac, level } = req.body;

  if (!email || !password || !displayName || !username) {
    return res.status(400).json({ error: 'email, password, displayName, and username are required' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }
  if (!/^[a-z0-9_]{2,30}$/.test(username)) {
    return res.status(400).json({ error: 'Username must be 2-30 lowercase letters, numbers, or underscores' });
  }

  const existing = db.prepare('SELECT id FROM users WHERE email=? OR username=?').get(email, username);
  if (existing) {
    return res.status(409).json({ error: 'Email or username already taken' });
  }

  const hash = bcrypt.hashSync(password, 10);
  const id = 'u_' + crypto.randomBytes(8).toString('hex');
  const now = Date.now();

  db.prepare(`
    INSERT INTO users (id,email,password_hash,display_name,username,dob,zodiac,level,avatar_data,join_year,created_at)
    VALUES (?,?,?,?,?,?,?,?,NULL,?,?)
  `).run(id, email.toLowerCase(), hash, displayName, username, dob || null, zodiac || null, level || 'believer', new Date().getFullYear(), now);

  const user = db.prepare('SELECT * FROM users WHERE id=?').get(id);
  res.status(201).json({ token: signToken(id), user: publicUser(user) });
});

// POST /api/auth/login
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'email and password required' });

  const user = db.prepare('SELECT * FROM users WHERE email=?').get(email.toLowerCase());
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }
  res.json({ token: signToken(user.id), user: publicUser(user) });
});

// ── Current user ──────────────────────────────────────────────────────────────

// GET /api/users/me
app.get('/api/users/me', requireAuth, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id=?').get(req.user.sub);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json(publicUser(user));
});

// PUT /api/users/me
app.put('/api/users/me', requireAuth, (req, res) => {
  const { displayName, username, dob, zodiac, level, avatarData, country, stateCode, cardBack, badges } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE id=?').get(req.user.sub);
  if (!user) return res.status(404).json({ error: 'User not found' });

  if (username && username !== user.username) {
    if (!/^[a-z0-9_]{2,30}$/.test(username)) {
      return res.status(400).json({ error: 'Invalid username format' });
    }
    const clash = db.prepare('SELECT id FROM users WHERE username=? AND id!=?').get(username, user.id);
    if (clash) return res.status(409).json({ error: 'Username already taken' });
  }

  const badgesJson = Array.isArray(badges) ? JSON.stringify(badges) : null;

  db.prepare(`
    UPDATE users SET
      display_name  = COALESCE(?, display_name),
      username      = COALESCE(?, username),
      dob           = COALESCE(?, dob),
      zodiac        = COALESCE(?, zodiac),
      level         = COALESCE(?, level),
      avatar_data   = COALESCE(?, avatar_data),
      country       = COALESCE(?, country),
      state_code    = COALESCE(?, state_code),
      card_back_id  = COALESCE(?, card_back_id),
      badges        = COALESCE(?, badges)
    WHERE id = ?
  `).run(
    displayName || null, username || null, dob || null,
    zodiac || null, level || null, avatarData || null,
    country || null, stateCode || null,
    cardBack !== undefined ? (cardBack || null) : null,
    badgesJson, user.id
  );

  const updated = db.prepare('SELECT * FROM users WHERE id=?').get(user.id);
  res.json(publicUser(updated));
});

// ── Public profile / cert ─────────────────────────────────────────────────────

// GET /api/users/:username
app.get('/api/users/:username', (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE username=?').get(req.params.username);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json(publicUser(user));
});

// ── Scores ────────────────────────────────────────────────────────────────────

// POST /api/scores  { topicId, score }
app.post('/api/scores', requireAuth, (req, res) => {
  const { topicId, score } = req.body;
  if (!VALID_TOPICS.includes(topicId)) {
    return res.status(400).json({ error: 'Invalid topicId' });
  }
  if (typeof score !== 'number' || score < 0 || score > 9999) {
    return res.status(400).json({ error: 'Invalid score' });
  }

  stmtInsertScore.run(req.user.sub, topicId, Math.floor(score), Date.now());

  const best = getBestScores(req.user.sub);
  res.json({ ok: true, bestScores: best });
});

// GET /api/scores/me  – full history for the current user
app.get('/api/scores/me', requireAuth, (req, res) => {
  const rows = db.prepare(
    'SELECT topic_id, score, played_at FROM scores WHERE user_id=? ORDER BY played_at DESC LIMIT 200'
  ).all(req.user.sub);
  res.json(rows);
});

// ── Leaderboard ───────────────────────────────────────────────────────────────

/*
  GET /api/leaderboard
  Query params:
    topic   = all | cards | colors | animals | zodiac | celebrities | brands
    zodiac  = all | Aries | Taurus | …
    time    = alltime | 2025 | 2026 | …
    limit   = 50 (max 100)
    offset  = 0
*/
app.get('/api/leaderboard', (req, res) => {
  const topic     = req.query.topic     || 'all';
  const zodiac    = req.query.zodiac    || 'all';
  const time      = req.query.time      || 'alltime';
  const country   = req.query.country   || 'all';
  const stateCode = req.query.stateCode || 'all';
  const limit     = Math.min(parseInt(req.query.limit)  || 50, 100);
  const offset    = parseInt(req.query.offset) || 0;

  // Build time filter on scores.played_at
  let timeClause = '';
  if (time === 'thismonth') {
    const now = new Date();
    const from = new Date(now.getFullYear(), now.getMonth(), 1).getTime();
    timeClause = `AND s.played_at >= ${from}`;
  } else if (time === '90days') {
    const cutoff = Date.now() - 90 * 24 * 60 * 60 * 1000;
    timeClause = `AND s.played_at >= ${cutoff}`;
  } else if (time !== 'alltime') {
    const year = parseInt(time);
    if (!isNaN(year)) {
      const from = new Date(year, 0, 1).getTime();
      const to   = new Date(year + 1, 0, 1).getTime();
      timeClause = `AND s.played_at >= ${from} AND s.played_at < ${to}`;
    }
  }

  // Build parameterised filter clauses
  const filterParams = [];
  const VALID_ZODIAC = ['Aries','Taurus','Gemini','Cancer','Leo','Virgo','Libra','Scorpio','Sagittarius','Capricorn','Aquarius','Pisces'];

  let topicClause = '';
  if (topic !== 'all' && VALID_TOPICS.includes(topic)) {
    topicClause = 'AND s.topic_id = ?';
    filterParams.push(topic);
  }

  let zodiacClause = '';
  if (zodiac !== 'all' && VALID_ZODIAC.includes(zodiac)) {
    zodiacClause = 'AND u.zodiac = ?';
    filterParams.push(zodiac);
  }

  let locationClause = '';
  if (country !== 'all' && /^[A-Z]{2}$/.test(country)) {
    locationClause += ' AND u.country = ?';
    filterParams.push(country);
    if (stateCode !== 'all' && /^[A-Z]{2}$/.test(stateCode)) {
      locationClause += ' AND u.state_code = ?';
      filterParams.push(stateCode);
    }
  }

  const rows = db.prepare(`
    SELECT
      u.id, u.display_name, u.username, u.zodiac, u.level, u.join_year, u.avatar_data,
      u.country, u.state_code,
      MAX(s.score) AS best_score,
      s.topic_id   AS best_topic
    FROM scores s
    JOIN users u ON u.id = s.user_id
    WHERE 1=1 ${timeClause} ${topicClause} ${zodiacClause} ${locationClause}
    GROUP BY u.id
    ORDER BY best_score DESC
    LIMIT ? OFFSET ?
  `).all(...filterParams, limit, offset);

  const total = db.prepare(`
    SELECT COUNT(DISTINCT s.user_id) AS cnt
    FROM scores s
    JOIN users u ON u.id = s.user_id
    WHERE 1=1 ${timeClause} ${topicClause} ${zodiacClause} ${locationClause}
  `).get(...filterParams).cnt;

  res.json({
    total,
    limit,
    offset,
    entries: rows.map((r, i) => ({
      rank: offset + i + 1,
      userId: r.id,
      displayName: r.display_name,
      username: r.username,
      zodiac: r.zodiac,
      level: r.level,
      joinYear: r.join_year,
      avatarData: r.avatar_data,
      country: r.country || null,
      stateCode: r.state_code || null,
      bestScore: r.best_score,
    })),
  });
});

// ── In-App Purchases ──────────────────────────────────────────────────────────

// Records a completed purchase for the authenticated user.
// The native TWA shell is responsible for verifying the receipt with Google/Apple
// before calling this endpoint — do not grant entitlements based solely on this call
// without adding server-side receipt verification when going live.
const VALID_PRODUCT_IDS = [
  'special_vibrant_mystics',
  'special_celestial_powers',
  'special_mages_knowledge',
  'special_supreme_psychic',
];

app.post('/api/purchases', requireAuth, (req, res) => {
  const { productId } = req.body;
  if (!VALID_PRODUCT_IDS.includes(productId)) {
    return res.status(400).json({ error: 'Invalid product ID' });
  }
  const user = db.prepare('SELECT * FROM users WHERE id=?').get(req.user.sub);
  if (!user) return res.status(404).json({ error: 'User not found' });

  let purchases = [];
  try { purchases = JSON.parse(user.purchases || '[]'); } catch {}
  if (!purchases.includes(productId)) {
    purchases.push(productId);
    db.prepare('UPDATE users SET purchases=? WHERE id=?')
      .run(JSON.stringify(purchases), user.id);
  }
  res.json({ purchases });
});

// ── Health ────────────────────────────────────────────────────────────────────

app.get('/api/health', (_req, res) => res.json({ ok: true }));

// Required for TWA (Trusted Web Activity) Play Store verification.
// Before submitting to Play Store:
//   1. Choose a package name (e.g. com.psychiciq.app) and add it below.
//   2. Generate a release keystore and get its SHA-256 fingerprint:
//        keytool -list -v -keystore release.keystore -alias release
//      Or copy it from Play Console → Setup → App integrity → App signing key certificate.
//   3. Paste the fingerprint string into sha256_cert_fingerprints below.
app.get('/.well-known/assetlinks.json', (_req, res) => {
  res.json([{
    relation: ['delegate_permission/common.handle_all_urls'],
    target: {
      namespace: 'android_app',
      package_name: 'com.psychiciq.app',         // ← update before TWA launch
      sha256_cert_fingerprints: [
        // 'AA:BB:CC:DD:...'                      // ← paste fingerprint here
      ],
    },
  }]);
});

app.get('/', (_req, res) => res.sendFile(path.join(__dirname, '..', 'psychic-test.html')));

// ── Start ─────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`Psychic Test API running on http://localhost:${PORT}`);
});
