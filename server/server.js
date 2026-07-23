require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');
const { google } = require('googleapis');
const { db, stmtInsertScore, getBestScores, publicUser } = require('./db');

// ── Google Play receipt verification ─────────────────────────────────────────
const ANDROID_PACKAGE_NAME = process.env.ANDROID_PACKAGE_NAME || 'com.psychicscore.app';

async function verifyPlayPurchase(productId, purchaseToken) {
  const serviceAccountJson = process.env.GOOGLE_SERVICE_ACCOUNT_JSON;
  if (!serviceAccountJson) {
    console.warn('GOOGLE_SERVICE_ACCOUNT_JSON not set — skipping receipt verification (dev mode)');
    return true;
  }
  try {
    const credentials = JSON.parse(serviceAccountJson);
    const auth = new google.auth.GoogleAuth({
      credentials,
      scopes: ['https://www.googleapis.com/auth/androidpublisher'],
    });
    const androidpublisher = google.androidpublisher({ version: 'v3', auth });
    const result = await androidpublisher.purchases.products.get({
      packageName: ANDROID_PACKAGE_NAME,
      productId,
      token: purchaseToken,
    });
    // purchaseState 0 = purchased, 1 = cancelled, 2 = pending
    return result.data.purchaseState === 0;
  } catch (err) {
    console.error('Play receipt verification failed:', err.message);
    return false;
  }
}

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-in-production';
if (!process.env.JWT_SECRET) console.warn('WARNING: JWT_SECRET env var not set — using insecure default. Set it in Railway variables.');
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '*';
const APP_URL = (process.env.APP_URL || `http://localhost:${PORT}`).replace(/\/$/, '');

// ── Email ─────────────────────────────────────────────────────────────────────
// Railway blocks outbound SMTP ports, so email is sent via Resend's HTTP API instead.

const RESEND_API_KEY = process.env.RESEND_API_KEY;
if (!RESEND_API_KEY) {
  console.warn('RESEND_API_KEY not set — password reset emails will be logged to console only.');
}

async function sendEmail({ to, subject, text, html }) {
  const from = process.env.SMTP_FROM || 'Psychic IQ <noreply@perseitylabs.com>';
  const r = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ from, to, subject, text, html }),
  });
  if (!r.ok) throw new Error(`Resend API error ${r.status}: ${await r.text()}`);
  return r.json();
}

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

const VALID_TOPICS = ['cards', 'colors', 'animals', 'zodiac', 'planets', 'gems', 'mythical', 'places'];

function todayUTCRange() {
  const now = new Date();
  const start = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
  return { start, end: start + 86400000, date: now.toISOString().slice(0, 10) };
}

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

  const certToken = crypto.randomBytes(16).toString('hex');
  db.prepare(`
    INSERT INTO users (id,email,password_hash,display_name,username,dob,zodiac,level,avatar_data,join_year,created_at,cert_token)
    VALUES (?,?,?,?,?,?,?,?,NULL,?,?,?)
  `).run(id, email.toLowerCase(), hash, displayName, username, dob || null, zodiac || null, level || 'believer', new Date().getFullYear(), now, certToken);

  const user = db.prepare('SELECT * FROM users WHERE id=?').get(id);
  res.status(201).json({ token: signToken(id), user: { ...publicUser(user), certToken: user.cert_token } });
});

// POST /api/auth/login
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'email and password required' });

  const user = db.prepare('SELECT * FROM users WHERE email=?').get(email.toLowerCase());
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }
  res.json({ token: signToken(user.id), user: { ...publicUser(user), certToken: user.cert_token } });
});

// GET /api/auth/check-email?email=...
app.get('/api/auth/check-email', (req, res) => {
  const email = (req.query.email || '').toLowerCase().trim();
  if (!email) return res.status(400).json({ error: 'email required' });
  const row = db.prepare('SELECT id FROM users WHERE email=?').get(email);
  res.json({ available: !row });
});

// POST /api/auth/forgot-password
app.post('/api/auth/forgot-password', (req, res) => {
  const email = (req.body.email || '').toLowerCase().trim();
  if (!email) return res.status(400).json({ error: 'email required' });

  const user = db.prepare('SELECT id, display_name FROM users WHERE email=?').get(email);
  // Always return success to avoid leaking whether an email is registered
  if (!user) return res.json({ ok: true });

  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = Date.now() + 60 * 60 * 1000; // 1 hour
  db.prepare('INSERT INTO password_resets (token, user_id, expires_at) VALUES (?,?,?)').run(token, user.id, expiresAt);

  const resetUrl = `${APP_URL}/?reset=${token}`;

  if (RESEND_API_KEY) {
    sendEmail({
      to: email,
      subject: 'Reset your Psychic IQ password',
      text: `Hi ${user.display_name},\n\nClick the link below to reset your password. It expires in 1 hour.\n\n${resetUrl}\n\nIf you didn't request this, you can ignore this email.`,
      html: `<p>Hi ${user.display_name},</p><p>Click the link below to reset your password. It expires in 1 hour.</p><p><a href="${resetUrl}">${resetUrl}</a></p><p>If you didn't request this, you can ignore this email.</p>`,
    }).then(info => console.log('Reset email sent:', JSON.stringify(info)))
      .catch(err => console.error('Reset email send failed:', err.message));
  } else {
    console.log(`[DEV] Password reset link for ${email}: ${resetUrl}`);
  }

  res.json({ ok: true });
});

// POST /api/auth/reset-password
app.post('/api/auth/reset-password', (req, res) => {
  const { token, password } = req.body;
  if (!token || !password) return res.status(400).json({ error: 'token and password required' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

  const row = db.prepare('SELECT * FROM password_resets WHERE token=?').get(token);
  if (!row || row.used || row.expires_at < Date.now()) {
    return res.status(400).json({ error: 'Reset link is invalid or has expired' });
  }

  const hash = bcrypt.hashSync(password, 10);
  db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(hash, row.user_id);
  db.prepare('UPDATE password_resets SET used=1 WHERE token=?').run(token);

  const user = db.prepare('SELECT * FROM users WHERE id=?').get(row.user_id);
  res.json({ token: signToken(user.id), user: { ...publicUser(user), certToken: user.cert_token } });
});

// ── Current user ──────────────────────────────────────────────────────────────

// GET /api/users/me
app.get('/api/users/me', requireAuth, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id=?').get(req.user.sub);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ ...publicUser(user), certToken: user.cert_token });
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
  res.json({ ...publicUser(updated), certToken: updated.cert_token });
});

// GET /api/users/me/rank  – real all-time and zodiac rank for the current user
app.get('/api/users/me/rank', requireAuth, (req, res) => {
  const userId = req.user.sub;
  const user = db.prepare('SELECT zodiac FROM users WHERE id=?').get(userId);
  if (!user) return res.status(404).json({ error: 'Not found' });

  const { rank } = db.prepare(`
    SELECT COUNT(*) + 1 AS rank
    FROM (SELECT user_id, MAX(score) AS best FROM scores GROUP BY user_id)
    WHERE best > (SELECT COALESCE(MAX(score), 0) FROM scores WHERE user_id = ?)
  `).get(userId);

  let zodiacRank = null;
  if (user.zodiac) {
    const { zrank } = db.prepare(`
      SELECT COUNT(*) + 1 AS zrank
      FROM (
        SELECT s.user_id, MAX(s.score) AS best
        FROM scores s JOIN users u ON u.id = s.user_id
        WHERE u.zodiac = ?
        GROUP BY s.user_id
      )
      WHERE best > (SELECT COALESCE(MAX(score), 0) FROM scores WHERE user_id = ?)
    `).get(user.zodiac, userId);
    zodiacRank = zrank;
  }

  res.json({ rank, zodiacRank });
});

// ── Public profile / cert ─────────────────────────────────────────────────────

// GET /api/users/by-token/:token  (used for public cert viewing — token is not guessable)
app.get('/api/users/by-token/:token', (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE cert_token=?').get(req.params.token);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json(publicUser(user));
});

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
  if (typeof score !== 'number' || score < 0 || score > 999999) {
    return res.status(400).json({ error: 'Invalid score' });
  }

  const playedAt = Date.now();
  stmtInsertScore.run(req.user.sub, topicId, Math.floor(score), playedAt);

  const best = getBestScores(req.user.sub);

  const { start, end } = todayUTCRange();
  const topToday = db.prepare(
    'SELECT MAX(score) AS top FROM scores WHERE played_at >= ? AND played_at < ?'
  ).get(start, end);
  const dailyLeader = score >= topToday.top;

  res.json({ ok: true, bestScores: best, dailyLeader });
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
  if (time === 'today') {
    const { start, end } = todayUTCRange();
    timeClause = `AND s.played_at >= ${start} AND s.played_at < ${end}`;
  } else if (time === 'thismonth') {
    const now = new Date();
    const from = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1);
    timeClause = `AND s.played_at >= ${from}`;
  } else if (time === '90days') {
    const cutoff = Date.now() - 90 * 24 * 60 * 60 * 1000;
    timeClause = `AND s.played_at >= ${cutoff}`;
  } else if (time !== 'alltime') {
    const year = parseInt(time);
    if (!isNaN(year)) {
      const from = Date.UTC(year, 0, 1);
      const to   = Date.UTC(year + 1, 0, 1);
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
  'analytics_dashboard',
];

app.post('/api/purchases', requireAuth, async (req, res) => {
  const { productId, purchaseToken } = req.body;
  if (!VALID_PRODUCT_IDS.includes(productId)) {
    return res.status(400).json({ error: 'Invalid product ID' });
  }

  if (process.env.GOOGLE_SERVICE_ACCOUNT_JSON) {
    if (!purchaseToken) return res.status(400).json({ error: 'Missing purchase token' });
    const valid = await verifyPlayPurchase(productId, purchaseToken);
    if (!valid) return res.status(400).json({ error: 'Purchase could not be verified' });
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

// ── Daily Champion Cron ───────────────────────────────────────────────────────

// Called by cron-job.org at 00:00 UTC every day.
// Awards a daily_champion badge to yesterday's top scorer.
app.post('/api/cron/daily-award', (req, res) => {
  const secret = process.env.CRON_SECRET;
  if (!secret || req.headers['x-cron-secret'] !== secret) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const yesterday = new Date(Date.now() - 86400000);
  const date = yesterday.toISOString().slice(0, 10);
  const start = Date.UTC(yesterday.getUTCFullYear(), yesterday.getUTCMonth(), yesterday.getUTCDate());
  const end = start + 86400000;

  const already = db.prepare('SELECT 1 FROM daily_champions WHERE date=?').get(date);
  if (already) return res.json({ ok: true, already: true, date });

  const winner = db.prepare(`
    SELECT user_id, topic_id, score
    FROM scores WHERE played_at >= ? AND played_at < ?
    ORDER BY score DESC LIMIT 1
  `).get(start, end);

  if (!winner || !winner.user_id) return res.json({ ok: true, noWinner: true, date });

  db.prepare('INSERT INTO daily_champions (date,user_id,topic_id,score,awarded_at) VALUES (?,?,?,?,?)')
    .run(date, winner.user_id, winner.topic_id, winner.score, Date.now());

  const user = db.prepare('SELECT * FROM users WHERE id=?').get(winner.user_id);
  let badges = [];
  try { badges = JSON.parse(user.badges || '[]'); } catch {}
  badges.push({ type: 'daily_champion', date, topicId: winner.topic_id, score: winner.score });
  db.prepare('UPDATE users SET badges=? WHERE id=?').run(JSON.stringify(badges), winner.user_id);

  res.json({ ok: true, date, winner: winner.user_id, score: winner.score });
});

// ── Admin ─────────────────────────────────────────────────────────────────────

const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || 'vbprog@hotmail.com').toLowerCase();

function requireAdmin(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) return res.status(401).json({ error: 'Missing token' });
  let payload;
  try { payload = jwt.verify(header.slice(7), JWT_SECRET); } catch { return res.status(401).json({ error: 'Invalid token' }); }
  const user = db.prepare('SELECT email FROM users WHERE id=?').get(payload.sub);
  if (!user || user.email.toLowerCase() !== ADMIN_EMAIL) return res.status(403).json({ error: 'Forbidden' });
  req.user = payload;
  next();
}

// GET /api/admin/stats
app.get('/api/admin/stats', requireAdmin, (_req, res) => {
  const now = Date.now();
  const todayStart = (() => {
    const d = new Date(); return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate());
  })();
  const thirtyDaysAgo = now - 30 * 86400000;

  const summary = {
    totalUsers:    db.prepare('SELECT COUNT(*) AS n FROM users').get().n,
    totalGames:    db.prepare('SELECT COUNT(*) AS n FROM scores').get().n,
    gamesToday:    db.prepare('SELECT COUNT(*) AS n FROM scores WHERE played_at >= ?').get(todayStart).n,
    countries:     db.prepare("SELECT COUNT(DISTINCT country) AS n FROM users WHERE country IS NOT NULL AND country != ''").get().n,
    newUsersToday: db.prepare('SELECT COUNT(*) AS n FROM users WHERE created_at >= ?').get(todayStart).n,
  };

  const byTopic = db.prepare(`
    SELECT topic_id, COUNT(*) AS games, MAX(score) AS max_score,
           CAST(AVG(score) AS INTEGER) AS avg_score
    FROM scores GROUP BY topic_id ORDER BY games DESC
  `).all();

  const dailyActivity = db.prepare(`
    SELECT CAST((played_at / 86400000) AS INTEGER) AS day_epoch,
           COUNT(*) AS games
    FROM scores WHERE played_at >= ?
    GROUP BY day_epoch ORDER BY day_epoch
  `).all(thirtyDaysAgo).map(r => ({
    date: new Date(r.day_epoch * 86400000).toISOString().slice(0, 10),
    games: r.games,
  }));

  const users = db.prepare(`
    SELECT u.id, u.email, u.display_name, u.username, u.country, u.state_code,
           u.zodiac, u.level, u.created_at,
           COUNT(s.id) AS games_played,
           COALESCE(MAX(s.score), 0) AS best_score,
           MAX(s.played_at) AS last_played
    FROM users u LEFT JOIN scores s ON s.user_id = u.id
    GROUP BY u.id ORDER BY u.created_at DESC
  `).all();

  const recentGames = db.prepare(`
    SELECT s.topic_id, s.score, s.played_at,
           u.display_name, u.username, u.country
    FROM scores s JOIN users u ON u.id = s.user_id
    ORDER BY s.played_at DESC LIMIT 100
  `).all();

  res.json({ summary, byTopic, dailyActivity, users, recentGames });
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
      package_name: 'com.psychicscore.app',
      sha256_cert_fingerprints: [
        'E5:28:55:29:8A:17:AC:79:CF:51:D8:77:86:9A:4C:44:C2:FE:3F:B6:FF:A0:4B:F6:1E:10:E9:6E:D3:90:71:A2',
      ],
    },
  }]);
});

app.get('/privacy', (_req, res) => {
  res.setHeader('Content-Type', 'text/html');
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Privacy Policy – Psychic IQ</title>
  <style>
    body { font-family: sans-serif; max-width: 720px; margin: 40px auto; padding: 0 20px; color: #222; line-height: 1.7; }
    h1 { font-size: 1.6em; } h2 { font-size: 1.1em; margin-top: 2em; }
    a { color: #5b4fcf; }
  </style>
</head>
<body>
  <h1>Privacy Policy</h1>
  <p><strong>Effective date:</strong> May 19, 2025</p>
  <p>Psychic IQ ("we", "our", or "us") is a casual ESP guessing game. This policy explains what information we collect, how we use it, and your choices.</p>

  <h2>Information We Collect</h2>
  <ul>
    <li><strong>Account information:</strong> email address, display name, and username when you create an account.</li>
    <li><strong>Profile information:</strong> zodiac sign, country, and state/region if you choose to provide them.</li>
    <li><strong>Gameplay data:</strong> scores, topics played, and session history to power your stats and the leaderboard.</li>
    <li><strong>Purchase records:</strong> if you make an in-app purchase, we receive a purchase token from Google Play to verify and fulfill your order. We do not store payment card details.</li>
  </ul>

  <h2>How We Use Your Information</h2>
  <ul>
    <li>To create and manage your account.</li>
    <li>To display your scores on the global leaderboard (display name and score only).</li>
    <li>To show ads via Google AdMob. AdMob may collect device identifiers and usage data subject to <a href="https://policies.google.com/privacy" target="_blank">Google's Privacy Policy</a>.</li>
    <li>To verify in-app purchases through the Google Play Developer API.</li>
    <li>To improve the app based on aggregate, anonymized usage patterns.</li>
  </ul>

  <h2>Data Sharing</h2>
  <p>We do not sell your personal information. We share data only with:</p>
  <ul>
    <li><strong>Google Play</strong> – for in-app purchase verification.</li>
    <li><strong>Google AdMob</strong> – for serving ads.</li>
  </ul>

  <h2>Data Retention</h2>
  <p>Your account and gameplay data are retained while your account is active. You may request deletion by emailing us at the address below.</p>

  <h2>Children</h2>
  <p>Psychic IQ is rated for general audiences. We do not knowingly collect personal information from children under 13 without parental consent. If you believe a child has provided us information, please contact us and we will delete it.</p>

  <h2>Your Choices</h2>
  <p>You can update your profile information in the app at any time. To delete your account and associated data, contact us at the email below.</p>

  <h2>Contact</h2>
  <p>Questions? Email us at <a href="mailto:vbprog@hotmail.com">vbprog@hotmail.com</a></p>

  <h2>Changes to This Policy</h2>
  <p>We may update this policy from time to time. The effective date at the top will reflect the most recent revision.</p>
</body>
</html>`);
});

app.get('/delete-account', (_req, res) => {
  res.setHeader('Content-Type', 'text/html');
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Delete Account – Psychic IQ</title>
  <style>
    body { font-family: sans-serif; max-width: 680px; margin: 40px auto; padding: 0 20px; color: #222; line-height: 1.7; }
    h1 { font-size: 1.6em; } h2 { font-size: 1.1em; margin-top: 2em; }
    .steps { background: #f9f9f9; border-left: 4px solid #5b4fcf; padding: 16px 20px; border-radius: 4px; margin: 20px 0; }
    a { color: #5b4fcf; }
  </style>
</head>
<body>
  <h1>Delete Your Psychic IQ Account</h1>
  <p>You can request deletion of your Psychic IQ account and all associated data at any time. We will process your request within 30 days.</p>

  <h2>How to request deletion</h2>
  <div class="steps">
    <p><strong>Send an email to: <a href="mailto:vbprog@hotmail.com">vbprog@hotmail.com</a></strong></p>
    <p>Subject: <em>Account Deletion Request</em><br>
    Include the email address associated with your Psychic IQ account so we can locate and remove it.</p>
  </div>

  <h2>What gets deleted</h2>
  <ul>
    <li>Your account (email, display name, username, password)</li>
    <li>Your profile information (zodiac, country, date of birth)</li>
    <li>Your game scores and psychic level history</li>
    <li>Your purchase records</li>
    <li>Your avatar and card back preferences</li>
  </ul>

  <h2>What may be retained</h2>
  <ul>
    <li>Anonymized, aggregated gameplay statistics that cannot be linked back to you</li>
    <li>Records required for legal or financial compliance (e.g. purchase receipts), retained for up to 7 years as required by law</li>
  </ul>

  <p>Questions? Email us at <a href="mailto:vbprog@hotmail.com">vbprog@hotmail.com</a></p>
</body>
</html>`);
});

app.get('*', (_req, res) => res.sendFile(path.join(__dirname, '..', 'psychic-test.html')));

// ── Start ─────────────────────────────────────────────────────────────────────

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Psychic Test API running on http://localhost:${PORT}`);
  });
}

module.exports = { app };
