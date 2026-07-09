const Database = require('better-sqlite3');
const path = require('path');

const dbPath = process.env.DB_PATH || path.join(__dirname, 'psychic.db');
const db = new Database(dbPath);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id         TEXT PRIMARY KEY,
    email      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    display_name  TEXT NOT NULL,
    username      TEXT UNIQUE NOT NULL,
    dob           TEXT,
    zodiac        TEXT,
    level         TEXT,
    avatar_data   TEXT,
    join_year     INTEGER NOT NULL,
    created_at    INTEGER NOT NULL,
    country       TEXT,
    state_code    TEXT
  );

  CREATE TABLE IF NOT EXISTS scores (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    topic_id   TEXT NOT NULL,
    score      INTEGER NOT NULL,
    played_at  INTEGER NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_scores_user   ON scores(user_id);
  CREATE INDEX IF NOT EXISTS idx_scores_topic  ON scores(topic_id);
  CREATE INDEX IF NOT EXISTS idx_scores_played ON scores(played_at);
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS daily_champions (
    date    TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    topic_id TEXT NOT NULL,
    score   INTEGER NOT NULL,
    awarded_at INTEGER NOT NULL
  )
`);

// Migrate existing databases that predate these columns
try { db.exec(`ALTER TABLE users ADD COLUMN country     TEXT`); } catch {}
try { db.exec(`ALTER TABLE users ADD COLUMN state_code  TEXT`); } catch {}
try { db.exec(`ALTER TABLE users ADD COLUMN purchases   TEXT`); } catch {}
try { db.exec(`ALTER TABLE users ADD COLUMN card_back_id TEXT`); } catch {}
try { db.exec(`ALTER TABLE users ADD COLUMN badges      TEXT`); } catch {}
try { db.exec(`ALTER TABLE users ADD COLUMN cert_token  TEXT`); } catch {}

db.exec(`
  CREATE TABLE IF NOT EXISTS password_resets (
    token      TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL,
    used       INTEGER NOT NULL DEFAULT 0
  )
`);

// Backfill cert_token for any existing users that don't have one
const { randomBytes } = require('crypto');
const missingTokens = db.prepare(`SELECT id FROM users WHERE cert_token IS NULL`).all();
const fillToken = db.prepare(`UPDATE users SET cert_token=? WHERE id=?`);
for (const row of missingTokens) fillToken.run(randomBytes(16).toString('hex'), row.id);

// Returns best score per topic for a user
const stmtBestByTopic = db.prepare(`
  SELECT topic_id, MAX(score) AS best
  FROM scores WHERE user_id = ?
  GROUP BY topic_id
`);

// Insert / update best score (keeps all runs for history)
const stmtInsertScore = db.prepare(
  `INSERT INTO scores (user_id, topic_id, score, played_at) VALUES (?,?,?,?)`
);

function getBestScores(userId) {
  return stmtBestByTopic.all(userId).reduce((acc, row) => {
    acc[row.topic_id] = row.best;
    return acc;
  }, {});
}

function publicUser(u) {
  let purchases = [], badges = [];
  try { purchases = JSON.parse(u.purchases || '[]'); } catch {}
  try { badges    = JSON.parse(u.badges    || '[]'); } catch {}
  return {
    id: u.id,
    displayName: u.display_name,
    username:    u.username,
    zodiac:      u.zodiac,
    level:       u.level,
    joinYear:    u.join_year,
    country:     u.country       || null,
    stateCode:   u.state_code    || null,
    cardBack:    u.card_back_id  || null,
    avatarData:  u.avatar_data   || null,
    purchases,
    badges,
    scores: getBestScores(u.id),
  };
}

module.exports = { db, stmtInsertScore, getBestScores, publicUser };
