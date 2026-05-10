const Database = require('better-sqlite3');
const path = require('path');

const db = new Database(path.join(__dirname, 'psychic.db'));
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
    created_at    INTEGER NOT NULL
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
  return {
    id: u.id,
    displayName: u.display_name,
    username: u.username,
    zodiac: u.zodiac,
    level: u.level,
    joinYear: u.join_year,
    scores: getBestScores(u.id),
  };
}

module.exports = { db, stmtInsertScore, getBestScores, publicUser };
