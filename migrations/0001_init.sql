CREATE TABLE IF NOT EXISTS players (
  id TEXT PRIMARY KEY,
  nickname TEXT NOT NULL,
  session_hash TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','blocked')),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  last_seen TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  player_id TEXT NOT NULL REFERENCES players(id),
  stage INTEGER NOT NULL CHECK(stage BETWEEN 1 AND 5),
  score INTEGER NOT NULL CHECK(score BETWEEN 0 AND 100000),
  coins INTEGER NOT NULL DEFAULT 0 CHECK(coins BETWEEN 0 AND 10000),
  elapsed INTEGER NOT NULL DEFAULT 0 CHECK(elapsed BETWEEN 0 AND 10000000),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_runs_player_stage ON runs(player_id,stage);
CREATE INDEX IF NOT EXISTS idx_runs_stage_score ON runs(stage,score DESC);
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  action TEXT NOT NULL,
  detail TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS admin_login_attempts (
  ip_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_admin_attempt_time ON admin_login_attempts(ip_hash,created_at);
