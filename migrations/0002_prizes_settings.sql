-- Apply once in Cloudflare D1 Console before deploying V21.
ALTER TABLE players ADD COLUMN phone TEXT;
ALTER TABLE players ADD COLUMN prize_consent_at TEXT;
CREATE TABLE IF NOT EXISTS stage_settings (
 stage INTEGER PRIMARY KEY CHECK(stage BETWEEN 1 AND 5),
 difficulty INTEGER NOT NULL DEFAULT 1 CHECK(difficulty BETWEEN 0 AND 2)
);
INSERT OR IGNORE INTO stage_settings(stage,difficulty) VALUES(1,1),(2,1),(3,1),(4,1),(5,1);
