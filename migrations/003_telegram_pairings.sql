CREATE TABLE IF NOT EXISTS telegram_pairings (
  id TEXT PRIMARY KEY,
  chat_id INTEGER NOT NULL,
  code TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL,
  requested_at TEXT NOT NULL,
  approved_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_telegram_pairings_chat_status
ON telegram_pairings(chat_id, status);

CREATE INDEX IF NOT EXISTS idx_telegram_pairings_status_requested
ON telegram_pairings(status, requested_at);
