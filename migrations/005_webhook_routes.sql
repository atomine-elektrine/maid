CREATE TABLE IF NOT EXISTS webhook_routes (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  path TEXT NOT NULL UNIQUE,
  token TEXT,
  group_id TEXT NOT NULL,
  task_id TEXT,
  prompt_template TEXT,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  last_triggered_at TEXT,
  FOREIGN KEY (group_id) REFERENCES groups(id),
  FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_webhook_routes_path_enabled
ON webhook_routes(path, enabled);

CREATE INDEX IF NOT EXISTS idx_webhook_routes_group_created
ON webhook_routes(group_id, created_at);
