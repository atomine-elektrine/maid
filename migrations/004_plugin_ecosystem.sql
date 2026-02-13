CREATE TABLE IF NOT EXISTS plugin_invocations (
  id TEXT PRIMARY KEY,
  plugin_name TEXT NOT NULL,
  plugin_version TEXT NOT NULL,
  command TEXT NOT NULL,
  actor TEXT NOT NULL,
  ok INTEGER NOT NULL,
  latency_ms INTEGER NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS plugin_health_daily (
  day TEXT NOT NULL,
  plugin_name TEXT NOT NULL,
  success_rate REAL NOT NULL,
  p50_latency_ms INTEGER NOT NULL,
  p95_latency_ms INTEGER NOT NULL,
  run_count INTEGER NOT NULL,
  PRIMARY KEY (day, plugin_name)
);

CREATE TABLE IF NOT EXISTS plugin_installs (
  plugin_name TEXT NOT NULL,
  version TEXT NOT NULL,
  source TEXT NOT NULL,
  actor TEXT NOT NULL,
  installed_at TEXT NOT NULL,
  PRIMARY KEY (plugin_name, version, actor)
);

CREATE INDEX IF NOT EXISTS idx_plugin_invocations_plugin_created
ON plugin_invocations(plugin_name, created_at);

CREATE INDEX IF NOT EXISTS idx_plugin_invocations_created
ON plugin_invocations(created_at);

CREATE INDEX IF NOT EXISTS idx_plugin_installs_plugin_installed
ON plugin_installs(plugin_name, installed_at);
