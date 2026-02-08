CREATE INDEX IF NOT EXISTS idx_messages_group_created_at
ON messages(group_id, created_at);

CREATE INDEX IF NOT EXISTS idx_tasks_group_status
ON tasks(group_id, status);

CREATE INDEX IF NOT EXISTS idx_task_runs_task_started_at
ON task_runs(task_id, started_at);

CREATE INDEX IF NOT EXISTS idx_audits_group_created_at
ON audits(group_id, created_at);
