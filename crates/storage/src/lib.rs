use std::path::Path;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use maid_core::{
    generate_pairing_code, new_id, Audit, Group, Message, MessageRole, NewAudit, NewTask,
    NewTaskRun, Storage, Task, TaskRun, TaskRunStatus, TaskStatus, TaskWithLastRun,
    TelegramPairing, TelegramPairingStatus,
};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};

#[derive(Clone)]
pub struct SqliteStore {
    pool: SqlitePool,
}

impl SqliteStore {
    pub async fn connect(database_path: &str) -> Result<Self> {
        let options = SqliteConnectOptions::new()
            .filename(database_path)
            .create_if_missing(true);

        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await
            .with_context(|| format!("failed to connect sqlite database at {database_path}"))?;

        let store = Self { pool };
        store.apply_pragmas().await?;
        store.ensure_schema_migration_table().await?;
        Ok(store)
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    pub async fn count_recent_skill_tool_calls(
        &self,
        skill_name: &str,
        since: DateTime<Utc>,
    ) -> Result<i64> {
        let actor = format!("skill:{skill_name}");
        let row = sqlx::query(
            "SELECT COUNT(*) as count \
             FROM audits \
             WHERE action = 'SKILL_TOOL_CALL' AND actor = ? AND created_at >= ?",
        )
        .bind(actor)
        .bind(since.to_rfc3339())
        .fetch_one(&self.pool)
        .await?;
        Ok(row.try_get::<i64, _>("count")?)
    }

    pub async fn list_recent_audits(
        &self,
        limit: i64,
        action: Option<&str>,
        actor: Option<&str>,
    ) -> Result<Vec<Audit>> {
        let limit = limit.clamp(1, 500);
        let rows = match (action, actor) {
            (Some(action), Some(actor)) => {
                sqlx::query(
                    "SELECT id, group_id, action, actor, result, created_at, metadata_json \
                     FROM audits \
                     WHERE action = ? AND actor = ? \
                     ORDER BY created_at DESC \
                     LIMIT ?",
                )
                .bind(action)
                .bind(actor)
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
            (Some(action), None) => {
                sqlx::query(
                    "SELECT id, group_id, action, actor, result, created_at, metadata_json \
                     FROM audits \
                     WHERE action = ? \
                     ORDER BY created_at DESC \
                     LIMIT ?",
                )
                .bind(action)
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
            (None, Some(actor)) => {
                sqlx::query(
                    "SELECT id, group_id, action, actor, result, created_at, metadata_json \
                     FROM audits \
                     WHERE actor = ? \
                     ORDER BY created_at DESC \
                     LIMIT ?",
                )
                .bind(actor)
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
            (None, None) => {
                sqlx::query(
                    "SELECT id, group_id, action, actor, result, created_at, metadata_json \
                     FROM audits \
                     ORDER BY created_at DESC \
                     LIMIT ?",
                )
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
        };

        rows.iter().map(row_to_audit).collect()
    }

    pub async fn list_recent_task_runs(&self, limit: i64) -> Result<Vec<TaskRun>> {
        let limit = limit.clamp(1, 500);
        let rows = sqlx::query(
            "SELECT id, task_id, started_at, finished_at, status, output_summary, error_text, scheduled_for \
             FROM task_runs \
             ORDER BY started_at DESC \
             LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(row_to_task_run).collect()
    }

    async fn ensure_schema_migration_table(&self) -> Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS schema_migrations (
                id TEXT PRIMARY KEY,
                applied_at TEXT NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn apply_pragmas(&self) -> Result<()> {
        sqlx::query("PRAGMA foreign_keys = ON")
            .execute(&self.pool)
            .await?;
        sqlx::query("PRAGMA journal_mode = WAL")
            .execute(&self.pool)
            .await?;
        sqlx::query("PRAGMA synchronous = NORMAL")
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn apply_migrations_from_dir(&self, migration_dir: &Path) -> Result<()> {
        let mut entries = std::fs::read_dir(migration_dir)
            .with_context(|| format!("failed to read migration dir {}", migration_dir.display()))?
            .filter_map(std::result::Result::ok)
            .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("sql"))
            .collect::<Vec<_>>();

        entries.sort_by_key(|e| e.file_name());

        for entry in entries {
            let file_name = entry.file_name().to_string_lossy().to_string();
            let exists = sqlx::query("SELECT id FROM schema_migrations WHERE id = ?")
                .bind(&file_name)
                .fetch_optional(&self.pool)
                .await?
                .is_some();
            if exists {
                continue;
            }

            let sql = std::fs::read_to_string(entry.path())
                .with_context(|| format!("failed to read migration file {file_name}"))?;

            let mut tx = self.pool.begin().await?;
            for statement in split_sql_statements(&sql) {
                sqlx::query(statement).execute(&mut *tx).await?;
            }
            sqlx::query("INSERT INTO schema_migrations (id, applied_at) VALUES (?, ?)")
                .bind(&file_name)
                .bind(Utc::now().to_rfc3339())
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
        }

        Ok(())
    }
}

fn split_sql_statements(sql: &str) -> Vec<&str> {
    sql.split(';')
        .map(str::trim)
        .filter(|stmt| !stmt.is_empty())
        .collect()
}

fn parse_dt(value: &str) -> Result<DateTime<Utc>> {
    Ok(DateTime::parse_from_rfc3339(value)
        .with_context(|| format!("invalid RFC3339 timestamp: {value}"))?
        .with_timezone(&Utc))
}

fn row_to_group(row: &sqlx::sqlite::SqliteRow) -> Result<Group> {
    Ok(Group {
        id: row.try_get("id")?,
        name: row.try_get("name")?,
        created_at: parse_dt(&row.try_get::<String, _>("created_at")?)?,
        root_path: row.try_get("root_path")?,
    })
}

fn row_to_message(row: &sqlx::sqlite::SqliteRow) -> Result<Message> {
    Ok(Message {
        id: row.try_get("id")?,
        group_id: row.try_get("group_id")?,
        role: MessageRole::from_db(&row.try_get::<String, _>("role")?)?,
        content: row.try_get("content")?,
        created_at: parse_dt(&row.try_get::<String, _>("created_at")?)?,
    })
}

fn row_to_task(row: &sqlx::sqlite::SqliteRow) -> Result<Task> {
    Ok(Task {
        id: row.try_get("id")?,
        group_id: row.try_get("group_id")?,
        name: row.try_get("name")?,
        schedule_rrule: row.try_get("schedule_rrule")?,
        prompt_template: row.try_get("prompt_template")?,
        status: TaskStatus::from_db(&row.try_get::<String, _>("status")?)?,
        created_at: parse_dt(&row.try_get::<String, _>("created_at")?)?,
        updated_at: parse_dt(&row.try_get::<String, _>("updated_at")?)?,
    })
}

fn row_to_task_run(row: &sqlx::sqlite::SqliteRow) -> Result<TaskRun> {
    let finished_raw: Option<String> = row.try_get("finished_at")?;
    let scheduled_for_raw: Option<String> = row.try_get("scheduled_for")?;
    Ok(TaskRun {
        id: row.try_get("id")?,
        task_id: row.try_get("task_id")?,
        started_at: parse_dt(&row.try_get::<String, _>("started_at")?)?,
        finished_at: finished_raw.as_deref().map(parse_dt).transpose()?,
        status: TaskRunStatus::from_db(&row.try_get::<String, _>("status")?)?,
        output_summary: row.try_get("output_summary")?,
        error_text: row.try_get("error_text")?,
        scheduled_for: scheduled_for_raw.as_deref().map(parse_dt).transpose()?,
    })
}

fn row_to_audit(row: &sqlx::sqlite::SqliteRow) -> Result<Audit> {
    let metadata_raw: Option<String> = row.try_get("metadata_json")?;
    Ok(Audit {
        id: row.try_get("id")?,
        group_id: row.try_get("group_id")?,
        action: row.try_get("action")?,
        actor: row.try_get("actor")?,
        result: row.try_get("result")?,
        created_at: parse_dt(&row.try_get::<String, _>("created_at")?)?,
        metadata_json: metadata_raw
            .as_deref()
            .map(serde_json::from_str)
            .transpose()
            .context("invalid metadata_json")?,
    })
}

fn row_to_telegram_pairing(row: &sqlx::sqlite::SqliteRow) -> Result<TelegramPairing> {
    let approved_raw: Option<String> = row.try_get("approved_at")?;
    Ok(TelegramPairing {
        id: row.try_get("id")?,
        chat_id: row.try_get("chat_id")?,
        code: row.try_get("code")?,
        status: TelegramPairingStatus::from_db(&row.try_get::<String, _>("status")?)?,
        requested_at: parse_dt(&row.try_get::<String, _>("requested_at")?)?,
        approved_at: approved_raw.as_deref().map(parse_dt).transpose()?,
    })
}

#[async_trait]
impl Storage for SqliteStore {
    async fn create_group(&self, name: &str, root_path: &str) -> Result<Group> {
        let created_at = Utc::now();
        let id = new_id();

        sqlx::query("INSERT INTO groups (id, name, created_at, root_path) VALUES (?, ?, ?, ?)")
            .bind(&id)
            .bind(name)
            .bind(created_at.to_rfc3339())
            .bind(root_path)
            .execute(&self.pool)
            .await
            .with_context(|| format!("failed to create group {name}"))?;

        self.get_group_by_id(&id)
            .await?
            .ok_or_else(|| anyhow!("failed to load inserted group"))
    }

    async fn list_groups(&self) -> Result<Vec<Group>> {
        let rows =
            sqlx::query("SELECT id, name, created_at, root_path FROM groups ORDER BY created_at")
                .fetch_all(&self.pool)
                .await?;

        rows.iter().map(row_to_group).collect()
    }

    async fn get_group_by_name(&self, name: &str) -> Result<Option<Group>> {
        let row = sqlx::query(
            "SELECT id, name, created_at, root_path FROM groups WHERE name = ? LIMIT 1",
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await?;

        row.as_ref().map(row_to_group).transpose()
    }

    async fn get_group_by_id(&self, id: &str) -> Result<Option<Group>> {
        let row =
            sqlx::query("SELECT id, name, created_at, root_path FROM groups WHERE id = ? LIMIT 1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?;

        row.as_ref().map(row_to_group).transpose()
    }

    async fn insert_message(
        &self,
        group_id: &str,
        role: MessageRole,
        content: &str,
    ) -> Result<Message> {
        let created_at = Utc::now();
        let id = new_id();

        sqlx::query(
            "INSERT INTO messages (id, group_id, role, content, created_at) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(group_id)
        .bind(role.as_str())
        .bind(content)
        .bind(created_at.to_rfc3339())
        .execute(&self.pool)
        .await?;

        let row = sqlx::query(
            "SELECT id, group_id, role, content, created_at FROM messages WHERE id = ? LIMIT 1",
        )
        .bind(&id)
        .fetch_one(&self.pool)
        .await?;
        row_to_message(&row)
    }

    async fn list_recent_messages(&self, group_id: &str, limit: i64) -> Result<Vec<Message>> {
        let rows = sqlx::query(
            "SELECT id, group_id, role, content, created_at \
             FROM messages \
             WHERE group_id = ? \
             ORDER BY created_at DESC \
             LIMIT ?",
        )
        .bind(group_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        let mut messages = rows
            .iter()
            .map(row_to_message)
            .collect::<Result<Vec<_>>>()?;
        messages.reverse();
        Ok(messages)
    }

    async fn create_task(&self, new_task: NewTask) -> Result<Task> {
        let now = Utc::now();
        let id = new_id();

        sqlx::query(
            "INSERT INTO tasks (id, group_id, name, schedule_rrule, prompt_template, status, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(&new_task.group_id)
        .bind(&new_task.name)
        .bind(&new_task.schedule_rrule)
        .bind(&new_task.prompt_template)
        .bind(TaskStatus::Active.as_str())
        .bind(now.to_rfc3339())
        .bind(now.to_rfc3339())
        .execute(&self.pool)
        .await?;

        self.get_task(&id)
            .await?
            .ok_or_else(|| anyhow!("failed to load inserted task"))
    }

    async fn list_tasks(&self, group_id: &str) -> Result<Vec<Task>> {
        let rows = sqlx::query(
            "SELECT id, group_id, name, schedule_rrule, prompt_template, status, created_at, updated_at \
             FROM tasks WHERE group_id = ? ORDER BY created_at",
        )
        .bind(group_id)
        .fetch_all(&self.pool)
        .await?;

        rows.iter().map(row_to_task).collect()
    }

    async fn get_task(&self, task_id: &str) -> Result<Option<Task>> {
        let row = sqlx::query(
            "SELECT id, group_id, name, schedule_rrule, prompt_template, status, created_at, updated_at \
             FROM tasks WHERE id = ? LIMIT 1",
        )
        .bind(task_id)
        .fetch_optional(&self.pool)
        .await?;

        row.as_ref().map(row_to_task).transpose()
    }

    async fn update_task_status(&self, task_id: &str, status: TaskStatus) -> Result<()> {
        sqlx::query("UPDATE tasks SET status = ?, updated_at = ? WHERE id = ?")
            .bind(status.as_str())
            .bind(Utc::now().to_rfc3339())
            .bind(task_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn delete_task(&self, task_id: &str) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM task_runs WHERE task_id = ?")
            .bind(task_id)
            .execute(&mut *tx)
            .await?;
        let deleted = sqlx::query("DELETE FROM tasks WHERE id = ?")
            .bind(task_id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        tx.commit().await?;
        Ok(deleted > 0)
    }

    async fn clear_tasks_for_group(&self, group_id: &str) -> Result<u64> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "DELETE FROM task_runs WHERE task_id IN (SELECT id FROM tasks WHERE group_id = ?)",
        )
        .bind(group_id)
        .execute(&mut *tx)
        .await?;
        let deleted = sqlx::query("DELETE FROM tasks WHERE group_id = ?")
            .bind(group_id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        tx.commit().await?;
        Ok(deleted)
    }

    async fn clear_all_tasks(&self) -> Result<u64> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM task_runs")
            .execute(&mut *tx)
            .await?;
        let deleted = sqlx::query("DELETE FROM tasks")
            .execute(&mut *tx)
            .await?
            .rows_affected();
        tx.commit().await?;
        Ok(deleted)
    }

    async fn insert_task_run(&self, new_run: NewTaskRun) -> Result<TaskRun> {
        let id = new_id();
        sqlx::query(
            "INSERT INTO task_runs (id, task_id, started_at, finished_at, status, output_summary, error_text, scheduled_for) \
             VALUES (?, ?, ?, NULL, ?, NULL, NULL, ?)",
        )
        .bind(&id)
        .bind(&new_run.task_id)
        .bind(new_run.started_at.to_rfc3339())
        .bind(new_run.status.as_str())
        .bind(new_run.scheduled_for.map(|v| v.to_rfc3339()))
        .execute(&self.pool)
        .await?;

        let row = sqlx::query(
            "SELECT id, task_id, started_at, finished_at, status, output_summary, error_text, scheduled_for \
             FROM task_runs WHERE id = ? LIMIT 1",
        )
        .bind(&id)
        .fetch_one(&self.pool)
        .await?;

        row_to_task_run(&row)
    }

    async fn finish_task_run(
        &self,
        run_id: &str,
        status: TaskRunStatus,
        output_summary: Option<&str>,
        error_text: Option<&str>,
        finished_at: DateTime<Utc>,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE task_runs SET status = ?, output_summary = ?, error_text = ?, finished_at = ? WHERE id = ?",
        )
        .bind(status.as_str())
        .bind(output_summary)
        .bind(error_text)
        .bind(finished_at.to_rfc3339())
        .bind(run_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list_active_tasks_with_last_run(&self) -> Result<Vec<TaskWithLastRun>> {
        let rows = sqlx::query(
            "SELECT \
                t.id, t.group_id, t.name, t.schedule_rrule, t.prompt_template, t.status, t.created_at, t.updated_at, \
                MAX(tr.started_at) as last_run_started_at \
             FROM tasks t \
             LEFT JOIN task_runs tr ON tr.task_id = t.id \
             WHERE t.status = 'ACTIVE' \
             GROUP BY t.id, t.group_id, t.name, t.schedule_rrule, t.prompt_template, t.status, t.created_at, t.updated_at \
             ORDER BY t.created_at",
        )
        .fetch_all(&self.pool)
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let task = row_to_task(&row)?;
            let last_run_raw: Option<String> = row.try_get("last_run_started_at")?;
            out.push(TaskWithLastRun {
                task,
                last_run_started_at: last_run_raw.as_deref().map(parse_dt).transpose()?,
            });
        }
        Ok(out)
    }

    async fn insert_audit(&self, new_audit: NewAudit) -> Result<Audit> {
        let id = new_id();
        let metadata = new_audit
            .metadata_json
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .context("failed to serialize metadata_json")?;

        sqlx::query(
            "INSERT INTO audits (id, group_id, action, actor, result, created_at, metadata_json) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(&new_audit.group_id)
        .bind(&new_audit.action)
        .bind(&new_audit.actor)
        .bind(&new_audit.result)
        .bind(new_audit.created_at.to_rfc3339())
        .bind(metadata)
        .execute(&self.pool)
        .await?;

        let row = sqlx::query(
            "SELECT id, group_id, action, actor, result, created_at, metadata_json FROM audits WHERE id = ?",
        )
        .bind(&id)
        .fetch_one(&self.pool)
        .await?;

        row_to_audit(&row)
    }

    async fn create_or_get_pending_telegram_pairing(
        &self,
        chat_id: i64,
    ) -> Result<TelegramPairing> {
        let existing = sqlx::query(
            "SELECT id, chat_id, code, status, requested_at, approved_at \
             FROM telegram_pairings \
             WHERE chat_id = ? AND status = 'PENDING' \
             ORDER BY requested_at DESC \
             LIMIT 1",
        )
        .bind(chat_id)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(row) = existing {
            return row_to_telegram_pairing(&row);
        }

        let id = new_id();
        let requested_at = Utc::now();
        let code = generate_pairing_code();

        sqlx::query(
            "INSERT INTO telegram_pairings (id, chat_id, code, status, requested_at, approved_at) \
             VALUES (?, ?, ?, 'PENDING', ?, NULL)",
        )
        .bind(&id)
        .bind(chat_id)
        .bind(&code)
        .bind(requested_at.to_rfc3339())
        .execute(&self.pool)
        .await?;

        let row = sqlx::query(
            "SELECT id, chat_id, code, status, requested_at, approved_at \
             FROM telegram_pairings \
             WHERE id = ? LIMIT 1",
        )
        .bind(&id)
        .fetch_one(&self.pool)
        .await?;

        row_to_telegram_pairing(&row)
    }

    async fn approve_telegram_pairing_by_code(&self, code: &str) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE telegram_pairings \
             SET status = 'APPROVED', approved_at = ? \
             WHERE code = ? AND status = 'PENDING'",
        )
        .bind(Utc::now().to_rfc3339())
        .bind(code.trim().to_uppercase())
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn is_telegram_chat_approved(&self, chat_id: i64) -> Result<bool> {
        let row = sqlx::query(
            "SELECT id FROM telegram_pairings \
             WHERE chat_id = ? AND status = 'APPROVED' \
             LIMIT 1",
        )
        .bind(chat_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.is_some())
    }

    async fn list_pending_telegram_pairings(&self) -> Result<Vec<TelegramPairing>> {
        let rows = sqlx::query(
            "SELECT id, chat_id, code, status, requested_at, approved_at \
             FROM telegram_pairings \
             WHERE status = 'PENDING' \
             ORDER BY requested_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(row_to_telegram_pairing).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maid_core::{MessageRole, TaskRunStatus, TaskStatus, TelegramPairingStatus};

    async fn setup_store() -> SqliteStore {
        let db_path = format!("/tmp/maid-storage-test-{}.db", new_id());
        let store = SqliteStore::connect(&db_path).await.unwrap();
        let migration_dir =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../migrations");
        store
            .apply_migrations_from_dir(&migration_dir)
            .await
            .unwrap();
        store
    }

    #[tokio::test]
    async fn group_and_message_crud() {
        let store = setup_store().await;
        let group = store.create_group("alpha", "/tmp/alpha").await.unwrap();
        assert_eq!(group.name, "alpha");

        store
            .insert_message(&group.id, MessageRole::User, "hello")
            .await
            .unwrap();
        let messages = store.list_recent_messages(&group.id, 10).await.unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].content, "hello");
    }

    #[tokio::test]
    async fn task_and_run_crud() {
        let store = setup_store().await;
        let group = store.create_group("ops", "/tmp/ops").await.unwrap();
        let task = store
            .create_task(NewTask {
                group_id: group.id,
                name: "daily".to_string(),
                schedule_rrule: "FREQ=HOURLY;INTERVAL=1".to_string(),
                prompt_template: "ping".to_string(),
            })
            .await
            .unwrap();

        assert_eq!(task.status, TaskStatus::Active);

        let run = store
            .insert_task_run(NewTaskRun {
                task_id: task.id.clone(),
                started_at: Utc::now(),
                status: TaskRunStatus::Running,
                scheduled_for: None,
            })
            .await
            .unwrap();

        store
            .finish_task_run(
                &run.id,
                TaskRunStatus::Succeeded,
                Some("ok"),
                None,
                Utc::now(),
            )
            .await
            .unwrap();

        let active = store.list_active_tasks_with_last_run().await.unwrap();
        assert_eq!(active.len(), 1);
        assert!(active[0].last_run_started_at.is_some());
    }

    #[tokio::test]
    async fn delete_and_clear_tasks() {
        let store = setup_store().await;
        let g1 = store.create_group("g1", "/tmp/g1").await.unwrap();
        let g2 = store.create_group("g2", "/tmp/g2").await.unwrap();

        let t1 = store
            .create_task(NewTask {
                group_id: g1.id.clone(),
                name: "a".to_string(),
                schedule_rrule: "FREQ=MINUTELY;INTERVAL=1".to_string(),
                prompt_template: "ping".to_string(),
            })
            .await
            .unwrap();

        store
            .insert_task_run(NewTaskRun {
                task_id: t1.id.clone(),
                started_at: Utc::now(),
                status: TaskRunStatus::Running,
                scheduled_for: None,
            })
            .await
            .unwrap();

        let deleted = store.delete_task(&t1.id).await.unwrap();
        assert!(deleted);
        assert!(store.get_task(&t1.id).await.unwrap().is_none());

        store
            .create_task(NewTask {
                group_id: g1.id.clone(),
                name: "b".to_string(),
                schedule_rrule: "FREQ=MINUTELY;INTERVAL=1".to_string(),
                prompt_template: "ping".to_string(),
            })
            .await
            .unwrap();
        store
            .create_task(NewTask {
                group_id: g1.id.clone(),
                name: "c".to_string(),
                schedule_rrule: "FREQ=MINUTELY;INTERVAL=1".to_string(),
                prompt_template: "ping".to_string(),
            })
            .await
            .unwrap();
        store
            .create_task(NewTask {
                group_id: g2.id.clone(),
                name: "d".to_string(),
                schedule_rrule: "FREQ=MINUTELY;INTERVAL=1".to_string(),
                prompt_template: "ping".to_string(),
            })
            .await
            .unwrap();

        let cleared = store.clear_tasks_for_group(&g1.id).await.unwrap();
        assert_eq!(cleared, 2);
        assert_eq!(store.list_tasks(&g1.id).await.unwrap().len(), 0);
        assert_eq!(store.list_tasks(&g2.id).await.unwrap().len(), 1);

        let cleared_all = store.clear_all_tasks().await.unwrap();
        assert_eq!(cleared_all, 1);
        assert_eq!(store.list_tasks(&g2.id).await.unwrap().len(), 0);
    }

    #[tokio::test]
    async fn audit_insert() {
        let store = setup_store().await;
        let audit = store
            .insert_audit(NewAudit {
                group_id: None,
                action: "TEST".to_string(),
                actor: "test".to_string(),
                result: "SUCCESS".to_string(),
                created_at: Utc::now(),
                metadata_json: Some(serde_json::json!({"a": 1})),
            })
            .await
            .unwrap();

        assert_eq!(audit.action, "TEST");
        assert!(audit.metadata_json.is_some());

        let listed = store
            .list_recent_audits(10, Some("TEST"), Some("test"))
            .await
            .unwrap();
        assert_eq!(listed.len(), 1);

        let count = store
            .count_recent_skill_tool_calls("unit", Utc::now() - chrono::Duration::minutes(1))
            .await
            .unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn telegram_pairing_lifecycle() {
        let store = setup_store().await;
        let chat_id = 42_i64;

        let pending = store
            .create_or_get_pending_telegram_pairing(chat_id)
            .await
            .unwrap();
        assert_eq!(pending.chat_id, chat_id);
        assert_eq!(pending.status, TelegramPairingStatus::Pending);

        let pending_again = store
            .create_or_get_pending_telegram_pairing(chat_id)
            .await
            .unwrap();
        assert_eq!(pending.id, pending_again.id);

        assert!(!store.is_telegram_chat_approved(chat_id).await.unwrap());
        assert!(store
            .approve_telegram_pairing_by_code(&pending.code)
            .await
            .unwrap());
        assert!(store.is_telegram_chat_approved(chat_id).await.unwrap());
        assert!(!store
            .approve_telegram_pairing_by_code("NOTREAL")
            .await
            .unwrap());
    }
}

#[cfg(test)]
mod task_status_tests {
    use super::*;

    async fn setup_store() -> SqliteStore {
        let db_path = format!("/tmp/maid-storage-status-test-{}.db", new_id());
        let store = SqliteStore::connect(&db_path).await.unwrap();
        let migration_dir =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../migrations");
        store
            .apply_migrations_from_dir(&migration_dir)
            .await
            .unwrap();
        store
    }

    #[tokio::test]
    async fn task_status_transitions() {
        let store = setup_store().await;
        let group = store.create_group("status", "/tmp/status").await.unwrap();
        let task = store
            .create_task(NewTask {
                group_id: group.id,
                name: "stateful".to_string(),
                schedule_rrule: "FREQ=HOURLY;INTERVAL=1".to_string(),
                prompt_template: "ping".to_string(),
            })
            .await
            .unwrap();

        store
            .update_task_status(&task.id, TaskStatus::Paused)
            .await
            .unwrap();
        let paused = store.get_task(&task.id).await.unwrap().unwrap();
        assert_eq!(paused.status, TaskStatus::Paused);

        store
            .update_task_status(&task.id, TaskStatus::Active)
            .await
            .unwrap();
        let active = store.get_task(&task.id).await.unwrap().unwrap();
        assert_eq!(active.status, TaskStatus::Active);
    }
}
