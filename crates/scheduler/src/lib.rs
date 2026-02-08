use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Datelike, Duration, TimeZone, Timelike, Utc, Weekday};
use maid_core::{
    NewAudit, NewTaskRun, Storage, TaskExecutionRequest, TaskExecutor, TaskRunStatus, TaskTrigger,
};
use tokio::sync::Semaphore;
use tokio::time;
use tracing::{error, warn};

const MISSED_GRACE_MINUTES: i64 = 10;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Schedule {
    Minutely {
        interval: u32,
    },
    Hourly {
        interval: u32,
    },
    Weekly {
        byday: Vec<Weekday>,
        byhour: u32,
        byminute: u32,
    },
}

impl Schedule {
    pub fn parse_rrule(input: &str) -> Result<Self> {
        let map = parse_kv(input)?;
        let freq = map
            .get("FREQ")
            .ok_or_else(|| anyhow!("RRULE missing FREQ"))?
            .as_str();

        match freq {
            "MINUTELY" => {
                let interval = map
                    .get("INTERVAL")
                    .ok_or_else(|| anyhow!("MINUTELY RRULE missing INTERVAL"))?
                    .parse::<u32>()
                    .context("invalid INTERVAL value")?;
                if interval == 0 {
                    return Err(anyhow!("INTERVAL must be greater than zero"));
                }
                Ok(Self::Minutely { interval })
            }
            "HOURLY" => {
                let interval = map
                    .get("INTERVAL")
                    .ok_or_else(|| anyhow!("HOURLY RRULE missing INTERVAL"))?
                    .parse::<u32>()
                    .context("invalid INTERVAL value")?;
                if interval == 0 {
                    return Err(anyhow!("INTERVAL must be greater than zero"));
                }
                Ok(Self::Hourly { interval })
            }
            "WEEKLY" => {
                let byday_raw = map
                    .get("BYDAY")
                    .ok_or_else(|| anyhow!("WEEKLY RRULE missing BYDAY"))?;
                let byhour = map
                    .get("BYHOUR")
                    .ok_or_else(|| anyhow!("WEEKLY RRULE missing BYHOUR"))?
                    .parse::<u32>()
                    .context("invalid BYHOUR")?;
                let byminute = map
                    .get("BYMINUTE")
                    .ok_or_else(|| anyhow!("WEEKLY RRULE missing BYMINUTE"))?
                    .parse::<u32>()
                    .context("invalid BYMINUTE")?;

                if byhour > 23 {
                    return Err(anyhow!("BYHOUR must be between 0 and 23"));
                }
                if byminute > 59 {
                    return Err(anyhow!("BYMINUTE must be between 0 and 59"));
                }

                let mut byday = Vec::new();
                for token in byday_raw.split(',') {
                    byday.push(parse_weekday(token)?);
                }
                if byday.is_empty() {
                    return Err(anyhow!("BYDAY cannot be empty"));
                }

                Ok(Self::Weekly {
                    byday,
                    byhour,
                    byminute,
                })
            }
            other => Err(anyhow!("unsupported FREQ in RRULE: {other}")),
        }
    }

    pub fn next_after(&self, after: DateTime<Utc>) -> Result<DateTime<Utc>> {
        match self {
            Self::Minutely { interval } => next_minutely(after, *interval),
            Self::Hourly { interval } => next_hourly(after, *interval),
            Self::Weekly {
                byday,
                byhour,
                byminute,
            } => next_weekly(after, byday, *byhour, *byminute),
        }
    }
}

#[derive(Clone)]
pub struct SchedulerEngine {
    store: Arc<dyn Storage>,
    executor: Arc<dyn TaskExecutor>,
    tick_seconds: u64,
    max_concurrency: usize,
}

impl SchedulerEngine {
    pub fn new(
        store: Arc<dyn Storage>,
        executor: Arc<dyn TaskExecutor>,
        tick_seconds: u64,
        max_concurrency: usize,
    ) -> Self {
        Self {
            store,
            executor,
            tick_seconds,
            max_concurrency,
        }
    }

    pub async fn run_until_shutdown(&self) -> Result<()> {
        let mut interval = time::interval(std::time::Duration::from_secs(self.tick_seconds));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Err(err) = self.tick_once(Utc::now()).await {
                        error!("scheduler tick failed: {err:#}");
                    }
                }
                _ = tokio::signal::ctrl_c() => {
                    break;
                }
            }
        }
        Ok(())
    }

    pub async fn tick_once(&self, now: DateTime<Utc>) -> Result<()> {
        let tasks = self.store.list_active_tasks_with_last_run().await?;
        let semaphore = Arc::new(Semaphore::new(self.max_concurrency.max(1)));

        let mut handles = Vec::new();
        for task_with_last in tasks {
            let schedule = match Schedule::parse_rrule(&task_with_last.task.schedule_rrule) {
                Ok(schedule) => schedule,
                Err(err) => {
                    warn!(
                        "invalid schedule for task {}: {err:#}",
                        task_with_last.task.id
                    );
                    self.store
                        .insert_audit(NewAudit {
                            group_id: Some(task_with_last.task.group_id.clone()),
                            action: "TASK_INVALID_SCHEDULE".to_string(),
                            actor: "scheduler".to_string(),
                            result: "FAILED".to_string(),
                            created_at: now,
                            metadata_json: Some(serde_json::json!({
                                "task_id": task_with_last.task.id,
                                "schedule_rrule": task_with_last.task.schedule_rrule,
                                "error": format!("{err:#}"),
                            })),
                        })
                        .await?;
                    continue;
                }
            };

            let anchor = task_with_last
                .last_run_started_at
                .unwrap_or(task_with_last.task.created_at - Duration::seconds(1));
            let scheduled_for = schedule.next_after(anchor)?;

            if scheduled_for > now {
                continue;
            }

            if now - scheduled_for > Duration::minutes(MISSED_GRACE_MINUTES) {
                let skipped_run = self
                    .store
                    .insert_task_run(NewTaskRun {
                        task_id: task_with_last.task.id.clone(),
                        started_at: scheduled_for,
                        status: TaskRunStatus::Skipped,
                        scheduled_for: Some(scheduled_for),
                    })
                    .await?;

                self.store
                    .finish_task_run(
                        &skipped_run.id,
                        TaskRunStatus::Skipped,
                        Some("skipped due to missed execution window"),
                        None,
                        now,
                    )
                    .await?;

                self.store
                    .insert_audit(NewAudit {
                        group_id: Some(task_with_last.task.group_id.clone()),
                        action: "TASK_SKIPPED_MISSED_WINDOW".to_string(),
                        actor: "scheduler".to_string(),
                        result: "SKIPPED".to_string(),
                        created_at: now,
                        metadata_json: Some(serde_json::json!({
                            "task_id": task_with_last.task.id,
                            "scheduled_for": scheduled_for.to_rfc3339(),
                        })),
                    })
                    .await?;
                continue;
            }

            let permit = semaphore.clone().acquire_owned().await?;
            let executor = self.executor.clone();
            let request = TaskExecutionRequest {
                task_id: task_with_last.task.id,
                trigger: TaskTrigger::Scheduled,
                scheduled_for: Some(scheduled_for),
                actor: "scheduler".to_string(),
            };
            handles.push(tokio::spawn(async move {
                let _permit = permit;
                executor.execute(request).await
            }));
        }

        for handle in handles {
            let join_result = handle
                .await
                .context("task execution join failure in scheduler")?;
            if let Err(err) = join_result {
                error!("scheduled task failed: {err:#}");
            }
        }

        Ok(())
    }
}

fn parse_kv(input: &str) -> Result<HashMap<String, String>> {
    let mut map = HashMap::new();
    for part in input.split(';') {
        if part.trim().is_empty() {
            continue;
        }
        let mut split = part.splitn(2, '=');
        let key = split
            .next()
            .ok_or_else(|| anyhow!("invalid RRULE segment"))?
            .trim()
            .to_uppercase();
        let value = split
            .next()
            .ok_or_else(|| anyhow!("invalid RRULE segment (missing '=')"))?
            .trim()
            .to_uppercase();
        map.insert(key, value);
    }
    Ok(map)
}

fn parse_weekday(token: &str) -> Result<Weekday> {
    match token {
        "MO" => Ok(Weekday::Mon),
        "TU" => Ok(Weekday::Tue),
        "WE" => Ok(Weekday::Wed),
        "TH" => Ok(Weekday::Thu),
        "FR" => Ok(Weekday::Fri),
        "SA" => Ok(Weekday::Sat),
        "SU" => Ok(Weekday::Sun),
        _ => Err(anyhow!("invalid BYDAY token: {token}")),
    }
}

fn next_hourly(after: DateTime<Utc>, interval: u32) -> Result<DateTime<Utc>> {
    let base = (after + Duration::seconds(1))
        .with_minute(0)
        .ok_or_else(|| anyhow!("failed to normalize minute"))?
        .with_second(0)
        .ok_or_else(|| anyhow!("failed to normalize second"))?
        .with_nanosecond(0)
        .ok_or_else(|| anyhow!("failed to normalize nanosecond"))?;

    let mut candidate = if base <= after {
        base + Duration::hours(1)
    } else {
        base
    };

    while (candidate.timestamp() / 3600) % i64::from(interval) != 0 {
        candidate += Duration::hours(1);
    }

    Ok(candidate)
}

fn next_minutely(after: DateTime<Utc>, interval: u32) -> Result<DateTime<Utc>> {
    let base = (after + Duration::seconds(1))
        .with_second(0)
        .ok_or_else(|| anyhow!("failed to normalize second"))?
        .with_nanosecond(0)
        .ok_or_else(|| anyhow!("failed to normalize nanosecond"))?;

    let mut candidate = if base <= after {
        base + Duration::minutes(1)
    } else {
        base
    };

    while (candidate.timestamp() / 60) % i64::from(interval) != 0 {
        candidate += Duration::minutes(1);
    }

    Ok(candidate)
}

fn next_weekly(
    after: DateTime<Utc>,
    byday: &[Weekday],
    byhour: u32,
    byminute: u32,
) -> Result<DateTime<Utc>> {
    let start_date = after.date_naive();

    for day_offset in 0..15_i64 {
        let date = start_date + Duration::days(day_offset);
        if !byday.contains(&date.weekday()) {
            continue;
        }

        let candidate = Utc
            .with_ymd_and_hms(date.year(), date.month(), date.day(), byhour, byminute, 0)
            .single()
            .ok_or_else(|| anyhow!("failed to build weekly candidate datetime"))?;

        if candidate > after {
            return Ok(candidate);
        }
    }

    Err(anyhow!("failed to compute next weekly schedule"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minutely_rule() {
        let parsed = Schedule::parse_rrule("FREQ=MINUTELY;INTERVAL=1").unwrap();
        assert_eq!(parsed, Schedule::Minutely { interval: 1 });
    }

    #[test]
    fn parse_hourly_rule() {
        let parsed = Schedule::parse_rrule("FREQ=HOURLY;INTERVAL=2").unwrap();
        assert_eq!(parsed, Schedule::Hourly { interval: 2 });
    }

    #[test]
    fn parse_weekly_rule() {
        let parsed = Schedule::parse_rrule("FREQ=WEEKLY;BYDAY=MO,WE;BYHOUR=9;BYMINUTE=30").unwrap();
        assert_eq!(
            parsed,
            Schedule::Weekly {
                byday: vec![Weekday::Mon, Weekday::Wed],
                byhour: 9,
                byminute: 30,
            }
        );
    }

    #[test]
    fn next_hourly_computes_future_time() {
        let rule = Schedule::parse_rrule("FREQ=HOURLY;INTERVAL=3").unwrap();
        let after = DateTime::parse_from_rfc3339("2026-02-08T10:10:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let next = rule.next_after(after).unwrap();
        assert!(next > after);
        assert_eq!(next.minute(), 0);
        assert_eq!(next.second(), 0);
    }

    #[test]
    fn next_minutely_computes_future_time() {
        let rule = Schedule::parse_rrule("FREQ=MINUTELY;INTERVAL=1").unwrap();
        let after = DateTime::parse_from_rfc3339("2026-02-08T10:10:30Z")
            .unwrap()
            .with_timezone(&Utc);
        let next = rule.next_after(after).unwrap();
        assert!(next > after);
        assert_eq!(next.second(), 0);
    }

    #[test]
    fn next_weekly_computes_matching_day() {
        let rule = Schedule::parse_rrule("FREQ=WEEKLY;BYDAY=MO;BYHOUR=8;BYMINUTE=0").unwrap();
        let after = DateTime::parse_from_rfc3339("2026-02-08T10:10:00Z")
            .unwrap()
            .with_timezone(&Utc); // Sunday
        let next = rule.next_after(after).unwrap();
        assert_eq!(next.weekday(), Weekday::Mon);
        assert_eq!(next.hour(), 8);
        assert_eq!(next.minute(), 0);
    }
}
