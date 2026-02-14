use std::io::{self, IsTerminal, Write};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use maid_scheduler::Schedule;

use crate::cli::TaskCommands;
use crate::AppService;
use crate::{print_table, truncate_line};

pub(crate) async fn handle_task_command(
    service: Arc<AppService>,
    command: TaskCommands,
) -> Result<()> {
    match command {
        TaskCommands::Create {
            group,
            name,
            schedule,
            prompt,
        } => {
            Schedule::parse_rrule(&schedule)
                .with_context(|| format!("invalid schedule RRULE: {}", schedule))?;

            let task = service
                .create_task(&group, &name, &schedule, &prompt, "cli")
                .await?;
            println!("created task '{}' ({})", task.name, task.id);
        }
        TaskCommands::Wizard {
            group,
            name,
            schedule,
            prompt,
        } => {
            run_task_wizard(service.clone(), group, name, schedule, prompt).await?;
        }
        TaskCommands::QuickAdd {
            group,
            name,
            every_minutes,
            prompt,
        } => {
            if every_minutes == 0 || every_minutes > 1_440 {
                return Err(anyhow!(
                    "--every-minutes must be between 1 and 1440 (got {every_minutes})"
                ));
            }
            let schedule = format!("FREQ=MINUTELY;INTERVAL={every_minutes}");
            Schedule::parse_rrule(&schedule)
                .with_context(|| format!("invalid generated schedule RRULE: {}", schedule))?;
            let task = service
                .create_task(&group, &name, &schedule, &prompt, "cli")
                .await?;
            println!(
                "created task '{}' ({}) with schedule {}",
                task.name, task.id, schedule
            );
        }
        TaskCommands::CronAdd {
            group,
            name,
            every_minutes,
            prompt,
        } => {
            if every_minutes == 0 || every_minutes > 1_440 {
                return Err(anyhow!(
                    "--every-minutes must be between 1 and 1440 (got {every_minutes})"
                ));
            }
            let schedule = format!("FREQ=MINUTELY;INTERVAL={every_minutes}");
            Schedule::parse_rrule(&schedule)
                .with_context(|| format!("invalid generated schedule RRULE: {}", schedule))?;
            let task = service
                .create_task(&group, &name, &schedule, &prompt, "cli")
                .await?;
            println!(
                "created cron task '{}' ({}) with schedule {}",
                task.name, task.id, schedule
            );
        }
        TaskCommands::List { group, json } => {
            let tasks = service.list_tasks(&group).await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&tasks)?);
            } else if tasks.is_empty() {
                println!("no tasks found for group '{group}'");
            } else {
                let rows = tasks
                    .into_iter()
                    .map(|task| {
                        vec![
                            task.id,
                            truncate_line(&task.name, 24),
                            task.status.as_str().to_string(),
                            task.schedule_rrule,
                        ]
                    })
                    .collect::<Vec<_>>();
                print_table(&["ID", "NAME", "STATUS", "SCHEDULE"], &rows);
            }
        }
        TaskCommands::CronList { group, json } => {
            let tasks = service.list_tasks(&group).await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&tasks)?);
            } else if tasks.is_empty() {
                println!("no cron tasks found for group '{group}'");
            } else {
                let rows = tasks
                    .into_iter()
                    .map(|task| {
                        vec![
                            task.id,
                            truncate_line(&task.name, 24),
                            task.status.as_str().to_string(),
                            task.schedule_rrule,
                        ]
                    })
                    .collect::<Vec<_>>();
                print_table(&["ID", "NAME", "STATUS", "SCHEDULE"], &rows);
            }
        }
        TaskCommands::Pause { id } => {
            service.pause_task(&id, "cli").await?;
            println!("paused task {id}");
        }
        TaskCommands::Resume { id } => {
            service.resume_task(&id, "cli").await?;
            println!("resumed task {id}");
        }
        TaskCommands::RunNow { id } => {
            let result = service.run_task_now(&id, "cli").await?;
            println!(
                "task run {} status={}{}{}",
                result.run_id,
                result.status.as_str(),
                result
                    .output_summary
                    .as_ref()
                    .map(|s| format!("\noutput:\n{s}"))
                    .unwrap_or_default(),
                result
                    .error_text
                    .as_ref()
                    .map(|s| format!("\nerror:\n{s}"))
                    .unwrap_or_default(),
            );
        }
        TaskCommands::Delete { id } => {
            let deleted = service.delete_task(&id, "cli").await?;
            if deleted {
                println!("deleted task {id}");
            } else {
                println!("task not found: {id}");
            }
        }
        TaskCommands::CronRemove { id } => {
            let deleted = service.delete_task(&id, "cli").await?;
            if deleted {
                println!("deleted cron task {id}");
            } else {
                println!("cron task not found: {id}");
            }
        }
        TaskCommands::Clear { group } => {
            let deleted = service.clear_tasks_for_group(&group, "cli").await?;
            println!("cleared {deleted} task(s) in group '{group}'");
        }
        TaskCommands::ClearAll => {
            let deleted = service.clear_all_tasks("cli").await?;
            println!("cleared {deleted} task(s) across all groups");
        }
    }
    Ok(())
}

async fn run_task_wizard(
    service: Arc<AppService>,
    group: Option<String>,
    name: Option<String>,
    schedule: Option<String>,
    prompt: Option<String>,
) -> Result<()> {
    if !io::stdin().is_terminal() {
        return Err(anyhow!(
            "task wizard requires an interactive terminal (or use --group/--name/--schedule/--prompt)"
        ));
    }

    println!("task wizard");
    println!("You can enter RRULE directly or natural language like: every 15 minutes, every weekday at 9am");

    let group = group
        .unwrap_or(prompt_with_default("Group", "work")?)
        .trim()
        .to_string();
    let task_name = name
        .unwrap_or(prompt_with_default("Task name", "morning-brief")?)
        .trim()
        .to_string();
    let schedule_input = schedule
        .unwrap_or(prompt_with_default("Schedule", "every weekday at 9am")?)
        .trim()
        .to_string();
    let prompt_text = prompt
        .unwrap_or(prompt_with_default(
            "Prompt",
            "Give me a concise morning brief.",
        )?)
        .trim()
        .to_string();

    if group.is_empty()
        || task_name.is_empty()
        || schedule_input.is_empty()
        || prompt_text.is_empty()
    {
        return Err(anyhow!("all wizard values must be non-empty"));
    }

    let schedule_rrule = schedule_from_human_or_rrule(&schedule_input)
        .with_context(|| format!("invalid schedule: {}", schedule_input))?;
    Schedule::parse_rrule(&schedule_rrule)
        .with_context(|| format!("invalid schedule RRULE: {}", schedule_rrule))?;

    service.ensure_group(&group, "cli").await?;
    let task = service
        .create_task(&group, &task_name, &schedule_rrule, &prompt_text, "cli")
        .await?;

    println!("created task '{}' ({})", task.name, task.id);
    println!("group: {}", group);
    println!("schedule: {}", schedule_rrule);
    println!("prompt: {}", prompt_text);
    Ok(())
}

pub(crate) fn prompt_with_default(label: &str, default: &str) -> Result<String> {
    print!("{label} [{default}]: ");
    io::stdout().flush().context("failed to flush stdout")?;
    let mut raw = String::new();
    io::stdin()
        .read_line(&mut raw)
        .context("failed to read input")?;
    let value = raw.trim();
    if value.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(value.to_string())
    }
}

pub(crate) fn schedule_from_human_or_rrule(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("schedule must not be empty"));
    }
    if trimmed.to_ascii_uppercase().starts_with("FREQ=") {
        return Ok(trimmed.to_string());
    }

    let lower = trimmed.to_ascii_lowercase();
    if lower == "hourly" || lower == "every hour" {
        return Ok("FREQ=HOURLY;INTERVAL=1".to_string());
    }
    if let Some(minutes) = parse_interval_phrase(&lower, "minute") {
        return Ok(format!("FREQ=MINUTELY;INTERVAL={minutes}"));
    }
    if let Some(hours) = parse_interval_phrase(&lower, "hour") {
        return Ok(format!("FREQ=HOURLY;INTERVAL={hours}"));
    }
    if let Some(time) = lower.strip_prefix("every weekday at ") {
        let (hour, minute) = parse_time_of_day(time)?;
        return Ok(format!(
            "FREQ=WEEKLY;BYDAY=MO,TU,WE,TH,FR;BYHOUR={hour};BYMINUTE={minute}"
        ));
    }
    if let Some(time) = lower.strip_prefix("weekdays at ") {
        let (hour, minute) = parse_time_of_day(time)?;
        return Ok(format!(
            "FREQ=WEEKLY;BYDAY=MO,TU,WE,TH,FR;BYHOUR={hour};BYMINUTE={minute}"
        ));
    }
    if let Some(time) = lower.strip_prefix("every day at ") {
        let (hour, minute) = parse_time_of_day(time)?;
        return Ok(format!(
            "FREQ=WEEKLY;BYDAY=MO,TU,WE,TH,FR,SA,SU;BYHOUR={hour};BYMINUTE={minute}"
        ));
    }
    if let Some(time) = lower.strip_prefix("daily at ") {
        let (hour, minute) = parse_time_of_day(time)?;
        return Ok(format!(
            "FREQ=WEEKLY;BYDAY=MO,TU,WE,TH,FR,SA,SU;BYHOUR={hour};BYMINUTE={minute}"
        ));
    }

    Err(anyhow!(
        "unsupported schedule phrase. Use RRULE or phrases like 'every 15 minutes', 'every hour', 'every weekday at 9am'"
    ))
}

fn parse_interval_phrase(lower: &str, unit: &str) -> Option<u64> {
    let plural = format!("{unit}s");
    let patterns = [
        format!("every 1 {unit}"),
        format!("every 1 {plural}"),
        format!("every {unit}"),
        format!("every {plural}"),
    ];
    if patterns.iter().any(|pattern| lower == pattern) {
        return Some(1);
    }
    for suffix in [format!(" {unit}"), format!(" {plural}")] {
        if let Some(raw) = lower
            .strip_prefix("every ")
            .and_then(|rest| rest.strip_suffix(&suffix))
        {
            if let Ok(value) = raw.trim().parse::<u64>() {
                if value > 0 {
                    return Some(value);
                }
            }
        }
    }
    None
}

pub(crate) fn parse_time_of_day(raw: &str) -> Result<(u32, u32)> {
    let compact = raw.trim().to_ascii_lowercase().replace(' ', "");
    if compact.is_empty() {
        return Err(anyhow!("missing time of day"));
    }

    let (base, is_pm, has_meridiem) = if let Some(value) = compact.strip_suffix("am") {
        (value, false, true)
    } else if let Some(value) = compact.strip_suffix("pm") {
        (value, true, true)
    } else {
        (compact.as_str(), false, false)
    };

    let (hour_raw, minute_raw) = if let Some((h, m)) = base.split_once(':') {
        (h, m)
    } else {
        (base, "0")
    };

    let mut hour = hour_raw
        .parse::<u32>()
        .map_err(|_| anyhow!("invalid hour in time '{}'", raw))?;
    let minute = minute_raw
        .parse::<u32>()
        .map_err(|_| anyhow!("invalid minute in time '{}'", raw))?;
    if minute > 59 {
        return Err(anyhow!("minute must be between 0 and 59"));
    }

    if has_meridiem {
        if hour == 0 || hour > 12 {
            return Err(anyhow!("hour with am/pm must be between 1 and 12"));
        }
        if is_pm && hour < 12 {
            hour += 12;
        }
        if !is_pm && hour == 12 {
            hour = 0;
        }
    } else if hour > 23 {
        return Err(anyhow!("hour must be between 0 and 23"));
    }

    Ok((hour, minute))
}
