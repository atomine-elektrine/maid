use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use maid_core::{ModelProvider, ModelRunRequest, NewAudit, Storage};
use serde::Deserialize;
use serde_json::json;

use crate::cli::SubagentCommands;
use crate::{
    extract_json_object, run_prompt_with_auto_tools, truncate_line, AppConfig, AppService,
};

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct SubagentPlan {
    #[serde(default)]
    pub(crate) rationale: Option<String>,
    #[serde(default)]
    pub(crate) final_instruction: Option<String>,
    #[serde(default)]
    pub(crate) steps: Vec<SubagentStep>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct SubagentStep {
    pub(crate) name: String,
    pub(crate) prompt: String,
}

pub(crate) async fn handle_subagent_command(
    cfg: &AppConfig,
    service: Arc<AppService>,
    command: SubagentCommands,
) -> Result<()> {
    match command {
        SubagentCommands::Run {
            group,
            prompt,
            max_steps,
        } => {
            let bounded_steps = max_steps.clamp(1, 8);
            let plan =
                request_subagent_plan(service.clone(), &group, &prompt, bounded_steps).await?;
            let mut steps = plan.steps;
            if steps.is_empty() {
                steps.push(SubagentStep {
                    name: "direct".to_string(),
                    prompt: prompt.clone(),
                });
            }
            steps.truncate(bounded_steps);

            let mut step_outputs = Vec::new();
            for (idx, step) in steps.iter().enumerate() {
                let step_prompt = format!(
                    "Subagent executor step {}/{}: {}\n\nTask:\n{}\n\nOriginal user goal:\n{}",
                    idx + 1,
                    steps.len(),
                    step.name,
                    step.prompt,
                    prompt
                );
                let output = run_prompt_with_auto_tools(
                    cfg,
                    service.clone(),
                    &group,
                    &step_prompt,
                    "subagent-executor",
                )
                .await?;
                step_outputs.push(json!({
                    "step": idx + 1,
                    "name": step.name,
                    "output": truncate_line(&output, 1800),
                }));
            }

            let final_instruction = plan
                .final_instruction
                .unwrap_or_else(|| "Synthesize a final answer for the user goal.".to_string());
            let final_prompt = format!(
                "You are the finalizer in a planner/executor subagent pipeline.\n\
Original user goal:\n{}\n\n\
Planner rationale:\n{}\n\n\
Executor outputs (JSON):\n{}\n\n\
Instruction:\n{}\n\n\
Return the final user-facing answer only.",
                prompt,
                plan.rationale.unwrap_or_else(|| "none".to_string()),
                serde_json::to_string_pretty(&step_outputs)?,
                final_instruction
            );
            let final_output = run_prompt_with_auto_tools(
                cfg,
                service.clone(),
                &group,
                &final_prompt,
                "subagent-finalizer",
            )
            .await?;

            let _ = service
                .store
                .insert_audit(NewAudit {
                    group_id: None,
                    action: "SUBAGENT_RUN".to_string(),
                    actor: "cli".to_string(),
                    result: "SUCCESS".to_string(),
                    created_at: Utc::now(),
                    metadata_json: Some(json!({
                        "group": group,
                        "max_steps": bounded_steps,
                        "executed_steps": step_outputs.len(),
                    })),
                })
                .await;

            println!("{final_output}");
        }
    }
    Ok(())
}

async fn request_subagent_plan(
    service: Arc<AppService>,
    group_name: &str,
    prompt: &str,
    max_steps: usize,
) -> Result<SubagentPlan> {
    let planner_prompt = format!(
        "You are a planning subagent.\n\
Return ONLY JSON with schema:\n\
{{\"rationale\":\"short reason\",\"final_instruction\":\"string\",\"steps\":[{{\"name\":\"short\",\"prompt\":\"exact task\"}}]}}\n\
Rules:\n\
- At most {} steps.\n\
- Keep steps concrete and executable.\n\
- If no decomposition is needed, return one direct step.\n\
- No markdown, no extra text.\n\n\
Group: {}\n\
User goal:\n{}",
        max_steps, group_name, prompt
    );

    let output = service
        .model
        .run(ModelRunRequest {
            group_name: group_name.to_string(),
            prompt: planner_prompt,
            history: Vec::new(),
        })
        .await?
        .output_text;

    parse_subagent_plan(&output)
}

pub(crate) fn parse_subagent_plan(raw: &str) -> Result<SubagentPlan> {
    let parsed = serde_json::from_str::<serde_json::Value>(raw.trim()).or_else(|_| {
        let extracted = extract_json_object(raw)
            .ok_or_else(|| anyhow!("subagent planner did not return valid JSON"))?;
        serde_json::from_str::<serde_json::Value>(&extracted)
            .context("failed to parse subagent planner JSON")
    })?;
    normalize_subagent_plan(parsed)
}

fn normalize_subagent_plan(value: serde_json::Value) -> Result<SubagentPlan> {
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("subagent planner payload must be a JSON object"))?;
    let rationale = object
        .get("rationale")
        .and_then(|v| v.as_str())
        .map(|v| v.to_string());
    let final_instruction = object
        .get("final_instruction")
        .and_then(|v| v.as_str())
        .map(|v| v.to_string());

    let mut steps: Vec<SubagentStep> = Vec::new();
    if let Some(items) = object.get("steps").and_then(|v| v.as_array()) {
        for item in items {
            let Some(step_obj) = item.as_object() else {
                continue;
            };
            let Some(name) = step_obj.get("name").and_then(|v| v.as_str()) else {
                continue;
            };
            let Some(prompt) = step_obj.get("prompt").and_then(|v| v.as_str()) else {
                continue;
            };
            if name.trim().is_empty() || prompt.trim().is_empty() {
                continue;
            }
            steps.push(SubagentStep {
                name: name.to_string(),
                prompt: prompt.to_string(),
            });
        }
    }

    Ok(SubagentPlan {
        rationale,
        final_instruction,
        steps,
    })
}
