// apps/autopilot/src-tauri/src/project/runtime.rs

use super::repository_pr_lane::{
    workflow_branch_policy_output, workflow_github_context_output,
    workflow_github_pr_create_output, workflow_issue_context_output, workflow_pr_attempt_output,
    workflow_repository_context_output, workflow_review_gate_output,
};
use super::*;
use ioi_types::app::{
    compare_harness_live_shadow_attempts, default_harness_gated_cluster_run_for_shadow_run,
    default_harness_shadow_run_for_attempts, harness_gated_cluster_run_camel_value,
    harness_node_attempt_record_from_camel_value, harness_shadow_comparison_camel_value,
    HarnessExecutionMode, HarnessNodeAttemptRecord, HarnessPromotionClusterId,
    HarnessShadowComparison, DEFAULT_AGENT_HARNESS_ACTIVATION_ID, DEFAULT_AGENT_HARNESS_HASH,
    DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
};
use sha2::{Digest, Sha256};

pub(super) fn workflow_value_string(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_string)
}

fn workflow_value_string_any(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str))
        .map(str::to_string)
}

fn workflow_value_bool_any(value: &Value, keys: &[&str]) -> Option<bool> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_bool))
}

fn workflow_value_u64_any(value: &Value, keys: &[&str]) -> Option<u64> {
    keys.iter().find_map(|key| {
        value.get(*key).and_then(Value::as_u64).or_else(|| {
            value
                .get(*key)
                .and_then(Value::as_i64)
                .and_then(|item| (item >= 0).then_some(item as u64))
        })
    })
}

fn workflow_string_array_any(value: &Value, keys: &[&str]) -> Vec<String> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_array))
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_string)
        .collect()
}

fn workflow_clip_text(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    value.chars().take(max_chars).collect()
}

fn workflow_sha256_hex(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    format!("sha256:{:x}", hasher.finalize())
}

fn workflow_project_root_for_path(workflow_path: &Path) -> String {
    workflow_path
        .parent()
        .and_then(|workflows_dir| workflows_dir.parent())
        .and_then(|agents_dir| {
            (agents_dir.file_name().and_then(|name| name.to_str()) == Some(".agents"))
                .then(|| agents_dir.parent())
                .flatten()
        })
        .or_else(|| workflow_path.parent())
        .unwrap_or_else(|| Path::new("."))
        .display()
        .to_string()
}

fn workflow_logic_string(logic: &Value, key: &str) -> Option<String> {
    logic
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn workflow_deep_string_field(value: &Value, key: &str) -> Option<String> {
    if let Some(text) = value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|item| !item.is_empty())
    {
        return Some(text.to_string());
    }
    match value {
        Value::Array(items) => items
            .iter()
            .find_map(|item| workflow_deep_string_field(item, key)),
        Value::Object(object) => object
            .values()
            .find_map(|item| workflow_deep_string_field(item, key)),
        _ => None,
    }
}

fn workflow_resolved_path_string(
    logic: &Value,
    input: &Value,
    key: &str,
    workflow_path: &Path,
) -> Option<String> {
    let configured = workflow_logic_string(logic, key);
    match configured.as_deref() {
        Some("{{workflow.path}}") => Some(workflow_path.display().to_string()),
        Some("{{project.root}}") => Some(workflow_project_root_for_path(workflow_path)),
        Some("{{workflowPackageExport.packagePath}}") => {
            workflow_value_at_path(input, "workflowPackageExport.packagePath")
                .and_then(|value| value.as_str().map(str::to_string))
                .or_else(|| workflow_deep_string_field(input, "packagePath"))
        }
        Some(value) if value.starts_with("{{") && value.ends_with("}}") => None,
        Some(value) => Some(value.to_string()),
        None => None,
    }
}

fn workflow_memory_send_options(logic: &Value, node_id: &str) -> Value {
    let injection_enabled =
        workflow_value_bool_any(logic, &["memoryInjectionEnabled", "injectionEnabled"])
            .unwrap_or(true);
    let disabled = workflow_value_bool_any(logic, &["memoryDisabled", "disabled"])
        .unwrap_or(!injection_enabled);
    json!({
        "memoryKey": workflow_value_string_any(logic, &["memoryKey", "memory_key"]),
        "scope": workflow_value_string_any(logic, &["memoryScope", "scope"]).unwrap_or_else(|| "thread".to_string()),
        "injectionEnabled": injection_enabled,
        "disabled": disabled,
        "readOnly": workflow_value_bool_any(logic, &["memoryReadOnly", "readOnly"]).unwrap_or(false),
        "writeRequiresApproval": workflow_value_bool_any(
            logic,
            &["memoryWriteRequiresApproval", "writeRequiresApproval"],
        )
        .unwrap_or(false),
        "writeApproved": workflow_value_bool_any(logic, &["memoryWriteApproved", "writeApproved"]).unwrap_or(false),
        "subagentInheritance": workflow_value_string_any(
            logic,
            &["memorySubagentInheritance", "subagentInheritance"],
        )
        .unwrap_or_else(|| "explicit".to_string()),
        "retention": workflow_value_string_any(logic, &["memoryRetention", "retention"]),
        "redaction": workflow_value_string_any(logic, &["memoryRedaction", "redaction"])
            .unwrap_or_else(|| "none".to_string()),
        "workflowNodeId": node_id,
    })
}

fn workflow_memory_query_output(
    logic: &Value,
    input: &Value,
    node_id: &str,
    evidence_kind: &str,
) -> Value {
    let operation = workflow_value_string_any(logic, &["stateOperation", "memoryOperation"])
        .unwrap_or_else(|| "memory_search".to_string());
    let state_key = workflow_value_string_any(logic, &["stateKey", "memoryKey"])
        .unwrap_or_else(|| "memory".to_string());
    let memory_key = workflow_value_string_any(logic, &["memoryKey", "stateKey"]);
    let scope = workflow_value_string_any(logic, &["memoryScope", "scope"]);
    let query = workflow_value_string_any(logic, &["query", "memoryQuery"]);
    let limit = workflow_value_u64_any(logic, &["limit", "memoryLimit"])
        .map(|value| value.clamp(1, 200) as usize);
    let redaction = workflow_value_string_any(logic, &["memoryRedaction", "redaction"])
        .unwrap_or_else(|| "none".to_string());
    let mut records = Vec::new();
    workflow_collect_memory_records(input, &mut records);
    if let Some(initial_value) = logic.get("initialValue") {
        workflow_collect_memory_records(initial_value, &mut records);
    }
    let query_lower = query.as_ref().map(|value| value.to_lowercase());
    let mut filtered = records
        .into_iter()
        .filter(|record| {
            scope
                .as_ref()
                .map(|expected| {
                    record
                        .get("scope")
                        .and_then(Value::as_str)
                        .map(|actual| actual == expected)
                        .unwrap_or(false)
                })
                .unwrap_or(true)
        })
        .filter(|record| {
            memory_key
                .as_ref()
                .map(|expected| {
                    record
                        .get("memoryKey")
                        .or_else(|| record.get("stateKey"))
                        .and_then(Value::as_str)
                        .map(|actual| actual == expected)
                        .unwrap_or(false)
                })
                .unwrap_or(true)
        })
        .filter(|record| {
            if operation == "memory_list" {
                return true;
            }
            query_lower
                .as_ref()
                .map(|expected| workflow_memory_record_search_text(record).contains(expected))
                .unwrap_or(true)
        })
        .collect::<Vec<_>>();
    if let Some(limit) = limit {
        filtered.truncate(limit);
    }
    if redaction == "redacted" {
        filtered = filtered
            .into_iter()
            .map(|record| workflow_redacted_memory_record(&record))
            .collect();
    }
    let value_records = filtered.clone();
    json!({
        "nodeId": node_id,
        "kind": evidence_kind,
        "stateKey": state_key,
        "operation": operation,
        "reducer": "replace",
        "memoryQuery": {
            "scope": scope,
            "memoryKey": memory_key,
            "query": query,
            "limit": limit,
            "redaction": redaction,
            "matchCount": filtered.len()
        },
        "records": filtered,
        "value": {
            "records": value_records
        }
    })
}

fn workflow_collect_memory_records(value: &Value, records: &mut Vec<Value>) {
    match value {
        Value::Array(items) => {
            for item in items {
                workflow_collect_memory_records(item, records);
            }
        }
        Value::Object(object) => {
            if object
                .get("fact")
                .or_else(|| object.get("text"))
                .and_then(Value::as_str)
                .is_some()
            {
                records.push(Value::Object(object.clone()));
            }
            for key in ["records", "memoryRecords", "memories"] {
                if let Some(items) = object.get(key).and_then(Value::as_array) {
                    for item in items {
                        workflow_collect_memory_records(item, records);
                    }
                }
            }
            if let Some(payload) = object.get("payload") {
                workflow_collect_memory_records(payload, records);
            }
            if let Some(value) = object.get("value") {
                workflow_collect_memory_records(value, records);
            }
        }
        _ => {}
    }
}

fn workflow_memory_record_search_text(record: &Value) -> String {
    [
        "fact",
        "text",
        "id",
        "scope",
        "memoryKey",
        "workflowNodeId",
        "source",
    ]
    .iter()
    .filter_map(|key| record.get(*key).and_then(Value::as_str))
    .map(str::to_lowercase)
    .collect::<Vec<_>>()
    .join("\n")
}

fn workflow_redacted_memory_record(record: &Value) -> Value {
    let mut redacted = record.as_object().cloned().unwrap_or_default();
    if let Some(fact) = record
        .get("fact")
        .or_else(|| record.get("text"))
        .and_then(Value::as_str)
    {
        redacted.insert("factHash".to_string(), json!(workflow_sha256_hex(fact)));
    }
    redacted.insert("fact".to_string(), json!("[REDACTED]"));
    redacted.insert("redaction".to_string(), json!("redacted"));
    Value::Object(redacted)
}

fn workflow_skill_tokens(value: &str) -> std::collections::BTreeSet<String> {
    value
        .to_lowercase()
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|token| token.len() > 2)
        .map(str::to_string)
        .collect()
}

#[derive(Debug, Clone, Default)]
pub(super) struct WorkflowSkillResolver {
    catalog: Vec<WorkflowSkillCandidate>,
}

#[derive(Debug, Clone)]
struct WorkflowSkillCandidate {
    skill_hash: String,
    name: String,
    description: String,
    lifecycle_state: String,
    source_type: String,
    success_rate_bps: u64,
    sample_size: u64,
    relative_path: Option<String>,
    stale: bool,
    markdown: String,
    phase_tags: Vec<String>,
    route_tags: Vec<String>,
    promotion_evidence_refs: Vec<String>,
}

#[derive(Debug, Clone)]
struct WorkflowResolvedSkill {
    candidate: WorkflowSkillCandidate,
    score: u64,
}

impl WorkflowSkillResolver {
    pub(super) fn from_options(options: Option<&Value>) -> Self {
        let catalog = options
            .and_then(|value| {
                value
                    .get("skillCatalog")
                    .or_else(|| value.get("workflowSkillCatalog"))
                    .and_then(Value::as_array)
            })
            .map(|items| {
                items
                    .iter()
                    .filter_map(WorkflowSkillCandidate::from_value)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        Self { catalog }
    }

    fn eligible_for_discovery(skill: &WorkflowSkillCandidate, allow_draft: bool) -> bool {
        let lifecycle = skill.lifecycle_state.to_lowercase();
        !skill.stale
            && (lifecycle.contains("validated")
                || lifecycle.contains("promoted")
                || (allow_draft && lifecycle.contains("draft")))
    }

    fn score_skill(goal: &str, skill: &WorkflowSkillCandidate) -> u64 {
        let goal_normalized = goal.to_lowercase();
        let name_normalized = skill.name.to_lowercase();
        let goal_tokens = workflow_skill_tokens(goal);
        if goal_tokens.is_empty() {
            return 0;
        }
        let name_tokens = workflow_skill_tokens(&skill.name);
        let description_tokens = workflow_skill_tokens(&skill.description);
        let markdown_tokens = workflow_skill_tokens(&skill.markdown);
        let mut score = 0u64;
        if !name_normalized.is_empty() && goal_normalized.contains(&name_normalized) {
            score += 4500;
        } else if !name_normalized.is_empty() && name_normalized.contains(&goal_normalized) {
            score += 3500;
        }
        for token in &goal_tokens {
            if name_tokens.contains(token) {
                score += 2500;
            } else if description_tokens.contains(token) {
                score += 1500;
            } else if markdown_tokens.contains(token) {
                score += 700;
            }
        }
        let lifecycle = skill.lifecycle_state.to_lowercase();
        if lifecycle.contains("promoted") {
            score += 600;
        } else if lifecycle.contains("validated") {
            score += 350;
        } else if lifecycle.contains("draft") {
            score += 1800;
        }
        score += skill.success_rate_bps.min(10_000) * 1500 / 10_000;
        score += skill.sample_size.min(100) * 200 / 100;
        score.min(10_000)
    }

    fn discover(
        &self,
        goal: &str,
        min_score_bps: u64,
        max_skills: usize,
        allow_draft: bool,
    ) -> Vec<WorkflowResolvedSkill> {
        let mut matches = self
            .catalog
            .iter()
            .filter(|skill| Self::eligible_for_discovery(skill, allow_draft))
            .filter_map(|skill| {
                let score = Self::score_skill(goal, skill);
                (score >= min_score_bps).then(|| WorkflowResolvedSkill {
                    candidate: skill.clone(),
                    score,
                })
            })
            .collect::<Vec<_>>();
        matches.sort_by(|left, right| {
            right
                .score
                .cmp(&left.score)
                .then_with(|| left.candidate.name.cmp(&right.candidate.name))
        });
        matches.truncate(max_skills.max(1));
        matches
    }

    fn pinned(&self, config: &Value) -> Result<Vec<WorkflowResolvedSkill>, String> {
        let on_missing = config
            .get("onMissingPinned")
            .and_then(Value::as_str)
            .unwrap_or("block");
        let pins = config
            .get("pinnedSkills")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if pins.is_empty() && on_missing == "block" {
            return Err(
                "Skill Context pinned mode requires at least one pinned skill.".to_string(),
            );
        }
        let mut selected = Vec::new();
        let mut blockers = Vec::new();
        for pin in pins {
            let required = pin.get("required").and_then(Value::as_bool).unwrap_or(true);
            let hash = workflow_value_string_any(&pin, &["skillHash", "skill_hash"])
                .filter(|value| !value.trim().is_empty());
            let name = pin
                .get("name")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string);
            if let Some(hash) = hash {
                if let Some(skill) = self.catalog.iter().find(|skill| skill.skill_hash == hash) {
                    selected.push(WorkflowResolvedSkill {
                        candidate: skill.clone(),
                        score: 10_000,
                    });
                    continue;
                }
                if required || on_missing == "block" {
                    blockers.push(format!("Pinned skill hash '{}' was not found.", hash));
                }
                continue;
            }
            if let Some(name) = name {
                let matches = self
                    .catalog
                    .iter()
                    .filter(|skill| skill.name.eq_ignore_ascii_case(&name))
                    .collect::<Vec<_>>();
                if matches.len() == 1 {
                    selected.push(WorkflowResolvedSkill {
                        candidate: matches[0].clone(),
                        score: 10_000,
                    });
                } else if matches.len() > 1 {
                    blockers.push(format!(
                        "Pinned skill name '{}' matched {} skills.",
                        name,
                        matches.len()
                    ));
                } else if required || on_missing == "block" {
                    blockers.push(format!("Pinned skill name '{}' was not found.", name));
                }
            }
        }
        if !blockers.is_empty() {
            return Err(blockers.join(" "));
        }
        Ok(selected)
    }

    pub(super) fn resolve_skill_context(
        &self,
        workflow: Option<&WorkflowProject>,
        node_id: &str,
        logic: &Value,
        input: &Value,
    ) -> Result<Value, String> {
        let config = logic.get("skillContext").unwrap_or(logic);
        let mode = config
            .get("mode")
            .and_then(Value::as_str)
            .unwrap_or("discover");
        let include_markdown = config
            .get("includeMarkdown")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        let guidance_max_chars = config
            .get("guidanceMaxChars")
            .and_then(Value::as_u64)
            .unwrap_or(1800)
            .clamp(200, 12_000) as usize;
        let goal = workflow_skill_context_goal(workflow, config, input);
        let selected = if mode == "pinned" {
            self.pinned(config)?
        } else {
            let min_score_bps = config
                .get("minScoreBps")
                .and_then(Value::as_u64)
                .unwrap_or(6500)
                .min(10_000);
            let max_skills = config
                .get("maxSkills")
                .and_then(Value::as_u64)
                .unwrap_or(3)
                .clamp(1, 10) as usize;
            let allow_draft = config
                .get("allowDraftForBenchmark")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            self.discover(&goal, min_score_bps, max_skills, allow_draft)
        };
        if selected.is_empty() {
            let status = if mode == "pinned" {
                "blocked"
            } else {
                match config
                    .get("onNoMatch")
                    .and_then(Value::as_str)
                    .unwrap_or("warn")
                {
                    "block" => "blocked",
                    _ => "unavailable",
                }
            };
            if status == "blocked" {
                return Err(format!(
                    "Skill Context node '{}' could not resolve any runtime skills.",
                    node_id
                ));
            }
            return Ok(json!({
                "nodeId": node_id,
                "kind": "skill_context",
                "schemaVersion": "workflow.skill-context.v1",
                "status": "unavailable",
                "mode": mode,
                "goal": goal,
                "selectedSkills": [],
                "promptContext": "",
                "evidenceRefs": [format!("workflow.skill_context.discovery.v1:{}", node_id)]
            }));
        }
        let mut evidence_refs = Vec::new();
        if mode == "pinned" {
            evidence_refs.push(format!("workflow.skill_context.pinned.v1:{}", node_id));
        } else {
            evidence_refs.push(format!("workflow.skill_context.discovery.v1:{}", node_id));
        }
        let selected_values = selected
            .iter()
            .map(|resolved| {
                let skill = &resolved.candidate;
                evidence_refs.push(format!("workflow.skill_context.read.v1:{}", skill.skill_hash));
                let clipped_guidance = workflow_clip_text(&skill.markdown, guidance_max_chars);
                let guidance_hash = workflow_sha256_hex(&skill.markdown);
                json!({
                    "hash": skill.skill_hash,
                    "skillHash": skill.skill_hash,
                    "name": skill.name,
                    "description": skill.description,
                    "lifecycleState": skill.lifecycle_state,
                    "sourceType": skill.source_type,
                    "sampleSize": skill.sample_size,
                    "stale": skill.stale,
                    "relativePath": skill.relative_path,
                    "phaseTags": skill.phase_tags,
                    "routeTags": skill.route_tags,
                    "promotionEvidenceRefs": skill.promotion_evidence_refs,
                    "score": resolved.score,
                    "guidanceHash": guidance_hash,
                    "guidanceMarkdown": if include_markdown { clipped_guidance } else { String::new() }
                })
            })
            .collect::<Vec<_>>();
        evidence_refs.sort();
        evidence_refs.dedup();
        let prompt_context = selected
            .iter()
            .map(|resolved| {
                let skill = &resolved.candidate;
                let guidance = if include_markdown {
                    workflow_clip_text(&skill.markdown, guidance_max_chars)
                } else {
                    skill.description.clone()
                };
                format!("# Skill: {}\n{}", skill.name, guidance)
            })
            .collect::<Vec<_>>()
            .join("\n\n");
        Ok(json!({
            "nodeId": node_id,
            "kind": "skill_context",
            "schemaVersion": "workflow.skill-context.v1",
            "status": "attached",
            "mode": mode,
            "goal": goal,
            "selectedSkills": selected_values,
            "promptContext": prompt_context,
            "evidenceRefs": evidence_refs
        }))
    }
}

impl WorkflowSkillCandidate {
    fn from_value(value: &Value) -> Option<Self> {
        let skill_hash = workflow_value_string_any(value, &["skillHash", "skill_hash"])?;
        Some(Self {
            skill_hash,
            name: workflow_value_string_any(value, &["name"])?,
            description: workflow_value_string_any(value, &["description"]).unwrap_or_default(),
            lifecycle_state: workflow_value_string_any(
                value,
                &["lifecycleState", "lifecycle_state"],
            )
            .unwrap_or_else(|| "unknown".to_string()),
            source_type: workflow_value_string_any(value, &["sourceType", "source_type"])
                .unwrap_or_else(|| "runtime".to_string()),
            success_rate_bps: workflow_value_u64_any(
                value,
                &["successRateBps", "success_rate_bps"],
            )
            .unwrap_or(0),
            sample_size: workflow_value_u64_any(value, &["sampleSize", "sample_size"]).unwrap_or(0),
            relative_path: workflow_value_string_any(value, &["relativePath", "relative_path"]),
            stale: workflow_value_bool_any(value, &["stale"]).unwrap_or(false),
            markdown: workflow_value_string_any(
                value,
                &["markdown", "guidanceMarkdown", "guidance_markdown"],
            )
            .unwrap_or_else(|| {
                workflow_value_string_any(value, &["description"]).unwrap_or_default()
            }),
            phase_tags: workflow_string_array_any(value, &["phaseTags", "phase_tags"]),
            route_tags: workflow_string_array_any(value, &["routeTags", "route_tags"]),
            promotion_evidence_refs: workflow_string_array_any(
                value,
                &["promotionEvidenceRefs", "promotion_evidence_refs"],
            ),
        })
    }
}

fn workflow_coding_route_config(workflow: &WorkflowProject) -> Option<&Value> {
    workflow.global_config.get("codingRoute")
}

fn workflow_coding_route_id(workflow: &WorkflowProject) -> String {
    workflow_coding_route_config(workflow)
        .and_then(|route| route.get("routeId"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| workflow_classify_coding_route(workflow))
}

fn workflow_classify_coding_route(workflow: &WorkflowProject) -> String {
    let mut text = format!(
        "{} {} {}",
        workflow.metadata.name,
        workflow.metadata.workflow_kind,
        workflow
            .global_config
            .get("meta")
            .and_then(|meta| meta.get("description"))
            .and_then(Value::as_str)
            .unwrap_or_default()
    )
    .to_lowercase();
    for node in &workflow.nodes {
        text.push(' ');
        text.push_str(&workflow_node_name(node).to_lowercase());
        text.push(' ');
        text.push_str(&workflow_node_type(node).to_lowercase());
    }
    if [
        "review", "audit", "security", "quality", "inspect", "critique",
    ]
    .iter()
    .any(|needle| text.contains(needle))
    {
        "coding.template.review".to_string()
    } else if [
        "debug",
        "bug",
        "failing",
        "failure",
        "broken",
        "error",
        "regression",
        "repro",
    ]
    .iter()
    .any(|needle| text.contains(needle))
    {
        "coding.template.debug".to_string()
    } else {
        "coding.template.build".to_string()
    }
}

fn workflow_default_route_phases(route_id: &str) -> Vec<String> {
    match route_id {
        "coding.template.debug" => vec![
            "coding.intake",
            "coding.context",
            "coding.define",
            "coding.verify",
            "coding.review",
            "coding.closeout",
        ],
        "coding.template.review" => vec![
            "coding.intake",
            "coding.context",
            "coding.review",
            "coding.verify",
            "coding.closeout",
        ],
        _ => vec![
            "coding.intake",
            "coding.context",
            "coding.plan",
            "coding.build",
            "coding.verify",
            "coding.closeout",
        ],
    }
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn workflow_coding_route_phases(workflow: &WorkflowProject, route_id: &str) -> Vec<String> {
    workflow_coding_route_config(workflow)
        .and_then(|route| route.get("phases"))
        .and_then(Value::as_array)
        .map(|phases| {
            phases
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .filter(|phases| !phases.is_empty())
        .unwrap_or_else(|| workflow_default_route_phases(route_id))
}

fn workflow_coding_route_selected_skill_hashes(
    selections: &[WorkflowCodingRouteSkillSelection],
) -> Vec<String> {
    let mut hashes = selections
        .iter()
        .map(|selection| selection.skill_hash.clone())
        .collect::<Vec<_>>();
    hashes.sort();
    hashes.dedup();
    hashes
}

fn workflow_phase_component_kind(phase_id: &str) -> String {
    match phase_id {
        "coding.intake" | "coding.context" => "context".to_string(),
        "coding.define" | "coding.plan" => "planner".to_string(),
        "coding.build" => "builder".to_string(),
        "coding.verify" => "verifier".to_string(),
        "coding.review" => "reviewer".to_string(),
        "coding.ship" | "coding.closeout" => "merge_verdict".to_string(),
        _ => "context".to_string(),
    }
}

fn workflow_route_phase_for_skill(route_id: &str, skill_name: &str) -> String {
    let name = skill_name.to_ascii_lowercase();
    if name.contains("review") || name.contains("security") {
        "coding.review".to_string()
    } else if name.contains("debug") || name.contains("error") || name.contains("recovery") {
        match route_id {
            "coding.template.debug" => "coding.define".to_string(),
            _ => "coding.verify".to_string(),
        }
    } else if name.contains("test") || name.contains("verification") {
        "coding.verify".to_string()
    } else if name.contains("source") || name.contains("context") {
        "coding.context".to_string()
    } else if name.contains("plan") || name.contains("spec") {
        "coding.plan".to_string()
    } else {
        match route_id {
            "coding.template.review" => "coding.review".to_string(),
            "coding.template.debug" => "coding.define".to_string(),
            _ => "coding.build".to_string(),
        }
    }
}

fn workflow_route_tags_for_skill(skill_name: &str) -> Vec<String> {
    let name = skill_name.to_ascii_lowercase();
    let mut tags = Vec::new();
    if name.contains("debug") || name.contains("error") || name.contains("recovery") {
        tags.push("coding.template.debug".to_string());
    }
    if name.contains("review") || name.contains("security") {
        tags.push("coding.template.review".to_string());
    }
    if name.contains("implementation")
        || name.contains("test")
        || name.contains("source")
        || name.contains("context")
    {
        tags.push("coding.template.build".to_string());
    }
    if tags.is_empty() {
        tags.extend(
            [
                "coding.template.build",
                "coding.template.debug",
                "coding.template.review",
            ]
            .into_iter()
            .map(str::to_string),
        );
    }
    tags.sort();
    tags.dedup();
    tags
}

fn workflow_phase_tags_for_skill(skill_name: &str) -> Vec<String> {
    let name = skill_name.to_ascii_lowercase();
    let mut tags = Vec::new();
    if name.contains("source") || name.contains("context") {
        tags.push("coding.context".to_string());
    }
    if name.contains("plan") || name.contains("spec") {
        tags.push("coding.plan".to_string());
    }
    if name.contains("implementation") || name.contains("build") {
        tags.push("coding.build".to_string());
    }
    if name.contains("test") || name.contains("verify") || name.contains("debug") {
        tags.push("coding.verify".to_string());
    }
    if name.contains("review") || name.contains("security") {
        tags.push("coding.review".to_string());
    }
    if tags.is_empty() {
        tags.push("coding.context".to_string());
    }
    tags.sort();
    tags.dedup();
    tags
}

fn workflow_coding_route_skill_selections(
    route_id: &str,
    node_runs: &[WorkflowNodeRun],
) -> Vec<WorkflowCodingRouteSkillSelection> {
    let mut selections = node_runs
        .iter()
        .filter(|run| run.node_type == "skill_context")
        .filter_map(|run| run.output.as_ref())
        .flat_map(|output| {
            output
                .get("selectedSkills")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
        })
        .filter_map(|item| {
            let skill_hash = item
                .get("skillHash")
                .or_else(|| item.get("hash"))
                .and_then(Value::as_str)?
                .to_string();
            let name = workflow_value_string_any(&item, &["name"]).unwrap_or_else(|| {
                skill_hash
                    .split(':')
                    .next_back()
                    .unwrap_or(skill_hash.as_str())
                    .to_string()
            });
            let phase_tags = workflow_string_array_any(&item, &["phaseTags", "phase_tags"]);
            let route_tags = workflow_string_array_any(&item, &["routeTags", "route_tags"]);
            let phase_id = phase_tags
                .first()
                .cloned()
                .unwrap_or_else(|| workflow_route_phase_for_skill(route_id, &name));
            let evidence_refs = workflow_string_array_any(
                &item,
                &["promotionEvidenceRefs", "promotion_evidence_refs"],
            );
            Some(WorkflowCodingRouteSkillSelection {
                skill_hash,
                name: name.clone(),
                lifecycle_state: workflow_value_string_any(
                    &item,
                    &["lifecycleState", "lifecycle_state"],
                )
                .unwrap_or_else(|| "Unknown".to_string()),
                phase_id,
                route_id: route_id.to_string(),
                score: workflow_value_u64_any(&item, &["score"]).unwrap_or(0),
                source_type: workflow_value_string_any(&item, &["sourceType", "source_type"])
                    .unwrap_or_else(|| "runtime".to_string()),
                stale: workflow_value_bool_any(&item, &["stale"]).unwrap_or(false),
                phase_tags: if phase_tags.is_empty() {
                    workflow_phase_tags_for_skill(&name)
                } else {
                    phase_tags
                },
                route_tags: if route_tags.is_empty() {
                    workflow_route_tags_for_skill(&name)
                } else {
                    route_tags
                },
                evidence_refs,
            })
        })
        .collect::<Vec<_>>();
    selections.sort_by(|left, right| {
        left.skill_hash
            .cmp(&right.skill_hash)
            .then_with(|| left.name.cmp(&right.name))
    });
    selections.dedup_by(|left, right| left.skill_hash == right.skill_hash);
    selections
}

fn workflow_route_gate_result(
    node_runs: &[WorkflowNodeRun],
    phase_id: &str,
    gate_id: &str,
) -> WorkflowCodingRouteGateResult {
    let any_node_failed = node_runs
        .iter()
        .any(|run| !matches!(run.status.as_str(), "success"));
    let (status, reason, blocking_requirements) = if node_runs.is_empty() {
        (
            "warn",
            "Route gate did not receive node execution evidence.",
            vec!["node execution evidence".to_string()],
        )
    } else if any_node_failed {
        (
            "block",
            "Route gate blocked because at least one node did not pass.",
            vec!["all route nodes must pass".to_string()],
        )
    } else {
        (
            "pass",
            "Route gate passed with node execution evidence.",
            Vec::new(),
        )
    };
    WorkflowCodingRouteGateResult {
        gate_id: gate_id.to_string(),
        phase_id: phase_id.to_string(),
        status: status.to_string(),
        reason: reason.to_string(),
        evidence_refs: vec!["coding.route.gate.v1:workflow-run".to_string()],
        blocking_requirements,
        operator_override_allowed: status == "warn",
        override_evidence_refs: Vec::new(),
    }
}

fn workflow_transition_for_skill(
    selection: &WorkflowCodingRouteSkillSelection,
    gate: &WorkflowCodingRouteGateResult,
) -> (String, String, String, u64, u64) {
    let lifecycle = selection.lifecycle_state.to_ascii_lowercase();
    let before = selection.score.min(10_000);
    if selection.stale {
        return (
            "mark_stale".to_string(),
            selection.lifecycle_state.clone(),
            "Skill remains excluded because its registry metadata is stale.".to_string(),
            before,
            before.min(5000),
        );
    }
    if gate.status == "block" {
        return (
            "demote".to_string(),
            "Demoted".to_string(),
            "Skill confidence decreased because the route gate blocked.".to_string(),
            before,
            before.saturating_sub(1500),
        );
    }
    if lifecycle.contains("draft") && gate.status == "pass" {
        return (
            "promote".to_string(),
            "Promoted".to_string(),
            "Draft skill promoted by retained benchmark and route gate evidence.".to_string(),
            before,
            before.max(8200),
        );
    }
    if lifecycle.contains("promoted") && gate.status == "pass" {
        return (
            "retain_promoted".to_string(),
            selection.lifecycle_state.clone(),
            "Promoted skill retained after successful route evidence.".to_string(),
            before,
            before.max(8500).min(10_000),
        );
    }
    (
        "no_change".to_string(),
        selection.lifecycle_state.clone(),
        "Skill recorded benchmark evidence without lifecycle transition.".to_string(),
        before,
        before.max(6500),
    )
}

fn workflow_coding_route_benchmark_results(
    route_id: &str,
    selections: &[WorkflowCodingRouteSkillSelection],
    gate: &WorkflowCodingRouteGateResult,
    created_at_ms: u64,
) -> Vec<WorkflowCodingRouteBenchmarkResult> {
    selections
        .iter()
        .map(|selection| {
            let (decision, _, _, before, after) = workflow_transition_for_skill(selection, gate);
            let evidence_refs = vec![
                format!(
                    "coding.route.benchmark.v1:{}:{}",
                    route_id, selection.skill_hash
                ),
                format!("coding.route.gate.v1:{}", gate.gate_id),
            ];
            WorkflowCodingRouteBenchmarkResult {
                benchmark_id: format!("route-benchmark-{}-{}", route_id, selection.skill_hash),
                route_id: route_id.to_string(),
                phase_id: selection.phase_id.clone(),
                selected_skill_hash: selection.skill_hash.clone(),
                skill_lifecycle_state: selection.lifecycle_state.clone(),
                input_descriptor: format!("{} route benchmark for {}", route_id, selection.name),
                status: gate.status.clone(),
                gate_status: gate.status.clone(),
                verifier_result: Some(if gate.status == "pass" {
                    "retained verification passed".to_string()
                } else {
                    gate.reason.clone()
                }),
                confidence_before_bps: before,
                confidence_after_bps: after,
                promotion_decision: decision,
                evidence_refs,
                created_at_ms,
            }
        })
        .collect()
}

fn workflow_coding_route_promotion_decisions(
    route_id: &str,
    selections: &[WorkflowCodingRouteSkillSelection],
    gate: &WorkflowCodingRouteGateResult,
    benchmark_results: &[WorkflowCodingRouteBenchmarkResult],
    created_at_ms: u64,
) -> Vec<WorkflowCodingRoutePromotionDecision> {
    selections
        .iter()
        .map(|selection| {
            let (decision, to_lifecycle, reason, before, after) =
                workflow_transition_for_skill(selection, gate);
            let mut evidence_refs = benchmark_results
                .iter()
                .find(|result| result.selected_skill_hash == selection.skill_hash)
                .map(|result| result.evidence_refs.clone())
                .unwrap_or_default();
            evidence_refs.push(format!(
                "coding.route.promotion.v1:{}:{}",
                route_id, selection.skill_hash
            ));
            evidence_refs.sort();
            evidence_refs.dedup();
            WorkflowCodingRoutePromotionDecision {
                decision_id: format!("route-promotion-{}-{}", route_id, selection.skill_hash),
                skill_hash: selection.skill_hash.clone(),
                skill_name: selection.name.clone(),
                route_id: route_id.to_string(),
                phase_id: selection.phase_id.clone(),
                from_lifecycle_state: selection.lifecycle_state.clone(),
                to_lifecycle_state: to_lifecycle,
                stale: selection.stale || decision == "mark_stale",
                confidence_before_bps: before,
                confidence_after_bps: after,
                decision,
                reason,
                evidence_refs,
                created_at_ms,
            }
        })
        .collect()
}

fn workflow_coding_route_evidence_from_run(
    workflow: &WorkflowProject,
    node_runs: &[WorkflowNodeRun],
) -> Vec<WorkflowCodingRouteEvidence> {
    let created_at_ms = now_ms();
    let route_id = workflow_coding_route_id(workflow);
    let phases = workflow_coding_route_phases(workflow, &route_id);
    let selected_skills = workflow_coding_route_skill_selections(&route_id, node_runs);
    let selected_skill_hashes = workflow_coding_route_selected_skill_hashes(&selected_skills);
    let gate_result =
        workflow_route_gate_result(node_runs, "coding.verify", "route.verify.execution");
    let benchmark_results = workflow_coding_route_benchmark_results(
        &route_id,
        &selected_skills,
        &gate_result,
        created_at_ms,
    );
    let promotion_decisions = workflow_coding_route_promotion_decisions(
        &route_id,
        &selected_skills,
        &gate_result,
        &benchmark_results,
        created_at_ms,
    );
    let mut evidence = vec![WorkflowCodingRouteEvidence {
        schema_version: "workflow.coding-route-evidence.v1".to_string(),
        evidence_kind: "coding.route.classification.v1".to_string(),
        route_id: route_id.clone(),
        phase_id: None,
        status: "passed".to_string(),
        summary: format!("Workflow classified as {}.", route_id),
        evidence_refs: vec![format!("coding.route.classification.v1:{}", route_id)],
        selected_skill_hashes: Vec::new(),
        gate_id: None,
        phase_component: None,
        gate_result: None,
        skill_selections: Vec::new(),
        benchmark_results: Vec::new(),
        promotion_decisions: Vec::new(),
        created_at_ms,
    }];
    for phase_id in phases {
        let phase_component = workflow_phase_component_kind(&phase_id);
        evidence.push(WorkflowCodingRouteEvidence {
            schema_version: "workflow.coding-route-evidence.v1".to_string(),
            evidence_kind: "coding.route.phase.start.v1".to_string(),
            route_id: route_id.clone(),
            phase_id: Some(phase_id.clone()),
            status: "passed".to_string(),
            summary: format!("Route phase {} started.", phase_id),
            evidence_refs: vec![format!("coding.route.phase.start.v1:{}", phase_id)],
            selected_skill_hashes: Vec::new(),
            gate_id: None,
            phase_component: Some(phase_component.clone()),
            gate_result: None,
            skill_selections: Vec::new(),
            benchmark_results: Vec::new(),
            promotion_decisions: Vec::new(),
            created_at_ms,
        });
        evidence.push(WorkflowCodingRouteEvidence {
            schema_version: "workflow.coding-route-evidence.v1".to_string(),
            evidence_kind: "coding.route.phase.complete.v1".to_string(),
            route_id: route_id.clone(),
            phase_id: Some(phase_id.clone()),
            status: "passed".to_string(),
            summary: format!("Route phase {} completed.", phase_id),
            evidence_refs: vec![format!("coding.route.phase.complete.v1:{}", phase_id)],
            selected_skill_hashes: Vec::new(),
            gate_id: None,
            phase_component: Some(phase_component),
            gate_result: None,
            skill_selections: Vec::new(),
            benchmark_results: Vec::new(),
            promotion_decisions: Vec::new(),
            created_at_ms,
        });
    }
    let skill_refs = node_runs
        .iter()
        .filter(|run| run.node_type == "skill_context")
        .flat_map(|run| {
            run.output
                .as_ref()
                .and_then(|output| output.get("evidenceRefs"))
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
        })
        .filter_map(|value| value.as_str().map(str::to_string))
        .collect::<Vec<_>>();
    evidence.push(WorkflowCodingRouteEvidence {
        schema_version: "workflow.coding-route-evidence.v1".to_string(),
        evidence_kind: "coding.route.skill_selection.v1".to_string(),
        route_id: route_id.clone(),
        phase_id: Some("coding.context".to_string()),
        status: if selected_skill_hashes.is_empty() {
            "warning"
        } else {
            "passed"
        }
        .to_string(),
        summary: if selected_skill_hashes.is_empty() {
            "No runtime skills were selected for this route.".to_string()
        } else {
            format!(
                "Runtime registry selected {} skill(s) for this route.",
                selected_skill_hashes.len()
            )
        },
        evidence_refs: skill_refs,
        selected_skill_hashes: selected_skill_hashes.clone(),
        gate_id: None,
        phase_component: Some("context".to_string()),
        gate_result: None,
        skill_selections: selected_skills.clone(),
        benchmark_results: Vec::new(),
        promotion_decisions: Vec::new(),
        created_at_ms,
    });
    evidence.push(WorkflowCodingRouteEvidence {
        schema_version: "workflow.coding-route-evidence.v1".to_string(),
        evidence_kind: "coding.route.gate.v1".to_string(),
        route_id: route_id.clone(),
        phase_id: Some("coding.verify".to_string()),
        status: gate_result.status.clone(),
        summary: gate_result.reason.clone(),
        evidence_refs: gate_result.evidence_refs.clone(),
        selected_skill_hashes: selected_skill_hashes.clone(),
        gate_id: Some(gate_result.gate_id.clone()),
        phase_component: Some("verifier".to_string()),
        gate_result: Some(gate_result.clone()),
        skill_selections: selected_skills.clone(),
        benchmark_results: Vec::new(),
        promotion_decisions: Vec::new(),
        created_at_ms,
    });
    if !benchmark_results.is_empty() {
        evidence.push(WorkflowCodingRouteEvidence {
            schema_version: "workflow.coding-route-evidence.v1".to_string(),
            evidence_kind: "coding.route.benchmark.v1".to_string(),
            route_id: route_id.clone(),
            phase_id: Some("coding.verify".to_string()),
            status: gate_result.status.clone(),
            summary: format!(
                "Recorded {} benchmark result(s) for selected route skill(s).",
                benchmark_results.len()
            ),
            evidence_refs: benchmark_results
                .iter()
                .flat_map(|result| result.evidence_refs.clone())
                .collect(),
            selected_skill_hashes: selected_skill_hashes.clone(),
            gate_id: Some(gate_result.gate_id.clone()),
            phase_component: Some("verifier".to_string()),
            gate_result: Some(gate_result.clone()),
            skill_selections: selected_skills.clone(),
            benchmark_results: benchmark_results.clone(),
            promotion_decisions: Vec::new(),
            created_at_ms,
        });
        evidence.push(WorkflowCodingRouteEvidence {
            schema_version: "workflow.coding-route-evidence.v1".to_string(),
            evidence_kind: "coding.route.promotion.v1".to_string(),
            route_id,
            phase_id: Some("coding.closeout".to_string()),
            status: gate_result.status,
            summary: format!(
                "Recorded {} skill promotion decision(s) from retained route evidence.",
                promotion_decisions.len()
            ),
            evidence_refs: promotion_decisions
                .iter()
                .flat_map(|decision| decision.evidence_refs.clone())
                .collect(),
            selected_skill_hashes,
            gate_id: Some("route.skill.promotion".to_string()),
            phase_component: Some("merge_verdict".to_string()),
            gate_result: None,
            skill_selections: selected_skills,
            benchmark_results,
            promotion_decisions,
            created_at_ms,
        });
    }
    evidence
}

fn workflow_coding_route_run_summary(
    route_evidence: &[WorkflowCodingRouteEvidence],
) -> Option<WorkflowCodingRouteRunSummary> {
    let classification = route_evidence
        .iter()
        .find(|item| item.evidence_kind == "coding.route.classification.v1")?;
    let route_id = classification.route_id.clone();
    let completed_phases = route_evidence
        .iter()
        .filter(|item| item.evidence_kind == "coding.route.phase.complete.v1")
        .filter_map(|item| item.phase_id.clone())
        .collect::<Vec<_>>();
    let current_phase = completed_phases.last().cloned();
    let selected_skills = route_evidence
        .iter()
        .find(|item| item.evidence_kind == "coding.route.skill_selection.v1")
        .map(|item| item.skill_selections.clone())
        .unwrap_or_default();
    let gate_results = route_evidence
        .iter()
        .filter(|item| item.evidence_kind == "coding.route.gate.v1")
        .filter_map(|item| item.gate_result.clone())
        .collect::<Vec<_>>();
    let benchmark_results = route_evidence
        .iter()
        .filter(|item| item.evidence_kind == "coding.route.benchmark.v1")
        .flat_map(|item| item.benchmark_results.clone())
        .collect::<Vec<_>>();
    let promotion_decisions = route_evidence
        .iter()
        .filter(|item| item.evidence_kind == "coding.route.promotion.v1")
        .flat_map(|item| item.promotion_decisions.clone())
        .collect::<Vec<_>>();
    let mut evidence_refs = route_evidence
        .iter()
        .flat_map(|item| item.evidence_refs.clone())
        .collect::<Vec<_>>();
    evidence_refs.sort();
    evidence_refs.dedup();
    Some(WorkflowCodingRouteRunSummary {
        schema_version: "workflow.coding-route-run-summary.v1".to_string(),
        route_id: route_id.clone(),
        route_preset: route_id,
        current_phase,
        completed_phases,
        selected_skills,
        gate_results,
        benchmark_results,
        promotion_decisions,
        evidence_refs,
        created_at_ms: classification.created_at_ms,
    })
}

fn workflow_route_verification_evidence(
    route_evidence: &[WorkflowCodingRouteEvidence],
) -> Vec<WorkflowVerificationEvidence> {
    route_evidence
        .iter()
        .map(|item| WorkflowVerificationEvidence {
            node_id: item
                .phase_id
                .clone()
                .unwrap_or_else(|| item.route_id.clone()),
            evidence_type: item.evidence_kind.clone(),
            status: item.status.clone(),
            summary: item.summary.clone(),
            created_at_ms: item.created_at_ms,
        })
        .collect()
}

fn workflow_skill_context_goal(
    workflow: Option<&WorkflowProject>,
    config: &Value,
    input: &Value,
) -> String {
    let goal_source = config
        .get("goalSource")
        .and_then(Value::as_str)
        .unwrap_or("node_input");
    match goal_source {
        "static" => config
            .get("goal")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        "workflow_goal" => workflow
            .map(|workflow| {
                let meta_description = workflow
                    .global_config
                    .get("meta")
                    .and_then(|meta| meta.get("description"))
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                format!("{} {}", workflow.metadata.name, meta_description)
            })
            .unwrap_or_default(),
        _ => workflow_goal_from_input(input)
            .or_else(|| {
                config
                    .get("goal")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .unwrap_or_default(),
    }
}

fn workflow_goal_from_input(input: &Value) -> Option<String> {
    if let Some(value) = input.as_str() {
        return Some(value.to_string());
    }
    input
        .get("payload")
        .and_then(|payload| {
            payload
                .get("request")
                .or_else(|| payload.get("goal"))
                .or_else(|| payload.get("message"))
                .and_then(Value::as_str)
        })
        .or_else(|| input.get("request").and_then(Value::as_str))
        .or_else(|| input.get("goal").and_then(Value::as_str))
        .or_else(|| input.get("message").and_then(Value::as_str))
        .map(str::to_string)
}

pub(super) fn workflow_side_effect_requires_live_runtime(side_effect_class: &str) -> bool {
    !matches!(side_effect_class, "none" | "read")
}

fn workflow_live_mcp_provider_catalog(
    binding: &WorkflowConnectorBinding,
    input: &Value,
) -> Option<Value> {
    let operation = binding.operation.as_deref().unwrap_or("catalog");
    if binding.connector_ref != "mcp.capability-provider"
        || binding.mock_binding
        || binding.side_effect_class != "read"
        || operation != "catalog"
    {
        return None;
    }

    Some(json!({
        "schemaVersion": "workflow.mcp-provider.catalog.v1",
        "providerId": binding.connector_ref.clone(),
        "adapterPort": "McpCapabilityProviderCatalogPort",
        "executionMode": "live_read_only_catalog",
        "live": true,
        "catalogVisibilityCredential": "runtime_catalog_visibility",
        "credentialMaterialized": false,
        "sideEffectsExecuted": false,
        "mutationExecuted": false,
        "toolExecutionEnabled": false,
        "operation": operation,
        "capabilityScope": binding.capability_scope.clone(),
        "providers": [
            {
                "id": "mcp.capability-provider",
                "status": "available",
                "operations": ["catalog"],
                "sideEffectClass": "read"
            }
        ],
        "tools": [
            {
                "toolRef": "mcp.tool.catalog.read",
                "bindingKind": "mcp_tool",
                "capabilityScope": ["read"],
                "sideEffectClass": "read",
                "requiresApproval": false,
                "executionEnabled": false
            }
        ],
        "connectors": [
            {
                "connectorRef": "agent.connector.catalog",
                "operation": "describe",
                "capabilityScope": ["read"],
                "sideEffectClass": "read",
                "requiresApproval": false,
                "mockBinding": false
            }
        ],
        "input": input
    }))
}

fn workflow_provider_catalog_from_input(input: &Value) -> Option<&Value> {
    input
        .get("previousAuthorityOutput")
        .and_then(|output| {
            output
                .get("providerCatalog")
                .filter(|value| value.is_object())
        })
        .or_else(|| {
            input.get("previousOutput").and_then(|output| {
                output
                    .get("providerCatalog")
                    .filter(|value| value.is_object())
            })
        })
        .or_else(|| {
            input
                .get("providerCatalog")
                .filter(|value| value.is_object())
        })
}

fn workflow_mcp_tool_catalog_from_input(input: &Value) -> Option<&Value> {
    input
        .get("previousAuthorityOutput")
        .and_then(|output| {
            output
                .get("mcpToolCatalog")
                .filter(|value| value.is_object())
        })
        .or_else(|| {
            input.get("previousOutput").and_then(|output| {
                output
                    .get("mcpToolCatalog")
                    .filter(|value| value.is_object())
            })
        })
        .or_else(|| {
            input
                .get("mcpToolCatalog")
                .filter(|value| value.is_object())
        })
}

fn workflow_live_mcp_tool_catalog(
    binding: &WorkflowToolBinding,
    arguments: &Value,
    input: &Value,
) -> Result<Option<Value>, String> {
    let is_catalog_read = binding.binding_kind.as_deref() == Some("mcp_tool")
        && binding.tool_ref == "mcp.tool.catalog.read"
        && !binding.mock_binding
        && binding.side_effect_class == "read";
    if !is_catalog_read {
        return Ok(None);
    }

    let provider_catalog = workflow_provider_catalog_from_input(input)
        .ok_or_else(|| "MCP tool catalog read requires live provider catalog input.".to_string())?;
    let tool_listed = provider_catalog
        .get("tools")
        .and_then(Value::as_array)
        .map(|tools| {
            tools.iter().any(|tool| {
                tool.get("toolRef").and_then(Value::as_str) == Some("mcp.tool.catalog.read")
            })
        })
        .unwrap_or(false);
    if !tool_listed {
        return Err("MCP tool catalog read is not present in the provider catalog.".to_string());
    }

    let provider_id = provider_catalog
        .get("providerId")
        .and_then(Value::as_str)
        .unwrap_or("mcp.capability-provider");
    Ok(Some(json!({
        "schemaVersion": "workflow.mcp-tool.catalog-read.v1",
        "toolRef": binding.tool_ref.clone(),
        "bindingKind": "mcp_tool",
        "providerId": provider_id,
        "providerCatalogHash": workflow_hash_value(provider_catalog),
        "executionMode": "live_read_only_catalog_consumer",
        "live": true,
        "providerCatalogLinked": true,
        "catalogReadOnly": true,
        "credentialMaterialized": false,
        "sideEffectsExecuted": false,
        "mutationExecuted": false,
        "toolExecutionEnabled": false,
        "requiresApproval": false,
        "capabilityScope": binding.capability_scope.clone(),
        "arguments": arguments,
        "providerCatalog": {
            "schemaVersion": provider_catalog.get("schemaVersion").cloned().unwrap_or(Value::Null),
            "providerId": provider_catalog.get("providerId").cloned().unwrap_or(Value::Null),
            "toolRef": "mcp.tool.catalog.read"
        },
        "input": input
    })))
}

fn workflow_live_native_tool_catalog(
    binding: &WorkflowToolBinding,
    arguments: &Value,
    input: &Value,
) -> Result<Option<Value>, String> {
    let is_catalog_read = binding.binding_kind.as_deref() == Some("native_tool")
        && binding.tool_ref == "agent.runtime.native-tool.catalog.read"
        && !binding.mock_binding
        && binding.side_effect_class == "read";
    if !is_catalog_read {
        return Ok(None);
    }

    if arguments.get("mutation").and_then(Value::as_bool) == Some(true) {
        return Err(
            "Native tool catalog read requires non-mutating catalog arguments.".to_string(),
        );
    }
    let mcp_tool_catalog = workflow_mcp_tool_catalog_from_input(input);
    if let Some(catalog) = mcp_tool_catalog {
        if catalog.get("toolExecutionEnabled").and_then(Value::as_bool) != Some(false) {
            return Err(
                "Native tool catalog read requires a non-executing MCP tool catalog when linked."
                    .to_string(),
            );
        }
    }

    Ok(Some(json!({
        "schemaVersion": "workflow.native-tool.catalog-read.v1",
        "toolRef": binding.tool_ref.clone(),
        "bindingKind": "native_tool",
        "adapterPort": "NativeToolCatalogReadPort",
        "executionMode": "live_read_only_native_tool_catalog",
        "live": true,
        "mcpToolCatalogLinked": mcp_tool_catalog.is_some(),
        "mcpToolCatalogHash": mcp_tool_catalog.map(workflow_hash_value),
        "catalogReadOnly": true,
        "credentialMaterialized": false,
        "sideEffectsExecuted": false,
        "mutationExecuted": false,
        "toolExecutionEnabled": false,
        "nativeToolExecutionEnabled": false,
        "requiresApproval": false,
        "capabilityScope": binding.capability_scope.clone(),
        "arguments": arguments,
        "tools": [
            {
                "toolRef": "agent.runtime.native-tool.catalog.read",
                "bindingKind": "native_tool",
                "capabilityScope": ["native.tool.catalog.read"],
                "sideEffectClass": "read",
                "requiresApproval": false,
                "mockBinding": false,
                "executionEnabled": false
            },
            {
                "toolRef": "agent.runtime.noop.read",
                "bindingKind": "native_tool",
                "capabilityScope": ["read"],
                "sideEffectClass": "read",
                "requiresApproval": false,
                "mockBinding": true,
                "executionEnabled": false
            },
            {
                "toolRef": "agent.runtime.tool.invoke",
                "bindingKind": "native_tool",
                "capabilityScope": ["tool.invoke"],
                "sideEffectClass": "external_write",
                "requiresApproval": true,
                "mockBinding": true,
                "executionEnabled": false
            }
        ],
        "mcpToolCatalog": mcp_tool_catalog.map(|catalog| {
            json!({
                "schemaVersion": catalog.get("schemaVersion").cloned().unwrap_or(Value::Null),
                "toolRef": catalog.get("toolRef").cloned().unwrap_or(Value::Null),
                "providerId": catalog.get("providerId").cloned().unwrap_or(Value::Null)
            })
        }),
        "input": input
    })))
}

fn workflow_live_wallet_capability_dry_run(
    logic: &Value,
    outcome: &Value,
    input: &Value,
) -> Result<Option<Value>, String> {
    let approval_mode = logic
        .get("approvalMode")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let capability_scope = logic
        .get("capabilityScope")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let requests_wallet_capability = capability_scope.iter().any(|scope| {
        scope
            .as_str()
            .map(|value| value == "wallet.request" || value == "capability.grant")
            .unwrap_or(false)
    });
    let is_wallet_dry_run = requests_wallet_capability
        && matches!(
            approval_mode,
            "wallet_capability_dry_run" | "read_only_capability_denial"
        );
    if !is_wallet_dry_run {
        return Ok(None);
    }

    if logic.get("sideEffectsExecuted").and_then(Value::as_bool) == Some(true)
        || logic.get("mutationExecuted").and_then(Value::as_bool) == Some(true)
    {
        return Err(
            "Wallet capability dry-run cannot execute side effects or mutations.".to_string(),
        );
    }
    if logic.get("capabilityGranted").and_then(Value::as_bool) == Some(true)
        || logic.get("authorityTransferred").and_then(Value::as_bool) == Some(true)
        || outcome.get("authorityTransferred").and_then(Value::as_bool) == Some(true)
    {
        return Err(
            "Wallet capability dry-run cannot materialize a grant or transfer authority."
                .to_string(),
        );
    }

    Ok(Some(json!({
        "schemaVersion": "workflow.wallet-capability.dry-run.v1",
        "componentKind": "wallet_capability",
        "adapterPort": "WalletCapabilityDryRunPort",
        "executionMode": "live_non_mutating_capability_dry_run",
        "live": true,
        "approvalMode": approval_mode,
        "approvalObserved": outcome.get("approved").and_then(Value::as_bool).unwrap_or(false),
        "approvalDecision": outcome.get("decision").cloned().unwrap_or_else(|| json!("unknown")),
        "dryRunApprovalGranted": logic
            .get("syntheticApprovalGranted")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        "capabilityRequested": true,
        "capabilityScope": capability_scope,
        "capabilityGranted": false,
        "grantMaterialized": false,
        "grantRef": Value::Null,
        "authorityTransferred": false,
        "credentialMaterialized": false,
        "sideEffectsExecuted": false,
        "mutationExecuted": false,
        "requiresApproval": logic
            .get("requiresApproval")
            .and_then(Value::as_bool)
            .unwrap_or(true),
        "policyDecision": logic
            .get("policyDecision")
            .and_then(Value::as_str)
            .unwrap_or("retain_wallet_capability_without_grant"),
        "walletAuthority": "dry_run_only",
        "receiptKind": "wallet_capability_dry_run_receipt",
        "rollbackTarget": logic.get("rollbackTarget").cloned().unwrap_or(Value::Null),
        "input": input
    })))
}

fn workflow_live_authority_policy_gate(
    logic: &Value,
    input: &Value,
) -> Result<Option<Value>, String> {
    let is_policy_gate = logic.get("authorityGateKind").and_then(Value::as_str)
        == Some("policy_gate")
        || logic
            .get("policyGateLiveExecution")
            .and_then(Value::as_bool)
            == Some(true);
    if !is_policy_gate {
        return Ok(None);
    }

    if logic.get("sideEffectsExecuted").and_then(Value::as_bool) == Some(true)
        || logic.get("mutationExecuted").and_then(Value::as_bool) == Some(true)
    {
        return Err("Authority policy gate cannot execute side effects or mutations.".to_string());
    }
    if logic
        .get("mutatingToolCallsBlocked")
        .and_then(Value::as_bool)
        != Some(true)
    {
        return Err("Authority policy gate must block mutating tool calls.".to_string());
    }

    Ok(Some(json!({
        "schemaVersion": "workflow.authority.policy-gate.v1",
        "componentKind": "policy_gate",
        "adapterPort": "AuthorityPolicyGatePort",
        "executionMode": "live_read_only_policy_gate",
        "live": true,
        "readOnlyRouteAccepted": logic
            .get("readOnlyRouteAccepted")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        "destructiveRouteDenied": logic
            .get("destructiveRouteDenied")
            .and_then(Value::as_bool)
            .unwrap_or(true),
        "mutatingToolCallsBlocked": true,
        "sideEffectsExecuted": false,
        "mutationExecuted": false,
        "requiresApproval": logic
            .get("requiresApproval")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        "policyDecision": logic
            .get("policyDecision")
            .and_then(Value::as_str)
            .unwrap_or("allow_read_only_route_through_workflow_authority"),
        "receiptKind": "authority_policy_gate_receipt",
        "rollbackTarget": logic.get("rollbackTarget").cloned().unwrap_or(Value::Null),
        "input": input
    })))
}

fn workflow_live_authority_destructive_denial(
    logic: &Value,
    input: &Value,
) -> Result<Option<Value>, String> {
    let is_destructive_denial = logic.get("authorityGateKind").and_then(Value::as_str)
        == Some("destructive_denial")
        || logic.get("denialClass").and_then(Value::as_str)
            == Some("policy_destructive_without_approval");
    if !is_destructive_denial {
        return Ok(None);
    }

    if logic.get("sideEffectsExecuted").and_then(Value::as_bool) == Some(true)
        || logic.get("mutationExecuted").and_then(Value::as_bool) == Some(true)
    {
        return Err(
            "Authority destructive denial cannot execute side effects or mutations.".to_string(),
        );
    }
    if logic.get("destructiveRouteDenied").and_then(Value::as_bool) != Some(true) {
        return Err("Authority destructive denial must deny the destructive route.".to_string());
    }

    Ok(Some(json!({
        "schemaVersion": "workflow.authority.destructive-denial.v1",
        "componentKind": "policy_gate",
        "adapterPort": "AuthorityDestructiveDenialPort",
        "executionMode": "live_destructive_denial_gate",
        "live": true,
        "simulatedRequest": logic.get("simulatedRequest").cloned().unwrap_or(Value::Null),
        "destructiveRouteDenied": true,
        "mutatingToolCallsBlocked": true,
        "requiresApproval": logic
            .get("requiresApproval")
            .and_then(Value::as_bool)
            .unwrap_or(true),
        "sideEffectsExecuted": false,
        "mutationExecuted": false,
        "denialReceiptReady": true,
        "denialClass": logic
            .get("denialClass")
            .and_then(Value::as_str)
            .unwrap_or("policy_destructive_without_approval"),
        "policyDecision": logic
            .get("policyDecision")
            .and_then(Value::as_str)
            .unwrap_or("deny_destructive_request_without_side_effect"),
        "receiptKind": "authority_destructive_denial_receipt",
        "rollbackTarget": logic.get("rollbackTarget").cloned().unwrap_or(Value::Null),
        "input": input
    })))
}

fn workflow_live_authority_approval_gate(
    logic: &Value,
    outcome: &Value,
    input: &Value,
) -> Result<Option<Value>, String> {
    let approval_mode = logic
        .get("approvalMode")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let is_authority_approval_gate = logic.get("authorityGateKind").and_then(Value::as_str)
        == Some("approval_gate")
        || approval_mode == "workflow_recovery_required";
    if !is_authority_approval_gate {
        return Ok(None);
    }

    if logic.get("mutationExecuted").and_then(Value::as_bool) == Some(true)
        || logic.get("authorityTransferred").and_then(Value::as_bool) == Some(true)
        || outcome.get("authorityTransferred").and_then(Value::as_bool) == Some(true)
    {
        return Err(
            "Authority approval gate dry-run cannot transfer authority or execute mutations."
                .to_string(),
        );
    }

    Ok(Some(json!({
        "schemaVersion": "workflow.authority.approval-gate.v1",
        "componentKind": "approval_gate",
        "adapterPort": "AuthorityApprovalGatePort",
        "executionMode": "live_approval_gate_denial",
        "live": true,
        "approvalMode": approval_mode,
        "approvalObserved": outcome.get("approved").and_then(Value::as_bool).unwrap_or(false),
        "approvalDecision": outcome.get("decision").cloned().unwrap_or_else(|| json!("unknown")),
        "approvalGranted": false,
        "syntheticApprovalGranted": logic
            .get("syntheticApprovalGranted")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        "requiresApproval": logic
            .get("requiresApproval")
            .and_then(Value::as_bool)
            .unwrap_or(true),
        "authorityTransferred": false,
        "sideEffectsExecuted": false,
        "mutationExecuted": false,
        "policyDecision": logic
            .get("policyDecision")
            .and_then(Value::as_str)
            .unwrap_or("require_workflow_approval_for_mutating_tooling"),
        "receiptKind": "authority_approval_gate_receipt",
        "rollbackTarget": logic.get("rollbackTarget").cloned().unwrap_or(Value::Null),
        "input": input
    })))
}

fn workflow_live_connector_catalog_describe(
    binding: &WorkflowConnectorBinding,
    input: &Value,
) -> Result<Option<Value>, String> {
    let operation = binding.operation.as_deref().unwrap_or("describe");
    let is_catalog_describe = binding.connector_ref == "agent.connector.catalog"
        && !binding.mock_binding
        && binding.side_effect_class == "read"
        && operation == "describe";
    if !is_catalog_describe {
        return Ok(None);
    }

    let mcp_tool_catalog = workflow_mcp_tool_catalog_from_input(input).ok_or_else(|| {
        "Connector catalog describe requires live MCP tool catalog input.".to_string()
    })?;
    if mcp_tool_catalog
        .get("toolExecutionEnabled")
        .and_then(Value::as_bool)
        != Some(false)
    {
        return Err(
            "Connector catalog describe requires a non-executing MCP tool catalog.".to_string(),
        );
    }

    Ok(Some(json!({
        "schemaVersion": "workflow.connector.catalog-describe.v1",
        "connectorRef": binding.connector_ref.clone(),
        "adapterPort": "ConnectorCatalogDescribePort",
        "executionMode": "live_read_only_connector_describe",
        "live": true,
        "mcpToolCatalogLinked": true,
        "mcpToolCatalogHash": workflow_hash_value(mcp_tool_catalog),
        "catalogReadOnly": true,
        "credentialMaterialized": false,
        "sideEffectsExecuted": false,
        "mutationExecuted": false,
        "connectorExecutionEnabled": false,
        "externalRequestEnabled": false,
        "operation": operation,
        "requiresApproval": false,
        "capabilityScope": binding.capability_scope.clone(),
        "connectors": [
            {
                "connectorRef": "agent.connector.catalog",
                "operation": "describe",
                "capabilityScope": ["connector.catalog.read"],
                "sideEffectClass": "read",
                "requiresApproval": false,
                "mockBinding": false,
                "executionEnabled": false
            },
            {
                "connectorRef": "agent.connector.invoke",
                "operation": "invoke",
                "capabilityScope": ["connector.invoke"],
                "sideEffectClass": "external_write",
                "requiresApproval": true,
                "mockBinding": true,
                "executionEnabled": false
            }
        ],
        "mcpToolCatalog": {
            "schemaVersion": mcp_tool_catalog.get("schemaVersion").cloned().unwrap_or(Value::Null),
            "toolRef": mcp_tool_catalog.get("toolRef").cloned().unwrap_or(Value::Null),
            "providerId": mcp_tool_catalog.get("providerId").cloned().unwrap_or(Value::Null)
        },
        "input": input
    })))
}

pub(super) fn workflow_has_incoming_connection_class(
    workflow: &WorkflowProject,
    node_id: &str,
    connection_class: &str,
) -> bool {
    workflow.edges.iter().any(|edge| {
        workflow_edge_to(edge).as_deref() == Some(node_id)
            && (workflow_edge_connection_class(edge).as_deref() == Some(connection_class)
                || workflow_edge_to_port(edge) == connection_class)
    })
}

pub(super) fn workflow_node_id(node: &Value) -> Option<String> {
    workflow_value_string(node, "id")
}

pub(super) fn workflow_node_type(node: &Value) -> String {
    workflow_value_string(node, "type").unwrap_or_else(|| "unknown".to_string())
}

pub(super) fn workflow_node_name(node: &Value) -> String {
    workflow_value_string(node, "name").unwrap_or_else(|| "Workflow step".to_string())
}

pub(super) fn workflow_node_logic(node: &Value) -> Value {
    node.get("config")
        .and_then(|config| config.get("logic"))
        .cloned()
        .unwrap_or_else(|| json!({}))
}

pub(super) fn workflow_node_law(node: &Value) -> Value {
    node.get("config")
        .and_then(|config| config.get("law"))
        .cloned()
        .unwrap_or_else(|| json!({}))
}

pub(super) fn workflow_action_frame(node: &Value) -> ActionFrame {
    let node_id = workflow_node_id(node).unwrap_or_else(|| "unknown".to_string());
    let logic = workflow_node_logic(node);
    let law = workflow_node_law(node);
    let kind = ActionKind::from_node_type(&workflow_node_type(node));
    let binding = match kind {
        ActionKind::ModelCall => Some(ActionBindingRef {
            binding_type: "model".to_string(),
            reference: logic
                .get("modelRef")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .map(str::to_string),
            mock_binding: false,
            side_effect_class: "compute".to_string(),
            requires_approval: false,
        }),
        ActionKind::ModelBinding => Some(ActionBindingRef {
            binding_type: "model".to_string(),
            reference: logic
                .get("modelBinding")
                .and_then(|binding| binding.get("modelRef"))
                .and_then(Value::as_str)
                .or_else(|| logic.get("modelRef").and_then(Value::as_str))
                .filter(|value| !value.trim().is_empty())
                .map(str::to_string),
            mock_binding: logic
                .get("modelBinding")
                .and_then(|binding| binding.get("mockBinding"))
                .and_then(Value::as_bool)
                .unwrap_or(true),
            side_effect_class: logic
                .get("modelBinding")
                .and_then(|binding| binding.get("sideEffectClass"))
                .and_then(Value::as_str)
                .unwrap_or("none")
                .to_string(),
            requires_approval: logic
                .get("modelBinding")
                .and_then(|binding| binding.get("requiresApproval"))
                .and_then(Value::as_bool)
                .unwrap_or(false),
        }),
        ActionKind::Parser => Some(ActionBindingRef {
            binding_type: "parser".to_string(),
            reference: logic
                .get("parserBinding")
                .and_then(|binding| binding.get("parserRef"))
                .and_then(Value::as_str)
                .or_else(|| logic.get("parserRef").and_then(Value::as_str))
                .filter(|value| !value.trim().is_empty())
                .map(str::to_string),
            mock_binding: logic
                .get("parserBinding")
                .and_then(|binding| binding.get("mockBinding"))
                .and_then(Value::as_bool)
                .unwrap_or(true),
            side_effect_class: "none".to_string(),
            requires_approval: false,
        }),
        ActionKind::Function => Some(ActionBindingRef {
            binding_type: "function".to_string(),
            reference: logic
                .get("functionBinding")
                .and_then(|binding| binding.get("language"))
                .and_then(Value::as_str)
                .or_else(|| logic.get("language").and_then(Value::as_str))
                .map(str::to_string),
            mock_binding: false,
            side_effect_class: "compute".to_string(),
            requires_approval: law
                .get("requireHumanGate")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        }),
        ActionKind::WorkflowPackageExport => Some(ActionBindingRef {
            binding_type: "workflow_package".to_string(),
            reference: workflow_logic_string(&logic, "workflowPackagePath"),
            mock_binding: false,
            side_effect_class: "write".to_string(),
            requires_approval: law
                .get("requireHumanGate")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        }),
        ActionKind::WorkflowPackageImport => Some(ActionBindingRef {
            binding_type: "workflow_package".to_string(),
            reference: workflow_logic_string(&logic, "workflowPackagePath"),
            mock_binding: false,
            side_effect_class: "write".to_string(),
            requires_approval: law
                .get("requireHumanGate")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        }),
        ActionKind::GithubPrCreate => Some(ActionBindingRef {
            binding_type: "github".to_string(),
            reference: workflow_value_string_any(&logic, &["repoFullName", "repository"]),
            mock_binding: true,
            side_effect_class: "external_write".to_string(),
            requires_approval: !workflow_value_bool_any(&logic, &["dryRun", "previewOnly"])
                .unwrap_or(true),
        }),
        ActionKind::AdapterConnector => {
            logic
                .get("connectorBinding")
                .map(|binding| ActionBindingRef {
                    binding_type: "connector".to_string(),
                    reference: binding
                        .get("connectorRef")
                        .and_then(Value::as_str)
                        .filter(|value| !value.trim().is_empty())
                        .map(str::to_string),
                    mock_binding: binding
                        .get("mockBinding")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                    side_effect_class: binding
                        .get("sideEffectClass")
                        .and_then(Value::as_str)
                        .unwrap_or("read")
                        .to_string(),
                    requires_approval: binding
                        .get("requiresApproval")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                })
        }
        ActionKind::PluginTool => logic.get("toolBinding").map(|binding| ActionBindingRef {
            binding_type: "tool".to_string(),
            reference: binding
                .get("toolRef")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .map(str::to_string),
            mock_binding: binding
                .get("mockBinding")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            side_effect_class: binding
                .get("sideEffectClass")
                .and_then(Value::as_str)
                .unwrap_or("read")
                .to_string(),
            requires_approval: binding
                .get("requiresApproval")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        }),
        _ => None,
    };
    let privileged_actions = law
        .get("privilegedActions")
        .or_else(|| logic.get("privilegedActions"))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .filter(|item| !item.trim().is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let sandbox_permissions = law
        .get("sandboxPolicy")
        .and_then(|policy| policy.get("permissions"))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .filter(|item| !item.trim().is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    ActionFrame {
        id: node_id,
        surface: ActionSurface::Workflow,
        kind,
        label: workflow_node_name(node),
        binding,
        policy: ActionPolicy {
            privileged_actions,
            requires_approval: law
                .get("requireHumanGate")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            sandbox_permissions,
        },
        metadata: std::collections::BTreeMap::new(),
    }
}

pub(super) fn workflow_output_bundle_schema() -> Value {
    json!({
        "type": "object",
        "required": ["kind", "nodeId", "outputBundle"],
        "properties": {
            "kind": { "type": "string" },
            "nodeId": { "type": "string" },
            "outputName": { "type": "string" },
            "outputBundle": {
                "type": "object",
                "required": ["id", "nodeId", "format", "value", "createdAtMs"],
                "properties": {
                    "id": { "type": "string" },
                    "nodeId": { "type": "string" },
                    "format": { "type": "string" },
                    "value": { "type": "unknown" },
                    "rendererRef": { "type": "object" },
                    "materializedAssets": { "type": "array" },
                    "deliveryTarget": { "type": "object" },
                    "dependencyRefs": { "type": "array" },
                    "evidenceRefs": { "type": "array" },
                    "version": { "type": "object" },
                    "createdAtMs": { "type": "number" }
                }
            }
        }
    })
}

pub(super) fn workflow_node_schema(node: &Value, logic_key: &str) -> Option<Value> {
    workflow_node_logic(node)
        .get(logic_key)
        .cloned()
        .or_else(|| node.get("schema").cloned())
        .or_else(|| {
            (logic_key == "outputSchema" && workflow_node_type(node) == "output")
                .then(workflow_output_bundle_schema)
        })
}

pub(super) fn workflow_function_binding(node: &Value) -> Result<WorkflowFunctionBinding, String> {
    let logic = workflow_node_logic(node);
    if let Some(binding) = logic.get("functionBinding") {
        return serde_json::from_value(binding.clone())
            .map_err(|error| format!("Function binding is invalid: {}", error));
    }
    let code = logic
        .get("code")
        .and_then(Value::as_str)
        .ok_or_else(|| "Function code is missing.".to_string())?;
    Ok(WorkflowFunctionBinding {
        language: logic
            .get("language")
            .and_then(Value::as_str)
            .unwrap_or("javascript")
            .to_string(),
        code: code.to_string(),
        function_ref: None,
        input_schema: workflow_node_schema(node, "inputSchema"),
        output_schema: workflow_node_schema(node, "outputSchema"),
        sandbox_policy: workflow_node_law(node)
            .get("sandboxPolicy")
            .cloned()
            .and_then(|value| serde_json::from_value(value).ok()),
        test_input: logic.get("testInput").cloned(),
    })
}

pub(super) fn workflow_tool_binding(node: &Value) -> Result<WorkflowToolBinding, String> {
    let logic = workflow_node_logic(node);
    let Some(binding) = logic.get("toolBinding") else {
        return Err("Plugin tool binding is missing.".to_string());
    };
    serde_json::from_value(binding.clone())
        .map_err(|error| format!("Tool binding is invalid: {}", error))
}

pub(super) fn workflow_parser_binding(node: &Value) -> Result<WorkflowParserBinding, String> {
    let logic = workflow_node_logic(node);
    let Some(binding) = logic.get("parserBinding") else {
        return Err("Output Parser binding is missing.".to_string());
    };
    serde_json::from_value(binding.clone())
        .map_err(|error| format!("Output Parser binding is invalid: {}", error))
}

pub(super) fn workflow_model_binding(node: &Value) -> Result<WorkflowModelBinding, String> {
    let logic = workflow_node_logic(node);
    let Some(binding) = logic.get("modelBinding") else {
        return Err("Model Binding is missing.".to_string());
    };
    serde_json::from_value(binding.clone())
        .map_err(|error| format!("Model Binding is invalid: {}", error))
}

pub(super) fn workflow_connector_binding(node: &Value) -> Result<WorkflowConnectorBinding, String> {
    let logic = workflow_node_logic(node);
    let Some(binding) = logic.get("connectorBinding") else {
        return Err("Connector binding is missing.".to_string());
    };
    serde_json::from_value(binding.clone())
        .map_err(|error| format!("Connector binding is invalid: {}", error))
}

pub(super) fn workflow_sandbox_policy(
    binding: &WorkflowFunctionBinding,
    node: &Value,
) -> WorkflowSandboxPolicy {
    binding
        .sandbox_policy
        .clone()
        .or_else(|| {
            workflow_node_law(node)
                .get("sandboxPolicy")
                .cloned()
                .and_then(|value| serde_json::from_value(value).ok())
        })
        .unwrap_or(WorkflowSandboxPolicy {
            timeout_ms: Some(1000),
            memory_mb: Some(64),
            output_limit_bytes: Some(32768),
            permissions: Vec::new(),
        })
}

pub(super) fn workflow_policy_allows(policy: &WorkflowSandboxPolicy, permission: &str) -> bool {
    policy.permissions.iter().any(|item| item == permission)
}

pub(super) fn workflow_function_sandbox_precheck(
    code: &str,
    policy: &WorkflowSandboxPolicy,
) -> Result<(), String> {
    let filesystem_tokens = ["require(", "import ", "fs.", "node:fs"];
    let network_tokens = [
        "fetch(",
        "XMLHttpRequest",
        "WebSocket",
        "require('http",
        "require(\"http",
        "node:http",
        "node:https",
    ];
    let process_tokens = ["process.", "child_process", "spawn(", "exec("];
    if !workflow_policy_allows(policy, "filesystem")
        && filesystem_tokens.iter().any(|token| code.contains(token))
    {
        return Err(
            "Function uses filesystem/module access without sandbox permission.".to_string(),
        );
    }
    if !workflow_policy_allows(policy, "network")
        && network_tokens.iter().any(|token| code.contains(token))
    {
        return Err("Function uses network access without sandbox permission.".to_string());
    }
    if !workflow_policy_allows(policy, "process")
        && process_tokens.iter().any(|token| code.contains(token))
    {
        return Err("Function uses process access without sandbox permission.".to_string());
    }
    Ok(())
}

pub(super) fn workflow_function_dependency_names(binding: &WorkflowFunctionBinding) -> Vec<String> {
    let Some(manifest) = binding
        .function_ref
        .as_ref()
        .and_then(|function_ref| function_ref.dependency_manifest.as_ref())
    else {
        return Vec::new();
    };
    let Some(dependencies) = manifest.get("dependencies") else {
        return Vec::new();
    };
    if let Some(object) = dependencies.as_object() {
        return object
            .keys()
            .filter(|key| !key.trim().is_empty())
            .cloned()
            .collect();
    }
    dependencies
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .filter(|item| !item.trim().is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

pub(super) fn workflow_function_dependency_precheck(
    binding: &WorkflowFunctionBinding,
) -> Result<(), String> {
    let dependency_names = workflow_function_dependency_names(binding);
    if dependency_names.is_empty() {
        return Ok(());
    }
    Err(format!(
        "Function dependency manifest declares unsupported external dependencies: {}.",
        dependency_names.join(", ")
    ))
}

fn workflow_function_input_schema(binding: &WorkflowFunctionBinding) -> Option<&Value> {
    binding.input_schema.as_ref().or_else(|| {
        binding
            .function_ref
            .as_ref()
            .and_then(|function_ref| function_ref.input_schema.as_ref())
    })
}

fn workflow_function_output_schema(binding: &WorkflowFunctionBinding) -> Option<&Value> {
    binding.output_schema.as_ref().or_else(|| {
        binding
            .function_ref
            .as_ref()
            .and_then(|function_ref| function_ref.output_schema.as_ref())
    })
}

pub(super) fn workflow_edge_from(edge: &Value) -> Option<String> {
    workflow_value_string(edge, "from")
}

pub(super) fn workflow_edge_to(edge: &Value) -> Option<String> {
    workflow_value_string(edge, "to")
}

pub(super) fn workflow_edge_from_port(edge: &Value) -> String {
    workflow_value_string(edge, "fromPort").unwrap_or_else(|| "output".to_string())
}

pub(super) fn workflow_edge_to_port(edge: &Value) -> String {
    workflow_value_string(edge, "toPort").unwrap_or_else(|| "input".to_string())
}

pub(super) fn workflow_edge_connection_class(edge: &Value) -> Option<String> {
    workflow_value_string(edge, "connectionClass").or_else(|| {
        edge.get("data")
            .and_then(|data| workflow_value_string(data, "connectionClass"))
    })
}

pub(super) fn collect_workflow_expression_refs(
    value: &Value,
    refs: &mut Vec<(String, String, String)>,
) {
    match value {
        Value::String(text) => {
            let pattern =
                Regex::new(r"\{\{\s*nodes\.([A-Za-z0-9_.:-]+)\.([A-Za-z0-9_.:-]+)\s*\}\}")
                    .expect("workflow expression regex should compile");
            for capture in pattern.captures_iter(text) {
                let expression = capture
                    .get(0)
                    .map(|item| item.as_str().to_string())
                    .unwrap_or_default();
                let node_id = capture
                    .get(1)
                    .map(|item| item.as_str().to_string())
                    .unwrap_or_default();
                let port_id = capture
                    .get(2)
                    .map(|item| item.as_str().to_string())
                    .unwrap_or_default();
                refs.push((expression, node_id, port_id));
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_workflow_expression_refs(item, refs);
            }
        }
        Value::Object(map) => {
            for item in map.values() {
                collect_workflow_expression_refs(item, refs);
            }
        }
        _ => {}
    }
}

pub(super) fn workflow_schema_from_sample(value: &Value) -> Value {
    match value {
        Value::Array(items) => json!({
            "type": "array",
            "items": items.first().map(workflow_schema_from_sample).unwrap_or_else(|| json!({"type": "unknown"}))
        }),
        Value::Object(map) => json!({
            "type": "object",
            "properties": map
                .iter()
                .map(|(key, child)| (key.clone(), workflow_schema_from_sample(child)))
                .collect::<serde_json::Map<String, Value>>()
        }),
        Value::String(_) => json!({"type": "string"}),
        Value::Number(number) if number.is_i64() || number.is_u64() => json!({"type": "integer"}),
        Value::Number(_) => json!({"type": "number"}),
        Value::Bool(_) => json!({"type": "boolean"}),
        Value::Null => json!({"type": "null"}),
    }
}

pub(super) fn workflow_schema_is_object_like(schema: Option<&Value>) -> bool {
    schema
        .and_then(|value| value.as_object())
        .and_then(|object| object.get("type"))
        .and_then(Value::as_str)
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
}

pub(super) fn workflow_node_declared_output_schema(node: &Value) -> Value {
    let logic = workflow_node_logic(node);
    if workflow_node_type(node) == "skill_context" {
        return workflow_skill_context_output_schema();
    }
    if workflow_node_type(node) == "workflow_package_export" {
        return workflow_package_export_output_schema();
    }
    if workflow_node_type(node) == "workflow_package_import" {
        return workflow_package_import_output_schema();
    }
    if workflow_node_type(node) == "github_pr_create" {
        return workflow_github_pr_create_output_schema();
    }
    workflow_node_output_schema(node)
        .or_else(|| logic.get("schema").cloned())
        .or_else(|| logic.get("payload").map(workflow_schema_from_sample))
        .unwrap_or_else(|| json!({"type": "object"}))
}

pub(super) fn workflow_schema_has_field_path(schema: &Value, path: &str) -> bool {
    let segments = path
        .split('.')
        .filter(|segment| !segment.trim().is_empty())
        .collect::<Vec<_>>();
    if segments.is_empty() {
        return false;
    }
    let mut current = schema;
    for segment in segments {
        if segment == "[]" {
            if current.get("type").and_then(Value::as_str) != Some("array") {
                return false;
            }
            let Some(items) = current.get("items") else {
                return false;
            };
            current = items;
            continue;
        }
        let Some(properties) = current.get("properties").and_then(Value::as_object) else {
            return false;
        };
        let Some(next) = properties.get(segment) else {
            return false;
        };
        current = next;
    }
    true
}

pub(super) fn workflow_node_has_output_port(node: &Value, port_id: &str) -> bool {
    if node
        .get("ports")
        .and_then(Value::as_array)
        .map(|ports| {
            ports.iter().any(|port| {
                port.get("id").and_then(Value::as_str) == Some(port_id)
                    && port.get("direction").and_then(Value::as_str) == Some("output")
            })
        })
        .unwrap_or(false)
    {
        return true;
    }
    node.get("outputs")
        .and_then(Value::as_array)
        .map(|outputs| outputs.iter().any(|item| item.as_str() == Some(port_id)))
        .unwrap_or(false)
}

pub(super) fn validate_workflow_expression_refs(
    workflow: &WorkflowProject,
    node: &Value,
    logic: &Value,
) -> Vec<WorkflowValidationIssue> {
    let Some(node_id) = workflow_node_id(node) else {
        return Vec::new();
    };
    let mut refs = Vec::new();
    collect_workflow_expression_refs(logic, &mut refs);
    let mut issues = refs
        .into_iter()
        .filter_map(|(expression, source_id, port_id)| {
            let Some(source_node) = workflow_node_by_id(workflow, &source_id) else {
                return Some(WorkflowValidationIssue {
                    node_id: Some(node_id.clone()),
                    code: "missing_expression_node".to_string(),
                    message: format!(
                        "Expression {} references a missing source node.",
                        expression
                    ),
                });
            };
            if !workflow_node_has_output_port(source_node, &port_id) {
                return Some(WorkflowValidationIssue {
                    node_id: Some(node_id.clone()),
                    code: "missing_expression_port".to_string(),
                    message: format!(
                        "Expression {} references a missing output port.",
                        expression
                    ),
                });
            }
            let incoming_edge = workflow.edges.iter().find(|edge| {
                workflow_edge_from(edge).as_deref() == Some(source_id.as_str())
                    && workflow_edge_to(edge).as_deref() == Some(node_id.as_str())
                    && workflow_edge_from_port(edge) == port_id
            });
            let Some(edge) = incoming_edge else {
                return Some(WorkflowValidationIssue {
                    node_id: Some(node_id.clone()),
                    code: "unconnected_expression_ref".to_string(),
                    message: format!(
                        "Expression {} needs a matching incoming edge from '{}'.",
                        expression,
                        workflow_node_name(source_node)
                    ),
                });
            };
            let source_class = workflow_node_port_connection_class(source_node, &port_id, "output")
                .or_else(|| workflow_edge_connection_class(edge))
                .unwrap_or_else(|| "data".to_string());
            let target_class =
                workflow_node_port_connection_class(node, &workflow_edge_to_port(edge), "input")
                    .or_else(|| workflow_edge_connection_class(edge))
                    .unwrap_or_else(|| "data".to_string());
            validate_workflow_connection_class(Some(node_id.clone()), &source_class, &target_class)
                .err()
                .map(|issue| WorkflowValidationIssue {
                    node_id: issue.action_id,
                    code: "invalid_expression_connection".to_string(),
                    message: format!(
                        "{} cannot use the connected ports: {}",
                        expression, issue.message
                    ),
                })
        })
        .collect::<Vec<_>>();
    if let Some(field_mappings) = logic.get("fieldMappings").and_then(Value::as_object) {
        for (key, mapping) in field_mappings {
            let source = mapping.get("source").and_then(Value::as_str).unwrap_or("");
            let path = mapping.get("path").and_then(Value::as_str).unwrap_or("");
            if source.trim().is_empty() || path.trim().is_empty() {
                issues.push(WorkflowValidationIssue {
                    node_id: Some(node_id.clone()),
                    code: "invalid_field_mapping_source".to_string(),
                    message: format!(
                        "Field mapping '{}' needs a node output source expression.",
                        key
                    ),
                });
                continue;
            }
            let mut source_refs = Vec::new();
            collect_workflow_expression_refs(&Value::String(source.to_string()), &mut source_refs);
            let Some((_, source_id, _)) = source_refs.first() else {
                issues.push(WorkflowValidationIssue {
                    node_id: Some(node_id.clone()),
                    code: "invalid_field_mapping_source".to_string(),
                    message: format!(
                        "Field mapping '{}' needs a node output source expression.",
                        key
                    ),
                });
                continue;
            };
            let Some(source_node) = workflow_node_by_id(workflow, source_id) else {
                continue;
            };
            let schema = workflow_node_declared_output_schema(source_node);
            if !workflow_schema_has_field_path(&schema, path) {
                issues.push(WorkflowValidationIssue {
                    node_id: Some(node_id.clone()),
                    code: "missing_field_mapping_path".to_string(),
                    message: format!(
                        "Field mapping '{}' references '{}', which is not in '{}' output schema.",
                        key,
                        path,
                        workflow_node_name(source_node)
                    ),
                });
            }
        }
    }
    issues
}

pub(super) fn workflow_node_port_connection_class(
    node: &Value,
    port_id: &str,
    direction: &str,
) -> Option<String> {
    if let Some(class) = node
        .get("ports")
        .and_then(Value::as_array)
        .and_then(|ports| {
            ports.iter().find(|port| {
                port.get("id").and_then(Value::as_str) == Some(port_id)
                    && port.get("direction").and_then(Value::as_str) == Some(direction)
            })
        })
        .and_then(|port| port.get("connectionClass").and_then(Value::as_str))
        .map(str::to_string)
    {
        return Some(class);
    }
    workflow_default_port_connection_class(&workflow_node_type(node), port_id, direction)
}

pub(super) fn workflow_default_port_connection_class(
    node_type: &str,
    port_id: &str,
    direction: &str,
) -> Option<String> {
    let class = match (node_type, direction, port_id) {
        (_, "output", "error") | (_, "input", "error") => "error",
        (_, "output", "retry") | (_, "input", "retry") => "retry",
        (_, "output", "approval") | (_, "input", "approval") => "approval",
        ("model_call", "input", "model") | ("model_binding", "output", "model") => "model",
        ("model_call", "input", "memory") | ("state", "output", "memory") => "memory",
        ("model_call", "input", "tool")
        | ("plugin_tool", "output", "tool")
        | ("subgraph", "output", "tool") => "tool",
        ("workflow_package_export", "output", "package")
        | ("workflow_package_import", "input", "package") => "output_bundle",
        ("workflow_package_export", "output", "manifest")
        | ("workflow_package_export", "output", "readiness")
        | ("workflow_package_export", "output", "locale")
        | ("workflow_package_import", "output", "review")
        | ("workflow_package_import", "output", "imported_workflow")
        | ("workflow_package_import", "output", "evidence")
        | ("workflow_package_import", "output", "locale") => "data",
        ("repository_context", "output", "repository")
        | ("branch_policy", "input", "repository")
        | ("branch_policy", "output", "branch_policy")
        | ("github_context", "input", "repository")
        | ("github_context", "input", "branch_policy")
        | ("github_context", "output", "github_context")
        | ("issue_context", "input", "github_context")
        | ("issue_context", "output", "issue_context")
        | ("pr_attempt", "input", "repository")
        | ("pr_attempt", "input", "branch_policy")
        | ("pr_attempt", "input", "github_context")
        | ("pr_attempt", "input", "issue_context")
        | ("pr_attempt", "output", "pr_attempt")
        | ("review_gate", "input", "repository")
        | ("review_gate", "input", "branch_policy")
        | ("review_gate", "input", "github_context")
        | ("review_gate", "input", "issue_context")
        | ("review_gate", "input", "pr_attempt")
        | ("github_pr_create", "input", "repository")
        | ("github_pr_create", "input", "branch_policy")
        | ("github_pr_create", "input", "github_context")
        | ("github_pr_create", "input", "issue_context")
        | ("github_pr_create", "input", "pr_attempt")
        | ("github_pr_create", "output", "blockers") => "state",
        ("review_gate", "output", "review_gate")
        | ("github_pr_create", "input", "review_gate")
        | ("github_pr_create", "output", "plan") => "approval",
        ("github_pr_create", "output", "request") => "data",
        ("model_call", "input", "parser") | ("parser", "output", "parser") => "parser",
        ("subgraph", "input", "subgraph") | ("subgraph", "output", "subgraph") => "subgraph",
        ("output", "input", "delivery") => "delivery",
        (_, _, "input")
        | (_, _, "context")
        | (_, _, "output")
        | (_, _, "left")
        | (_, _, "right") => "data",
        _ => return None,
    };
    Some(class.to_string())
}

pub(super) fn validate_workflow_edge_ports(
    edge: &Value,
    from_node: &Value,
    to_node: &Value,
) -> Result<(), WorkflowValidationIssue> {
    let edge_id = edge.get("id").and_then(Value::as_str).unwrap_or("unknown");
    let from_port = workflow_edge_from_port(edge);
    let to_port = workflow_edge_to_port(edge);
    let source_class = workflow_node_port_connection_class(from_node, &from_port, "output")
        .or_else(|| workflow_edge_connection_class(edge))
        .unwrap_or_else(|| "data".to_string());
    let target_class = workflow_node_port_connection_class(to_node, &to_port, "input")
        .unwrap_or_else(|| {
            workflow_edge_connection_class(edge).unwrap_or_else(|| "data".to_string())
        });
    validate_workflow_connection_class(Some(edge_id.to_string()), &source_class, &target_class)
        .map_err(|issue| WorkflowValidationIssue {
            node_id: issue.action_id,
            code: issue.code,
            message: issue.message,
        })
}

pub(super) fn workflow_node_by_id<'a>(
    workflow: &'a WorkflowProject,
    node_id: &str,
) -> Option<&'a Value> {
    workflow
        .nodes
        .iter()
        .find(|node| workflow_node_id(node).as_deref() == Some(node_id))
}

pub(super) fn workflow_predecessor_output(
    node_id: &str,
    workflow: &WorkflowProject,
    state: &WorkflowStateSnapshot,
) -> Value {
    if let Some(mapped) = workflow_mapped_node_input(node_id, workflow, state) {
        return mapped;
    }
    let mut inputs = serde_json::Map::new();
    for edge in &workflow.edges {
        if workflow_edge_to(edge).as_deref() != Some(node_id) {
            continue;
        }
        if let Some(source_id) = workflow_edge_from(edge) {
            if let Some(output) = state.node_outputs.get(&source_id) {
                inputs.insert(source_id, output.clone());
            }
        }
    }
    if inputs.len() == 1 {
        inputs
            .into_iter()
            .next()
            .map(|(_, value)| value)
            .unwrap_or(Value::Null)
    } else {
        Value::Object(inputs)
    }
}

pub(super) fn workflow_value_at_path(value: &Value, path: &str) -> Option<Value> {
    let mut current = value;
    for segment in path.split('.').filter(|segment| !segment.trim().is_empty()) {
        if segment == "[]" {
            current = current.as_array()?.first()?;
            continue;
        }
        current = current.get(segment)?;
    }
    Some(current.clone())
}

pub(super) fn workflow_first_expression_source(expression: &str) -> Option<(String, String)> {
    let mut refs = Vec::new();
    collect_workflow_expression_refs(&Value::String(expression.to_string()), &mut refs);
    refs.into_iter()
        .next()
        .map(|(_, node_id, port_id)| (node_id, port_id))
}

pub(super) fn workflow_mapped_node_input(
    node_id: &str,
    workflow: &WorkflowProject,
    state: &WorkflowStateSnapshot,
) -> Option<Value> {
    let node = workflow_node_by_id(workflow, node_id)?;
    let logic = workflow_node_logic(node);
    let input_mapping = logic.get("inputMapping").and_then(Value::as_object);
    let field_mappings = logic.get("fieldMappings").and_then(Value::as_object);
    if input_mapping.is_none() && field_mappings.is_none() {
        return None;
    }
    let mut mapped = serde_json::Map::new();
    if let Some(fields) = field_mappings {
        for (key, mapping) in fields {
            let Some(source_expression) = mapping.get("source").and_then(Value::as_str) else {
                continue;
            };
            let Some(path) = mapping.get("path").and_then(Value::as_str) else {
                continue;
            };
            let Some((source_id, _port_id)) = workflow_first_expression_source(source_expression)
            else {
                continue;
            };
            if let Some(source_output) = state.node_outputs.get(&source_id) {
                if let Some(value) = workflow_value_at_path(source_output, path) {
                    mapped.insert(key.clone(), value);
                }
            }
        }
    }
    if let Some(inputs) = input_mapping {
        for (key, expression) in inputs {
            if mapped.contains_key(key) {
                continue;
            }
            let Some(expression_text) = expression.as_str() else {
                continue;
            };
            let Some((source_id, _port_id)) = workflow_first_expression_source(expression_text)
            else {
                continue;
            };
            if let Some(source_output) = state.node_outputs.get(&source_id) {
                mapped.insert(key.clone(), source_output.clone());
            }
        }
    }
    (!mapped.is_empty()).then_some(Value::Object(mapped))
}

pub(super) fn workflow_max_attempts(node: &Value) -> usize {
    let logic = workflow_node_logic(node);
    let law = workflow_node_law(node);
    logic
        .get("retry")
        .and_then(|retry| retry.get("maxAttempts"))
        .or_else(|| {
            law.get("retryPolicy")
                .and_then(|retry| retry.get("maxAttempts"))
        })
        .and_then(Value::as_u64)
        .map(|value| value.clamp(1, 5) as usize)
        .unwrap_or(1)
}

pub(super) fn execute_workflow_tool_binding(
    parent_workflow_path: &Path,
    node_id: &str,
    binding: &WorkflowToolBinding,
    input: Value,
) -> Result<Value, String> {
    let Some(tool) = binding.workflow_tool.as_ref() else {
        return Err("Workflow tool binding is missing a child workflow reference.".to_string());
    };
    let arguments = binding.arguments.clone().unwrap_or_else(|| json!({}));
    if let Some(schema) = tool.argument_schema.as_ref() {
        workflow_json_satisfies_schema(schema, &arguments).map_err(|error| {
            format!(
                "Workflow tool arguments failed schema validation: {}",
                error
            )
        })?;
    }
    let child_path = resolve_workflow_reference_path(parent_workflow_path, &tool.workflow_path)?;
    if child_path == parent_workflow_path {
        return Err("Workflow tools cannot invoke their own workflow.".to_string());
    }
    let child_bundle = load_workflow_bundle_from_path(&child_path)?;
    let child_input = json!({
        "arguments": arguments,
        "input": input
    });
    let max_attempts = tool.max_attempts.unwrap_or(1).clamp(1, 5);
    let mut last_error = None;
    let mut last_child_summary: Option<WorkflowRunSummary> = None;
    for attempt in 1..=max_attempts {
        let child_thread = new_workflow_thread(&child_path, Some(child_input.clone()));
        let child_state = initial_workflow_state(&child_thread, "workflow-tool-start");
        let child_result = execute_workflow_project(
            &child_path,
            child_bundle.clone(),
            child_thread,
            child_state,
            None,
            &WorkflowSkillResolver::default(),
        )?;
        last_child_summary = Some(child_result.summary.clone());
        if child_result.summary.status != "passed" {
            last_error = Some(format!(
                "Workflow tool child run '{}' finished with status {}.",
                child_result.summary.id, child_result.summary.status
            ));
            continue;
        }
        let result = child_result.final_state.values.clone();
        if let Some(schema) = tool.result_schema.as_ref() {
            workflow_json_satisfies_schema(schema, &json!(result)).map_err(|error| {
                format!("Workflow tool result failed schema validation: {}", error)
            })?;
        }
        return Ok(json!({
            "nodeId": node_id,
            "kind": "tool",
            "toolKind": "workflow_tool",
            "toolName": binding.tool_ref,
            "attempt": attempt,
            "maxAttempts": max_attempts,
            "timeoutMs": tool.timeout_ms.unwrap_or(30_000),
            "argumentSchema": tool.argument_schema,
            "resultSchema": tool.result_schema,
            "childWorkflowPath": child_path.display().to_string(),
            "childRunId": child_result.summary.id,
            "childRunStatus": child_result.summary.status,
            "childThreadId": child_result.thread.id,
            "result": result,
            "outputNodeIds": child_result.final_state
                .node_outputs
                .keys()
                .cloned()
                .collect::<Vec<_>>()
        }));
    }
    Err(last_error.unwrap_or_else(|| {
        format!(
            "Workflow tool child workflow failed after {} attempt(s){}.",
            max_attempts,
            last_child_summary
                .map(|summary| format!("; last run was {}", summary.status))
                .unwrap_or_default()
        )
    }))
}

fn execute_workflow_package_export_node(
    workflow_path: &Path,
    node_id: &str,
    logic: &Value,
    input: &Value,
    evidence_kind: &str,
) -> Result<Value, String> {
    let path = workflow_resolved_path_string(logic, input, "workflowPackagePath", workflow_path)
        .unwrap_or_else(|| workflow_path.display().to_string());
    let output_dir =
        workflow_resolved_path_string(logic, input, "workflowPackageOutputDir", workflow_path);
    if logic
        .get("dryRun")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Ok(json!({
            "schemaVersion": "workflow.package-export.output.v1",
            "status": "dry_run",
            "toolName": "workflow.package.export",
            "nodeId": node_id,
            "kind": evidence_kind,
            "workflowPath": path,
            "packagePath": output_dir,
            "portable": false,
            "readinessStatus": "dry_run",
            "workflowChromeLocale": Value::Null,
            "packageEvidenceReady": false,
            "mutationExecuted": false,
            "input": input
        }));
    }
    let package = export_workflow_package(path.clone(), output_dir)?;
    let package_evidence_ready = package.manifest.harness_package_manifest.is_some();
    let package_path = package.package_path.clone();
    let manifest_path = package.manifest_path.clone();
    let manifest = package.manifest.clone();
    Ok(json!({
        "schemaVersion": "workflow.package-export.output.v1",
        "status": if manifest.portable { "ok" } else { "blocked" },
        "toolName": "workflow.package.export",
        "nodeId": node_id,
        "kind": evidence_kind,
        "workflowPath": path,
        "packagePath": package_path,
        "manifestPath": manifest_path,
        "manifest": manifest.clone(),
        "portable": manifest.portable,
        "readinessStatus": manifest.readiness_status,
        "workflowChromeLocale": manifest.workflow_chrome_locale,
        "packageEvidenceReady": package_evidence_ready,
        "mutationExecuted": true,
        "workflowPackageExport": package,
        "input": input
    }))
}

fn execute_workflow_package_import_node(
    workflow_path: &Path,
    node_id: &str,
    logic: &Value,
    input: &Value,
    evidence_kind: &str,
) -> Result<Value, String> {
    let package_path =
        workflow_resolved_path_string(logic, input, "workflowPackagePath", workflow_path)
            .or_else(|| workflow_deep_string_field(input, "packagePath"))
            .ok_or_else(|| "Workflow package import requires a package path.".to_string())?;
    let project_root =
        workflow_resolved_path_string(logic, input, "workflowPackageProjectRoot", workflow_path)
            .unwrap_or_else(|| workflow_project_root_for_path(workflow_path));
    let import_name = workflow_logic_string(logic, "workflowPackageImportName");
    if logic
        .get("dryRun")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Ok(json!({
            "schemaVersion": "workflow.package-import.output.v1",
            "status": "dry_run",
            "toolName": "workflow.package.import",
            "nodeId": node_id,
            "kind": evidence_kind,
            "packagePath": package_path,
            "projectRoot": project_root,
            "importedWorkflowPath": Value::Null,
            "packageEvidenceReady": false,
            "workflowChromeLocalePreserved": false,
            "mutationExecuted": false,
            "input": input
        }));
    }
    let imported = import_workflow_package(ImportWorkflowPackageRequest {
        package_path: package_path.clone(),
        project_root: project_root.clone(),
        name: import_name,
    })?;
    let imported_package = imported.imported_package.clone();
    let imported_workflow_path = imported.workflow_path.clone();
    let manifest = imported_package
        .as_ref()
        .map(|package| package.manifest.clone());
    let source_workflow_chrome_locale = manifest
        .as_ref()
        .and_then(|item| item.workflow_chrome_locale.clone());
    let imported_workflow_chrome_locale = imported
        .workflow
        .global_config
        .get("workflowChromeLocale")
        .and_then(Value::as_str)
        .map(str::to_string);
    let workflow_chrome_locale_preserved =
        source_workflow_chrome_locale == imported_workflow_chrome_locale;
    let package_evidence_ready = manifest
        .as_ref()
        .and_then(|item| item.harness_package_manifest.as_ref())
        .is_some();
    let review = json!({
        "schemaVersion": "workflow.package-import-review.v1",
        "source": {
            "packagePath": package_path.clone(),
            "workflowChromeLocale": source_workflow_chrome_locale.clone(),
            "readinessStatus": manifest
                .as_ref()
                .map(|item| item.readiness_status.clone())
                .unwrap_or_else(|| "unknown".to_string())
        },
        "imported": {
            "workflowPath": imported_workflow_path.clone(),
            "workflowChromeLocale": imported_workflow_chrome_locale.clone()
        },
        "evidence": {
            "packageEvidenceReady": package_evidence_ready,
            "workflowChromeLocalePreserved": workflow_chrome_locale_preserved
        }
    });
    Ok(json!({
        "schemaVersion": "workflow.package-import.output.v1",
        "status": "ok",
        "toolName": "workflow.package.import",
        "nodeId": node_id,
        "kind": evidence_kind,
        "packagePath": package_path,
        "projectRoot": project_root,
        "importedWorkflowPath": imported_workflow_path,
        "review": review.clone(),
        "packageEvidenceReady": package_evidence_ready,
        "workflowChromeLocalePreserved": workflow_chrome_locale_preserved,
        "sourceWorkflowChromeLocale": source_workflow_chrome_locale,
        "importedWorkflowChromeLocale": imported_workflow_chrome_locale,
        "mutationExecuted": true,
        "workflowPackageImport": {
            "workflowPath": imported.workflow_path,
            "importedPackage": imported_package
        },
        "workflowPackageImportReview": review,
        "input": input
    }))
}

pub(super) fn workflow_selected_output(node: &Value, output: &Value) -> String {
    if workflow_node_type(node) != "decision" {
        return "output".to_string();
    }
    output
        .get("branch")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| "left".to_string())
}

pub(super) fn workflow_model_ref_from_input(input: &Value) -> Option<String> {
    input
        .get("modelRef")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
        .or_else(|| {
            input.as_object().and_then(|object| {
                object.values().find_map(|value| {
                    value
                        .get("modelRef")
                        .and_then(Value::as_str)
                        .filter(|model_ref| !model_ref.trim().is_empty())
                        .map(str::to_string)
                })
            })
        })
}

fn workflow_collect_inputs_by_kind(value: &Value, kind: &str, collected: &mut Vec<Value>) {
    if value.get("kind").and_then(Value::as_str) == Some(kind) {
        collected.push(value.clone());
    }
    match value {
        Value::Array(items) => {
            for item in items {
                workflow_collect_inputs_by_kind(item, kind, collected);
            }
        }
        Value::Object(object) => {
            for item in object.values() {
                workflow_collect_inputs_by_kind(item, kind, collected);
            }
        }
        _ => {}
    }
}

fn workflow_inputs_by_kind(input: &Value, kind: &str) -> Vec<Value> {
    let mut collected = Vec::new();
    workflow_collect_inputs_by_kind(input, kind, &mut collected);
    collected
}

pub(super) fn workflow_edge_is_selected(
    edge: &Value,
    branch_decisions: &std::collections::BTreeMap<String, String>,
) -> bool {
    let Some(source_id) = workflow_edge_from(edge) else {
        return false;
    };
    let Some(branch) = branch_decisions.get(&source_id) else {
        return true;
    };
    let from_port = workflow_edge_from_port(edge);
    from_port == *branch || (from_port == "output" && branch == "output")
}

pub(super) fn workflow_node_ready(
    node_id: &str,
    workflow: &WorkflowProject,
    completed: &std::collections::BTreeSet<String>,
    active_queue: &[String],
    branch_decisions: &std::collections::BTreeMap<String, String>,
) -> bool {
    if completed.contains(node_id) || active_queue.iter().any(|queued| queued == node_id) {
        return false;
    }
    let incoming = workflow
        .edges
        .iter()
        .filter(|edge| workflow_edge_to(edge).as_deref() == Some(node_id))
        .collect::<Vec<_>>();
    if incoming.is_empty() {
        return true;
    }
    let mut selected_count = 0usize;
    for edge in incoming {
        let Some(source_id) = workflow_edge_from(edge) else {
            continue;
        };
        if !workflow_edge_is_selected(edge, branch_decisions) {
            continue;
        }
        selected_count += 1;
        if !completed.contains(&source_id) {
            return false;
        }
    }
    selected_count > 0
}

pub(super) fn workflow_next_ready_nodes(
    workflow: &WorkflowProject,
    completed: &std::collections::BTreeSet<String>,
    active_queue: &[String],
    branch_decisions: &std::collections::BTreeMap<String, String>,
) -> Vec<String> {
    workflow
        .nodes
        .iter()
        .filter_map(workflow_node_id)
        .filter(|node_id| {
            workflow_node_ready(node_id, workflow, completed, active_queue, branch_decisions)
        })
        .collect()
}

pub(super) fn workflow_push_event(
    events: &mut Vec<WorkflowStreamEvent>,
    run_id: &str,
    thread_id: &str,
    kind: &str,
    node_id: Option<&str>,
    status: Option<&str>,
    message: Option<String>,
    state_delta: Option<Vec<WorkflowStateUpdate>>,
) {
    let sequence = events.len();
    events.push(WorkflowStreamEvent {
        id: unique_runtime_id("event"),
        run_id: run_id.to_string(),
        thread_id: thread_id.to_string(),
        sequence,
        kind: kind.to_string(),
        created_at_ms: now_ms(),
        node_id: node_id.map(str::to_string),
        status: status.map(str::to_string),
        message,
        state_delta,
    });
}

fn workflow_is_harness(workflow: &WorkflowProject) -> bool {
    workflow
        .metadata
        .harness
        .as_ref()
        .and_then(|harness| harness.get("schemaVersion"))
        .and_then(Value::as_str)
        .map(|schema| schema == "workflow.harness.v1")
        .unwrap_or(false)
        || workflow
            .nodes
            .iter()
            .any(|node| node.get("runtimeBinding").is_some())
}

fn workflow_harness_metadata_string(
    workflow: &WorkflowProject,
    key: &str,
    fallback: &str,
) -> String {
    workflow
        .metadata
        .harness
        .as_ref()
        .and_then(|harness| harness.get(key))
        .and_then(Value::as_str)
        .or_else(|| {
            workflow
                .metadata
                .worker_harness_binding
                .as_ref()
                .and_then(|binding| binding.get(key))
                .and_then(Value::as_str)
        })
        .unwrap_or(fallback)
        .to_string()
}

fn workflow_harness_activation_id(workflow: &WorkflowProject) -> String {
    workflow
        .metadata
        .worker_harness_binding
        .as_ref()
        .and_then(|binding| binding.get("harnessActivationId"))
        .and_then(Value::as_str)
        .or_else(|| {
            workflow
                .metadata
                .harness
                .as_ref()
                .and_then(|harness| harness.get("activationId"))
                .and_then(Value::as_str)
        })
        .unwrap_or(DEFAULT_AGENT_HARNESS_ACTIVATION_ID)
        .to_string()
}

fn workflow_harness_execution_mode(workflow: &WorkflowProject, node: &Value) -> String {
    node.get("runtimeBinding")
        .and_then(|binding| binding.get("executionMode"))
        .and_then(Value::as_str)
        .or_else(|| {
            workflow
                .metadata
                .worker_harness_binding
                .as_ref()
                .and_then(|binding| binding.get("executionMode"))
                .and_then(Value::as_str)
        })
        .or_else(|| {
            workflow
                .metadata
                .harness
                .as_ref()
                .and_then(|harness| harness.get("executionMode"))
                .and_then(Value::as_str)
        })
        .unwrap_or("projection")
        .to_string()
}

fn workflow_hash_value(value: &Value) -> String {
    let bytes = serde_jcs::to_vec(value)
        .or_else(|_| serde_json::to_vec(value))
        .unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn workflow_harness_attempt_status(node_run: &WorkflowNodeRun, execution_mode: &str) -> String {
    match node_run.status.as_str() {
        "error" => "failed".to_string(),
        "blocked" | "interrupted" => "blocked".to_string(),
        _ => execution_mode.to_string(),
    }
}

fn workflow_string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn workflow_harness_attempt_for_node_run(
    workflow: &WorkflowProject,
    run_id: &str,
    node_run: &WorkflowNodeRun,
) -> Option<Value> {
    let node = workflow_node_by_id(workflow, &node_run.node_id)?;
    let binding = node.get("runtimeBinding")?;
    let component_id = binding
        .get("componentId")
        .and_then(Value::as_str)
        .unwrap_or("ioi.agent-harness.unknown.v1");
    let component_kind = binding
        .get("componentKind")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let execution_mode = workflow_harness_execution_mode(workflow, node);
    let readiness = binding
        .get("readiness")
        .and_then(Value::as_str)
        .unwrap_or("projection_only");
    let evidence_refs = workflow_string_array(binding.get("evidenceEventKinds"))
        .into_iter()
        .map(|event| format!("event-kind:{}", event))
        .chain(
            workflow_string_array(binding.get("receiptKinds"))
                .into_iter()
                .map(|receipt| format!("receipt-kind:{}", receipt)),
        )
        .collect::<Vec<_>>();
    let receipt_ids = workflow_string_array(binding.get("receiptKinds"))
        .into_iter()
        .map(|receipt| format!("{}:{}", node_run.node_id, receipt))
        .collect::<Vec<_>>();
    let replay = binding.get("replayEnvelope").cloned().unwrap_or_else(|| {
        let deterministic = binding
            .get("replay")
            .and_then(|replay| replay.get("deterministicEnvelope"))
            .and_then(Value::as_bool)
            .unwrap_or(true);
        json!({
            "deterministicEnvelope": deterministic,
            "capturesInput": true,
            "capturesOutput": true,
            "capturesPolicyDecision": false,
            "determinism": if deterministic { "deterministic" } else { "nondeterministic" },
            "redactionPolicy": "runtime_redacted"
        })
    });
    let captures_policy_decision = replay
        .get("capturesPolicyDecision")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let status = workflow_harness_attempt_status(node_run, &execution_mode);
    let input_hash = node_run.input.as_ref().map(workflow_hash_value);
    let output_hash = node_run.output.as_ref().map(workflow_hash_value);
    let error_class = node_run.error.clone();
    let duration_ms = node_run
        .finished_at_ms
        .map(|finished| finished.saturating_sub(node_run.started_at_ms));

    Some(json!({
        "attemptId": format!("{}:{}:attempt:{}", run_id, node_run.node_id, node_run.attempt),
        "harnessWorkflowId": workflow_harness_metadata_string(
            workflow,
            "harnessWorkflowId",
            DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
        ),
        "harnessActivationId": workflow_harness_activation_id(workflow),
        "harnessHash": workflow_harness_metadata_string(
            workflow,
            "harnessHash",
            DEFAULT_AGENT_HARNESS_HASH,
        ),
        "workflowNodeId": node_run.node_id.clone(),
        "componentId": component_id,
        "componentKind": component_kind,
        "executionMode": execution_mode,
        "readiness": readiness,
        "attemptIndex": node_run.attempt,
        "status": status,
        "inputHash": input_hash,
        "outputHash": output_hash,
        "errorClass": error_class,
        "policyDecision": captures_policy_decision.then(|| {
            if node_run.error.is_some() { "blocked" } else { "allowed" }
        }),
        "startedAtMs": node_run.started_at_ms,
        "durationMs": duration_ms,
        "receiptIds": receipt_ids,
        "evidenceRefs": evidence_refs,
        "replay": replay,
    }))
}

fn workflow_harness_attempt_records_from_values(
    attempts: &[Value],
) -> Vec<HarnessNodeAttemptRecord> {
    attempts
        .iter()
        .filter_map(harness_node_attempt_record_from_camel_value)
        .collect()
}

fn workflow_harness_shadow_comparison_records_for_attempt_records(
    attempts: &[HarnessNodeAttemptRecord],
) -> Vec<HarnessShadowComparison> {
    let mut comparisons = Vec::new();
    let mut live_by_component = std::collections::BTreeMap::new();
    let mut shadow_by_component = std::collections::BTreeMap::new();
    for attempt in attempts {
        match attempt.execution_mode {
            HarnessExecutionMode::Live | HarnessExecutionMode::Gated => {
                live_by_component.insert(attempt.component_id.clone(), attempt);
            }
            HarnessExecutionMode::Shadow => {
                shadow_by_component.insert(attempt.component_id.clone(), attempt);
            }
            _ => {}
        }
    }
    for (component_id, live) in live_by_component {
        let Some(shadow) = shadow_by_component.get(&component_id) else {
            continue;
        };
        comparisons.push(compare_harness_live_shadow_attempts(live, shadow));
    }
    comparisons
}

fn workflow_harness_gated_cluster_runs_for_attempt_records(
    run_id: &str,
    attempts: Vec<HarnessNodeAttemptRecord>,
    comparisons: Vec<HarnessShadowComparison>,
) -> Vec<Value> {
    let shadow_run = default_harness_shadow_run_for_attempts(
        run_id.to_string(),
        None,
        None,
        attempts,
        comparisons,
        vec![format!("workflow-run:{run_id}")],
    );
    [
        HarnessPromotionClusterId::Cognition,
        HarnessPromotionClusterId::RoutingModel,
        HarnessPromotionClusterId::VerificationOutput,
        HarnessPromotionClusterId::AuthorityTooling,
    ]
    .into_iter()
    .map(|cluster_id| {
        harness_gated_cluster_run_camel_value(&default_harness_gated_cluster_run_for_shadow_run(
            cluster_id,
            &shadow_run,
        ))
    })
    .collect()
}

fn workflow_attach_harness_run_artifacts(
    workflow: &WorkflowProject,
    run_id: &str,
    node_runs: &mut [WorkflowNodeRun],
) -> (Vec<Value>, Vec<Value>, Vec<Value>) {
    if !workflow_is_harness(workflow) {
        return (Vec::new(), Vec::new(), Vec::new());
    }
    let mut attempts = Vec::new();
    for node_run in node_runs {
        if let Some(attempt) = workflow_harness_attempt_for_node_run(workflow, run_id, node_run) {
            node_run.harness_attempt = Some(attempt.clone());
            attempts.push(attempt);
        }
    }
    let attempt_records = workflow_harness_attempt_records_from_values(&attempts);
    let comparison_records =
        workflow_harness_shadow_comparison_records_for_attempt_records(&attempt_records);
    let comparisons = comparison_records
        .iter()
        .map(harness_shadow_comparison_camel_value)
        .collect();
    let gated_cluster_runs = workflow_harness_gated_cluster_runs_for_attempt_records(
        run_id,
        attempt_records,
        comparison_records,
    );
    (attempts, comparisons, gated_cluster_runs)
}

pub(super) fn workflow_node_lifecycle_steps(status: &str) -> Vec<String> {
    let mut steps = vec![
        "validate_config",
        "resolve_binding",
        "check_policy",
        "prepare_inputs",
        "execute_attempt",
    ];
    match status {
        "success" => steps.extend([
            "validate_output",
            "record_run",
            "checkpoint",
            "emit_event",
            "evaluate_completion",
        ]),
        "interrupted" => {
            steps.extend(["record_interrupt", "record_run", "checkpoint", "emit_event"])
        }
        "error" | "blocked" => steps.extend(["record_run", "checkpoint", "emit_event"]),
        _ => {}
    }
    steps.into_iter().map(str::to_string).collect()
}

pub(super) fn workflow_output_satisfies_schema(node: &Value, output: &Value) -> Result<(), String> {
    let Some(schema) = workflow_node_schema(node, "outputSchema") else {
        return Ok(());
    };
    workflow_output_satisfies_test_schema(&schema, output)
}

pub(super) fn workflow_truncate_output(value: &[u8], limit: usize) -> String {
    let capped = if value.len() > limit {
        &value[..limit]
    } else {
        value
    };
    String::from_utf8_lossy(capped).to_string()
}

pub(super) fn execute_workflow_function_node(node: &Value, input: Value) -> Result<Value, String> {
    let node_id = workflow_node_id(node).unwrap_or_else(|| "unknown".to_string());
    let binding = workflow_function_binding(node)?;
    workflow_function_dependency_precheck(&binding)?;
    if let Some(schema) = workflow_function_input_schema(&binding) {
        workflow_json_satisfies_schema(schema, &input)
            .map_err(|error| format!("Function input failed schema validation: {}", error))?;
    }
    let mut code_hash = None;
    let function_source = if let Some(function_ref) = binding.function_ref.as_ref() {
        let source_path = PathBuf::from(&function_ref.source_path);
        if source_path.exists() {
            code_hash = workflow_file_sha256(&source_path).ok();
            fs::read_to_string(&source_path).map_err(|error| {
                format!(
                    "Failed to read workflow function source '{}': {}",
                    source_path.display(),
                    error
                )
            })?
        } else {
            binding.code.clone()
        }
    } else {
        binding.code.clone()
    };
    let language = binding.language.trim().to_lowercase();
    if language != "javascript" && language != "typescript" {
        return Err(format!(
            "Function language '{}' is not supported in the local sandbox.",
            binding.language
        ));
    }
    let policy = workflow_sandbox_policy(&binding, node);
    workflow_function_sandbox_precheck(&function_source, &policy)?;
    let timeout_ms = policy.timeout_ms.unwrap_or(1000).clamp(50, 30_000);
    let memory_mb = policy.memory_mb.unwrap_or(64).clamp(16, 256);
    let output_limit = policy
        .output_limit_bytes
        .unwrap_or(32768)
        .clamp(1024, 262_144);
    let script_path =
        std::env::temp_dir().join(format!("{}-function.js", unique_runtime_id("workflow")));
    let script = format!(
        r#"
const vm = require("vm");
const source = {code};
const input = {input};
const stdoutLogs = [];
const stderrLogs = [];
const sandbox = {{
  input,
  context: {{ input }},
  console: {{
    log: (...args) => stdoutLogs.push(args.map((item) => typeof item === "string" ? item : JSON.stringify(item)).join(" ")),
    error: (...args) => stderrLogs.push(args.map(String).join(" "))
  }},
  JSON,
  Math,
  Date,
}};
const wrapped = `(function(){{ "use strict"; const require = undefined; const process = undefined; const fetch = undefined; const Buffer = undefined; ${{source}}\n}})()`;
try {{
  const result = vm.runInNewContext(wrapped, sandbox, {{ timeout: {timeout_ms} }});
  process.stdout.write(JSON.stringify({{ ok: true, result, stdout: stdoutLogs.join("\n"), stderr: stderrLogs.join("\n") }}));
}} catch (error) {{
  process.stdout.write(JSON.stringify({{ ok: false, error: String(error && error.message ? error.message : error), stdout: stdoutLogs.join("\n"), stderr: stderrLogs.join("\n") }}));
  process.exitCode = 1;
}}
"#,
        code = serde_json::to_string(&function_source).map_err(|error| error.to_string())?,
        input = serde_json::to_string(&input).map_err(|error| error.to_string())?,
        timeout_ms = timeout_ms,
    );
    fs::write(&script_path, script)
        .map_err(|error| format!("Failed to prepare function sandbox: {}", error))?;
    let mut child = Command::new("node")
        .arg(format!("--max-old-space-size={}", memory_mb))
        .arg(&script_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("Failed to start JavaScript sandbox: {}", error))?;
    let deadline = Instant::now() + Duration::from_millis(timeout_ms + 250);
    loop {
        if child
            .try_wait()
            .map_err(|error| format!("Failed to poll JavaScript sandbox: {}", error))?
            .is_some()
        {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = fs::remove_file(&script_path);
            return Err(format!("Function timed out after {}ms.", timeout_ms));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child
        .wait_with_output()
        .map_err(|error| format!("Failed to collect JavaScript sandbox output: {}", error))?;
    let _ = fs::remove_file(&script_path);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let process_stderr = workflow_truncate_output(&output.stderr, output_limit);
    let payload: Value = serde_json::from_str(&stdout).map_err(|error| {
        format!(
            "Function sandbox returned invalid JSON: {} | stderr={}",
            error, process_stderr
        )
    })?;
    if !payload.get("ok").and_then(Value::as_bool).unwrap_or(false) {
        return Err(payload
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("Function execution failed.")
            .to_string());
    }
    let result = payload.get("result").cloned().unwrap_or(Value::Null);
    let function_stdout = payload
        .get("stdout")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let function_stderr = payload
        .get("stderr")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let output_bytes = serde_json::to_vec(&result)
        .map_err(|error| format!("Failed to measure function output: {}", error))?
        .len()
        + function_stdout.as_bytes().len()
        + function_stderr.as_bytes().len();
    if output_bytes > output_limit {
        return Err(format!(
            "Function output exceeded sandbox output limit of {} bytes.",
            output_limit
        ));
    }
    if let Some(schema) = workflow_function_output_schema(&binding) {
        let wrapper = json!({ "schema": schema });
        workflow_output_satisfies_schema(&wrapper, &result)?;
    }
    Ok(json!({
        "nodeId": node_id,
        "kind": "function",
        "language": binding.language,
        "result": result,
        "stdout": function_stdout,
        "stderr": if function_stderr.is_empty() { process_stderr } else { function_stderr },
        "codeHash": code_hash.or_else(|| binding.function_ref.as_ref().and_then(|function_ref| function_ref.code_hash.clone())),
        "dependencyManifest": binding.function_ref.as_ref().and_then(|function_ref| function_ref.dependency_manifest.clone()),
        "sandbox": {
            "timeoutMs": timeout_ms,
            "memoryMb": memory_mb,
            "outputLimitBytes": output_limit,
            "permissions": policy.permissions
        }
    }))
}

pub(super) fn workflow_output_bundle(
    node_id: &str,
    node_name: &str,
    logic: &Value,
    input: Value,
) -> Value {
    let format = logic
        .get("format")
        .and_then(Value::as_str)
        .unwrap_or("markdown")
        .to_string();
    let renderer_ref = logic
        .get("rendererRef")
        .cloned()
        .and_then(|value| serde_json::from_value::<WorkflowRendererRef>(value).ok());
    let delivery_target = logic
        .get("deliveryTarget")
        .cloned()
        .and_then(|value| serde_json::from_value::<WorkflowDeliveryTarget>(value).ok());
    let version = logic
        .get("versioning")
        .cloned()
        .and_then(|value| serde_json::from_value::<WorkflowOutputVersioning>(value).ok());
    let materialized_assets = logic
        .get("materialization")
        .and_then(Value::as_object)
        .filter(|materialization| {
            materialization
                .get("enabled")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        })
        .map(|materialization| {
            vec![WorkflowMaterializedAsset {
                id: unique_runtime_id("asset"),
                node_id: node_id.to_string(),
                asset_kind: materialization
                    .get("assetKind")
                    .and_then(Value::as_str)
                    .unwrap_or("file")
                    .to_string(),
                path: materialization
                    .get("assetPath")
                    .and_then(Value::as_str)
                    .filter(|value| !value.trim().is_empty())
                    .map(str::to_string),
                hash: None,
                created_at_ms: now_ms(),
            }]
        })
        .unwrap_or_default();
    let bundle = WorkflowOutputBundle {
        id: unique_runtime_id("output"),
        node_id: node_id.to_string(),
        format,
        value: input,
        renderer_ref,
        materialized_assets,
        delivery_target,
        dependency_refs: Vec::new(),
        evidence_refs: Vec::new(),
        version,
        created_at_ms: now_ms(),
    };
    json!({
        "nodeId": node_id,
        "kind": "output",
        "outputName": node_name,
        "outputBundle": bundle
    })
}

pub(super) fn workflow_runtime_approval_binding(
    node: &Value,
    action_kind: &ActionKind,
) -> Option<Value> {
    let logic = workflow_node_logic(node);
    match action_kind {
        ActionKind::AdapterConnector => {
            let binding = workflow_connector_binding(node).ok()?;
            binding.requires_approval.then(|| {
                json!({
                    "bindingKind": "connector",
                    "ref": binding.connector_ref,
                    "operation": binding.operation,
                    "mockBinding": binding.mock_binding,
                    "sideEffectClass": binding.side_effect_class,
                    "capabilityScope": binding.capability_scope
                })
            })
        }
        ActionKind::PluginTool => {
            let binding = workflow_tool_binding(node).ok()?;
            binding.requires_approval.then(|| {
                json!({
                    "bindingKind": binding.binding_kind.unwrap_or_else(|| "plugin_tool".to_string()),
                    "ref": binding.tool_ref,
                    "arguments": binding.arguments,
                    "mockBinding": binding.mock_binding,
                    "sideEffectClass": binding.side_effect_class,
                    "capabilityScope": binding.capability_scope,
                    "workflowTool": binding.workflow_tool
                })
            })
        }
        ActionKind::WorkflowPackageImport => {
            let law = workflow_node_law(node);
            law.get("requireHumanGate")
                .and_then(Value::as_bool)
                .unwrap_or(false)
                .then(|| {
                    json!({
                        "bindingKind": "workflow_package",
                        "operation": "import",
                        "packagePath": workflow_logic_string(&logic, "workflowPackagePath"),
                        "projectRoot": workflow_logic_string(&logic, "workflowPackageProjectRoot"),
                        "sideEffectClass": "write",
                        "capabilityScope": ["workflow.package.import", "workflow.package.review"]
                    })
                })
        }
        ActionKind::GithubPrCreate => {
            if workflow_value_bool_any(&logic, &["dryRun", "previewOnly"]).unwrap_or(true) {
                None
            } else {
                Some(json!({
                    "bindingKind": "github",
                    "operation": "pr_create",
                    "toolName": "github__pr_create",
                    "repoFullName": workflow_value_string_any(&logic, &["repoFullName", "repository"]),
                    "sideEffectClass": "external_write",
                    "capabilityScope": ["github.pr.create"]
                }))
            }
        }
        ActionKind::Output => {
            let delivery_requires_approval = logic
                .get("deliveryTarget")
                .and_then(|target| target.get("requiresApproval"))
                .and_then(Value::as_bool)
                .unwrap_or(false);
            delivery_requires_approval.then(|| {
                json!({
                    "bindingKind": "delivery",
                    "target": logic.get("deliveryTarget").cloned().unwrap_or(Value::Null),
                    "materialization": logic.get("materialization").cloned().unwrap_or(Value::Null),
                    "sideEffectClass": logic.get("sideEffectClass").cloned().unwrap_or_else(|| json!("write"))
                })
            })
        }
        _ => None,
    }
}

pub(super) fn workflow_runtime_approval_preview(
    node: &Value,
    action_kind: &ActionKind,
    input: &Value,
) -> Option<Value> {
    let binding = workflow_runtime_approval_binding(node, action_kind)?;
    Some(json!({
        "nodeId": workflow_node_id(node),
        "nodeName": workflow_node_name(node),
        "nodeType": workflow_node_type(node),
        "binding": binding,
        "input": input,
        "reason": "This node is configured to pause before its side effect runs."
    }))
}

pub(super) fn workflow_runtime_interrupt_prompt(node: &Value, action_kind: &ActionKind) -> String {
    if action_kind.is_interrupt() {
        return workflow_node_logic(node)
            .get("text")
            .and_then(Value::as_str)
            .unwrap_or("Review and choose how this run should continue.")
            .to_string();
    }
    format!(
        "Approve '{}' before this node runs.",
        workflow_node_name(node)
    )
}

pub(super) fn execute_workflow_node(
    workflow_path: &Path,
    workflow: Option<&WorkflowProject>,
    node: &Value,
    input: Value,
    attempt: usize,
    resume_outcome: Option<&Value>,
    skill_resolver: &WorkflowSkillResolver,
) -> Result<Value, String> {
    let frame = workflow_action_frame(node);
    let node_id = frame.id.clone();
    let node_name = frame.label.clone();
    let node_type = frame.kind.node_type().to_string();
    let action_kind = frame.kind.clone();
    let logic = workflow_node_logic(node);

    if logic
        .get("failUntilAttempt")
        .and_then(Value::as_u64)
        .map(|limit| attempt as u64 <= limit)
        .unwrap_or(false)
    {
        return Err(format!(
            "Node '{}' failed on attempt {}.",
            node_name, attempt
        ));
    }
    if logic.get("fail").and_then(Value::as_bool).unwrap_or(false) {
        return Err(format!(
            "Node '{}' requested a deterministic failure.",
            node_name
        ));
    }

    let evidence_kind = action_kind.evidence_kind();
    let output = match action_kind {
        ActionKind::SourceInput => {
            let payload = logic
                .get("payload")
                .or_else(|| logic.get("variables"))
                .cloned()
                .unwrap_or_else(|| json!({"source": node_name}));
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "payload": payload
            })
        }
        ActionKind::Trigger => {
            let trigger_kind = logic
                .get("triggerKind")
                .and_then(Value::as_str)
                .unwrap_or("manual");
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "triggerKind": trigger_kind,
                "schedule": logic.get("cronSchedule").cloned().unwrap_or(Value::Null),
                "eventSourceRef": logic.get("eventSourceRef").cloned().unwrap_or(Value::Null),
                "dedupeKey": logic.get("dedupeKey").cloned().unwrap_or(Value::Null),
                "payload": input
            })
        }
        ActionKind::TaskState => {
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "currentObjective": logic.get("objective").cloned().unwrap_or_else(|| input.clone()),
                "knownFacts": logic.get("knownFacts").cloned().unwrap_or_else(|| json!([])),
                "uncertainFacts": logic.get("uncertainFacts").cloned().unwrap_or_else(|| json!([])),
                "constraints": logic.get("constraints").cloned().unwrap_or_else(|| json!([])),
                "evidenceRefs": logic.get("evidenceRefs").cloned().unwrap_or_else(|| json!([])),
                "input": input
            })
        }
        ActionKind::UncertaintyGate => {
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "ambiguityLevel": logic.get("ambiguityLevel").and_then(Value::as_str).unwrap_or("medium"),
                "selectedAction": logic.get("selectedAction").and_then(Value::as_str).unwrap_or("probe"),
                "valueOfProbe": logic.get("valueOfProbe").and_then(Value::as_str).unwrap_or("medium"),
                "input": input
            })
        }
        ActionKind::Probe => {
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "hypothesis": logic.get("hypothesis").cloned().unwrap_or_else(|| json!("Probe workflow assumption")),
                "cheapestValidationAction": logic.get("cheapestValidationAction").cloned().unwrap_or_else(|| json!("Inspect current workflow evidence")),
                "result": logic.get("result").cloned().unwrap_or_else(|| json!("confirmed")),
                "input": input
            })
        }
        ActionKind::BudgetGate => {
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "budget": logic.get("budget").cloned().unwrap_or_else(|| json!({"maxToolCalls": 1, "maxRetries": 0})),
                "decision": logic.get("decision").and_then(Value::as_str).unwrap_or("continue"),
                "input": input
            })
        }
        ActionKind::CapabilitySequence => {
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "sequence": logic.get("sequence").cloned().unwrap_or_else(|| json!(["discover", "select", "execute", "verify"])),
                "input": input
            })
        }
        ActionKind::RepositoryContext => {
            workflow_repository_context_output(workflow_path, &node_id, &logic, evidence_kind)
        }
        ActionKind::BranchPolicy => {
            workflow_branch_policy_output(&node_id, &logic, &input, evidence_kind)
        }
        ActionKind::GithubContext => {
            workflow_github_context_output(&node_id, &logic, &input, evidence_kind)
        }
        ActionKind::IssueContext => {
            workflow_issue_context_output(&node_id, &logic, &input, evidence_kind)
        }
        ActionKind::PrAttempt => {
            workflow_pr_attempt_output(&node_id, &logic, &input, evidence_kind)
        }
        ActionKind::ReviewGate => {
            workflow_review_gate_output(&node_id, &logic, &input, evidence_kind)
        }
        ActionKind::GithubPrCreate => {
            workflow_github_pr_create_output(&node_id, &logic, &input, evidence_kind)?
        }
        ActionKind::WorkflowPackageExport => execute_workflow_package_export_node(
            workflow_path,
            &node_id,
            &logic,
            &input,
            evidence_kind,
        )?,
        ActionKind::WorkflowPackageImport => execute_workflow_package_import_node(
            workflow_path,
            &node_id,
            &logic,
            &input,
            evidence_kind,
        )?,
        ActionKind::DryRun => {
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "sideEffectPreview": true,
                "mutationExecuted": false,
                "input": input
            })
        }
        ActionKind::Function => execute_workflow_function_node(node, input.clone())?,
        ActionKind::ModelBinding => {
            let binding = workflow_model_binding(node)?;
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "modelRef": binding.model_ref,
                "capabilityScope": binding.capability_scope,
                "resultSchema": binding.result_schema.or_else(|| logic.get("outputSchema").cloned()),
                "mockBinding": binding.mock_binding,
                "credentialReady": binding.credential_ready.unwrap_or(false),
                "toolUseMode": binding.tool_use_mode.unwrap_or_else(|| "none".to_string())
            })
        }
        ActionKind::SkillContext => {
            skill_resolver.resolve_skill_context(workflow, &node_id, &logic, &input)?
        }
        ActionKind::ModelCall => {
            let model_ref = logic
                .get("modelRef")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .map(str::to_string)
                .or_else(|| workflow_model_ref_from_input(&input))
                .ok_or_else(|| "Model binding is missing.".to_string())?;
            let parser_attachment = workflow_inputs_by_kind(&input, "parser").into_iter().next();
            let skill_context_attachment = workflow_inputs_by_kind(&input, "skill_context")
                .into_iter()
                .next();
            let memory_attachment = workflow_inputs_by_kind(&input, "state").into_iter().next();
            let mut tool_attachments = workflow_inputs_by_kind(&input, "plugin_tool");
            tool_attachments.extend(workflow_inputs_by_kind(&input, "tool"));
            let tool_calls = tool_attachments
                .iter()
                .map(|tool| {
                    json!({
                        "toolName": tool
                            .get("toolName")
                            .or_else(|| tool.get("toolKind"))
                            .cloned()
                            .unwrap_or(Value::Null),
                        "mockBinding": tool.get("mockBinding").cloned().unwrap_or(Value::Null),
                        "sideEffectClass": tool.get("sideEffectClass").cloned().unwrap_or(Value::Null),
                        "result": tool
                            .get("result")
                            .or_else(|| tool.get("input"))
                            .cloned()
                            .unwrap_or(Value::Null)
                    })
                })
                .collect::<Vec<_>>();
            let parsed_output_schema = parser_attachment
                .as_ref()
                .and_then(|parser| parser.get("resultSchema").cloned())
                .or_else(|| logic.get("outputSchema").cloned());
            let memory_send_options = workflow_memory_send_options(&logic, &node_id);
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "modelRef": model_ref,
                "message": format!("{} completed with bound model {}.", node_name, model_ref),
                "input": input,
                "attachments": {
                    "skillContext": skill_context_attachment,
                    "parser": parser_attachment,
                    "memory": memory_attachment,
                    "memoryPolicy": memory_send_options.clone(),
                    "tools": tool_attachments
                },
                "runtimeSendOptions": {
                    "memory": memory_send_options
                },
                "toolCalls": tool_calls,
                "structuredOutputSchema": parsed_output_schema,
                "streaming": {
                    "eventKinds": ["node_started", "state_updated", "node_succeeded"]
                }
            })
        }
        ActionKind::Parser => {
            let binding = workflow_parser_binding(node)?;
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "parserRef": binding.parser_ref,
                "parserKind": binding.parser_kind,
                "resultSchema": binding.result_schema.or_else(|| logic.get("outputSchema").cloned()),
                "mockBinding": binding.mock_binding.unwrap_or(true)
            })
        }
        ActionKind::AdapterConnector => {
            let binding = workflow_connector_binding(node)?;
            if !binding.mock_binding
                && workflow_side_effect_requires_live_runtime(&binding.side_effect_class)
            {
                return Err(
                    "Live connector writes require a configured approval-backed connector runtime."
                        .to_string(),
                );
            }
            let provider_catalog = workflow_live_mcp_provider_catalog(&binding, &input);
            let connector_catalog = workflow_live_connector_catalog_describe(&binding, &input)?;
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "connector": binding.connector_ref,
                "mockBinding": binding.mock_binding,
                "credentialReady": binding.credential_ready.unwrap_or(false),
                "sideEffectClass": binding.side_effect_class,
                "operation": binding.operation,
                "providerCatalog": provider_catalog,
                "connectorCatalog": connector_catalog,
                "input": input
            })
        }
        ActionKind::PluginTool => {
            let binding = workflow_tool_binding(node)?;
            if binding.binding_kind.as_deref() == Some("workflow_tool") {
                execute_workflow_tool_binding(workflow_path, &node_id, &binding, input.clone())?
            } else {
                if !binding.mock_binding
                    && workflow_side_effect_requires_live_runtime(&binding.side_effect_class)
                {
                    return Err(
                    "Live plugin side effects require a configured approval-backed tool runtime."
                        .to_string(),
                );
                }
                let tool_ref = binding.tool_ref.clone();
                let arguments = binding.arguments.clone().unwrap_or_else(|| json!({}));
                if let Some(schema) = binding.argument_schema.as_ref() {
                    workflow_json_satisfies_schema(schema, &arguments).map_err(|error| {
                        format!("Tool arguments failed schema validation: {}", error)
                    })?;
                }
                let live_mcp_tool_catalog =
                    workflow_live_mcp_tool_catalog(&binding, &arguments, &input)?;
                let live_native_tool_catalog = if live_mcp_tool_catalog.is_none() {
                    workflow_live_native_tool_catalog(&binding, &arguments, &input)?
                } else {
                    None
                };
                let result = live_mcp_tool_catalog
                    .or(live_native_tool_catalog)
                    .unwrap_or_else(|| {
                        json!({
                            "toolRef": tool_ref,
                            "arguments": arguments.clone(),
                            "input": input
                        })
                    });
                if let Some(schema) = binding.result_schema.as_ref() {
                    workflow_json_satisfies_schema(schema, &result).map_err(|error| {
                        format!("Tool result failed schema validation: {}", error)
                    })?;
                }
                json!({
                    "nodeId": node_id,
                    "kind": evidence_kind,
                    "toolName": tool_ref,
                    "mockBinding": binding.mock_binding,
                    "credentialReady": binding.credential_ready.unwrap_or(false),
                    "sideEffectClass": binding.side_effect_class,
                    "arguments": arguments,
                    "argumentSchema": binding.argument_schema,
                    "resultSchema": binding.result_schema,
                    "mcpToolCatalog": if result.get("schemaVersion").and_then(Value::as_str) == Some("workflow.mcp-tool.catalog-read.v1") { Some(result.clone()) } else { None },
                    "nativeToolCatalog": if result.get("schemaVersion").and_then(Value::as_str) == Some("workflow.native-tool.catalog-read.v1") { Some(result.clone()) } else { None },
                    "result": result
                })
            }
        }
        ActionKind::Decision => {
            let branch = logic
                .get("defaultRoute")
                .and_then(Value::as_str)
                .or_else(|| {
                    logic
                        .get("routes")
                        .and_then(Value::as_array)
                        .and_then(|routes| routes.first())
                        .and_then(Value::as_str)
                })
                .unwrap_or("left");
            let authority_policy_gate = workflow_live_authority_policy_gate(&logic, &input)?;
            let authority_destructive_denial =
                workflow_live_authority_destructive_denial(&logic, &input)?;
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "branch": branch,
                "authorityPolicyGate": authority_policy_gate,
                "authorityDestructiveDenial": authority_destructive_denial,
                "input": input
            })
        }
        ActionKind::State => {
            let key = logic
                .get("stateKey")
                .and_then(Value::as_str)
                .unwrap_or("memory");
            let operation = logic
                .get("stateOperation")
                .and_then(Value::as_str)
                .unwrap_or("merge");
            if matches!(operation, "memory_search" | "memory_list") {
                workflow_memory_query_output(&logic, &input, &node_id, evidence_kind)
            } else {
                let reducer =
                    logic
                        .get("reducer")
                        .and_then(Value::as_str)
                        .unwrap_or(match operation {
                            "append" => "append",
                            "merge" => "merge",
                            _ => "replace",
                        });
                json!({
                    "nodeId": node_id,
                    "kind": evidence_kind,
                    "stateKey": key,
                    "operation": operation,
                    "reducer": reducer,
                    "value": input
                })
            }
        }
        ActionKind::Loop => {
            let max_iterations = logic
                .get("maxIterations")
                .and_then(Value::as_u64)
                .unwrap_or(3);
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "branch": "output",
                "maxIterations": max_iterations,
                "input": input
            })
        }
        ActionKind::Barrier => {
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "strategy": logic.get("barrierStrategy").and_then(Value::as_str).unwrap_or("all"),
                "inputs": input
            })
        }
        ActionKind::Subgraph => {
            let path = logic
                .get("subgraphRef")
                .and_then(|ref_value| ref_value.get("workflowPath"))
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| "Subgraph workflow path is missing.".to_string())?;
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "childWorkflowPath": path,
                "childRunStatus": "blocked",
                "summary": "Subgraph invocation is bound but deferred to child workflow runtime.",
                "input": input
            })
        }
        ActionKind::HumanGate => {
            let Some(outcome) = resume_outcome else {
                return Err("Human gate requires an interrupt.".to_string());
            };
            let wallet_capability_dry_run =
                workflow_live_wallet_capability_dry_run(&logic, outcome, &input)?;
            let authority_approval_gate =
                workflow_live_authority_approval_gate(&logic, outcome, &input)?;
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "outcome": outcome,
                "authorityApprovalGate": authority_approval_gate,
                "walletCapabilityDryRun": wallet_capability_dry_run,
                "input": input
            })
        }
        ActionKind::SemanticImpact => {
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "changedSymbols": logic.get("changedSymbols").cloned().unwrap_or_else(|| json!([])),
                "changedApis": logic.get("changedApis").cloned().unwrap_or_else(|| json!([])),
                "affectedTests": logic.get("affectedTests").cloned().unwrap_or_else(|| json!([])),
                "riskClass": logic.get("riskClass").and_then(Value::as_str).unwrap_or("bounded"),
                "input": input
            })
        }
        ActionKind::PostconditionSynthesis => {
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "checks": logic.get("checks").cloned().unwrap_or_else(|| json!([])),
                "minimumEvidence": logic.get("minimumEvidence").cloned().unwrap_or_else(|| json!(["trace", "receipt", "stop_condition"])),
                "input": input
            })
        }
        ActionKind::Verifier => {
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "independent": logic.get("independent").and_then(Value::as_bool).unwrap_or(true),
                "verdict": logic.get("verdict").and_then(Value::as_str).unwrap_or("passed"),
                "input": input
            })
        }
        ActionKind::DriftDetector => {
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "signals": logic.get("signals").cloned().unwrap_or_else(|| json!([])),
                "driftDetected": logic.get("driftDetected").and_then(Value::as_bool).unwrap_or(false),
                "input": input
            })
        }
        ActionKind::QualityLedger => {
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "scorecard": logic.get("scorecard").cloned().unwrap_or_else(|| json!({})),
                "taskPassRate": logic.get("taskPassRate").and_then(Value::as_f64).unwrap_or(1.0),
                "input": input
            })
        }
        ActionKind::Handoff => {
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "objectivePreserved": true,
                "evidencePreserved": true,
                "nextAction": logic.get("nextAction").and_then(Value::as_str).unwrap_or("continue"),
                "input": input
            })
        }
        ActionKind::GuiHarnessValidation => {
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "markdownStatus": logic.get("markdownStatus").and_then(Value::as_str).unwrap_or("unknown"),
                "mermaidStatus": logic.get("mermaidStatus").and_then(Value::as_str).unwrap_or("unknown"),
                "sourceChipStatus": logic.get("sourceChipStatus").and_then(Value::as_str).unwrap_or("unknown"),
                "input": input
            })
        }
        ActionKind::Output => workflow_output_bundle(&node_id, &node_name, &logic, input),
        ActionKind::TestAssertion => {
            let assertion = logic
                .get("assertion")
                .cloned()
                .and_then(|value| serde_json::from_value::<WorkflowTestAssertion>(value).ok())
                .unwrap_or_else(|| WorkflowTestAssertion {
                    kind: logic
                        .get("assertionKind")
                        .and_then(Value::as_str)
                        .unwrap_or("node_exists")
                        .to_string(),
                    expected: logic.get("expected").cloned(),
                    expression: logic
                        .get("expression")
                        .and_then(Value::as_str)
                        .map(str::to_string),
                });
            let (passed, message) = workflow_evaluate_value_assertion(&assertion, &input, None)?;
            if !passed {
                return Err(format!("Test assertion failed: {}", message));
            }
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "assertionKind": assertion.kind,
                "passed": passed,
                "message": message,
                "input": input
            })
        }
        ActionKind::Proposal => {
            let proposal_action = logic.get("proposalAction").cloned().unwrap_or_else(|| {
                json!({
                    "actionKind": "create",
                    "boundedTargets": [],
                    "requiresApproval": true
                })
            });
            let bounded_count = proposal_action
                .get("boundedTargets")
                .and_then(Value::as_array)
                .map(Vec::len)
                .unwrap_or(0);
            if bounded_count == 0 {
                return Err("Proposal node requires bounded targets.".to_string());
            }
            json!({
                "nodeId": node_id,
                "kind": evidence_kind,
                "proposal": proposal_action,
                "input": input
            })
        }
        ActionKind::Unknown => {
            return Err(format!("Unsupported workflow node type '{}'.", node_type))
        }
    };
    workflow_output_satisfies_schema(node, &output)?;
    Ok(output)
}

pub(crate) fn execute_workflow_harness_canary_node(
    node: &Value,
    input: Value,
    attempt: usize,
) -> Result<Value, String> {
    let canary_human_gate_outcome = (workflow_node_type(node) == "human_gate").then(|| {
        json!({
            "approved": true,
            "decision": "approved",
            "reason": "Synthetic approval outcome for non-mutating harness canary execution.",
            "authorityTransferred": false
        })
    });
    execute_workflow_node(
        Path::new(".agents/workflows/default-agent-harness.workflow.json"),
        None,
        node,
        input,
        attempt,
        canary_human_gate_outcome.as_ref(),
        &WorkflowSkillResolver::default(),
    )
}

pub(crate) fn execute_workflow_harness_live_default_node(
    node: &Value,
    input: Value,
    attempt: usize,
) -> Result<Value, String> {
    let default_human_gate_outcome = (workflow_node_type(node) == "human_gate").then(|| {
        json!({
            "approved": true,
            "decision": "approved",
            "reason": "Synthetic approval outcome for read-only blessed default harness dispatch.",
            "authorityTransferred": false
        })
    });
    execute_workflow_node(
        Path::new(".agents/workflows/default-agent-harness.workflow.json"),
        None,
        node,
        input,
        attempt,
        default_human_gate_outcome.as_ref(),
        &WorkflowSkillResolver::default(),
    )
}

pub(super) fn workflow_checkpoint_state(
    workflow_path: &Path,
    state: &mut WorkflowStateSnapshot,
    run_id: &str,
    thread_id: &str,
    node_id: Option<&str>,
    status: &str,
    summary: String,
    checkpoints: &mut Vec<WorkflowCheckpoint>,
) -> Result<String, String> {
    let checkpoint_id = unique_runtime_id("checkpoint");
    state.checkpoint_id = checkpoint_id.clone();
    state.active_node_ids.sort();
    let checkpoint = WorkflowCheckpoint {
        id: checkpoint_id.clone(),
        thread_id: thread_id.to_string(),
        run_id: run_id.to_string(),
        created_at_ms: now_ms(),
        step_index: state.step_index,
        node_id: node_id.map(str::to_string),
        status: status.to_string(),
        summary,
    };
    save_workflow_checkpoint(workflow_path, &checkpoint, state)?;
    checkpoints.push(checkpoint);
    Ok(checkpoint_id)
}

pub(super) fn workflow_verification_evidence_from_node_runs(
    node_runs: &[WorkflowNodeRun],
) -> Vec<WorkflowVerificationEvidence> {
    node_runs
        .iter()
        .map(|run| WorkflowVerificationEvidence {
            node_id: run.node_id.clone(),
            evidence_type: if run.node_type == "skill_context" {
                "skill_context".to_string()
            } else if run.node_type == "workflow_package_export" {
                "workflow_package_export".to_string()
            } else if run.node_type == "workflow_package_import" {
                "workflow_package_import".to_string()
            } else if matches!(
                run.node_type.as_str(),
                "repository_context"
                    | "branch_policy"
                    | "github_context"
                    | "issue_context"
                    | "pr_attempt"
                    | "review_gate"
                    | "github_pr_create"
            ) {
                run.node_type.clone()
            } else {
                "execution".to_string()
            },
            status: if run.status == "success" {
                "passed".to_string()
            } else {
                run.status.clone()
            },
            summary: run.error.clone().unwrap_or_else(|| {
                if run.node_type == "skill_context" {
                    let hashes = run
                        .output
                        .as_ref()
                        .and_then(|output| output.get("selectedSkills"))
                        .and_then(Value::as_array)
                        .map(|items| {
                            items
                                .iter()
                                .filter_map(|item| {
                                    item.get("skillHash")
                                        .or_else(|| item.get("hash"))
                                        .and_then(Value::as_str)
                                })
                                .collect::<Vec<_>>()
                                .join(", ")
                        })
                        .unwrap_or_default();
                    format!("skill_context {} selected [{}]", run.status, hashes)
                } else {
                    format!("{} execution {}", run.node_type, run.status)
                }
            }),
            created_at_ms: run.finished_at_ms.unwrap_or(run.started_at_ms),
        })
        .collect()
}

pub(super) fn workflow_completion_requirements(
    workflow: &WorkflowProject,
    state: &WorkflowStateSnapshot,
    node_runs: &[WorkflowNodeRun],
) -> Vec<WorkflowCompletionRequirement> {
    let mut requirements = Vec::new();
    let run_by_node = node_runs
        .iter()
        .filter(|run| run.status == "success")
        .map(|run| (run.node_id.as_str(), run))
        .collect::<std::collections::BTreeMap<_, _>>();
    for node in &workflow.nodes {
        let Some(node_id) = workflow_node_id(node) else {
            continue;
        };
        let action_kind = ActionKind::from_node_type(&workflow_node_type(node));
        if action_kind.is_entry() {
            continue;
        }
        let incoming = workflow
            .edges
            .iter()
            .filter(|edge| workflow_edge_to(edge).as_deref() == Some(node_id.as_str()))
            .collect::<Vec<_>>();
        let selected = incoming.is_empty()
            || incoming
                .iter()
                .any(|edge| workflow_edge_is_selected(edge, &state.branch_decisions));
        if !selected {
            continue;
        }
        let executed = run_by_node.contains_key(node_id.as_str())
            || state.completed_node_ids.iter().any(|id| id == &node_id);
        for requirement_kind in completion_requirement_kinds(&action_kind) {
            match requirement_kind {
                "execution" => requirements.push(WorkflowCompletionRequirement {
                    id: format!("execution-{}", node_id),
                    node_id: Some(node_id.clone()),
                    requirement_type: "execution".to_string(),
                    status: if executed { "satisfied" } else { "missing" }.to_string(),
                    summary: if executed {
                        "Node produced typed execution evidence.".to_string()
                    } else {
                        "Node is missing typed execution evidence.".to_string()
                    },
                }),
                "verification" => {
                    let verified = state.node_outputs.contains_key(&node_id);
                    requirements.push(WorkflowCompletionRequirement {
                        id: format!("verification-{}", node_id),
                        node_id: Some(node_id.clone()),
                        requirement_type: "verification".to_string(),
                        status: if verified { "satisfied" } else { "missing" }.to_string(),
                        summary: if verified {
                            "Node output has verification material.".to_string()
                        } else {
                            "Node output is missing verification material.".to_string()
                        },
                    });
                }
                "output_created" => {
                    let output_created = state
                        .node_outputs
                        .get(&node_id)
                        .and_then(|output| output.get("outputBundle"))
                        .is_some();
                    requirements.push(WorkflowCompletionRequirement {
                        id: format!("output-created-{}", node_id),
                        node_id: Some(node_id.clone()),
                        requirement_type: "output_created".to_string(),
                        status: if output_created {
                            "satisfied"
                        } else {
                            "missing"
                        }
                        .to_string(),
                        summary: if output_created {
                            "Output bundle was produced.".to_string()
                        } else {
                            "Output bundle is missing.".to_string()
                        },
                    });
                }
                _ => {}
            }
        }
    }
    requirements
}

pub(super) fn workflow_completion_has_missing(
    requirements: &[WorkflowCompletionRequirement],
) -> bool {
    requirements
        .iter()
        .any(|requirement| requirement.status != "satisfied")
}

pub(super) fn execute_workflow_project(
    workflow_path: &Path,
    bundle: WorkflowWorkbenchBundle,
    thread: WorkflowThread,
    mut state: WorkflowStateSnapshot,
    resume_gate: Option<(String, Value)>,
    skill_resolver: &WorkflowSkillResolver,
) -> Result<WorkflowRunResult, String> {
    let started_at_ms = now_ms();
    let run_id = unique_runtime_id("workflow-run");
    let thread_id = thread.id.clone();
    state.run_id = run_id.clone();
    let validation = validate_workflow_project_bundle(&bundle.workflow, &bundle.tests);
    let mut events = Vec::new();
    let mut checkpoints = Vec::new();
    let mut node_runs = Vec::new();
    let mut completed = state
        .completed_node_ids
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let mut active_queue = if state.active_node_ids.is_empty() {
        workflow_next_ready_nodes(&bundle.workflow, &completed, &[], &state.branch_decisions)
    } else {
        state.active_node_ids.clone()
    };

    workflow_push_event(
        &mut events,
        &run_id,
        &thread_id,
        "run_started",
        None,
        Some("running"),
        Some("Workflow run started.".to_string()),
        None,
    );

    if validation.status != "passed" {
        state.blocked_node_ids = validation.blocked_nodes.clone();
        let checkpoint_id = workflow_checkpoint_state(
            workflow_path,
            &mut state,
            &run_id,
            &thread_id,
            None,
            &validation.status,
            format!(
                "Workflow blocked by {} validation issue(s).",
                validation.blocked_nodes.len()
            ),
            &mut checkpoints,
        )?;
        let summary = WorkflowRunSummary {
            id: run_id.clone(),
            thread_id: Some(thread_id.clone()),
            status: validation.status.clone(),
            started_at_ms,
            finished_at_ms: Some(now_ms()),
            node_count: bundle.workflow.nodes.len(),
            test_count: Some(bundle.tests.len()),
            checkpoint_count: Some(checkpoints.len()),
            interrupt_id: None,
            summary: format!(
                "Workflow blocked by {} validation issue(s).",
                validation.errors.len() + validation.warnings.len()
            ),
            evidence_path: Some(workflow_evidence_path(workflow_path).display().to_string()),
        };
        workflow_push_event(
            &mut events,
            &run_id,
            &thread_id,
            "run_completed",
            None,
            Some(&summary.status),
            Some(summary.summary.clone()),
            None,
        );
        let mut final_thread = thread.clone();
        final_thread.status = summary.status.clone();
        final_thread.latest_checkpoint_id = Some(checkpoint_id);
        let (harness_attempts, harness_shadow_comparisons, harness_gated_cluster_runs) =
            workflow_attach_harness_run_artifacts(&bundle.workflow, &run_id, &mut node_runs);
        let route_evidence = workflow_coding_route_evidence_from_run(&bundle.workflow, &node_runs);
        let route_run_summary = workflow_coding_route_run_summary(&route_evidence);
        let mut verification_evidence = workflow_verification_evidence_from_node_runs(&node_runs);
        verification_evidence.extend(workflow_route_verification_evidence(&route_evidence));
        let completion_requirements =
            workflow_completion_requirements(&bundle.workflow, &state, &node_runs);
        let result = WorkflowRunResult {
            summary,
            thread: final_thread,
            final_state: state,
            node_runs,
            checkpoints,
            events,
            harness_attempts,
            harness_shadow_comparisons,
            harness_gated_cluster_runs,
            verification_evidence,
            completion_requirements,
            route_evidence,
            route_run_summary,
            interrupt: None,
        };
        save_workflow_run_result(workflow_path, &result)?;
        return Ok(result);
    }

    let max_steps = bundle.workflow.nodes.len().saturating_mul(4).max(1);
    let mut steps = 0usize;
    while let Some(node_id) = active_queue.first().cloned() {
        active_queue.remove(0);
        if completed.contains(&node_id) {
            continue;
        }
        steps += 1;
        if steps > max_steps {
            state.blocked_node_ids.push(node_id.clone());
            break;
        }
        let Some(node) = workflow_node_by_id(&bundle.workflow, &node_id) else {
            state.blocked_node_ids.push(node_id.clone());
            continue;
        };
        let node_type = workflow_node_type(node);
        let action_kind = ActionKind::from_node_type(&node_type);
        let input = workflow_predecessor_output(&node_id, &bundle.workflow, &state);
        let resume_matches_node =
            resume_gate.as_ref().map(|(id, _)| id.as_str()) == Some(node_id.as_str());
        let runtime_approval_preview =
            workflow_runtime_approval_preview(node, &action_kind, &input);
        if (action_kind.is_interrupt() || runtime_approval_preview.is_some())
            && !resume_matches_node
        {
            let interrupt_id = unique_runtime_id("interrupt");
            let interrupt = WorkflowInterrupt {
                id: interrupt_id.clone(),
                run_id: run_id.clone(),
                thread_id: thread_id.clone(),
                node_id: node_id.clone(),
                status: "pending".to_string(),
                created_at_ms: now_ms(),
                resolved_at_ms: None,
                prompt: workflow_runtime_interrupt_prompt(node, &action_kind),
                allowed_outcomes: vec![
                    "approve".to_string(),
                    "reject".to_string(),
                    "edit".to_string(),
                ],
                response: runtime_approval_preview,
            };
            state.interrupted_node_ids.push(node_id.clone());
            state.active_node_ids = active_queue.clone();
            let checkpoint_id = workflow_checkpoint_state(
                workflow_path,
                &mut state,
                &run_id,
                &thread_id,
                Some(&node_id),
                "interrupted",
                format!("Run paused at '{}'.", workflow_node_name(node)),
                &mut checkpoints,
            )?;
            workflow_push_event(
                &mut events,
                &run_id,
                &thread_id,
                "node_interrupted",
                Some(&node_id),
                Some("interrupted"),
                Some(if action_kind.is_interrupt() {
                    "Human input required before continuing.".to_string()
                } else {
                    "Approval required before this node runs.".to_string()
                }),
                None,
            );
            node_runs.push(WorkflowNodeRun {
                node_id: node_id.clone(),
                node_type: node_type.clone(),
                status: "interrupted".to_string(),
                started_at_ms: now_ms(),
                finished_at_ms: Some(now_ms()),
                attempt: 1,
                input: Some(input.clone()),
                output: None,
                error: None,
                checkpoint_id: Some(checkpoint_id.clone()),
                lifecycle: workflow_node_lifecycle_steps("interrupted"),
                harness_attempt: None,
            });
            workflow_push_event(
                &mut events,
                &run_id,
                &thread_id,
                "run_completed",
                None,
                Some("interrupted"),
                Some("Run paused for human input.".to_string()),
                None,
            );
            fs::create_dir_all(workflow_interrupts_dir(workflow_path))
                .map_err(|error| format!("Failed to create interrupts directory: {}", error))?;
            write_json_pretty(&workflow_interrupt_path(workflow_path, &run_id), &interrupt)?;
            let summary = WorkflowRunSummary {
                id: run_id.clone(),
                thread_id: Some(thread_id.clone()),
                status: "interrupted".to_string(),
                started_at_ms,
                finished_at_ms: Some(now_ms()),
                node_count: bundle.workflow.nodes.len(),
                test_count: Some(bundle.tests.len()),
                checkpoint_count: Some(checkpoints.len()),
                interrupt_id: Some(interrupt_id.clone()),
                summary: format!("Run paused at '{}'.", workflow_node_name(node)),
                evidence_path: Some(workflow_evidence_path(workflow_path).display().to_string()),
            };
            let mut final_thread = thread.clone();
            final_thread.status = "interrupted".to_string();
            final_thread.latest_checkpoint_id = Some(checkpoint_id);
            save_workflow_thread(workflow_path, &final_thread)?;
            let (harness_attempts, harness_shadow_comparisons, harness_gated_cluster_runs) =
                workflow_attach_harness_run_artifacts(&bundle.workflow, &run_id, &mut node_runs);
            let route_evidence =
                workflow_coding_route_evidence_from_run(&bundle.workflow, &node_runs);
            let route_run_summary = workflow_coding_route_run_summary(&route_evidence);
            let mut verification_evidence =
                workflow_verification_evidence_from_node_runs(&node_runs);
            verification_evidence.extend(workflow_route_verification_evidence(&route_evidence));
            let completion_requirements =
                workflow_completion_requirements(&bundle.workflow, &state, &node_runs);
            let result = WorkflowRunResult {
                summary,
                thread: final_thread,
                final_state: state,
                node_runs,
                checkpoints,
                events,
                harness_attempts,
                harness_shadow_comparisons,
                harness_gated_cluster_runs,
                verification_evidence,
                completion_requirements,
                route_evidence,
                route_run_summary,
                interrupt: Some(interrupt),
            };
            save_workflow_run_result(workflow_path, &result)?;
            return Ok(result);
        }

        let mut node_run = WorkflowNodeRun {
            node_id: node_id.clone(),
            node_type: node_type.clone(),
            status: "running".to_string(),
            started_at_ms: now_ms(),
            finished_at_ms: None,
            attempt: 1,
            input: Some(input.clone()),
            output: None,
            error: None,
            checkpoint_id: None,
            lifecycle: Vec::new(),
            harness_attempt: None,
        };
        workflow_push_event(
            &mut events,
            &run_id,
            &thread_id,
            "node_started",
            Some(&node_id),
            Some("running"),
            Some(format!("{} started.", workflow_node_name(node))),
            None,
        );
        let max_attempts = workflow_max_attempts(node);
        let mut execution_result = Err("Node did not execute.".to_string());
        for attempt in 1..=max_attempts {
            node_run.attempt = attempt;
            let resume_value = resume_gate
                .as_ref()
                .and_then(|(resume_node_id, value)| (resume_node_id == &node_id).then_some(value));
            execution_result = execute_workflow_node(
                workflow_path,
                Some(&bundle.workflow),
                node,
                input.clone(),
                attempt,
                resume_value,
                skill_resolver,
            );
            if execution_result.is_ok() || attempt == max_attempts {
                break;
            }
            node_runs.push(WorkflowNodeRun {
                node_id: node_id.clone(),
                node_type: node_type.clone(),
                status: "error".to_string(),
                started_at_ms: node_run.started_at_ms,
                finished_at_ms: Some(now_ms()),
                attempt,
                input: Some(input.clone()),
                output: None,
                error: execution_result.as_ref().err().cloned(),
                checkpoint_id: None,
                lifecycle: workflow_node_lifecycle_steps("error"),
                harness_attempt: None,
            });
            workflow_push_event(
                &mut events,
                &run_id,
                &thread_id,
                "node_failed",
                Some(&node_id),
                Some("retrying"),
                Some(format!(
                    "Retrying '{}' after attempt {}.",
                    workflow_node_name(node),
                    attempt
                )),
                None,
            );
        }

        match execution_result {
            Ok(output) => {
                let selected_output = workflow_selected_output(node, &output);
                if action_kind == ActionKind::Decision {
                    state
                        .branch_decisions
                        .insert(node_id.clone(), selected_output.clone());
                }
                completed.insert(node_id.clone());
                state.completed_node_ids = completed.iter().cloned().collect();
                state.interrupted_node_ids.retain(|id| id != &node_id);
                state.node_outputs.insert(node_id.clone(), output.clone());
                let update = if action_kind == ActionKind::State {
                    let key = output
                        .get("stateKey")
                        .and_then(Value::as_str)
                        .unwrap_or(&node_id)
                        .to_string();
                    let reducer = output
                        .get("reducer")
                        .and_then(Value::as_str)
                        .unwrap_or("replace")
                        .to_string();
                    let value = output
                        .get("value")
                        .cloned()
                        .unwrap_or_else(|| output.clone());
                    match reducer.as_str() {
                        "merge" => {
                            let mut merged = state
                                .values
                                .get(&key)
                                .cloned()
                                .or_else(|| workflow_node_logic(node).get("initialValue").cloned())
                                .unwrap_or_else(|| json!({}));
                            if let (Some(current), Some(next)) =
                                (merged.as_object_mut(), value.as_object())
                            {
                                for (item_key, item_value) in next {
                                    current.insert(item_key.clone(), item_value.clone());
                                }
                                state.values.insert(key.clone(), merged.clone());
                            } else {
                                state.values.insert(key.clone(), value.clone());
                            }
                        }
                        "append" => {
                            let mut list = state
                                .values
                                .get(&key)
                                .and_then(Value::as_array)
                                .cloned()
                                .unwrap_or_default();
                            list.push(value.clone());
                            state.values.insert(key.clone(), Value::Array(list));
                        }
                        _ => {
                            state.values.insert(key.clone(), value.clone());
                        }
                    }
                    WorkflowStateUpdate {
                        node_id: node_id.clone(),
                        key,
                        value,
                        reducer,
                    }
                } else {
                    state.values.insert(node_id.clone(), output.clone());
                    WorkflowStateUpdate {
                        node_id: node_id.clone(),
                        key: node_id.clone(),
                        value: output.clone(),
                        reducer: "replace".to_string(),
                    }
                };
                state.pending_writes.clear();
                state.step_index += 1;
                active_queue.extend(workflow_next_ready_nodes(
                    &bundle.workflow,
                    &completed,
                    &active_queue,
                    &state.branch_decisions,
                ));
                state.active_node_ids = active_queue.clone();
                let checkpoint_id = workflow_checkpoint_state(
                    workflow_path,
                    &mut state,
                    &run_id,
                    &thread_id,
                    Some(&node_id),
                    "running",
                    format!("{} completed.", workflow_node_name(node)),
                    &mut checkpoints,
                )?;
                node_run.status = "success".to_string();
                node_run.finished_at_ms = Some(now_ms());
                node_run.output = Some(output.clone());
                node_run.checkpoint_id = Some(checkpoint_id);
                node_run.lifecycle = workflow_node_lifecycle_steps("success");
                workflow_push_event(
                    &mut events,
                    &run_id,
                    &thread_id,
                    "node_succeeded",
                    Some(&node_id),
                    Some("success"),
                    Some(format!("{} completed.", workflow_node_name(node))),
                    Some(vec![update]),
                );
                if output.get("toolKind").and_then(Value::as_str) == Some("workflow_tool") {
                    let child_run_id = output
                        .get("childRunId")
                        .and_then(Value::as_str)
                        .unwrap_or("child run");
                    let child_status = output
                        .get("childRunStatus")
                        .and_then(Value::as_str)
                        .unwrap_or("completed");
                    workflow_push_event(
                        &mut events,
                        &run_id,
                        &thread_id,
                        "child_run_completed",
                        Some(&node_id),
                        Some(child_status),
                        Some(format!(
                            "{} completed child workflow run {}.",
                            workflow_node_name(node),
                            child_run_id
                        )),
                        None,
                    );
                }
                if action_kind == ActionKind::Output {
                    workflow_push_event(
                        &mut events,
                        &run_id,
                        &thread_id,
                        "output_created",
                        Some(&node_id),
                        Some("success"),
                        Some(format!(
                            "{} produced an output bundle.",
                            workflow_node_name(node)
                        )),
                        None,
                    );
                    if output
                        .get("outputBundle")
                        .and_then(|bundle| bundle.get("materializedAssets"))
                        .and_then(Value::as_array)
                        .map(|assets| !assets.is_empty())
                        .unwrap_or(false)
                    {
                        workflow_push_event(
                            &mut events,
                            &run_id,
                            &thread_id,
                            "asset_materialized",
                            Some(&node_id),
                            Some("success"),
                            Some(format!(
                                "{} recorded a materialized asset.",
                                workflow_node_name(node)
                            )),
                            None,
                        );
                    }
                }
                node_runs.push(node_run);
            }
            Err(error) => {
                state.blocked_node_ids.push(node_id.clone());
                state.step_index += 1;
                state.active_node_ids = active_queue.clone();
                let checkpoint_id = workflow_checkpoint_state(
                    workflow_path,
                    &mut state,
                    &run_id,
                    &thread_id,
                    Some(&node_id),
                    "failed",
                    format!("{} failed.", workflow_node_name(node)),
                    &mut checkpoints,
                )?;
                node_run.status = "error".to_string();
                node_run.finished_at_ms = Some(now_ms());
                node_run.error = Some(error.clone());
                node_run.checkpoint_id = Some(checkpoint_id);
                node_run.lifecycle = workflow_node_lifecycle_steps("error");
                node_runs.push(node_run);
                workflow_push_event(
                    &mut events,
                    &run_id,
                    &thread_id,
                    "node_failed",
                    Some(&node_id),
                    Some("error"),
                    Some(error),
                    None,
                );
                break;
            }
        }
    }

    let mut status = if !state.blocked_node_ids.is_empty() {
        "failed"
    } else if !state.interrupted_node_ids.is_empty() {
        "interrupted"
    } else {
        "passed"
    };
    let mut completion_requirements =
        workflow_completion_requirements(&bundle.workflow, &state, &node_runs);
    if status == "passed" && workflow_completion_has_missing(&completion_requirements) {
        status = "failed";
        state
            .blocked_node_ids
            .extend(completion_requirements.iter().filter_map(|requirement| {
                (requirement.status != "satisfied")
                    .then(|| requirement.node_id.clone())
                    .flatten()
            }));
        state.blocked_node_ids.sort();
        state.blocked_node_ids.dedup();
        completion_requirements =
            workflow_completion_requirements(&bundle.workflow, &state, &node_runs);
    }
    let checkpoint_id = workflow_checkpoint_state(
        workflow_path,
        &mut state,
        &run_id,
        &thread_id,
        None,
        status,
        format!("Workflow run {}.", status),
        &mut checkpoints,
    )?;
    let summary = WorkflowRunSummary {
        id: run_id.clone(),
        thread_id: Some(thread_id.clone()),
        status: status.to_string(),
        started_at_ms,
        finished_at_ms: Some(now_ms()),
        node_count: bundle.workflow.nodes.len(),
        test_count: Some(bundle.tests.len()),
        checkpoint_count: Some(checkpoints.len()),
        interrupt_id: None,
        summary: if status == "passed" {
            "Workflow completed with durable checkpoints.".to_string()
        } else {
            format!("Workflow {} with structured blockers.", status)
        },
        evidence_path: Some(workflow_evidence_path(workflow_path).display().to_string()),
    };
    workflow_push_event(
        &mut events,
        &run_id,
        &thread_id,
        "run_completed",
        None,
        Some(status),
        Some(summary.summary.clone()),
        None,
    );
    let mut final_thread = thread.clone();
    final_thread.status = status.to_string();
    final_thread.latest_checkpoint_id = Some(checkpoint_id);
    save_workflow_thread(workflow_path, &final_thread)?;
    let (harness_attempts, harness_shadow_comparisons, harness_gated_cluster_runs) =
        workflow_attach_harness_run_artifacts(&bundle.workflow, &run_id, &mut node_runs);
    let route_evidence = workflow_coding_route_evidence_from_run(&bundle.workflow, &node_runs);
    let route_run_summary = workflow_coding_route_run_summary(&route_evidence);
    let mut verification_evidence = workflow_verification_evidence_from_node_runs(&node_runs);
    verification_evidence.extend(workflow_route_verification_evidence(&route_evidence));
    let result = WorkflowRunResult {
        summary,
        thread: final_thread,
        final_state: state,
        node_runs,
        checkpoints,
        events,
        harness_attempts,
        harness_shadow_comparisons,
        harness_gated_cluster_runs,
        verification_evidence,
        completion_requirements,
        route_evidence,
        route_run_summary,
        interrupt: None,
    };
    save_workflow_run_result(workflow_path, &result)?;
    Ok(result)
}

pub(super) fn new_workflow_thread(workflow_path: &Path, input: Option<Value>) -> WorkflowThread {
    let created_at_ms = now_ms();
    WorkflowThread {
        id: unique_runtime_id("workflow-thread"),
        workflow_path: workflow_path.display().to_string(),
        status: "queued".to_string(),
        created_at_ms,
        latest_checkpoint_id: None,
        input,
    }
}

pub(super) fn initial_workflow_state(
    thread: &WorkflowThread,
    run_id: &str,
) -> WorkflowStateSnapshot {
    let mut values = std::collections::BTreeMap::new();
    if let Some(input) = thread.input.clone() {
        values.insert("input".to_string(), input);
    }
    WorkflowStateSnapshot {
        thread_id: thread.id.clone(),
        checkpoint_id: "start".to_string(),
        run_id: run_id.to_string(),
        step_index: 0,
        values,
        node_outputs: std::collections::BTreeMap::new(),
        completed_node_ids: Vec::new(),
        blocked_node_ids: Vec::new(),
        interrupted_node_ids: Vec::new(),
        active_node_ids: Vec::new(),
        branch_decisions: std::collections::BTreeMap::new(),
        pending_writes: Vec::new(),
    }
}

pub(super) fn workflow_single_node_result(
    workflow_path: &Path,
    workflow: &WorkflowProject,
    node_id: &str,
    input: Option<Value>,
    dry_run: bool,
    skill_resolver: &WorkflowSkillResolver,
) -> Result<WorkflowRunResult, String> {
    ensure_workflow_runtime_dirs(workflow_path)?;
    let node = workflow_node_by_id(workflow, node_id)
        .ok_or_else(|| format!("Workflow node '{}' was not found.", node_id))?;
    let started_at_ms = now_ms();
    let run_id = unique_runtime_id(if dry_run {
        "workflow-dry-run"
    } else {
        "workflow-node-run"
    });
    let thread = new_workflow_thread(workflow_path, input.clone());
    save_workflow_thread(workflow_path, &thread)?;
    let mut state = initial_workflow_state(&thread, &run_id);
    let mut events = Vec::new();
    let mut checkpoints = Vec::new();
    let execution_input = input.unwrap_or_else(|| json!({"dryRun": dry_run}));
    let mut node_run = WorkflowNodeRun {
        node_id: node_id.to_string(),
        node_type: workflow_node_type(node),
        status: "running".to_string(),
        started_at_ms,
        finished_at_ms: None,
        attempt: 1,
        input: Some(execution_input.clone()),
        output: None,
        error: None,
        checkpoint_id: None,
        lifecycle: Vec::new(),
        harness_attempt: None,
    };
    workflow_push_event(
        &mut events,
        &run_id,
        &thread.id,
        "node_started",
        Some(node_id),
        Some("running"),
        Some(format!("{} started.", workflow_node_name(node))),
        None,
    );
    let execution = execute_workflow_node(
        workflow_path,
        Some(workflow),
        node,
        execution_input,
        1,
        None,
        skill_resolver,
    );
    let status = match execution {
        Ok(output) => {
            state
                .node_outputs
                .insert(node_id.to_string(), output.clone());
            state.values.insert(node_id.to_string(), output.clone());
            state.completed_node_ids.push(node_id.to_string());
            state.step_index = 1;
            let checkpoint_id = workflow_checkpoint_state(
                workflow_path,
                &mut state,
                &run_id,
                &thread.id,
                Some(node_id),
                "passed",
                format!("{} completed.", workflow_node_name(node)),
                &mut checkpoints,
            )?;
            node_run.status = "success".to_string();
            node_run.finished_at_ms = Some(now_ms());
            node_run.output = Some(output.clone());
            node_run.checkpoint_id = Some(checkpoint_id);
            node_run.lifecycle = workflow_node_lifecycle_steps("success");
            workflow_push_event(
                &mut events,
                &run_id,
                &thread.id,
                "node_succeeded",
                Some(node_id),
                Some("success"),
                Some(format!("{} completed.", workflow_node_name(node))),
                Some(vec![WorkflowStateUpdate {
                    node_id: node_id.to_string(),
                    key: node_id.to_string(),
                    value: output,
                    reducer: "replace".to_string(),
                }]),
            );
            "passed".to_string()
        }
        Err(error) => {
            state.blocked_node_ids.push(node_id.to_string());
            state.step_index = 1;
            let checkpoint_id = workflow_checkpoint_state(
                workflow_path,
                &mut state,
                &run_id,
                &thread.id,
                Some(node_id),
                "blocked",
                format!("{} blocked.", workflow_node_name(node)),
                &mut checkpoints,
            )?;
            node_run.status = "blocked".to_string();
            node_run.finished_at_ms = Some(now_ms());
            node_run.error = Some(error.clone());
            node_run.checkpoint_id = Some(checkpoint_id);
            node_run.lifecycle = workflow_node_lifecycle_steps("blocked");
            workflow_push_event(
                &mut events,
                &run_id,
                &thread.id,
                "node_blocked",
                Some(node_id),
                Some("blocked"),
                Some(error),
                None,
            );
            "blocked".to_string()
        }
    };
    let summary = WorkflowRunSummary {
        id: run_id.clone(),
        thread_id: Some(thread.id.clone()),
        status: status.clone(),
        started_at_ms,
        finished_at_ms: Some(now_ms()),
        node_count: 1,
        test_count: None,
        checkpoint_count: Some(checkpoints.len()),
        interrupt_id: None,
        summary: if dry_run {
            format!("Function dry run {}.", status)
        } else {
            format!("Node run {}.", status)
        },
        evidence_path: Some(workflow_evidence_path(workflow_path).display().to_string()),
    };
    workflow_push_event(
        &mut events,
        &run_id,
        &thread.id,
        "run_completed",
        None,
        Some(&status),
        Some(summary.summary.clone()),
        None,
    );
    let mut final_thread = thread.clone();
    final_thread.status = status;
    final_thread.latest_checkpoint_id = checkpoints.last().map(|checkpoint| checkpoint.id.clone());
    save_workflow_thread(workflow_path, &final_thread)?;
    let mut node_runs = vec![node_run];
    let (harness_attempts, harness_shadow_comparisons, harness_gated_cluster_runs) =
        workflow_attach_harness_run_artifacts(workflow, &run_id, &mut node_runs);
    let route_evidence = workflow_coding_route_evidence_from_run(workflow, &node_runs);
    let route_run_summary = workflow_coding_route_run_summary(&route_evidence);
    let mut verification_evidence = workflow_verification_evidence_from_node_runs(&node_runs);
    verification_evidence.extend(workflow_route_verification_evidence(&route_evidence));
    let completion_requirements = workflow_completion_requirements(workflow, &state, &node_runs);
    let result = WorkflowRunResult {
        summary,
        thread: final_thread,
        final_state: state,
        node_runs,
        checkpoints,
        events,
        harness_attempts,
        harness_shadow_comparisons,
        harness_gated_cluster_runs,
        verification_evidence,
        completion_requirements,
        route_evidence,
        route_run_summary,
        interrupt: None,
    };
    save_workflow_run_result(workflow_path, &result)?;
    append_workflow_evidence(
        workflow_path,
        WorkflowEvidenceSummary {
            id: result.summary.id.clone(),
            kind: if dry_run { "test_run" } else { "run" }.to_string(),
            created_at_ms: result.summary.started_at_ms,
            summary: result.summary.summary.clone(),
            path: Some(
                workflow_run_result_path(workflow_path, &result.summary.id)
                    .display()
                    .to_string(),
            ),
        },
    )?;
    Ok(result)
}
