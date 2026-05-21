// apps/autopilot/src-tauri/src/project/workflow_coding_route_lane.rs

use super::workflow_value_helpers::{
    workflow_sha256_hex, workflow_string_array_any, workflow_value_bool_any,
    workflow_value_string_any, workflow_value_u64_any,
};
use super::*;

fn workflow_coding_route_node_string(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_string)
}

fn workflow_coding_route_node_type(node: &Value) -> String {
    workflow_coding_route_node_string(node, "type").unwrap_or_else(|| "unknown".to_string())
}

fn workflow_coding_route_node_name(node: &Value) -> String {
    workflow_coding_route_node_string(node, "name").unwrap_or_else(|| "Workflow step".to_string())
}

fn workflow_clip_text(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    value.chars().take(max_chars).collect()
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
        text.push_str(&workflow_coding_route_node_name(node).to_lowercase());
        text.push(' ');
        text.push_str(&workflow_coding_route_node_type(node).to_lowercase());
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

pub(super) fn workflow_coding_route_evidence_from_run(
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

pub(super) fn workflow_coding_route_run_summary(
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

pub(super) fn workflow_route_verification_evidence(
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
