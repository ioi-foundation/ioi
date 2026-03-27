use crate::agentic::desktop::types::{
    WorkerCompletionContract, WorkerMergeMode, WorkerTemplateDefinition,
    WorkerTemplateWorkflowDefinition,
};
use ioi_types::app::agentic::LlmToolDefinition;

pub fn builtin_worker_templates() -> Vec<WorkerTemplateDefinition> {
    vec![
        WorkerTemplateDefinition {
            template_id: "researcher".to_string(),
            label: "Research Worker".to_string(),
            role: "Research Worker".to_string(),
            summary:
                "Bounded child worker for source gathering, evidence synthesis, and concise research handoff."
                    .to_string(),
            default_budget: 120,
            max_retries: 1,
            allowed_tools: vec![
                "web__search".to_string(),
                "web__read".to_string(),
                "memory__search".to_string(),
                "memory__inspect".to_string(),
                "model__responses".to_string(),
                "agent__complete".to_string(),
                "agent__await_result".to_string(),
            ],
            completion_contract: WorkerCompletionContract {
                success_criteria:
                    "Return a compact evidence-backed summary with cited sources or a deterministic explanation of what blocked the research pass."
                        .to_string(),
                expected_output:
                    "Markdown research brief with findings, citations, and open questions."
                        .to_string(),
                merge_mode: WorkerMergeMode::AppendSummaryToParent,
                verification_hint: Some(
                    "Parent verifies citations, source freshness, and whether the brief resolves the delegated question."
                        .to_string(),
                ),
            },
            workflows: vec![WorkerTemplateWorkflowDefinition {
                workflow_id: "live_research_brief".to_string(),
                label: "Live Research Brief".to_string(),
                summary:
                    "Current-web or memory-backed evidence sweep that collapses into a cited brief with open questions."
                        .to_string(),
                goal_template:
                    "Research {topic} using current web and local memory evidence, then return a cited brief with findings, uncertainties, and next checks."
                        .to_string(),
                trigger_intents: vec!["web.research".to_string(), "memory.recall".to_string()],
                default_budget: Some(90),
                max_retries: Some(1),
                allowed_tools: vec![
                    "web__search".to_string(),
                    "web__read".to_string(),
                    "memory__search".to_string(),
                    "memory__inspect".to_string(),
                    "agent__complete".to_string(),
                    "agent__await_result".to_string(),
                ],
                completion_contract: Some(WorkerCompletionContract {
                    success_criteria:
                        "Return a cited research brief that answers the delegated topic, calls out freshness windows, and names unresolved questions or blockers."
                            .to_string(),
                    expected_output:
                        "Research brief with findings, sources, freshness notes, and open questions."
                            .to_string(),
                    merge_mode: WorkerMergeMode::AppendSummaryToParent,
                    verification_hint: Some(
                        "Parent verifies source freshness, citation quality, and whether the brief actually answers the delegated topic."
                            .to_string(),
                    ),
                }),
            }],
        },
        WorkerTemplateDefinition {
            template_id: "verifier".to_string(),
            label: "Verification Worker".to_string(),
            role: "Verification Worker".to_string(),
            summary:
                "Bounded child worker for checking postconditions, validating outputs, and reporting deterministic gaps."
                    .to_string(),
            default_budget: 80,
            max_retries: 1,
            allowed_tools: vec![
                "memory__inspect".to_string(),
                "memory__search".to_string(),
                "model__rerank".to_string(),
                "model__responses".to_string(),
                "agent__complete".to_string(),
                "agent__await_result".to_string(),
            ],
            completion_contract: WorkerCompletionContract {
                success_criteria:
                    "Return a compact verification report that clearly states pass/fail confidence and the evidence used."
                        .to_string(),
                expected_output:
                    "Verification report with verdict, evidence, and unresolved risks."
                        .to_string(),
                merge_mode: WorkerMergeMode::AppendAsEvidence,
                verification_hint: Some(
                    "Parent checks whether the report actually resolves the requested verification criteria."
                        .to_string(),
                ),
            },
            workflows: vec![WorkerTemplateWorkflowDefinition {
                workflow_id: "postcondition_audit".to_string(),
                label: "Postcondition Audit".to_string(),
                summary:
                    "Bounded verification pass that checks whether a claimed outcome holds, cites supporting evidence, and names gaps."
                        .to_string(),
                goal_template:
                    "Verify whether {topic} holds by inspecting the available evidence, then return a pass/fail audit with supporting facts, blockers, and next checks."
                        .to_string(),
                trigger_intents: vec!["delegation.task".to_string()],
                default_budget: Some(48),
                max_retries: Some(0),
                allowed_tools: vec![
                    "memory__inspect".to_string(),
                    "memory__search".to_string(),
                    "model__rerank".to_string(),
                    "agent__complete".to_string(),
                    "agent__await_result".to_string(),
                ],
                completion_contract: Some(WorkerCompletionContract {
                    success_criteria:
                        "Return a deterministic verification audit with an explicit verdict, supporting evidence, and clearly named gaps or blockers."
                            .to_string(),
                    expected_output:
                        "Verification audit with verdict, evidence, postcondition status, and unresolved risks."
                            .to_string(),
                    merge_mode: WorkerMergeMode::AppendAsEvidence,
                    verification_hint: Some(
                        "Parent checks that the audit includes a clear pass/fail verdict, evidence references, and any unresolved postcondition gaps."
                            .to_string(),
                    ),
                }),
            }],
        },
        WorkerTemplateDefinition {
            template_id: "coder".to_string(),
            label: "Coding Worker".to_string(),
            role: "Coding Worker".to_string(),
            summary:
                "Bounded child worker for narrow implementation slices and deterministic handoff back to the parent."
                    .to_string(),
            default_budget: 160,
            max_retries: 1,
            allowed_tools: vec![
                "filesystem__read_file".to_string(),
                "filesystem__list_directory".to_string(),
                "filesystem__search".to_string(),
                "filesystem__patch".to_string(),
                "filesystem__write_file".to_string(),
                "sys__change_directory".to_string(),
                "sys__exec_session".to_string(),
                "agent__complete".to_string(),
            ],
            completion_contract: WorkerCompletionContract {
                success_criteria:
                    "Return a concise implementation handoff that states what changed, what was verified, and any remaining risks."
                        .to_string(),
                expected_output:
                    "Implementation handoff with touched surfaces, verification notes, and residual risk."
                        .to_string(),
                merge_mode: WorkerMergeMode::AppendSummaryToParent,
                verification_hint: Some(
                    "Parent checks file edits, verification commands, and whether the patch actually closes the delegated slice."
                        .to_string(),
                ),
            },
            workflows: vec![WorkerTemplateWorkflowDefinition {
                workflow_id: "patch_build_verify".to_string(),
                label: "Patch, Build, Verify".to_string(),
                summary:
                    "Bounded code-change pass that inspects the workspace, applies a narrow patch, runs focused verification, and reports residual risk."
                        .to_string(),
                goal_template:
                    "Implement {topic} as a narrow workspace patch, run focused verification commands, and return a concise handoff with touched files, command results, and remaining risks."
                        .to_string(),
                trigger_intents: vec!["workspace.ops".to_string(), "delegation.task".to_string()],
                default_budget: Some(96),
                max_retries: Some(1),
                allowed_tools: vec![
                    "filesystem__read_file".to_string(),
                    "filesystem__list_directory".to_string(),
                    "filesystem__search".to_string(),
                    "filesystem__patch".to_string(),
                    "filesystem__write_file".to_string(),
                    "sys__change_directory".to_string(),
                    "sys__exec_session".to_string(),
                    "agent__complete".to_string(),
                ],
                completion_contract: Some(WorkerCompletionContract {
                    success_criteria:
                        "Return a deterministic implementation handoff that names the patch, the focused verification commands that ran, their outcomes, and any residual blockers or risks."
                            .to_string(),
                    expected_output:
                        "Patch/build/test handoff with touched files, command results, and residual risk."
                            .to_string(),
                    merge_mode: WorkerMergeMode::AppendSummaryToParent,
                    verification_hint: Some(
                        "Parent checks the concrete diff, verifies the named build or test commands, and confirms the delegated implementation slice is actually closed."
                            .to_string(),
                    ),
                }),
            }],
        },
    ]
}

pub fn builtin_worker_template(template_id: Option<&str>) -> Option<WorkerTemplateDefinition> {
    let template_id = template_id
        .map(str::trim)
        .filter(|value| !value.is_empty())?;
    builtin_worker_templates()
        .into_iter()
        .find(|template| template.template_id == template_id)
}

pub fn builtin_worker_workflow(
    template_id: Option<&str>,
    workflow_id: Option<&str>,
) -> Option<WorkerTemplateWorkflowDefinition> {
    let template = builtin_worker_template(template_id)?;
    let requested_workflow_id = workflow_id.map(str::trim).filter(|value| !value.is_empty());
    match requested_workflow_id {
        Some(requested_workflow_id) => template
            .workflows
            .into_iter()
            .find(|workflow| workflow.workflow_id == requested_workflow_id),
        None => template.workflows.into_iter().next(),
    }
}

pub fn default_worker_role_label(template_id: Option<&str>) -> &'static str {
    match template_id.map(str::trim).filter(|value| !value.is_empty()) {
        Some("researcher") => "Research Worker",
        Some("verifier") => "Verification Worker",
        Some("coder") => "Coding Worker",
        _ => "Sub-Worker",
    }
}

pub fn delegation_template_hint() -> String {
    builtin_worker_templates()
        .into_iter()
        .map(|template| {
            let workflow_hint = template
                .workflows
                .first()
                .map(|workflow| format!(" starter flow `{}`", workflow.workflow_id))
                .unwrap_or_default();
            format!(
                "`{}` for {}{}",
                template.template_id,
                template.summary.to_ascii_lowercase(),
                workflow_hint,
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

pub fn render_worker_template_catalog(tools: &[LlmToolDefinition]) -> Option<String> {
    let supports_delegation = tools.iter().any(|tool| tool.name == "agent__delegate");
    if !supports_delegation {
        return None;
    }

    let mut lines = vec!["[WORKER TEMPLATES]".to_string()];
    for template in builtin_worker_templates() {
        let allowed_tools = if template.allowed_tools.is_empty() {
            "No specific tool allowances.".to_string()
        } else {
            format!("Allowed tools: {}.", template.allowed_tools.join(", "))
        };
        lines.push(format!(
            "- `{}` ({}) -> {} Budget {}. Merge `{}`. Expected output: {}. {}",
            template.template_id,
            template.role,
            template.summary,
            template.default_budget,
            template.completion_contract.merge_mode.as_label(),
            template.completion_contract.expected_output,
            allowed_tools,
        ));
        for workflow in template.workflows {
            let trigger_summary = if workflow.trigger_intents.is_empty() {
                "Trigger intents: ad hoc.".to_string()
            } else {
                format!("Trigger intents: {}.", workflow.trigger_intents.join(", "))
            };
            let workflow_budget = workflow
                .default_budget
                .map(|budget| format!(" Budget {}.", budget))
                .unwrap_or_default();
            let workflow_retries = workflow
                .max_retries
                .map(|retries| format!(" Retries {}.", retries))
                .unwrap_or_default();
            let workflow_tools = if workflow.allowed_tools.is_empty() {
                String::new()
            } else {
                format!(" Allowed tools: {}.", workflow.allowed_tools.join(", "))
            };
            lines.push(format!(
                "  Playbook `{}` -> {} Goal template: {} {}{}{}{}",
                workflow.workflow_id,
                workflow.summary,
                workflow.goal_template,
                trigger_summary,
                workflow_budget,
                workflow_retries,
                workflow_tools,
            ));
        }
    }

    Some(lines.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_worker_catalog_contains_researcher_verifier_and_coder() {
        let templates = builtin_worker_templates();
        assert_eq!(templates.len(), 3);
        assert!(templates
            .iter()
            .any(|template| template.template_id == "researcher"));
        assert!(templates
            .iter()
            .any(|template| template.template_id == "verifier"));
        assert!(templates
            .iter()
            .any(|template| template.template_id == "coder"));
        let researcher = templates
            .iter()
            .find(|template| template.template_id == "researcher")
            .expect("researcher template should exist");
        assert!(researcher
            .workflows
            .iter()
            .any(|workflow| workflow.workflow_id == "live_research_brief"));
        let verifier = templates
            .iter()
            .find(|template| template.template_id == "verifier")
            .expect("verifier template should exist");
        let verifier_workflow = verifier
            .workflows
            .iter()
            .find(|workflow| workflow.workflow_id == "postcondition_audit")
            .expect("verifier workflow should exist");
        assert_eq!(verifier_workflow.default_budget, Some(48));
        assert_eq!(verifier_workflow.max_retries, Some(0));
        assert!(verifier_workflow
            .allowed_tools
            .iter()
            .any(|tool| tool == "model__rerank"));
        assert!(verifier_workflow
            .allowed_tools
            .iter()
            .all(|tool| tool != "model__responses"));
        let coder = templates
            .iter()
            .find(|template| template.template_id == "coder")
            .expect("coder template should exist");
        let coder_workflow = coder
            .workflows
            .iter()
            .find(|workflow| workflow.workflow_id == "patch_build_verify")
            .expect("coder workflow should exist");
        assert_eq!(coder_workflow.default_budget, Some(96));
        assert_eq!(coder_workflow.max_retries, Some(1));
        assert!(coder_workflow
            .allowed_tools
            .iter()
            .any(|tool| tool == "filesystem__patch"));
        assert!(coder_workflow
            .allowed_tools
            .iter()
            .any(|tool| tool == "sys__exec_session"));
        assert!(coder_workflow
            .allowed_tools
            .iter()
            .any(|tool| tool == "agent__complete"));
    }
}
