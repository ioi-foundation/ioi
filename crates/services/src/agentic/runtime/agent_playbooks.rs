use crate::agentic::runtime::types::{
    AgentPlaybookDefinition, AgentPlaybookStepDefinition, WorkerCompletionContract, WorkerMergeMode,
};
use ioi_types::app::agentic::{LlmToolDefinition, ResolvedIntentState};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentPlaybookDecisionRecord {
    pub route_family: &'static str,
    pub topology: &'static str,
    pub planner_authority: &'static str,
    pub verifier_role: Option<&'static str>,
    pub requires_verifier: bool,
}

pub fn playbook_decision_record(playbook_id: &str) -> AgentPlaybookDecisionRecord {
    match playbook_id.trim() {
        "evidence_audited_patch" => AgentPlaybookDecisionRecord {
            route_family: "coding",
            topology: "planner_specialist_verifier",
            planner_authority: "kernel",
            verifier_role: Some("test_verifier"),
            requires_verifier: true,
        },
        "citation_grounded_brief" => AgentPlaybookDecisionRecord {
            route_family: "research",
            topology: "planner_specialist_verifier",
            planner_authority: "kernel",
            verifier_role: Some("citation_verifier"),
            requires_verifier: true,
        },
        "browser_postcondition_gate" => AgentPlaybookDecisionRecord {
            route_family: "computer_use",
            topology: "planner_specialist_verifier",
            planner_authority: "kernel",
            verifier_role: Some("postcondition_verifier"),
            requires_verifier: true,
        },
        "artifact_generation_gate" => AgentPlaybookDecisionRecord {
            route_family: "artifacts",
            topology: "planner_specialist_verifier",
            planner_authority: "kernel",
            verifier_role: Some("artifact_validation_verifier"),
            requires_verifier: true,
        },
        "research_backed_artifact_gate" => AgentPlaybookDecisionRecord {
            route_family: "artifacts",
            topology: "planner_specialist_verifier",
            planner_authority: "kernel",
            verifier_role: Some("artifact_validation_verifier"),
            requires_verifier: true,
        },
        _ => AgentPlaybookDecisionRecord {
            route_family: "general",
            topology: "planner_specialist",
            planner_authority: "kernel",
            verifier_role: None,
            requires_verifier: false,
        },
    }
}

fn normalized_query_text(query: &str) -> String {
    let normalized_chars = query
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_') {
                ch.to_ascii_lowercase()
            } else {
                ' '
            }
        })
        .collect::<String>();
    format!(
        " {} ",
        normalized_chars
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    )
}

fn query_contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

fn query_requests_code_change_work(query: &str) -> bool {
    let normalized = normalized_query_text(query);
    let code_action = query_contains_any(
        &normalized,
        &[
            " fix ",
            " patch ",
            " implement ",
            " refactor ",
            " port ",
            " bug ",
            " regression ",
            " code ",
            " write ",
            " add ",
            " update ",
            " modify ",
            " edit ",
            " failing test ",
            " failing tests ",
            " broken test ",
            " broken tests ",
            " compile error ",
        ],
    );
    let code_context = query_contains_any(
        &normalized,
        &[
            " repo ",
            " repository ",
            " codebase ",
            " function ",
            " module ",
            " component ",
            " class ",
            " method ",
            " crate ",
            " rust ",
            " typescript ",
            " javascript ",
            " python ",
            " test ",
            " tests ",
            " file ",
            " source ",
            " workspace ",
        ],
    );
    code_action && code_context
}

fn query_requests_research_work(query: &str) -> bool {
    let normalized = normalized_query_text(query);
    query_contains_any(
        &normalized,
        &[
            " research ",
            " investigate ",
            " find sources ",
            " gather evidence ",
            " compare sources ",
            " fact check ",
            " fact-check ",
        ],
    )
}

fn query_requests_deep_research_work(query: &str) -> bool {
    let normalized = normalized_query_text(query);
    query_requests_research_work(query)
        || query_contains_any(
            &normalized,
            &[
                " briefing ",
                " brief ",
                " report ",
                " deep dive ",
                " literature review ",
                " source freshness ",
                " grounded ",
                " citations ",
                " cited ",
            ],
        )
}

fn query_requests_verification_work(query: &str) -> bool {
    let normalized = normalized_query_text(query);
    query_contains_any(
        &normalized,
        &[
            " verify ",
            " verification ",
            " validate ",
            " validation ",
            " check ",
            " double check ",
            " double-check ",
            " audit ",
            " review ",
            " confirm ",
            " inspect ",
            " parity ",
        ],
    )
}

fn query_requests_browser_work(query: &str) -> bool {
    let normalized = normalized_query_text(query);
    let browser_action = query_contains_any(
        &normalized,
        &[
            " click ",
            " type ",
            " select ",
            " submit ",
            " navigate ",
            " open ",
            " fill ",
        ],
    );
    let browser_context = query_contains_any(
        &normalized,
        &[
            " browser ",
            " website ",
            " webpage ",
            " page ",
            " tab ",
            " form ",
            " dialog ",
            " dropdown ",
            " ui ",
            " screen ",
        ],
    );
    browser_action && browser_context
}

fn query_requests_artifact_work(query: &str) -> bool {
    let normalized = normalized_query_text(query);
    let artifact_action = query_contains_any(
        &normalized,
        &[
            " build ",
            " create ",
            " generate ",
            " design ",
            " draft ",
            " refine ",
            " make ",
        ],
    );
    let artifact_context = query_contains_any(
        &normalized,
        &[
            " artifact ",
            " landing page ",
            " dashboard ",
            " mockup ",
            " wireframe ",
            " microsite ",
            " html ",
            " prototype ",
            " ui concept ",
            " visual treatment ",
        ],
    );
    artifact_action && artifact_context
}

fn query_requests_research_backed_artifact_work(query: &str) -> bool {
    if !query_requests_artifact_work(query) {
        return false;
    }

    let normalized = normalized_query_text(query);
    let currentness_or_sources = query_contains_any(
        &normalized,
        &[
            " latest ",
            " recent ",
            " current ",
            " today ",
            " citations ",
            " cited ",
            " source ",
            " sources ",
            " references ",
            " compare ",
            " comparison ",
            " benchmark ",
            " trends ",
            " practices ",
            " up to date ",
        ],
    );
    let explainer_shape = query_contains_any(
        &normalized,
        &[
            " explain ",
            " explains ",
            " explained ",
            " explainer ",
            " overview ",
            " guide ",
            " primer ",
            " tutorial ",
            " introduction ",
            " basics ",
        ],
    );
    let likely_private_branding = query_contains_any(
        &normalized,
        &[
            " my product ",
            " our product ",
            " my startup ",
            " our startup ",
            " my company ",
            " our company ",
            " marketing site ",
            " product launch ",
        ],
    );

    query_requests_deep_research_work(query)
        || currentness_or_sources
        || (explainer_shape && !likely_private_branding)
}

pub fn builtin_agent_playbooks() -> Vec<AgentPlaybookDefinition> {
    vec![
        AgentPlaybookDefinition {
            playbook_id: "evidence_audited_patch".to_string(),
            label: "Evidence-Audited Patch".to_string(),
            summary:
                "Higher-order parent playbook for repo-grounded issue work: capture bounded context first, land a narrow patch, verify it with targeted tests, then synthesize one coherent final handoff."
                    .to_string(),
            goal_template:
                "Close {topic} by first capturing bounded repo context, then applying a narrow workspace patch, then verifying it with targeted tests before synthesizing the final handoff."
                    .to_string(),
            trigger_intents: vec!["workspace.ops".to_string(), "delegation.task".to_string()],
            recommended_for: vec![
                "Ports, parity work, and bugfixes that need explicit repo context, bounded execution, targeted verification, and a final synthesized handoff."
                    .to_string(),
                "Complex code changes where the parent should keep planner authority while bounded workers handle research, implementation, and verification."
                    .to_string(),
            ],
            default_budget: 196,
            completion_contract: WorkerCompletionContract {
                success_criteria:
                    "Return a parent-level handoff that includes the repo context brief, implementation summary, targeted verification verdict, and final patch synthesis."
                        .to_string(),
                expected_output:
                    "Evidence-backed implementation handoff with repo context, patch summary, targeted-test verdict, and synthesis status."
                        .to_string(),
                merge_mode: WorkerMergeMode::AppendSummaryToParent,
                verification_hint: Some(
                    "Parent confirms the repo context informed the patch, targeted verification stayed bounded, and the synthesized handoff matches the verifier result."
                        .to_string(),
                ),
            },
            steps: vec![
                AgentPlaybookStepDefinition {
                    step_id: "context".to_string(),
                    label: "Capture repo context".to_string(),
                    summary:
                        "Bound the task with repo-grounded context, likely files, selected skills, and targeted verification suggestions before any patch lands."
                            .to_string(),
                    worker_template_id: "context_worker".to_string(),
                    worker_workflow_id: "repo_context_brief".to_string(),
                    goal_template:
                        "Capture repo context for {topic}, identify likely files and skills, and return a bounded context brief with targeted verification suggestions and open questions."
                            .to_string(),
                    depends_on: Vec::new(),
                },
                AgentPlaybookStepDefinition {
                    step_id: "implement".to_string(),
                    label: "Patch the workspace".to_string(),
                    summary:
                        "Apply the narrowest viable code change informed by the repo context brief and run only the smallest executor-side checks needed to keep momentum."
                            .to_string(),
                    worker_template_id: "coder".to_string(),
                    worker_workflow_id: "patch_build_verify".to_string(),
                    goal_template:
                        "Implement {topic} as a narrow workspace patch informed by the repo context brief, run focused executor-side checks, and return touched files, command results, and residual risk."
                            .to_string(),
                    depends_on: vec!["context".to_string()],
                },
                AgentPlaybookStepDefinition {
                    step_id: "verify".to_string(),
                    label: "Verify targeted tests".to_string(),
                    summary:
                        "Run the targeted verifier lane separately from the executor so bounded test evidence and regression risk are explicit."
                            .to_string(),
                    worker_template_id: "verifier".to_string(),
                    worker_workflow_id: "targeted_test_audit".to_string(),
                    goal_template:
                        "Verify the coding result for {topic} by running targeted checks first, widen only if needed, and return a coding verifier scorecard with blockers and next checks."
                            .to_string(),
                    depends_on: vec!["implement".to_string()],
                },
                AgentPlaybookStepDefinition {
                    step_id: "synthesize".to_string(),
                    label: "Synthesize final patch".to_string(),
                    summary:
                        "Collapse executor and verifier evidence into one coherent final handoff that states verification readiness and residual risk."
                            .to_string(),
                    worker_template_id: "patch_synthesizer".to_string(),
                    worker_workflow_id: "patch_synthesis_handoff".to_string(),
                    goal_template:
                        "Synthesize the verified patch for {topic} into a final handoff that names touched files, verification readiness, and residual risk."
                            .to_string(),
                    depends_on: vec!["implement".to_string(), "verify".to_string()],
                },
            ],
        },
        AgentPlaybookDefinition {
            playbook_id: "citation_grounded_brief".to_string(),
            label: "Citation-Grounded Brief".to_string(),
            summary:
                "Parent playbook for research work that separates source gathering from explicit verification before the final brief is accepted."
                    .to_string(),
            goal_template:
                "Answer {topic} by gathering current evidence first, then verifying freshness and grounding before the parent accepts the final brief."
                    .to_string(),
            trigger_intents: vec![
                "web.research".to_string(),
                "memory.recall".to_string(),
                "delegation.task".to_string(),
            ],
            recommended_for: vec![
                "Comparative or freshness-sensitive research questions that need a bounded research pass and an explicit verification pass."
                    .to_string(),
            ],
            default_budget: 132,
            completion_contract: WorkerCompletionContract {
                success_criteria:
                    "Return a cited brief plus a verification verdict that confirms freshness, grounding, and remaining source gaps."
                        .to_string(),
                expected_output:
                    "Cited research brief with a separate verification verdict.".to_string(),
                merge_mode: WorkerMergeMode::AppendSummaryToParent,
                verification_hint: Some(
                    "Parent confirms that the cited brief and verification verdict agree on freshness, grounding, and unresolved gaps."
                        .to_string(),
                ),
            },
            steps: vec![
                AgentPlaybookStepDefinition {
                    step_id: "research".to_string(),
                    label: "Gather current sources".to_string(),
                    summary:
                        "Collect current web or memory evidence and collapse it into a compact cited brief."
                            .to_string(),
                    worker_template_id: "researcher".to_string(),
                    worker_workflow_id: "live_research_brief".to_string(),
                    goal_template:
                        "Research {topic} using current web and local memory evidence, then return a cited brief with findings, freshness notes, and unresolved questions."
                            .to_string(),
                    depends_on: Vec::new(),
                },
                AgentPlaybookStepDefinition {
                    step_id: "verify".to_string(),
                    label: "Verify grounding".to_string(),
                    summary:
                        "Audit freshness, grounding, and unresolved comparison gaps before the parent accepts the brief."
                            .to_string(),
                    worker_template_id: "verifier".to_string(),
                    worker_workflow_id: "citation_audit".to_string(),
                    goal_template:
                        "Verify whether the cited brief for {topic} is current, grounded, and sufficiently independent, then return a citation verifier scorecard with blockers and next checks."
                            .to_string(),
                    depends_on: vec!["research".to_string()],
                },
            ],
        },
        AgentPlaybookDefinition {
            playbook_id: "browser_postcondition_gate".to_string(),
            label: "Browser Postcondition Gate".to_string(),
            summary:
                "Parent playbook for browser and GUI work: capture the current UI state, execute the route in a bounded operator lane, then explicitly audit the observed postcondition and recovery need."
                    .to_string(),
            goal_template:
                "Carry out {topic} in the browser or GUI by first capturing the current UI state, then executing the bounded route, then verifying that the observed postcondition actually holds before completion."
                    .to_string(),
            trigger_intents: vec!["delegation.task".to_string()],
            recommended_for: vec![
                "Browser or GUI tasks where the parent should distinguish perception, execution, and postcondition verification."
                    .to_string(),
            ],
            default_budget: 160,
            completion_contract: WorkerCompletionContract {
                success_criteria:
                    "Return the UI-state brief, execution handoff, and a verification verdict that says whether the browser task really completed or needs recovery."
                        .to_string(),
                expected_output:
                    "Browser perception brief, execution handoff, and verification verdict."
                        .to_string(),
                merge_mode: WorkerMergeMode::AppendSummaryToParent,
                verification_hint: Some(
                    "Parent confirms the perceived UI state informed execution and that the verifier clearly states postcondition and recovery state before completing the browser route."
                        .to_string(),
                ),
            },
            steps: vec![
                AgentPlaybookStepDefinition {
                    step_id: "perceive".to_string(),
                    label: "Capture UI state".to_string(),
                    summary:
                        "Observe the current browser or GUI surface, identify the likely target state, and name the next safe action before execution."
                            .to_string(),
                    worker_template_id: "perception_worker".to_string(),
                    worker_workflow_id: "ui_state_brief".to_string(),
                    goal_template:
                        "Inspect the current browser or GUI state for {topic}, then return a UI-state brief with surface_status, ui_state, target, approval_risk, next_action, and notes."
                            .to_string(),
                    depends_on: Vec::new(),
                },
                AgentPlaybookStepDefinition {
                    step_id: "execute".to_string(),
                    label: "Execute in browser".to_string(),
                    summary:
                        "Use grounded browser or GUI tools to advance the task and report the observed postcondition."
                            .to_string(),
                    worker_template_id: "browser_operator".to_string(),
                    worker_workflow_id: "browser_postcondition_pass".to_string(),
                    goal_template:
                        "Carry out {topic} in the browser or GUI using grounded observations first, then return executed_steps, observed_postcondition, approval_state, recovery_status, next_recovery_step, blocker_summary, and notes."
                            .to_string(),
                    depends_on: vec!["perceive".to_string()],
                },
                AgentPlaybookStepDefinition {
                    step_id: "verify".to_string(),
                    label: "Verify postcondition".to_string(),
                    summary:
                        "Check whether the browser task's claimed completion state actually holds or needs recovery."
                            .to_string(),
                    worker_template_id: "verifier".to_string(),
                    worker_workflow_id: "browser_postcondition_audit".to_string(),
                    goal_template:
                        "Verify whether the browser postcondition for {topic} actually holds by inspecting the execution handoff, then return a computer-use verifier scorecard with verdict, postcondition_status, approval_state, recovery_status, and notes."
                            .to_string(),
                    depends_on: vec!["execute".to_string()],
                },
            ],
        },
        AgentPlaybookDefinition {
            playbook_id: "artifact_generation_gate".to_string(),
            label: "Artifact Generation Gate".to_string(),
            summary:
                "Parent playbook for artifact work that captures artifact context first, then separates file-backed generation from the final quality gate."
                    .to_string(),
            goal_template:
                "Create or refine {topic} as a file-backed artifact by first capturing artifact context, then generating the deliverable, then validating whether the retained output is ready for presentation."
                    .to_string(),
            trigger_intents: vec!["delegation.task".to_string()],
            recommended_for: vec![
                "Landing pages, mockups, and other artifact tasks that need explicit context, retained output, and a separate quality gate."
                    .to_string(),
            ],
            default_budget: 196,
            completion_contract: WorkerCompletionContract {
                success_criteria:
                    "Return the artifact context brief, produced artifact files, retained verification signals, and a validation outcome that says whether the artifact is ready or still needs repair."
                        .to_string(),
                expected_output:
                    "Artifact context brief, generation handoff, and validation outcome."
                        .to_string(),
                merge_mode: WorkerMergeMode::AppendSummaryToParent,
                verification_hint: Some(
                    "Parent confirms the captured artifact context, retained output files, and validation verdict before presenting the final artifact route."
                        .to_string(),
                ),
            },
            steps: vec![
                AgentPlaybookStepDefinition {
                    step_id: "context".to_string(),
                    label: "Capture artifact context".to_string(),
                    summary:
                        "Bound the artifact request with the intended deliverable shape, likely output files, relevant frontend or UX skills, and targeted presentation checks before generation begins."
                            .to_string(),
                    worker_template_id: "context_worker".to_string(),
                    worker_workflow_id: "artifact_context_brief".to_string(),
                    goal_template:
                        "Inspect available context for {topic}, identify the intended artifact shape, likely output files, relevant frontend or UX skills, and targeted presentation checks, then return a bounded artifact context brief."
                            .to_string(),
                    depends_on: Vec::new(),
                },
                AgentPlaybookStepDefinition {
                    step_id: "build".to_string(),
                    label: "Generate artifact".to_string(),
                    summary:
                        "Create or refine the requested artifact and retain the important file outputs for the parent."
                            .to_string(),
                    worker_template_id: "artifact_builder".to_string(),
                    worker_workflow_id: "artifact_generate_repair".to_string(),
                    goal_template:
                        "Generate or refine {topic} as a file-backed artifact using the captured context, retain the important output files and verification signals, and return a concise handoff with produced_files, verification_signals, presentation_status, repair_status, and remaining visual or structural gaps."
                            .to_string(),
                    depends_on: vec!["context".to_string()],
                },
                AgentPlaybookStepDefinition {
                    step_id: "validation".to_string(),
                    label: "Validate artifact quality".to_string(),
                    summary:
                        "Validate whether the retained artifact output is request-faithful and presentation-ready or still needs repair."
                            .to_string(),
                    worker_template_id: "verifier".to_string(),
                    worker_workflow_id: "artifact_validation_audit".to_string(),
                    goal_template:
                        "Validate whether the generated artifact for {topic} is faithful and presentation-ready by inspecting the retained files and generation handoff, then return an artifact validation scorecard with verdict, fidelity_status, presentation_status, repair_status, and notes."
                            .to_string(),
                    depends_on: vec!["build".to_string()],
                },
            ],
        },
        AgentPlaybookDefinition {
            playbook_id: "research_backed_artifact_gate".to_string(),
            label: "Research-Backed Artifact Gate".to_string(),
            summary:
                "Parent playbook for researched artifact work that captures artifact context, gathers fresh source material, then builds and validates the retained deliverable."
                    .to_string(),
            goal_template:
                "Create {topic} as a researched file-backed artifact by first bounding the artifact brief, then gathering current source material, then generating the deliverable, then validating whether the retained output is ready for presentation."
                    .to_string(),
            trigger_intents: vec!["delegation.task".to_string()],
            recommended_for: vec![
                "Explainer pages, researched HTML artifacts, and citation-sensitive artifact asks where the builder should write from fresh evidence instead of memory."
                    .to_string(),
            ],
            default_budget: 228,
            completion_contract: WorkerCompletionContract {
                success_criteria:
                    "Return the artifact context brief, a retained research handoff, produced artifact files, retained verification signals, and a validation outcome that says whether the artifact is ready or still needs repair."
                        .to_string(),
                expected_output:
                    "Artifact context brief, research handoff, generation handoff, and validation outcome."
                        .to_string(),
                merge_mode: WorkerMergeMode::AppendSummaryToParent,
                verification_hint: Some(
                    "Parent confirms the builder wrote from the retained research handoff, the output files are preserved, and the validation verdict matches the actual presentation state."
                        .to_string(),
                ),
            },
            steps: vec![
                AgentPlaybookStepDefinition {
                    step_id: "context".to_string(),
                    label: "Capture artifact context".to_string(),
                    summary:
                        "Bound the artifact request with the intended deliverable shape, likely output files, relevant frontend or UX skills, and targeted presentation checks before research or generation begins."
                            .to_string(),
                    worker_template_id: "context_worker".to_string(),
                    worker_workflow_id: "artifact_context_brief".to_string(),
                    goal_template:
                        "Inspect available context for {topic}, identify the intended artifact shape, likely output files, relevant frontend or UX skills, and targeted presentation checks, then return a bounded artifact context brief."
                            .to_string(),
                    depends_on: Vec::new(),
                },
                AgentPlaybookStepDefinition {
                    step_id: "research".to_string(),
                    label: "Gather current sources".to_string(),
                    summary:
                        "Collect current web or memory evidence that should directly inform the artifact structure, claims, and citations."
                            .to_string(),
                    worker_template_id: "researcher".to_string(),
                    worker_workflow_id: "live_research_brief".to_string(),
                    goal_template:
                        "Research {topic} using current web and local memory evidence, then return a cited artifact research handoff with findings, source highlights, freshness notes, and unresolved questions that should shape the artifact."
                            .to_string(),
                    depends_on: vec!["context".to_string()],
                },
                AgentPlaybookStepDefinition {
                    step_id: "build".to_string(),
                    label: "Generate artifact".to_string(),
                    summary:
                        "Create or refine the requested artifact using the captured context and retained research handoff, then preserve the important file outputs for the parent."
                            .to_string(),
                    worker_template_id: "artifact_builder".to_string(),
                    worker_workflow_id: "artifact_generate_repair".to_string(),
                    goal_template:
                        "Generate or refine {topic} as a researched file-backed artifact using the captured context and retained research handoff, retain the important output files and verification signals, and return a concise handoff with produced_files, verification_signals, presentation_status, repair_status, citations_used, and remaining visual or structural gaps."
                            .to_string(),
                    depends_on: vec!["context".to_string(), "research".to_string()],
                },
                AgentPlaybookStepDefinition {
                    step_id: "validation".to_string(),
                    label: "Validate artifact quality".to_string(),
                    summary:
                        "Validate whether the retained researched artifact output is request-faithful, grounded, and presentation-ready or still needs repair."
                            .to_string(),
                    worker_template_id: "verifier".to_string(),
                    worker_workflow_id: "artifact_validation_audit".to_string(),
                    goal_template:
                        "Validate whether the generated researched artifact for {topic} is faithful, grounded, and presentation-ready by inspecting the retained files, research handoff, and generation handoff, then return an artifact validation scorecard with verdict, fidelity_status, presentation_status, repair_status, and notes."
                            .to_string(),
                    depends_on: vec!["build".to_string()],
                },
            ],
        },
    ]
}

pub fn builtin_agent_playbook(playbook_id: Option<&str>) -> Option<AgentPlaybookDefinition> {
    let playbook_id = playbook_id
        .map(str::trim)
        .filter(|value| !value.is_empty())?;
    builtin_agent_playbooks()
        .into_iter()
        .find(|playbook| playbook.playbook_id == playbook_id)
}

pub fn recommended_agent_playbook(
    goal: &str,
    resolved_intent: Option<&ResolvedIntentState>,
) -> Option<AgentPlaybookDefinition> {
    let resolved_intent = resolved_intent?;
    let intent_id = resolved_intent.intent_id.trim();
    let code_change = query_requests_code_change_work(goal);
    let evidence_heavy =
        query_requests_deep_research_work(goal) || query_requests_verification_work(goal);
    match intent_id {
        "workspace.ops" | "delegation.task"
            if code_change && (evidence_heavy || goal.to_ascii_lowercase().contains("port")) =>
        {
            builtin_agent_playbook(Some("evidence_audited_patch"))
        }
        "web.research" | "memory.recall"
            if query_requests_deep_research_work(goal)
                || query_requests_verification_work(goal) =>
        {
            builtin_agent_playbook(Some("citation_grounded_brief"))
        }
        "delegation.task" if query_requests_research_backed_artifact_work(goal) => {
            builtin_agent_playbook(Some("research_backed_artifact_gate"))
        }
        "delegation.task" if query_requests_artifact_work(goal) => {
            builtin_agent_playbook(Some("artifact_generation_gate"))
        }
        "delegation.task" if query_requests_browser_work(goal) => {
            builtin_agent_playbook(Some("browser_postcondition_gate"))
        }
        "delegation.task"
            if query_requests_deep_research_work(goal)
                || query_requests_verification_work(goal) =>
        {
            builtin_agent_playbook(Some("citation_grounded_brief"))
        }
        _ => None,
    }
}

pub fn render_agent_playbook_catalog(
    tools: &[LlmToolDefinition],
    goal: &str,
    resolved_intent: Option<&ResolvedIntentState>,
) -> Option<String> {
    let supports_delegation = tools.iter().any(|tool| tool.name == "agent__delegate");
    if !supports_delegation {
        return None;
    }

    let mut lines = vec!["[PARENT PLAYBOOKS]".to_string()];
    if let Some(recommended) = recommended_agent_playbook(goal, resolved_intent) {
        lines.push(format!(
            "Recommended now: `{}` for this task's higher-order route.",
            recommended.playbook_id,
        ));
    }

    for playbook in builtin_agent_playbooks() {
        lines.push(format!(
            "- `{}` -> {} Trigger intents: {}. Budget {}. Final merge `{}`. Expected output: {}.",
            playbook.playbook_id,
            playbook.summary,
            if playbook.trigger_intents.is_empty() {
                "none".to_string()
            } else {
                playbook.trigger_intents.join(", ")
            },
            playbook.default_budget,
            playbook.completion_contract.merge_mode.as_label(),
            playbook.completion_contract.expected_output
        ));
        lines.push(format!("  Goal template: {}", playbook.goal_template));
        for step in playbook.steps {
            let dependency_suffix = if step.depends_on.is_empty() {
                String::new()
            } else {
                format!(" depends on {}", step.depends_on.join(", "))
            };
            lines.push(format!(
                "  Step `{}` -> {}/{}{}: {} Goal template: {}",
                step.step_id,
                step.worker_template_id,
                step.worker_workflow_id,
                dependency_suffix,
                step.summary,
                step.goal_template
            ));
        }
    }

    Some(lines.join("\n"))
}

#[cfg(test)]
#[path = "agent_playbooks/tests.rs"]
mod tests;
