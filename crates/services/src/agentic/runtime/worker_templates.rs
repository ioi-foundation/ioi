use crate::agentic::runtime::types::{
    WorkerCompletionContract, WorkerMergeMode, WorkerTemplateDefinition,
    WorkerTemplateWorkflowDefinition,
};
use ioi_types::app::agentic::LlmToolDefinition;

pub fn builtin_worker_templates() -> Vec<WorkerTemplateDefinition> {
    vec![
        WorkerTemplateDefinition {
            template_id: "context_worker".to_string(),
            label: "Context Worker".to_string(),
            role: "Context Worker".to_string(),
            summary:
                "Bounded child worker for repo-grounded context capture, skill selection, and targeted-check planning before any code patch lands."
                    .to_string(),
            default_budget: 72,
            max_retries: 1,
            allowed_tools: vec![
                "file__read".to_string(),
                "file__list".to_string(),
                "file__search".to_string(),
                "file__info".to_string(),
                "memory__search".to_string(),
                "memory__read".to_string(),
                "agent__complete".to_string(),
                "agent__await".to_string(),
            ],
            completion_contract: WorkerCompletionContract {
                success_criteria:
                    "Return a compact repo context brief that names likely files, selected skills, targeted verification suggestions, and open questions."
                        .to_string(),
                expected_output:
                    "Repo context brief with likely files, skill cues, suggested verification targets, and open questions."
                        .to_string(),
                merge_mode: WorkerMergeMode::AppendAsEvidence,
                verification_hint: Some(
                    "Parent checks that the context brief stays bounded, names plausible repo surfaces, and suggests targeted verification instead of generic full-suite advice."
                        .to_string(),
                ),
            },
            workflows: vec![WorkerTemplateWorkflowDefinition {
                workflow_id: "repo_context_brief".to_string(),
                label: "Repo Context Brief".to_string(),
                summary:
                    "Repo-grounded context pass that identifies relevant files, skills, and targeted checks before code execution begins."
                        .to_string(),
                goal_template:
                    "Inspect repo context for {topic}, identify the most relevant files and skills, then return a bounded context brief with targeted validation suggestions and open questions."
                        .to_string(),
                trigger_intents: vec!["workspace.ops".to_string(), "delegation.task".to_string()],
                default_budget: Some(48),
                max_retries: Some(1),
                allowed_tools: vec![
                    "file__read".to_string(),
                    "file__list".to_string(),
                    "file__search".to_string(),
                    "file__info".to_string(),
                    "memory__search".to_string(),
                    "memory__read".to_string(),
                    "agent__complete".to_string(),
                    "agent__await".to_string(),
                ],
                completion_contract: Some(WorkerCompletionContract {
                    success_criteria:
                        "Return a deterministic repo context brief with likely files, selected skills, targeted verification ideas, and explicit unknowns."
                            .to_string(),
                    expected_output:
                        "Repo context brief with likely files, skill cues, targeted checks, and open questions."
                            .to_string(),
                    merge_mode: WorkerMergeMode::AppendAsEvidence,
                    verification_hint: Some(
                        "Parent checks that the brief identifies concrete repo surfaces and targeted checks without attempting the patch itself."
                            .to_string(),
                    ),
                }),
            },
            WorkerTemplateWorkflowDefinition {
                workflow_id: "artifact_context_brief".to_string(),
                label: "Artifact Context Brief".to_string(),
                summary:
                    "Artifact-focused context pass that identifies the intended deliverable shape, relevant frontend or UX skills, likely output files, and presentation checks before generation begins."
                        .to_string(),
                goal_template:
                    "Inspect available context for {topic}, identify the intended artifact shape, likely output files, relevant frontend or UX skills, and targeted presentation checks, then return a bounded artifact context brief."
                        .to_string(),
                trigger_intents: vec!["delegation.task".to_string()],
                default_budget: Some(44),
                max_retries: Some(1),
                allowed_tools: vec![
                    "file__read".to_string(),
                    "file__list".to_string(),
                    "file__search".to_string(),
                    "file__info".to_string(),
                    "memory__search".to_string(),
                    "memory__read".to_string(),
                    "agent__complete".to_string(),
                    "agent__await".to_string(),
                ],
                completion_contract: Some(WorkerCompletionContract {
                    success_criteria:
                        "Return a deterministic artifact context brief with artifact_goal, likely_output_files, selected_skills, verification_plan, and open questions."
                            .to_string(),
                    expected_output:
                        "Artifact context brief using markdown bullets for artifact_goal, likely_output_files, selected_skills, verification_plan, and notes."
                            .to_string(),
                    merge_mode: WorkerMergeMode::AppendAsEvidence,
                    verification_hint: Some(
                        "Parent checks that the brief names a plausible artifact shape, output files, and presentation checks without attempting generation."
                            .to_string(),
                    ),
                }),
            }],
        },
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
                "memory__read".to_string(),
                "model__responses".to_string(),
                "agent__complete".to_string(),
                "agent__await".to_string(),
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
                    "memory__read".to_string(),
                    "agent__complete".to_string(),
                    "agent__await".to_string(),
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
            template_id: "perception_worker".to_string(),
            label: "Perception Worker".to_string(),
            role: "Perception Worker".to_string(),
            summary:
                "Bounded child worker for observing the current browser surface, naming the likely target state, and stating the next safe action before execution."
                    .to_string(),
            default_budget: 64,
            max_retries: 1,
            allowed_tools: vec![
                "browser__inspect".to_string(),
                "agent__complete".to_string(),
            ],
            completion_contract: WorkerCompletionContract {
                success_criteria:
                    "Return a deterministic UI-state brief with the observed surface, likely target, approval risk, and next safe action."
                        .to_string(),
                expected_output:
                    "UI-state brief using markdown bullets for surface_status, ui_state, target, approval_risk, next_action, and notes."
                        .to_string(),
                merge_mode: WorkerMergeMode::AppendAsEvidence,
                verification_hint: Some(
                    "Parent checks that the brief describes the current UI state and next safe action without taking side effects."
                        .to_string(),
                ),
            },
            workflows: vec![WorkerTemplateWorkflowDefinition {
                workflow_id: "ui_state_brief".to_string(),
                label: "UI State Brief".to_string(),
                summary:
                    "Computer-use perception pass that reports what the system thinks the current browser surface is before execution begins."
                        .to_string(),
                goal_template:
                    "Inspect the current browser or GUI state for {topic}, then return a UI-state brief with surface_status, ui_state, target, approval_risk, next_action, and notes."
                        .to_string(),
                trigger_intents: vec!["delegation.task".to_string()],
                default_budget: Some(36),
                max_retries: Some(1),
                allowed_tools: vec![
                    "browser__inspect".to_string(),
                    "agent__complete".to_string(),
                ],
                completion_contract: Some(WorkerCompletionContract {
                    success_criteria:
                        "Return a deterministic UI-state brief with the observed surface, likely target, approval risk, and next safe action."
                            .to_string(),
                    expected_output:
                        "UI-state brief using markdown bullets for surface_status, ui_state, target, approval_risk, next_action, and notes."
                            .to_string(),
                    merge_mode: WorkerMergeMode::AppendAsEvidence,
                    verification_hint: Some(
                        "Parent checks that the perception pass names the current UI state and likely next action without attempting the browser task itself."
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
                "Bounded child worker for checking success_conditions, validating outputs, and reporting deterministic gaps."
                    .to_string(),
            default_budget: 80,
            max_retries: 1,
            allowed_tools: vec![
                "memory__read".to_string(),
                "memory__search".to_string(),
                "model__rerank".to_string(),
                "model__responses".to_string(),
                "agent__complete".to_string(),
                "agent__await".to_string(),
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
                    "memory__read".to_string(),
                    "memory__search".to_string(),
                    "model__rerank".to_string(),
                    "agent__complete".to_string(),
                    "agent__await".to_string(),
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
            },
            WorkerTemplateWorkflowDefinition {
                workflow_id: "citation_audit".to_string(),
                label: "Citation Audit".to_string(),
                summary:
                    "Research-specific verification pass that audits the inherited cited brief for freshness, citation grounding, source coverage, and source independence before the parent accepts it."
                        .to_string(),
                goal_template:
                    "Verify whether the inherited cited brief for {topic} is current, grounded, and supported by independent sources, then return a citation verifier scorecard with blockers and next checks."
                        .to_string(),
                trigger_intents: vec![
                    "web.research".to_string(),
                    "memory.recall".to_string(),
                    "delegation.task".to_string(),
                ],
                default_budget: Some(48),
                max_retries: Some(0),
                allowed_tools: vec![
                    "memory__read".to_string(),
                    "agent__complete".to_string(),
                    "agent__await".to_string(),
                ],
                completion_contract: Some(WorkerCompletionContract {
                    success_criteria:
                        "Return a deterministic citation-verifier scorecard from the inherited cited brief, with verdict, freshness status, quote-grounding status, and clearly named evidence gaps or blockers."
                            .to_string(),
                    expected_output:
                        "Citation verifier scorecard using markdown bullets for verdict, freshness_status, quote_grounding_status, notes, and supporting evidence."
                            .to_string(),
                    merge_mode: WorkerMergeMode::AppendAsEvidence,
                    verification_hint: Some(
                        "Parent checks that the scorecard explicitly covers freshness, quote grounding, and the remaining source gaps from the inherited research handoff before accepting the brief."
                            .to_string(),
                    ),
                }),
            },
            WorkerTemplateWorkflowDefinition {
                workflow_id: "artifact_validation_audit".to_string(),
                label: "Artifact Validation Audit".to_string(),
                summary:
                    "Artifact-specific verification pass that validates brief fidelity, presentation readiness, and repair need from the retained artifact handoff."
                        .to_string(),
                goal_template:
                    "Validate whether the generated artifact for {topic} is faithful and presentation-ready by inspecting the retained files and generation handoff, then return an artifact validation scorecard with verdict, fidelity_status, presentation_status, repair_status, and notes."
                        .to_string(),
                trigger_intents: vec!["delegation.task".to_string()],
                default_budget: Some(52),
                max_retries: Some(0),
                allowed_tools: vec![
                    "memory__read".to_string(),
                    "memory__search".to_string(),
                    "model__rerank".to_string(),
                    "agent__complete".to_string(),
                    "agent__await".to_string(),
                ],
                completion_contract: Some(WorkerCompletionContract {
                    success_criteria:
                        "Return a deterministic artifact validation scorecard with verdict, fidelity status, presentation status, repair status, and clearly named blockers."
                            .to_string(),
                    expected_output:
                        "Artifact quality scorecard using markdown bullets for verdict, fidelity_status, presentation_status, repair_status, notes, and next_repair_step."
                            .to_string(),
                    merge_mode: WorkerMergeMode::AppendAsEvidence,
                    verification_hint: Some(
                        "Parent checks that the scorecard clearly separates brief fidelity, presentation readiness, and repair need before presenting the artifact route."
                            .to_string(),
                    ),
                }),
            },
            WorkerTemplateWorkflowDefinition {
                workflow_id: "browser_postcondition_audit".to_string(),
                label: "Browser Postcondition Audit".to_string(),
                summary:
                    "Computer-use verification pass that checks the claimed postcondition, approval state, and recovery need from the execution handoff."
                        .to_string(),
                goal_template:
                    "Verify whether the browser postcondition for {topic} actually holds by inspecting the execution handoff, then return a computer-use verifier scorecard with verdict, postcondition_status, approval_state, recovery_status, and notes."
                        .to_string(),
                trigger_intents: vec!["delegation.task".to_string()],
                default_budget: Some(48),
                max_retries: Some(0),
                allowed_tools: vec![
                    "memory__read".to_string(),
                    "memory__search".to_string(),
                    "model__rerank".to_string(),
                    "agent__complete".to_string(),
                    "agent__await".to_string(),
                ],
                completion_contract: Some(WorkerCompletionContract {
                    success_criteria:
                        "Return a deterministic computer-use verifier scorecard with verdict, postcondition state, approval state, recovery state, and clearly named blockers."
                            .to_string(),
                    expected_output:
                        "Computer-use verifier scorecard using markdown bullets for verdict, postcondition_status, approval_state, recovery_status, notes, and supporting evidence."
                            .to_string(),
                    merge_mode: WorkerMergeMode::AppendAsEvidence,
                    verification_hint: Some(
                        "Parent checks that the scorecard distinguishes claimed completion from verified postcondition state and makes any recovery need explicit."
                            .to_string(),
                    ),
                }),
            },
            WorkerTemplateWorkflowDefinition {
                workflow_id: "targeted_test_audit".to_string(),
                label: "Targeted Test Audit".to_string(),
                summary:
                    "Coding-specific verification pass that runs targeted commands first, widens only if needed, and reports regression risk as a typed scorecard."
                        .to_string(),
                goal_template:
                    "Verify the coding result for {topic} by running targeted checks first, widen only if the evidence requires it, then return a coding verifier scorecard with verdict, widening status, regression status, and blockers."
                        .to_string(),
                trigger_intents: vec!["workspace.ops".to_string(), "delegation.task".to_string()],
                default_budget: Some(56),
                max_retries: Some(0),
                allowed_tools: vec![
                    "file__read".to_string(),
                    "file__list".to_string(),
                    "file__search".to_string(),
                    "memory__read".to_string(),
                    "memory__search".to_string(),
                    "shell__cd".to_string(),
                    "shell__start".to_string(),
                    "agent__complete".to_string(),
                    "agent__await".to_string(),
                ],
                completion_contract: Some(WorkerCompletionContract {
                    success_criteria:
                        "Return a deterministic coding verifier scorecard with verdict, targeted command coverage, widening status, regression status, and clearly named blockers."
                            .to_string(),
                    expected_output:
                        "Coding verifier scorecard using markdown bullets for verdict, targeted_command_status, widening_status, regression_status, notes, and supporting command evidence."
                            .to_string(),
                    merge_mode: WorkerMergeMode::AppendAsEvidence,
                    verification_hint: Some(
                        "Parent checks that targeted commands ran first, any widened coverage is explicitly justified, and regression risk is stated separately from executor output."
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
                "file__read".to_string(),
                "file__list".to_string(),
                "file__search".to_string(),
                "file__edit".to_string(),
                "file__replace_line".to_string(),
                "file__write".to_string(),
                "shell__cd".to_string(),
                "shell__start".to_string(),
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
                    "file__read".to_string(),
                    "file__list".to_string(),
                    "file__search".to_string(),
                    "file__edit".to_string(),
                    "file__replace_line".to_string(),
                    "file__write".to_string(),
                    "shell__cd".to_string(),
                    "shell__start".to_string(),
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
        WorkerTemplateDefinition {
            template_id: "patch_synthesizer".to_string(),
            label: "Patch Synthesizer".to_string(),
            role: "Patch Synthesizer".to_string(),
            summary:
                "Bounded child worker for collapsing executor and verifier evidence into one coherent final patch handoff."
                    .to_string(),
            default_budget: 56,
            max_retries: 0,
            allowed_tools: vec![
                "file__read".to_string(),
                "file__list".to_string(),
                "file__search".to_string(),
                "memory__read".to_string(),
                "memory__search".to_string(),
                "agent__complete".to_string(),
                "agent__await".to_string(),
            ],
            completion_contract: WorkerCompletionContract {
                success_criteria:
                    "Return a final patch handoff that names touched files, accepted verification state, and residual risk without re-running the executor lane."
                        .to_string(),
                expected_output:
                    "Patch synthesis handoff with touched files, verification-ready status, and residual risk."
                        .to_string(),
                merge_mode: WorkerMergeMode::AppendSummaryToParent,
                verification_hint: Some(
                    "Parent checks that the final handoff aligns the executor summary with verifier evidence and clearly states any remaining risk."
                        .to_string(),
                ),
            },
            workflows: vec![WorkerTemplateWorkflowDefinition {
                workflow_id: "patch_synthesis_handoff".to_string(),
                label: "Patch Synthesis Handoff".to_string(),
                summary:
                    "Final synthesis pass that turns executor and verifier evidence into one coherent patch handoff."
                        .to_string(),
                goal_template:
                    "Synthesize the verified patch for {topic} into a final handoff that names touched files, accepted verification state, and residual risk."
                        .to_string(),
                trigger_intents: vec!["workspace.ops".to_string(), "delegation.task".to_string()],
                default_budget: Some(40),
                max_retries: Some(0),
                allowed_tools: vec![
                    "file__read".to_string(),
                    "file__list".to_string(),
                    "file__search".to_string(),
                    "memory__read".to_string(),
                    "memory__search".to_string(),
                    "agent__complete".to_string(),
                    "agent__await".to_string(),
                ],
                completion_contract: Some(WorkerCompletionContract {
                    success_criteria:
                        "Return a deterministic patch synthesis summary with status, touched files, verification readiness, and residual risk."
                            .to_string(),
                    expected_output:
                        "Patch synthesis summary using markdown bullets for status, touched_files, verification_ready, notes, and residual risk."
                            .to_string(),
                    merge_mode: WorkerMergeMode::AppendSummaryToParent,
                    verification_hint: Some(
                        "Parent checks that the synthesis step does not invent new execution work and that it faithfully carries forward the verifier verdict."
                            .to_string(),
                    ),
                }),
            }],
        },
        WorkerTemplateDefinition {
            template_id: "browser_specialist".to_string(),
            label: "Browser Specialist".to_string(),
            role: "Browser Specialist".to_string(),
            summary:
                "Bounded browser-only child worker for one-call autonomous browser sessions that return a final semantic report to the parent."
                    .to_string(),
            default_budget: 144,
            max_retries: 1,
            allowed_tools: vec![
                "browser__navigate".to_string(),
                "browser__inspect".to_string(),
                "browser__click".to_string(),
                "browser__hover".to_string(),
                "browser__click_at".to_string(),
                "browser__scroll".to_string(),
                "browser__type".to_string(),
                "browser__select".to_string(),
                "browser__press_key".to_string(),
                "browser__copy".to_string(),
                "browser__paste".to_string(),
                "browser__find_text".to_string(),
                "browser__wait".to_string(),
                "browser__upload".to_string(),
                "browser__list_options".to_string(),
                "browser__select_option".to_string(),
                "browser__back".to_string(),
                "browser__list_tabs".to_string(),
                "browser__switch_tab".to_string(),
                "browser__close_tab".to_string(),
                "browser__screenshot".to_string(),
                "agent__complete".to_string(),
            ],
            completion_contract: WorkerCompletionContract {
                success_criteria:
                    "Return one semantic browser-specialist report that states the executed browser actions, the observed state, whether the requested browser goal was achieved, and any blocker or approval handoff."
                        .to_string(),
                expected_output:
                    "Browser specialist report using markdown bullets for executed_steps, observed_state, goal_status, blocker_summary, approval_state, and notes."
                        .to_string(),
                merge_mode: WorkerMergeMode::AppendSummaryToParent,
                verification_hint: Some(
                    "Parent checks that the browser-specialist report names the observed state, distinguishes completion from blockage, and stays within browser-only execution."
                        .to_string(),
                ),
            },
            workflows: vec![WorkerTemplateWorkflowDefinition {
                workflow_id: "browser_subagent_session".to_string(),
                label: "Browser Subagent Session".to_string(),
                summary:
                    "One-call autonomous browser session that stays inside browser tools and returns a final semantic report to the parent."
                        .to_string(),
                goal_template:
                    "Complete the browser task for {topic} using only browser tools, then return a final semantic report with executed_steps, observed_state, goal_status, blocker_summary, approval_state, and notes."
                        .to_string(),
                trigger_intents: vec!["delegation.task".to_string()],
                default_budget: Some(96),
                max_retries: Some(1),
                allowed_tools: vec![
                    "browser__navigate".to_string(),
                    "browser__inspect".to_string(),
                    "browser__click".to_string(),
                    "browser__hover".to_string(),
                    "browser__click_at".to_string(),
                    "browser__scroll".to_string(),
                    "browser__type".to_string(),
                    "browser__select".to_string(),
                    "browser__press_key".to_string(),
                    "browser__copy".to_string(),
                    "browser__paste".to_string(),
                    "browser__find_text".to_string(),
                    "browser__wait".to_string(),
                    "browser__upload".to_string(),
                    "browser__list_options".to_string(),
                    "browser__select_option".to_string(),
                    "browser__back".to_string(),
                    "browser__list_tabs".to_string(),
                    "browser__switch_tab".to_string(),
                    "browser__close_tab".to_string(),
                    "browser__screenshot".to_string(),
                    "agent__complete".to_string(),
                ],
                completion_contract: Some(WorkerCompletionContract {
                    success_criteria:
                        "Return a deterministic final browser-session report with executed steps, observed state, goal status, approval state, and blocker summary."
                            .to_string(),
                    expected_output:
                        "Browser specialist report using markdown bullets for executed_steps, observed_state, goal_status, blocker_summary, approval_state, and notes."
                            .to_string(),
                    merge_mode: WorkerMergeMode::AppendSummaryToParent,
                    verification_hint: Some(
                        "Parent checks that the report is browser-grounded, names the observed state, and clearly distinguishes completion from handoff."
                            .to_string(),
                    ),
                }),
            }],
        },
        WorkerTemplateDefinition {
            template_id: "browser_operator".to_string(),
            label: "Browser Operator".to_string(),
            role: "Browser Operator".to_string(),
            summary:
                "Bounded child worker for browser and GUI execution passes that must report a clear postcondition back to the parent."
                    .to_string(),
            default_budget: 120,
            max_retries: 1,
            allowed_tools: vec![
                "browser__navigate".to_string(),
                "browser__inspect".to_string(),
                "browser__click".to_string(),
                "browser__click_at".to_string(),
                "browser__press_key".to_string(),
                "browser__type".to_string(),
                "browser__wait".to_string(),
                "screen__click".to_string(),
                "screen__type".to_string(),
                "agent__complete".to_string(),
            ],
            completion_contract: WorkerCompletionContract {
                success_criteria:
                    "Return a concise execution handoff that states the browser or GUI actions taken, the observed postcondition, approval state, recovery status, and any blocker."
                        .to_string(),
                expected_output:
                    "Computer-use handoff using markdown bullets for executed_steps, observed_postcondition, approval_state, recovery_status, next_recovery_step, blocker_summary, and notes."
                        .to_string(),
                merge_mode: WorkerMergeMode::AppendSummaryToParent,
                verification_hint: Some(
                    "Parent checks the observed postcondition, approval state, and whether the browser task actually progressed."
                        .to_string(),
                ),
            },
            workflows: vec![WorkerTemplateWorkflowDefinition {
                workflow_id: "browser_postcondition_pass".to_string(),
                label: "Browser Postcondition Pass".to_string(),
                summary:
                    "Bounded browser execution pass that uses grounded browser tools first, then returns the observed postcondition and any recovery need."
                        .to_string(),
                goal_template:
                    "Carry out {topic} in the browser or GUI using grounded observations first, then return the executed steps, observed postcondition, approval state, and blocker summary."
                        .to_string(),
                trigger_intents: vec!["delegation.task".to_string()],
                default_budget: Some(72),
                max_retries: Some(1),
                allowed_tools: vec![
                    "browser__navigate".to_string(),
                    "browser__inspect".to_string(),
                    "browser__click".to_string(),
                    "browser__click_at".to_string(),
                    "browser__press_key".to_string(),
                    "browser__type".to_string(),
                    "browser__wait".to_string(),
                    "screen__click".to_string(),
                    "screen__type".to_string(),
                    "agent__complete".to_string(),
                ],
                completion_contract: Some(WorkerCompletionContract {
                    success_criteria:
                        "Return a deterministic browser execution handoff with the observed postcondition, approval state, recovery status, and the next safe recovery step when blocked."
                            .to_string(),
                    expected_output:
                        "Browser execution handoff using markdown bullets for executed_steps, observed_postcondition, approval_state, recovery_status, next_recovery_step, blocker_summary, and notes."
                            .to_string(),
                    merge_mode: WorkerMergeMode::AppendSummaryToParent,
                    verification_hint: Some(
                        "Parent checks the observed browser state and whether the delegated task reached the intended postcondition."
                            .to_string(),
                    ),
                }),
            }],
        },
        WorkerTemplateDefinition {
            template_id: "artifact_builder".to_string(),
            label: "Artifact Builder".to_string(),
            role: "Artifact Builder".to_string(),
            summary:
                "Bounded child worker for generating or refining file-backed artifacts with retained implementation evidence."
                    .to_string(),
            default_budget: 168,
            max_retries: 1,
            allowed_tools: vec![
                "file__read".to_string(),
                "file__list".to_string(),
                "file__search".to_string(),
                "file__edit".to_string(),
                "file__write".to_string(),
                "shell__cd".to_string(),
                "shell__start".to_string(),
                "model__responses".to_string(),
                "agent__complete".to_string(),
            ],
            completion_contract: WorkerCompletionContract {
                success_criteria:
                    "Return an artifact handoff that names produced files, verification signals, presentation status, repair status, and the most important remaining visual or structural gaps."
                        .to_string(),
                expected_output:
                    "Artifact handoff using markdown bullets for produced_files, verification_signals, presentation_status, repair_status, and notes."
                        .to_string(),
                merge_mode: WorkerMergeMode::AppendSummaryToParent,
                verification_hint: Some(
                    "Parent checks the produced files, retained verification signals, and whether the artifact remains faithful to the requested brief."
                        .to_string(),
                ),
            },
            workflows: vec![WorkerTemplateWorkflowDefinition {
                workflow_id: "artifact_generate_repair".to_string(),
                label: "Artifact Generate and Repair".to_string(),
                summary:
                    "Bounded artifact-generation pass that creates or refines file-backed deliverables, records retained evidence, and calls out remaining validation gaps."
                        .to_string(),
                goal_template:
                    "Generate or refine {topic} as a file-backed artifact, retain the important output files and verification signals, and return a concise handoff with produced_files, verification_signals, presentation_status, repair_status, and remaining visual or structural gaps."
                        .to_string(),
                trigger_intents: vec!["delegation.task".to_string()],
                default_budget: Some(108),
                max_retries: Some(1),
                allowed_tools: vec![
                    "file__read".to_string(),
                    "file__list".to_string(),
                    "file__search".to_string(),
                    "file__edit".to_string(),
                    "file__write".to_string(),
                    "shell__cd".to_string(),
                    "shell__start".to_string(),
                    "model__responses".to_string(),
                    "agent__complete".to_string(),
                ],
                completion_contract: Some(WorkerCompletionContract {
                    success_criteria:
                        "Return a deterministic artifact handoff with produced files, retained verification signals, presentation status, repair status, and any unresolved design or rendering blockers."
                            .to_string(),
                    expected_output:
                        "Artifact handoff using markdown bullets for produced_files, verification_signals, presentation_status, repair_status, and notes."
                            .to_string(),
                    merge_mode: WorkerMergeMode::AppendSummaryToParent,
                    verification_hint: Some(
                        "Parent checks the produced files, retained verification signals, and whether the artifact still needs repair before presentation."
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
        Some("context_worker") => "Context Worker",
        Some("researcher") => "Research Worker",
        Some("perception_worker") => "Perception Worker",
        Some("verifier") => "Verification Worker",
        Some("coder") => "Coding Worker",
        Some("patch_synthesizer") => "Patch Synthesizer",
        Some("browser_specialist") => "Browser Specialist",
        Some("browser_operator") => "Browser Operator",
        Some("artifact_builder") => "Artifact Builder",
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
#[path = "worker_templates/tests.rs"]
mod tests;
