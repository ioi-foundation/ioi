use super::clarification::clarification_request_for_outcome_request;
use super::route_contract::{
    append_route_contract_event, execution_strategy_id, non_artifact_route_summary,
    route_decision_for_outcome_request,
};
use super::*;
use crate::models::StudioArtifactFileRole;
use base64::Engine as _;
use ioi_types::app::StudioDomainPolicyBundle;

fn outcome_kind_id(kind: StudioOutcomeKind) -> &'static str {
    match kind {
        StudioOutcomeKind::Conversation => "conversation",
        StudioOutcomeKind::ToolWidget => "tool_widget",
        StudioOutcomeKind::Visualizer => "visualizer",
        StudioOutcomeKind::Artifact => "artifact",
    }
}

fn non_artifact_route_title(intent: &str, outcome_request: &StudioOutcomeRequest) -> String {
    let base = derive_artifact_title(intent);
    match outcome_request.outcome_kind {
        StudioOutcomeKind::Conversation => format!("Conversation route · {base}"),
        StudioOutcomeKind::ToolWidget => format!("Tool widget route · {base}"),
        StudioOutcomeKind::Visualizer => format!("Visualizer route · {base}"),
        StudioOutcomeKind::Artifact => base,
    }
}

fn non_artifact_execution_domain(kind: StudioOutcomeKind) -> String {
    format!("studio_{}", outcome_kind_id(kind))
}

fn non_artifact_adapter_label(
    kind: StudioOutcomeKind,
    strategy: StudioExecutionStrategy,
) -> String {
    format!(
        "{}_{}_v1",
        outcome_kind_id(kind),
        execution_strategy_id(strategy)
    )
}

fn route_hint_details(outcome_request: &StudioOutcomeRequest) -> Vec<String> {
    outcome_request.routing_hints.clone()
}

fn non_artifact_swarm_plan(outcome_request: &StudioOutcomeRequest) -> SwarmPlan {
    let execution_domain = non_artifact_execution_domain(outcome_request.outcome_kind);
    let adapter_label = non_artifact_adapter_label(
        outcome_request.outcome_kind,
        outcome_request.execution_strategy,
    );
    let strategy = execution_strategy_id(outcome_request.execution_strategy).to_string();
    let responder_title = match outcome_request.outcome_kind {
        StudioOutcomeKind::Conversation => "Conversation handoff",
        StudioOutcomeKind::ToolWidget => "Tool-widget handoff",
        StudioOutcomeKind::Visualizer => "Visualizer handoff",
        StudioOutcomeKind::Artifact => "Artifact handoff",
    };
    let responder_summary = match outcome_request.outcome_kind {
        StudioOutcomeKind::Conversation => {
            "Keep the request on the conversation surface and preserve the shared execution evidence."
        }
        StudioOutcomeKind::ToolWidget => {
            "Keep the request on the tool-widget surface and preserve the shared execution evidence."
        }
        StudioOutcomeKind::Visualizer => {
            "Keep the request on the visualizer surface and preserve the shared execution evidence."
        }
        StudioOutcomeKind::Artifact => {
            "Keep the request on the artifact surface and preserve the shared execution evidence."
        }
    };

    SwarmPlan {
        version: 1,
        strategy,
        execution_domain,
        adapter_label,
        parallelism_mode: "sequential_by_default".to_string(),
        top_level_objective: Some(format!(
            "Route the request onto the {} surface and preserve truthful execution evidence.",
            outcome_kind_id(outcome_request.outcome_kind)
        )),
        decomposition_hypothesis: Some(
            "The request can be satisfied with a small known non-artifact work graph."
                .to_string(),
        ),
        decomposition_type: Some("small_graph_functional_decomposition".to_string()),
        first_frontier_ids: vec!["handoff".to_string()],
        spawn_conditions: vec![
            "Spawn a clarification gate only when the router discovers unresolved ambiguity."
                .to_string(),
        ],
        prune_conditions: vec![
            "Prune clarification work once the reply handoff is already unblocked.".to_string(),
        ],
        merge_strategy: Some("typed_reply_surface_projection".to_string()),
        verification_strategy: Some("route_truth_before_reply".to_string()),
        fallback_collapse_strategy: Some(
            "Collapse to the reply handoff once clarification obligations are satisfied."
                .to_string(),
        ),
        completion_invariant: Some(ioi_api::execution::ExecutionCompletionInvariant {
            summary:
                "Complete once the mandatory non-artifact handoff is satisfied and route truth is preserved."
                    .to_string(),
            status: ExecutionCompletionInvariantStatus::Satisfied,
            required_work_item_ids: vec!["planner".to_string(), "handoff".to_string()],
            satisfied_work_item_ids: vec!["planner".to_string(), "handoff".to_string()],
            speculative_work_item_ids: if outcome_request.needs_clarification {
                vec!["clarification_gate".to_string()]
            } else {
                Vec::new()
            },
            pruned_work_item_ids: Vec::new(),
            required_verification_ids: vec!["route_truth".to_string()],
            satisfied_verification_ids: vec!["route_truth".to_string()],
            required_artifact_paths: Vec::new(),
            remaining_obligations: Vec::new(),
            allows_early_exit: true,
        }),
        work_items: vec![
            SwarmWorkItem {
                id: "planner".to_string(),
                title: "Outcome planner".to_string(),
                role: SwarmWorkerRole::Planner,
                summary:
                    "Lock the correct non-artifact route and execution strategy before any downstream handoff."
                        .to_string(),
                spawned_from_id: None,
                read_paths: vec!["request".to_string(), "route_context".to_string()],
                write_paths: Vec::new(),
                write_regions: Vec::new(),
                lease_requirements: Vec::new(),
                acceptance_criteria: vec![
                    "Outcome route is explicit.".to_string(),
                    "Execution strategy is explicit.".to_string(),
                ],
                dependency_ids: Vec::new(),
                blocked_on_ids: Vec::new(),
                verification_policy: None,
                retry_budget: None,
                status: SwarmWorkItemStatus::Succeeded,
            },
            SwarmWorkItem {
                id: "handoff".to_string(),
                title: responder_title.to_string(),
                role: SwarmWorkerRole::Responder,
                summary: responder_summary.to_string(),
                spawned_from_id: None,
                read_paths: vec!["request".to_string(), "execution_plan".to_string()],
                write_paths: Vec::new(),
                write_regions: Vec::new(),
                lease_requirements: Vec::new(),
                acceptance_criteria: vec![
                    "Studio reply remains truthful about the chosen surface.".to_string(),
                    "No artifact renderer is implied when none was invoked.".to_string(),
                ],
                dependency_ids: vec!["planner".to_string()],
                blocked_on_ids: Vec::new(),
                verification_policy: None,
                retry_budget: None,
                status: SwarmWorkItemStatus::Succeeded,
            },
        ],
    }
}

fn non_artifact_swarm_worker_receipts(
    outcome_request: &StudioOutcomeRequest,
    provenance: &crate::models::StudioRuntimeProvenance,
    swarm_plan: &SwarmPlan,
) -> Vec<SwarmWorkerReceipt> {
    let now = now_iso();
    let handoff_summary = match outcome_request.outcome_kind {
        StudioOutcomeKind::Conversation => {
            "Conversation stayed primary and no artifact renderer was launched."
        }
        StudioOutcomeKind::ToolWidget => {
            "Tool-widget stayed primary and no artifact renderer was launched."
        }
        StudioOutcomeKind::Visualizer => {
            "Visualizer stayed primary and no artifact renderer was launched."
        }
        StudioOutcomeKind::Artifact => "Artifact stayed primary.",
    };

    let clarification_questions = outcome_request.clarification_questions.clone();
    let planner_spawned_items = if outcome_request.needs_clarification {
        vec!["clarification_gate".to_string()]
    } else {
        Vec::new()
    };
    let handoff_status = swarm_plan
        .work_items
        .iter()
        .find(|item| item.id == "handoff")
        .map(|item| item.status)
        .unwrap_or(SwarmWorkItemStatus::Succeeded);

    let mut receipts = vec![SwarmWorkerReceipt {
        work_item_id: "planner".to_string(),
        role: SwarmWorkerRole::Planner,
        status: SwarmWorkItemStatus::Succeeded,
        result_kind: Some(if outcome_request.needs_clarification {
            ioi_api::execution::SwarmWorkerResultKind::DependencyDiscovered
        } else {
            ioi_api::execution::SwarmWorkerResultKind::Completed
        }),
        summary: format!(
            "Selected the {} route with the {} strategy.",
            outcome_kind_id(outcome_request.outcome_kind),
            execution_strategy_id(outcome_request.execution_strategy)
        ),
        started_at: now.clone(),
        finished_at: Some(now.clone()),
        runtime: provenance.clone(),
        read_paths: vec!["request".to_string(), "route_context".to_string()],
        write_paths: Vec::new(),
        write_regions: Vec::new(),
        spawned_work_item_ids: planner_spawned_items,
        blocked_on_ids: Vec::new(),
        prompt_bytes: None,
        output_bytes: None,
        output_preview: None,
        preview_language: None,
        notes: if outcome_request.needs_clarification {
            clarification_questions.clone()
        } else {
            let mut notes = vec!["No artifact files were requested on this route.".to_string()];
            notes.extend(route_hint_details(outcome_request));
            notes
        },
        failure: None,
    }];
    if outcome_request.needs_clarification {
        receipts.push(SwarmWorkerReceipt {
            work_item_id: "clarification_gate".to_string(),
            role: SwarmWorkerRole::Coordinator,
            status: SwarmWorkItemStatus::Blocked,
            result_kind: Some(ioi_api::execution::SwarmWorkerResultKind::Blocked),
            summary:
                "Clarification is required before the shared responder can safely finalize the route."
                    .to_string(),
            started_at: now.clone(),
            finished_at: Some(now.clone()),
            runtime: provenance.clone(),
            read_paths: vec!["request".to_string(), "clarification_questions".to_string()],
            write_paths: Vec::new(),
            write_regions: Vec::new(),
            spawned_work_item_ids: Vec::new(),
            blocked_on_ids: Vec::new(),
            prompt_bytes: None,
            output_bytes: None,
            output_preview: None,
            preview_language: None,
            notes: clarification_questions.clone(),
            failure: None,
        });
    }
    receipts.push(SwarmWorkerReceipt {
        work_item_id: "handoff".to_string(),
        role: SwarmWorkerRole::Responder,
        status: handoff_status,
        result_kind: Some(if outcome_request.needs_clarification {
            ioi_api::execution::SwarmWorkerResultKind::Blocked
        } else {
            ioi_api::execution::SwarmWorkerResultKind::Completed
        }),
        summary: handoff_summary.to_string(),
        started_at: now.clone(),
        finished_at: Some(now),
        runtime: provenance.clone(),
        read_paths: vec!["request".to_string(), "execution_plan".to_string()],
        write_paths: Vec::new(),
        write_regions: Vec::new(),
        spawned_work_item_ids: Vec::new(),
        blocked_on_ids: if outcome_request.needs_clarification {
            vec!["clarification_gate".to_string()]
        } else {
            Vec::new()
        },
        prompt_bytes: None,
        output_bytes: None,
        output_preview: None,
        preview_language: None,
        notes: vec![
            "Studio kept the shared execution evidence instead of surfacing a blocked artifact failure."
                .to_string(),
            route_hint_details(outcome_request).join(" · "),
        ],
        failure: if outcome_request.needs_clarification {
            Some("Clarification is still required before reply handoff can complete.".to_string())
        } else {
            None
        },
    });
    receipts
}

fn non_artifact_swarm_verification_receipts(
    outcome_request: &StudioOutcomeRequest,
) -> Vec<SwarmVerificationReceipt> {
    let status = if outcome_request.needs_clarification {
        "blocked"
    } else {
        "ready"
    };
    let route_detail = match outcome_request.outcome_kind {
        StudioOutcomeKind::Conversation => "conversation surface",
        StudioOutcomeKind::ToolWidget => "tool-widget surface",
        StudioOutcomeKind::Visualizer => "visualizer surface",
        StudioOutcomeKind::Artifact => "artifact surface",
    };

    vec![
        SwarmVerificationReceipt {
            id: "route_verification".to_string(),
            kind: "route_verification".to_string(),
            status: status.to_string(),
            summary: if outcome_request.needs_clarification {
                "Studio blocked execution because clarification is still required.".to_string()
            } else {
                format!(
                    "Studio verified that this request belongs on the {}.",
                    route_detail
                )
            },
            details: if outcome_request.needs_clarification {
                outcome_request.clarification_questions.clone()
            } else {
                route_hint_details(outcome_request)
            },
        },
        SwarmVerificationReceipt {
            id: "reply_surface".to_string(),
            kind: "reply_surface".to_string(),
            status: status.to_string(),
            summary: if outcome_request.needs_clarification {
                "The shared reply lane is blocked until the user answers the clarification."
                    .to_string()
            } else {
                "The shared reply lane remains available and no artifact renderer is required."
                    .to_string()
            },
            details: {
                let mut details = vec![format!(
                    "strategy:{}",
                    execution_strategy_id(outcome_request.execution_strategy)
                )];
                details.extend(route_hint_details(outcome_request));
                details
            },
        },
    ]
}

fn non_artifact_materialization_contract(
    intent: &str,
    outcome_request: &StudioOutcomeRequest,
    summary: &str,
    provenance: &crate::models::StudioRuntimeProvenance,
) -> StudioArtifactMaterializationContract {
    let mut swarm_plan = non_artifact_swarm_plan(outcome_request);
    let mut graph_mutation_receipts = Vec::<ExecutionGraphMutationReceipt>::new();
    let mut replan_receipts = Vec::<ExecutionReplanReceipt>::new();
    if outcome_request.needs_clarification {
        let clarification_gate = SwarmWorkItem {
            id: "clarification_gate".to_string(),
            title: "Clarification gate".to_string(),
            role: SwarmWorkerRole::Coordinator,
            summary:
                "Hold the response until the user answers the required clarification questions."
                    .to_string(),
            spawned_from_id: Some("planner".to_string()),
            read_paths: vec!["request".to_string(), "clarification_questions".to_string()],
            write_paths: Vec::new(),
            write_regions: Vec::new(),
            lease_requirements: Vec::new(),
            acceptance_criteria: vec![
                "Clarification questions stay visible.".to_string(),
                "Responder stays blocked until clarification arrives.".to_string(),
            ],
            dependency_ids: vec!["planner".to_string()],
            blocked_on_ids: Vec::new(),
            verification_policy: Some(ioi_api::execution::SwarmVerificationPolicy::Blocking),
            retry_budget: Some(0),
            status: SwarmWorkItemStatus::Blocked,
        };
        let clarification_gate_id = clarification_gate.id.clone();
        let clarification_details = outcome_request.clarification_questions.clone();
        let _ = spawn_follow_up_swarm_work_item(&mut swarm_plan, clarification_gate);
        let _ = block_swarm_work_item_on(
            &mut swarm_plan,
            "handoff",
            std::slice::from_ref(&clarification_gate_id),
        );
        graph_mutation_receipts.push(ExecutionGraphMutationReceipt {
            id: "clarification-gate-spawned".to_string(),
            mutation_kind: "subtask_spawned".to_string(),
            status: "applied".to_string(),
            summary:
                "The planner discovered a clarification dependency and spawned a gate before reply handoff."
                    .to_string(),
            triggered_by_work_item_id: Some("planner".to_string()),
            affected_work_item_ids: vec![clarification_gate_id.clone(), "handoff".to_string()],
            details: clarification_details.clone(),
        });
        replan_receipts.push(ExecutionReplanReceipt {
            id: "clarification-replan".to_string(),
            status: "blocked".to_string(),
            summary:
                "Shared execution widened the plan with a clarification gate before the responder could finalize."
                    .to_string(),
            triggered_by_work_item_id: Some("planner".to_string()),
            spawned_work_item_ids: vec![clarification_gate_id],
            blocked_work_item_ids: vec!["handoff".to_string()],
            details: clarification_details,
        });
    }
    let swarm_worker_receipts =
        non_artifact_swarm_worker_receipts(outcome_request, provenance, &swarm_plan);
    let swarm_verification_receipts = non_artifact_swarm_verification_receipts(outcome_request);
    let verification_status = if outcome_request.needs_clarification {
        "blocked".to_string()
    } else {
        "ready".to_string()
    };
    let completed_work_items = swarm_plan
        .work_items
        .iter()
        .filter(|item| {
            matches!(
                item.status,
                SwarmWorkItemStatus::Succeeded | SwarmWorkItemStatus::Skipped
            )
        })
        .count();
    let failed_work_items = swarm_plan
        .work_items
        .iter()
        .filter(|item| {
            matches!(
                item.status,
                SwarmWorkItemStatus::Blocked
                    | SwarmWorkItemStatus::Failed
                    | SwarmWorkItemStatus::Rejected
            )
        })
        .count();
    let swarm_execution = SwarmExecutionSummary {
        enabled: true,
        current_stage: if outcome_request.needs_clarification {
            "routing".to_string()
        } else {
            "reply".to_string()
        },
        execution_stage: Some(if outcome_request.needs_clarification {
            ExecutionStage::Dispatch
        } else {
            ExecutionStage::Finalize
        }),
        active_worker_role: None,
        total_work_items: swarm_plan.work_items.len(),
        completed_work_items,
        failed_work_items,
        verification_status,
        strategy: swarm_plan.strategy.clone(),
        execution_domain: swarm_plan.execution_domain.clone(),
        adapter_label: swarm_plan.adapter_label.clone(),
        parallelism_mode: swarm_plan.parallelism_mode.clone(),
    };
    let dispatch_batches = plan_swarm_dispatch_batches(&swarm_plan);
    let execution_budget_summary = ExecutionBudgetSummary {
        planned_worker_count: Some(swarm_plan.work_items.len()),
        dispatched_worker_count: Some(
            swarm_worker_receipts
                .iter()
                .filter(|receipt| {
                    !matches!(receipt.result_kind, Some(SwarmWorkerResultKind::Blocked))
                })
                .count(),
        ),
        token_budget: None,
        token_usage: None,
        wall_clock_ms: None,
        coordination_overhead_ms: None,
        status: if outcome_request.needs_clarification {
            "blocked".to_string()
        } else {
            "completed".to_string()
        },
    };
    let mut execution_envelope = build_execution_envelope_from_swarm_with_receipts(
        Some(outcome_request.execution_strategy),
        Some(swarm_plan.execution_domain.clone()),
        Some(execution_domain_kind_for_outcome(
            outcome_request.outcome_kind,
        )),
        Some(&swarm_plan),
        Some(&swarm_execution),
        &swarm_worker_receipts,
        &[],
        &[],
        &swarm_verification_receipts,
        &graph_mutation_receipts,
        &dispatch_batches,
        &[],
        &replan_receipts,
        Some(execution_budget_summary),
        &[],
    );
    annotate_execution_envelope(
        &mut execution_envelope,
        outcome_request.execution_mode_decision.clone(),
        Some(ioi_api::execution::completion_invariant_for_plan(
            &swarm_plan,
            &swarm_verification_receipts,
            Vec::new(),
        )),
    );

    StudioArtifactMaterializationContract {
        version: 7,
        request_kind: outcome_kind_id(outcome_request.outcome_kind).to_string(),
        normalized_intent: intent.trim().to_string(),
        summary: summary.to_string(),
        artifact_brief: None,
        preparation_needs: None,
        prepared_context_resolution: None,
        skill_discovery_resolution: None,
        blueprint: None,
        artifact_ir: None,
        selected_skills: Vec::new(),
        retrieved_exemplars: Vec::new(),
        edit_intent: None,
        candidate_summaries: Vec::new(),
        winning_candidate_id: None,
        winning_candidate_rationale: None,
        execution_envelope,
        swarm_execution: Some(swarm_execution),
        swarm_plan: Some(swarm_plan),
        swarm_worker_receipts,
        swarm_change_receipts: Vec::new(),
        swarm_merge_receipts: Vec::new(),
        swarm_verification_receipts,
        render_evaluation: None,
        validation: None,
        output_origin: Some(output_origin_from_runtime_provenance(provenance)),
        production_provenance: Some(provenance.clone()),
        acceptance_provenance: Some(provenance.clone()),
        fallback_used: false,
        ux_lifecycle: Some(StudioArtifactUxLifecycle::Validated),
        failure: None,
        navigator_nodes: Vec::new(),
        file_writes: Vec::new(),
        command_intents: Vec::new(),
        preview_intent: None,
        verification_steps: vec![
            verification_step("route", "Verify route", "success"),
            verification_step(
                "reply_surface",
                "Verify reply surface",
                if outcome_request.needs_clarification {
                    "blocked"
                } else {
                    "success"
                },
            ),
        ],
        pipeline_steps: Vec::new(),
        runtime_narration_events: Vec::new(),
        notes: vec![
            "Studio intentionally kept this request off the artifact materialization path."
                .to_string(),
            "The shared execution envelope still records plan, worker, and verification state."
                .to_string(),
            "No renderer-specific fallback artifact was injected for this route.".to_string(),
            if outcome_request.routing_hints.is_empty() {
                "routing_hints:none".to_string()
            } else {
                format!(
                    "routing_hints:{}",
                    outcome_request.routing_hints.join(" | ")
                )
            },
        ],
    }
}

fn verified_reply_for_non_artifact_route(
    title: &str,
    summary: &str,
    lifecycle_state: StudioArtifactLifecycleState,
    provenance: &crate::models::StudioRuntimeProvenance,
    outcome_request: &StudioOutcomeRequest,
) -> StudioVerifiedReply {
    let status = match lifecycle_state {
        StudioArtifactLifecycleState::Draft
        | StudioArtifactLifecycleState::Planned
        | StudioArtifactLifecycleState::Materializing
        | StudioArtifactLifecycleState::Rendering
        | StudioArtifactLifecycleState::Implementing
        | StudioArtifactLifecycleState::Verifying => StudioArtifactVerificationStatus::Pending,
        StudioArtifactLifecycleState::Ready => StudioArtifactVerificationStatus::Ready,
        StudioArtifactLifecycleState::Blocked => StudioArtifactVerificationStatus::Blocked,
        StudioArtifactLifecycleState::Failed => StudioArtifactVerificationStatus::Failed,
        StudioArtifactLifecycleState::Partial => StudioArtifactVerificationStatus::Partial,
    };

    StudioVerifiedReply {
        status,
        lifecycle_state,
        title: title.to_string(),
        summary: summary.to_string(),
        evidence: vec![
            format!("outcome:{}", outcome_kind_id(outcome_request.outcome_kind)),
            format!(
                "strategy:{}",
                execution_strategy_id(outcome_request.execution_strategy)
            ),
            format!("provenance:{}", provenance.label),
        ]
        .into_iter()
        .chain(
            outcome_request
                .routing_hints
                .iter()
                .map(|hint| format!("route_hint:{hint}")),
        )
        .collect(),
        production_provenance: Some(provenance.clone()),
        acceptance_provenance: Some(provenance.clone()),
        failure: None,
        updated_at: now_iso(),
    }
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn text_data_url(mime: &str, content: &str) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(content.as_bytes());
    format!("data:{mime};base64,{encoded}")
}

fn non_artifact_domain_policy_bundle(
    outcome_request: &StudioOutcomeRequest,
    widget_state: Option<&StudioRetainedWidgetState>,
) -> StudioDomainPolicyBundle {
    derive_studio_domain_policy_bundle(
        outcome_request.lane_frame.as_ref(),
        outcome_request.request_frame.as_ref(),
        outcome_request.source_selection.as_ref(),
        outcome_request.outcome_kind,
        &outcome_request.routing_hints,
        outcome_request.needs_clarification,
        widget_state,
    )
}

fn extract_mermaid_block(content: &str) -> Option<String> {
    let trimmed = content.trim();
    let stripped = trimmed.strip_prefix("```mermaid")?;
    let stripped = stripped.strip_suffix("```")?;
    let block = stripped.trim();
    if block.is_empty() {
        None
    } else {
        Some(block.to_string())
    }
}

fn non_artifact_surface_markdown(
    title: &str,
    summary: &str,
    route_decision: &RoutingRouteDecision,
    domain_policy_bundle: &StudioDomainPolicyBundle,
    outcome_request: &StudioOutcomeRequest,
) -> String {
    let mut sections = vec![
        format!("# {title}"),
        String::new(),
        summary.trim().to_string(),
        String::new(),
        "## Route contract".to_string(),
        format!("- route family: {}", route_decision.route_family),
        format!("- output intent: {}", route_decision.output_intent),
        format!(
            "- direct answer allowed: {}",
            route_decision.direct_answer_allowed
        ),
    ];
    if let Some(policy) = domain_policy_bundle.presentation_policy.as_ref() {
        sections.push(format!(
            "- presentation surface: {}",
            policy.primary_surface
        ));
    }
    if !domain_policy_bundle.source_ranking.is_empty() {
        sections.push(String::new());
        sections.push("## Source ranking".to_string());
        for entry in &domain_policy_bundle.source_ranking {
            sections.push(format!(
                "- {}. {:?}: {}",
                entry.rank, entry.source, entry.rationale
            ));
        }
    }
    if let Some(widget_state) = domain_policy_bundle.retained_widget_state.as_ref() {
        if !widget_state.bindings.is_empty() {
            sections.push(String::new());
            sections.push("## Retained widget state".to_string());
            for binding in &widget_state.bindings {
                sections.push(format!(
                    "- {} = {} ({})",
                    binding.key, binding.value, binding.source
                ));
            }
        }
    }
    if outcome_request.needs_clarification && !outcome_request.clarification_questions.is_empty() {
        sections.push(String::new());
        sections.push("## Clarification".to_string());
        for question in &outcome_request.clarification_questions {
            sections.push(format!("- {question}"));
        }
    }
    sections.join("\n")
}

fn non_artifact_surface_html(
    title: &str,
    summary: &str,
    route_decision: &RoutingRouteDecision,
    domain_policy_bundle: &StudioDomainPolicyBundle,
    outcome_request: &StudioOutcomeRequest,
) -> String {
    let summary_html = summary
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| format!("<p>{}</p>", escape_html(line)))
        .collect::<Vec<_>>()
        .join("");
    let chips = [
        Some(format!("Route: {}", route_decision.route_family)),
        Some(format!("Output: {}", route_decision.output_intent)),
        domain_policy_bundle
            .presentation_policy
            .as_ref()
            .map(|policy| format!("Surface: {}", policy.primary_surface)),
        domain_policy_bundle
            .risk_profile
            .as_ref()
            .map(|risk| format!("Risk: {:?}", risk.sensitivity).to_ascii_lowercase()),
    ]
    .into_iter()
    .flatten()
    .map(|label: String| {
        format!(
            "<span class=\"chip\">{}</span>",
            escape_html(label.as_str())
        )
    })
    .collect::<Vec<_>>()
    .join("");
    let ranking_html = if domain_policy_bundle.source_ranking.is_empty() {
        String::new()
    } else {
        format!(
            "<section><h3>Source ranking</h3><ol>{}</ol></section>",
            domain_policy_bundle
                .source_ranking
                .iter()
                .map(|entry| format!(
                    "<li><strong>{:?}</strong> · {}</li>",
                    entry.source,
                    escape_html(&entry.rationale)
                ))
                .collect::<Vec<_>>()
                .join("")
        )
    };
    let clarification_html = if outcome_request.needs_clarification
        && !outcome_request.clarification_questions.is_empty()
    {
        format!(
            "<section><h3>Clarification</h3><ul>{}</ul></section>",
            outcome_request
                .clarification_questions
                .iter()
                .map(|question| format!("<li>{}</li>", escape_html(question)))
                .collect::<Vec<_>>()
                .join("")
        )
    } else {
        String::new()
    };
    let retained_widget_state = domain_policy_bundle
        .retained_widget_state
        .as_ref()
        .map(|state| serde_json::to_string(state).unwrap_or_else(|_| "null".to_string()))
        .unwrap_or_else(|| "null".to_string());
    format!(
        "<!doctype html>
<html lang=\"en\">
  <head>
    <meta charset=\"utf-8\" />
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
    <title>{title}</title>
    <style>
      :root {{
        color-scheme: dark;
        --bg: #0d1117;
        --panel: #111821;
        --muted: #8b99ad;
        --text: #ecf1f7;
        --line: rgba(255,255,255,0.08);
        --accent: #59b3ff;
      }}
      body {{
        margin: 0;
        padding: 24px;
        font-family: ui-sans-serif, system-ui, sans-serif;
        background: radial-gradient(circle at top, #182334 0%, var(--bg) 60%);
        color: var(--text);
      }}
      .shell {{
        max-width: 920px;
        margin: 0 auto;
        background: rgba(10, 14, 20, 0.8);
        border: 1px solid var(--line);
        border-radius: 20px;
        padding: 24px;
        box-shadow: 0 24px 60px rgba(0, 0, 0, 0.28);
      }}
      .eyebrow {{
        font-size: 12px;
        text-transform: uppercase;
        letter-spacing: 0.12em;
        color: var(--muted);
      }}
      h1 {{
        margin: 8px 0 0;
        font-size: 28px;
      }}
      .chips {{
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
        margin: 18px 0 20px;
      }}
      .chip {{
        font-size: 12px;
        padding: 6px 10px;
        border-radius: 999px;
        border: 1px solid var(--line);
        background: rgba(255,255,255,0.04);
      }}
      section {{
        margin-top: 22px;
        padding-top: 18px;
        border-top: 1px solid var(--line);
      }}
      h3 {{
        margin: 0 0 10px;
        font-size: 14px;
        letter-spacing: 0.04em;
        text-transform: uppercase;
        color: var(--muted);
      }}
      p, li {{
        line-height: 1.55;
      }}
      code {{
        color: var(--accent);
      }}
    </style>
  </head>
  <body>
    <main class=\"shell\">
      <div class=\"eyebrow\">Studio parity surface</div>
      <h1>{title_html}</h1>
      <div class=\"chips\">{chips}</div>
      <section>
        <h3>Outcome</h3>
        {summary_html}
      </section>
      {ranking_html}
      {clarification_html}
    </main>
    <script>
      const widgetState = {retained_widget_state};
      if (widgetState) {{
        window.parent.postMessage({{
          __studioWidgetState: true,
          widgetState,
        }}, \"*\");
      }}
    </script>
  </body>
</html>",
        title = escape_html(title),
        title_html = escape_html(title),
        chips = chips,
        summary_html = summary_html,
        ranking_html = ranking_html,
        clarification_html = clarification_html,
        retained_widget_state = retained_widget_state,
    )
}

fn non_artifact_manifest(
    artifact_id: &str,
    title: &str,
    summary: &str,
    lifecycle_state: StudioArtifactLifecycleState,
    provenance: &crate::models::StudioRuntimeProvenance,
    outcome_request: &StudioOutcomeRequest,
    widget_state: Option<&StudioRetainedWidgetState>,
) -> StudioArtifactManifest {
    let route_decision = route_decision_for_outcome_request(outcome_request);
    let domain_policy_bundle = non_artifact_domain_policy_bundle(outcome_request, widget_state);
    let source_markdown = non_artifact_surface_markdown(
        title,
        summary,
        &route_decision,
        &domain_policy_bundle,
        outcome_request,
    );
    let (renderer, render_path, render_mime, render_content) =
        if outcome_request.outcome_kind == StudioOutcomeKind::Visualizer {
            if let Some(mermaid) = extract_mermaid_block(summary) {
                (
                    StudioRendererKind::Mermaid,
                    "surface/diagram.mmd".to_string(),
                    "text/plain".to_string(),
                    mermaid,
                )
            } else {
                (
                    StudioRendererKind::HtmlIframe,
                    "surface/index.html".to_string(),
                    "text/html".to_string(),
                    non_artifact_surface_html(
                        title,
                        summary,
                        &route_decision,
                        &domain_policy_bundle,
                        outcome_request,
                    ),
                )
            }
        } else {
            (
                StudioRendererKind::HtmlIframe,
                "surface/index.html".to_string(),
                "text/html".to_string(),
                non_artifact_surface_html(
                    title,
                    summary,
                    &route_decision,
                    &domain_policy_bundle,
                    outcome_request,
                ),
            )
        };

    StudioArtifactManifest {
        artifact_id: artifact_id.to_string(),
        title: title.to_string(),
        artifact_class: match outcome_request.outcome_kind {
            StudioOutcomeKind::Visualizer => StudioArtifactClass::Visual,
            StudioOutcomeKind::ToolWidget => StudioArtifactClass::InteractiveSingleFile,
            _ => StudioArtifactClass::Document,
        },
        renderer,
        primary_tab: "render".to_string(),
        tabs: vec![
            StudioArtifactManifestTab {
                id: "render".to_string(),
                label: "Render".to_string(),
                kind: StudioArtifactTabKind::Render,
                renderer: Some(renderer),
                file_path: Some(render_path.clone()),
                lens: Some("render".to_string()),
            },
            StudioArtifactManifestTab {
                id: "source".to_string(),
                label: "Source".to_string(),
                kind: StudioArtifactTabKind::Source,
                renderer: None,
                file_path: Some("surface/route.md".to_string()),
                lens: Some("source".to_string()),
            },
            StudioArtifactManifestTab {
                id: "evidence".to_string(),
                label: "Evidence".to_string(),
                kind: StudioArtifactTabKind::Evidence,
                renderer: None,
                file_path: None,
                lens: Some("evidence".to_string()),
            },
        ],
        files: vec![
            StudioArtifactManifestFile {
                path: render_path,
                mime: render_mime.clone(),
                role: StudioArtifactFileRole::Primary,
                renderable: true,
                downloadable: false,
                artifact_id: None,
                external_url: Some(text_data_url(&render_mime, &render_content)),
            },
            StudioArtifactManifestFile {
                path: "surface/route.md".to_string(),
                mime: "text/markdown".to_string(),
                role: StudioArtifactFileRole::Source,
                renderable: false,
                downloadable: false,
                artifact_id: None,
                external_url: Some(text_data_url("text/markdown", &source_markdown)),
            },
        ],
        verification: StudioArtifactManifestVerification {
            status: if outcome_request.needs_clarification {
                StudioArtifactVerificationStatus::Blocked
            } else {
                StudioArtifactVerificationStatus::Ready
            },
            lifecycle_state,
            summary: summary.to_string(),
            production_provenance: Some(provenance.clone()),
            acceptance_provenance: Some(provenance.clone()),
            failure: None,
        },
        storage: None,
    }
}

pub(in crate::kernel::studio) fn refresh_non_artifact_studio_surface(
    studio_session: &mut StudioArtifactSession,
) {
    if studio_session.outcome_request.outcome_kind == StudioOutcomeKind::Artifact {
        return;
    }
    let title = studio_session.title.clone();
    let summary = studio_session.verified_reply.summary.clone();
    let lifecycle_state = studio_session.lifecycle_state;
    let provenance = studio_session
        .verified_reply
        .production_provenance
        .clone()
        .or_else(|| studio_session.verified_reply.acceptance_provenance.clone())
        .unwrap_or(crate::models::StudioRuntimeProvenance {
            kind: crate::models::StudioRuntimeProvenanceKind::InferenceUnavailable,
            label: "inference unavailable".to_string(),
            model: None,
            endpoint: None,
        });
    if studio_session.widget_state.is_none() {
        studio_session.widget_state =
            non_artifact_domain_policy_bundle(&studio_session.outcome_request, None)
                .retained_widget_state;
    }
    let manifest = non_artifact_manifest(
        &studio_session.artifact_id,
        &title,
        &summary,
        lifecycle_state,
        &provenance,
        &studio_session.outcome_request,
        studio_session.widget_state.as_ref(),
    );
    studio_session.artifact_manifest = manifest;
    studio_session.current_lens = "render".to_string();
    studio_session.available_lenses = vec![
        "render".to_string(),
        "source".to_string(),
        "evidence".to_string(),
    ];
    studio_session.navigator_nodes =
        navigator_nodes_for_manifest(&studio_session.artifact_manifest);
}

pub(in crate::kernel::studio) fn attach_non_artifact_studio_session(
    task: &mut AgentTask,
    intent: &str,
    provenance: crate::models::StudioRuntimeProvenance,
    outcome_request: &StudioOutcomeRequest,
) {
    let mut resolved_outcome_request = outcome_request.clone();
    let retained_widget_state = task
        .studio_session
        .as_ref()
        .and_then(|session| session.widget_state.as_ref());
    super::refresh_outcome_request_topology(&mut resolved_outcome_request, retained_widget_state);
    super::apply_retained_widget_state_resolution(
        &mut resolved_outcome_request,
        retained_widget_state,
    );

    let lifecycle_state = if resolved_outcome_request.needs_clarification {
        StudioArtifactLifecycleState::Blocked
    } else {
        StudioArtifactLifecycleState::Ready
    };
    let title = non_artifact_route_title(intent, &resolved_outcome_request);
    let summary = non_artifact_route_summary(&resolved_outcome_request);
    let mut materialization = non_artifact_materialization_contract(
        intent,
        &resolved_outcome_request,
        &summary,
        &provenance,
    );
    let route_decision = route_decision_for_outcome_request(&resolved_outcome_request);
    materialization
        .notes
        .push(format!("Route family: {}", route_decision.route_family));
    materialization
        .notes
        .push(format!("Output intent: {}", route_decision.output_intent));
    if !route_decision
        .effective_tool_surface
        .projected_tools
        .is_empty()
    {
        materialization.notes.push(format!(
            "Projected surface: {}",
            route_decision
                .effective_tool_surface
                .projected_tools
                .join(", ")
        ));
    }
    let domain_policy_bundle = non_artifact_domain_policy_bundle(&resolved_outcome_request, None);
    let manifest = non_artifact_manifest(
        &Uuid::new_v4().to_string(),
        &title,
        &summary,
        lifecycle_state,
        &provenance,
        &resolved_outcome_request,
        domain_policy_bundle.retained_widget_state.as_ref(),
    );
    let artifact_id = manifest.artifact_id.clone();
    let navigator_nodes = navigator_nodes_for_manifest(&manifest);
    materialization.navigator_nodes = navigator_nodes.clone();
    let created_at = now_iso();
    let mut studio_session = StudioArtifactSession {
        session_id: Uuid::new_v4().to_string(),
        thread_id: task.session_id.clone().unwrap_or_else(|| task.id.clone()),
        artifact_id,
        origin_prompt_event_id: None,
        title: title.clone(),
        summary: summary.clone(),
        current_lens: "source".to_string(),
        navigator_backing_mode: "logical".to_string(),
        navigator_nodes,
        attached_artifact_ids: Vec::new(),
        available_lenses: vec!["source".to_string(), "evidence".to_string()],
        materialization,
        outcome_request: resolved_outcome_request.clone(),
        artifact_manifest: manifest,
        verified_reply: verified_reply_for_non_artifact_route(
            &title,
            &summary,
            lifecycle_state,
            &provenance,
            &resolved_outcome_request,
        ),
        lifecycle_state,
        status: lifecycle_state_label(lifecycle_state).to_string(),
        active_revision_id: None,
        revisions: Vec::new(),
        taste_memory: None,
        retrieved_exemplars: Vec::new(),
        selected_targets: Vec::new(),
        widget_state: domain_policy_bundle.retained_widget_state.clone(),
        ux_lifecycle: Some(StudioArtifactUxLifecycle::Validated),
        created_at: created_at.clone(),
        updated_at: created_at,
        build_session_id: None,
        workspace_root: None,
        renderer_session_id: None,
    };
    refresh_non_artifact_studio_surface(&mut studio_session);
    refresh_pipeline_steps(&mut studio_session, None);
    let initial_revision = initial_revision_for_session(&studio_session, intent);
    studio_session.active_revision_id = Some(initial_revision.revision_id.clone());
    studio_session.revisions = vec![initial_revision];
    task.studio_outcome = Some(resolved_outcome_request.clone());
    task.studio_session = Some(studio_session);
    task.renderer_session = None;
    task.build_session = None;
    task.gate_info = None;
    task.pending_request_hash = None;
    task.credential_request = None;
    task.clarification_request =
        clarification_request_for_outcome_request(&resolved_outcome_request);
    append_route_contract_event(
        task,
        &resolved_outcome_request,
        "Studio route decision",
        &summary,
        !resolved_outcome_request.needs_clarification,
    );
}
