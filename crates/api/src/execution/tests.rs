use super::*;
use ioi_types::app::{
    ChatArtifactClass, ChatArtifactDeliverableShape, ChatArtifactPersistenceMode,
    ChatExecutionSubstrate, ChatOutcomeArtifactScope, ChatOutcomeArtifactVerificationRequest,
    ChatPresentationSurface, ChatRendererKind, ChatRuntimeProvenance, ChatRuntimeProvenanceKind,
};

fn test_work_graph_plan(strategy: &str, work_items: Vec<WorkGraphWorkItem>) -> WorkGraphPlan {
    WorkGraphPlan {
        version: 1,
        strategy: strategy.to_string(),
        execution_domain: "chat_artifact".to_string(),
        adapter_label: "artifact_graph_v1".to_string(),
        parallelism_mode: "sequential_by_default".to_string(),
        top_level_objective: Some("Test objective".to_string()),
        decomposition_hypothesis: Some("Test decomposition hypothesis".to_string()),
        decomposition_type: Some("test_decomposition".to_string()),
        first_frontier_ids: vec!["planner".to_string()],
        spawn_conditions: vec!["verification failure".to_string()],
        prune_conditions: vec!["completion invariant satisfied".to_string()],
        merge_strategy: Some("bounded_merge".to_string()),
        verification_strategy: Some("validate_then_verify".to_string()),
        fallback_collapse_strategy: Some("collapse_to_remaining_frontier".to_string()),
        completion_invariant: Some(ExecutionCompletionInvariant {
            summary: "Complete when mandatory work and verification pass.".to_string(),
            status: ExecutionCompletionInvariantStatus::Pending,
            required_work_item_ids: work_items
                .iter()
                .filter(|item| {
                    item.role != WorkGraphWorkerRole::Repair && !item.id.starts_with("repair-pass-")
                })
                .map(|item| item.id.clone())
                .collect(),
            satisfied_work_item_ids: Vec::new(),
            speculative_work_item_ids: work_items
                .iter()
                .filter(|item| {
                    item.role == WorkGraphWorkerRole::Repair || item.id.starts_with("repair-pass-")
                })
                .map(|item| item.id.clone())
                .collect(),
            pruned_work_item_ids: Vec::new(),
            required_verification_ids: vec!["artifact-validation".to_string()],
            satisfied_verification_ids: Vec::new(),
            required_artifact_paths: vec!["index.html".to_string()],
            remaining_obligations: vec!["verification:artifact-validation".to_string()],
            allows_early_exit: true,
        }),
        work_items,
    }
}

#[test]
fn build_execution_envelope_derives_strategy_and_domain_kind_from_work_graph() {
    let plan = test_work_graph_plan("work_graph", Vec::new());
    let summary = WorkGraphExecutionSummary {
        enabled: true,
        current_stage: "merge".to_string(),
        execution_stage: Some(ExecutionStage::Merge),
        active_worker_role: None,
        total_work_items: 3,
        completed_work_items: 2,
        failed_work_items: 0,
        verification_status: "pending".to_string(),
        strategy: "work_graph".to_string(),
        execution_domain: "chat_artifact".to_string(),
        adapter_label: "artifact_work_graph_v1".to_string(),
        parallelism_mode: "serial".to_string(),
    };

    let envelope = build_execution_envelope_from_work_graph(
        None,
        None,
        None,
        Some(&plan),
        Some(&summary),
        &[],
        &[],
        &[],
        &[],
    )
    .expect("expected execution envelope");

    assert_eq!(
        envelope.strategy,
        Some(ChatExecutionStrategy::AdaptiveWorkGraph)
    );
    assert_eq!(envelope.execution_domain, "chat_artifact");
    assert_eq!(envelope.domain_kind, Some(ExecutionDomainKind::Artifact));
    assert_eq!(
        envelope
            .execution_summary
            .as_ref()
            .map(|entry| entry.current_stage.as_str()),
        Some("merge")
    );
    validate_execution_envelope(&envelope).expect("derived execution envelope should validate");
}

#[test]
fn execution_envelope_rejects_tampered_workflow_root_hash() {
    let worker_receipts = vec![WorkGraphWorkerReceipt {
        work_item_id: "draft".to_string(),
        role: WorkGraphWorkerRole::Integrator,
        status: WorkGraphWorkItemStatus::Succeeded,
        result_kind: Some(WorkGraphWorkerResultKind::Completed),
        summary: "Drafted artifact".to_string(),
        started_at: "1".to_string(),
        finished_at: Some("2".to_string()),
        runtime: ChatRuntimeProvenance {
            kind: ChatRuntimeProvenanceKind::MockRuntime,
            label: "mock".to_string(),
            model: None,
            endpoint: None,
        },
        read_paths: Vec::new(),
        write_paths: vec!["index.html".to_string()],
        write_regions: vec!["main".to_string()],
        spawned_work_item_ids: Vec::new(),
        blocked_on_ids: Vec::new(),
        prompt_bytes: None,
        output_bytes: None,
        output_preview: None,
        preview_language: None,
        notes: Vec::new(),
        failure: None,
    }];
    let change_receipts = vec![WorkGraphChangeReceipt {
        work_item_id: "draft".to_string(),
        status: WorkGraphWorkItemStatus::Succeeded,
        summary: "Patched index".to_string(),
        operation_count: 1,
        touched_paths: vec!["index.html".to_string()],
        touched_regions: vec!["main".to_string()],
        operation_kinds: vec!["replace_region".to_string()],
        preview: None,
        preview_language: None,
        failure: None,
    }];
    let merge_receipts = vec![WorkGraphMergeReceipt {
        work_item_id: "draft".to_string(),
        status: WorkGraphWorkItemStatus::Succeeded,
        summary: "Merged draft".to_string(),
        applied_operation_count: 1,
        touched_paths: vec!["index.html".to_string()],
        touched_regions: vec!["main".to_string()],
        rejected_reason: None,
    }];
    let envelope = build_execution_envelope_from_work_graph_with_receipts(
        Some(ChatExecutionStrategy::AdaptiveWorkGraph),
        Some("chat_artifact".to_string()),
        Some(ExecutionDomainKind::Artifact),
        None,
        None,
        &worker_receipts,
        &change_receipts,
        &merge_receipts,
        &[],
        &[],
        &[],
        &[],
        &[],
        None,
        &[],
    )
    .expect("envelope");
    validate_execution_envelope(&envelope).expect("canonical envelope should validate");

    let mut tampered = envelope.clone();
    tampered.workflow_artifact_root_hash = Some("bad-root".to_string());
    let err = validate_execution_envelope(&tampered).expect_err("tampered root hash must fail");
    assert!(err.contains("workflow_artifact_root_hash"));
}

#[test]
fn artifact_outcomes_default_single_document_renderers_to_direct_author() {
    let html_request = ChatOutcomeArtifactRequest {
        artifact_class: ChatArtifactClass::InteractiveSingleFile,
        deliverable_shape: ChatArtifactDeliverableShape::SingleFile,
        renderer: ChatRendererKind::HtmlIframe,
        presentation_surface: ChatPresentationSurface::SidePanel,
        persistence: ChatArtifactPersistenceMode::SharedArtifactScoped,
        execution_substrate: ChatExecutionSubstrate::ClientSandbox,
        workspace_recipe_id: None,
        presentation_variant_id: None,
        scope: ChatOutcomeArtifactScope {
            target_project: None,
            create_new_workspace: false,
            mutation_boundary: vec!["artifact".to_string()],
        },
        verification: ChatOutcomeArtifactVerificationRequest {
            require_render: true,
            require_build: false,
            require_preview: false,
            require_export: false,
            require_diff_review: false,
        },
    };
    let markdown_request = ChatOutcomeArtifactRequest {
        renderer: ChatRendererKind::Markdown,
        execution_substrate: ChatExecutionSubstrate::None,
        ..html_request.clone()
    };
    let svg_request = ChatOutcomeArtifactRequest {
        artifact_class: ChatArtifactClass::Visual,
        renderer: ChatRendererKind::Svg,
        execution_substrate: ChatExecutionSubstrate::None,
        ..html_request.clone()
    };
    let pdf_request = ChatOutcomeArtifactRequest {
        artifact_class: ChatArtifactClass::Document,
        renderer: ChatRendererKind::PdfEmbed,
        execution_substrate: ChatExecutionSubstrate::BinaryGenerator,
        ..html_request.clone()
    };

    assert_eq!(
        execution_strategy_for_outcome(ChatOutcomeKind::Artifact, None),
        ChatExecutionStrategy::PlanExecute
    );
    assert_eq!(
        execution_strategy_for_outcome(ChatOutcomeKind::Artifact, Some(&html_request)),
        ChatExecutionStrategy::DirectAuthor
    );
    assert_eq!(
        execution_strategy_for_outcome(ChatOutcomeKind::Artifact, Some(&markdown_request)),
        ChatExecutionStrategy::DirectAuthor
    );
    assert_eq!(
        execution_strategy_for_outcome(ChatOutcomeKind::Artifact, Some(&svg_request)),
        ChatExecutionStrategy::DirectAuthor
    );
    assert_eq!(
        execution_strategy_for_outcome(ChatOutcomeKind::Artifact, Some(&pdf_request)),
        ChatExecutionStrategy::DirectAuthor
    );
}

#[test]
fn derive_execution_mode_decision_routes_simple_conversation_to_single_pass() {
    let decision = derive_execution_mode_decision(
        ChatOutcomeKind::Conversation,
        None,
        ChatExecutionStrategy::PlanExecute,
        0.94,
        false,
        false,
    );

    assert_eq!(
        decision.requested_strategy,
        ChatExecutionStrategy::PlanExecute
    );
    assert_eq!(
        decision.resolved_strategy,
        ChatExecutionStrategy::SinglePass
    );
    assert!(!decision.work_graph_required);
    assert!(decision.one_shot_sufficiency >= 0.7);
    assert_eq!(decision.budget_envelope.max_workers, 1);
}

#[test]
fn derive_execution_mode_decision_preserves_requested_conversation_work_graph() {
    let decision = derive_execution_mode_decision(
        ChatOutcomeKind::Conversation,
        None,
        ChatExecutionStrategy::AdaptiveWorkGraph,
        0.91,
        false,
        false,
    );

    assert_eq!(
        decision.requested_strategy,
        ChatExecutionStrategy::AdaptiveWorkGraph
    );
    assert_eq!(
        decision.resolved_strategy,
        ChatExecutionStrategy::AdaptiveWorkGraph
    );
    assert!(decision.work_graph_required);
    assert!(decision.budget_envelope.max_workers >= 4);
}

#[test]
fn derive_execution_mode_decision_routes_fresh_bounded_document_to_direct_author() {
    let request = ChatOutcomeArtifactRequest {
        artifact_class: ChatArtifactClass::Document,
        deliverable_shape: ChatArtifactDeliverableShape::SingleFile,
        renderer: ChatRendererKind::Markdown,
        presentation_surface: ChatPresentationSurface::SidePanel,
        persistence: ChatArtifactPersistenceMode::ArtifactScoped,
        execution_substrate: ChatExecutionSubstrate::None,
        workspace_recipe_id: None,
        presentation_variant_id: None,
        scope: ChatOutcomeArtifactScope {
            target_project: None,
            create_new_workspace: false,
            mutation_boundary: vec!["artifact".to_string()],
        },
        verification: ChatOutcomeArtifactVerificationRequest {
            require_render: true,
            require_build: false,
            require_preview: false,
            require_export: true,
            require_diff_review: false,
        },
    };

    let decision = derive_execution_mode_decision(
        ChatOutcomeKind::Artifact,
        Some(&request),
        ChatExecutionStrategy::PlanExecute,
        0.92,
        false,
        false,
    );

    assert_eq!(
        decision.resolved_strategy,
        ChatExecutionStrategy::DirectAuthor
    );
    assert!(!decision.work_graph_required);
    assert_eq!(decision.work_graph_size_estimate, 1);
    assert_eq!(decision.budget_envelope.max_workers, 1);
    assert_eq!(decision.budget_envelope.max_replans, 0);
    assert_eq!(
        decision.budget_envelope.expansion_policy,
        ChatExecutionBudgetExpansionPolicy::Fixed
    );
}

#[test]
fn derive_execution_mode_decision_routes_workspace_artifacts_to_adaptive_work_graph() {
    let request = ChatOutcomeArtifactRequest {
        artifact_class: ChatArtifactClass::WorkspaceProject,
        deliverable_shape: ChatArtifactDeliverableShape::WorkspaceProject,
        renderer: ChatRendererKind::WorkspaceSurface,
        presentation_surface: ChatPresentationSurface::TabbedPanel,
        persistence: ChatArtifactPersistenceMode::WorkspaceFilesystem,
        execution_substrate: ChatExecutionSubstrate::WorkspaceRuntime,
        workspace_recipe_id: Some("react".to_string()),
        presentation_variant_id: None,
        scope: ChatOutcomeArtifactScope {
            target_project: Some("workspace".to_string()),
            create_new_workspace: true,
            mutation_boundary: vec!["workspace".to_string()],
        },
        verification: ChatOutcomeArtifactVerificationRequest {
            require_render: true,
            require_build: true,
            require_preview: true,
            require_export: false,
            require_diff_review: true,
        },
    };

    let decision = derive_execution_mode_decision(
        ChatOutcomeKind::Artifact,
        Some(&request),
        ChatExecutionStrategy::PlanExecute,
        0.86,
        false,
        false,
    );

    assert_eq!(
        decision.resolved_strategy,
        ChatExecutionStrategy::AdaptiveWorkGraph
    );
    assert!(decision.work_graph_required);
    assert_eq!(decision.budget_envelope.max_workers, 8);
    assert_eq!(
        decision.budget_envelope.expansion_policy,
        ChatExecutionBudgetExpansionPolicy::FrontierAdaptive
    );
    assert!(decision.hidden_dependency_likelihood >= 0.7);
}

#[test]
fn annotate_execution_envelope_carries_mode_decision_budget_and_invariant() {
    let mut envelope = build_execution_envelope_from_work_graph(
        Some(ChatExecutionStrategy::PlanExecute),
        Some("chat_artifact".to_string()),
        Some(ExecutionDomainKind::Artifact),
        None,
        None,
        &[],
        &[],
        &[],
        &[],
    );
    let decision = ChatExecutionModeDecision {
        requested_strategy: ChatExecutionStrategy::PlanExecute,
        resolved_strategy: ChatExecutionStrategy::MicroWorkGraph,
        mode_confidence: 0.81,
        one_shot_sufficiency: 0.44,
        ambiguity: 0.12,
        work_graph_size_estimate: 3,
        hidden_dependency_likelihood: 0.35,
        verification_pressure: 0.4,
        revision_cost: 0.25,
        evidence_breadth: 0.35,
        merge_burden: 0.55,
        decomposition_payoff: 0.58,
        work_graph_required: true,
        decomposition_reason: "A bounded work graph is justified.".to_string(),
        budget_envelope: execution_budget_envelope_for_strategy(
            ChatExecutionStrategy::MicroWorkGraph,
        ),
    };
    let invariant = completion_invariant_for_direct_execution(
        ChatExecutionStrategy::MicroWorkGraph,
        vec!["index.html".to_string()],
        vec!["verify".to_string()],
        ExecutionCompletionInvariantStatus::Pending,
    );

    annotate_execution_envelope(
        &mut envelope,
        Some(decision.clone()),
        Some(invariant.clone()),
    );

    let envelope = envelope.expect("execution envelope");
    assert_eq!(
        envelope.strategy,
        Some(ChatExecutionStrategy::MicroWorkGraph)
    );
    assert_eq!(envelope.mode_decision, Some(decision));
    assert_eq!(
        envelope.budget_envelope,
        Some(invariant_allows_micro_budget())
    );
    assert_eq!(envelope.completion_invariant, Some(invariant));
}

fn invariant_allows_micro_budget() -> ChatExecutionBudgetEnvelope {
    execution_budget_envelope_for_strategy(ChatExecutionStrategy::MicroWorkGraph)
}

#[test]
fn parse_execution_strategy_id_accepts_legacy_work_graph_alias() {
    assert_eq!(
        parse_execution_strategy_id("direct_author"),
        Some(ChatExecutionStrategy::DirectAuthor)
    );
    assert_eq!(
        parse_execution_strategy_id("work_graph"),
        Some(ChatExecutionStrategy::AdaptiveWorkGraph)
    );
    assert_eq!(
        parse_execution_strategy_id("adaptive_work_graph"),
        Some(ChatExecutionStrategy::AdaptiveWorkGraph)
    );
    assert_eq!(
        parse_execution_strategy_id("micro_work_graph"),
        Some(ChatExecutionStrategy::MicroWorkGraph)
    );
}

#[test]
fn spawn_follow_up_work_item_preserves_parent_lineage_and_increments_version() {
    let mut plan = test_work_graph_plan(
        "adaptive_work_graph",
        vec![WorkGraphWorkItem {
            id: "repair".to_string(),
            title: "Repair".to_string(),
            role: WorkGraphWorkerRole::Repair,
            summary: "Repair cited failures.".to_string(),
            spawned_from_id: None,
            read_paths: vec!["index.html".to_string()],
            write_paths: vec!["index.html".to_string()],
            write_regions: vec!["section:hero".to_string()],
            lease_requirements: vec![exclusive_write_lease_for_region("section:hero")],
            acceptance_criteria: vec!["Stay scoped.".to_string()],
            dependency_ids: vec!["validation".to_string()],
            blocked_on_ids: Vec::new(),
            verification_policy: Some(WorkGraphVerificationPolicy::Blocking),
            retry_budget: Some(2),
            status: WorkGraphWorkItemStatus::Pending,
        }],
    );

    spawn_follow_up_work_graph_work_item(
        &mut plan,
        WorkGraphWorkItem {
            id: "repair-pass-1".to_string(),
            title: "Repair pass 1".to_string(),
            role: WorkGraphWorkerRole::Repair,
            summary: "Resolve the first blocked verification issue.".to_string(),
            spawned_from_id: Some("repair".to_string()),
            read_paths: vec!["index.html".to_string()],
            write_paths: vec!["index.html".to_string()],
            write_regions: vec!["section:hero".to_string()],
            lease_requirements: vec![exclusive_write_lease_for_region("section:hero")],
            acceptance_criteria: vec!["Patch only cited issues.".to_string()],
            dependency_ids: vec!["validation".to_string()],
            blocked_on_ids: Vec::new(),
            verification_policy: Some(WorkGraphVerificationPolicy::Blocking),
            retry_budget: Some(0),
            status: WorkGraphWorkItemStatus::Pending,
        },
    )
    .expect("follow-up work item should append");

    let follow_up = plan
        .work_items
        .iter()
        .find(|item| item.id == "repair-pass-1")
        .expect("follow-up repair item");
    assert_eq!(plan.version, 2);
    assert_eq!(follow_up.spawned_from_id.as_deref(), Some("repair"));
    assert!(follow_up
        .dependency_ids
        .iter()
        .any(|dependency| dependency == "repair"));
}

#[test]
fn exclusive_write_leases_conflict_on_the_same_target() {
    let left = WorkGraphWorkItem {
        id: "section-1".to_string(),
        title: "Section 1".to_string(),
        role: WorkGraphWorkerRole::SectionContent,
        summary: "Own hero copy.".to_string(),
        spawned_from_id: None,
        read_paths: vec!["index.html".to_string()],
        write_paths: vec!["index.html".to_string()],
        write_regions: vec!["section:hero".to_string()],
        lease_requirements: vec![exclusive_write_lease_for_region("section:hero")],
        acceptance_criteria: vec!["Keep hero visible.".to_string()],
        dependency_ids: vec!["skeleton".to_string()],
        blocked_on_ids: Vec::new(),
        verification_policy: Some(WorkGraphVerificationPolicy::Normal),
        retry_budget: Some(0),
        status: WorkGraphWorkItemStatus::Pending,
    };
    let right = WorkGraphWorkItem {
        id: "repair-pass-1".to_string(),
        title: "Repair pass 1".to_string(),
        role: WorkGraphWorkerRole::Repair,
        summary: "Patch hero issues.".to_string(),
        spawned_from_id: Some("repair".to_string()),
        read_paths: vec!["index.html".to_string()],
        write_paths: vec!["index.html".to_string()],
        write_regions: vec!["section:hero".to_string()],
        lease_requirements: vec![exclusive_write_lease_for_region("section:hero")],
        acceptance_criteria: vec!["Stay bounded.".to_string()],
        dependency_ids: vec!["validation".to_string()],
        blocked_on_ids: Vec::new(),
        verification_policy: Some(WorkGraphVerificationPolicy::Blocking),
        retry_budget: Some(0),
        status: WorkGraphWorkItemStatus::Pending,
    };

    assert!(work_graph_work_item_lease_conflicts(&left, &right));
}

#[test]
fn block_work_graph_work_item_on_adds_runtime_blockers() {
    let mut plan = test_work_graph_plan(
        "plan_execute",
        vec![
            WorkGraphWorkItem {
                id: "planner".to_string(),
                title: "Planner".to_string(),
                role: WorkGraphWorkerRole::Planner,
                summary: "Plan".to_string(),
                spawned_from_id: None,
                read_paths: Vec::new(),
                write_paths: Vec::new(),
                write_regions: Vec::new(),
                lease_requirements: Vec::new(),
                acceptance_criteria: Vec::new(),
                dependency_ids: Vec::new(),
                blocked_on_ids: Vec::new(),
                verification_policy: None,
                retry_budget: None,
                status: WorkGraphWorkItemStatus::Succeeded,
            },
            WorkGraphWorkItem {
                id: "handoff".to_string(),
                title: "Handoff".to_string(),
                role: WorkGraphWorkerRole::Responder,
                summary: "Reply".to_string(),
                spawned_from_id: None,
                read_paths: Vec::new(),
                write_paths: Vec::new(),
                write_regions: Vec::new(),
                lease_requirements: Vec::new(),
                acceptance_criteria: Vec::new(),
                dependency_ids: vec!["planner".to_string()],
                blocked_on_ids: Vec::new(),
                verification_policy: None,
                retry_budget: None,
                status: WorkGraphWorkItemStatus::Pending,
            },
        ],
    );
    plan.execution_domain = "chat_conversation".to_string();
    plan.adapter_label = "conversation_route_v1".to_string();

    spawn_follow_up_work_graph_work_item(
        &mut plan,
        WorkGraphWorkItem {
            id: "clarification_gate".to_string(),
            title: "Clarification gate".to_string(),
            role: WorkGraphWorkerRole::Coordinator,
            summary: "Wait for the user.".to_string(),
            spawned_from_id: Some("planner".to_string()),
            read_paths: Vec::new(),
            write_paths: Vec::new(),
            write_regions: Vec::new(),
            lease_requirements: Vec::new(),
            acceptance_criteria: Vec::new(),
            dependency_ids: vec!["planner".to_string()],
            blocked_on_ids: Vec::new(),
            verification_policy: Some(WorkGraphVerificationPolicy::Blocking),
            retry_budget: Some(0),
            status: WorkGraphWorkItemStatus::Pending,
        },
    )
    .expect("clarification gate should spawn");
    block_work_graph_work_item_on(&mut plan, "handoff", &[String::from("clarification_gate")])
        .expect("handoff should become blocked");

    let handoff = plan
        .work_items
        .iter()
        .find(|item| item.id == "handoff")
        .expect("handoff item");
    assert_eq!(handoff.status, WorkGraphWorkItemStatus::Blocked);
    assert!(handoff
        .blocked_on_ids
        .iter()
        .any(|entry| entry == "clarification_gate"));
}

#[test]
fn dispatch_batches_respect_dependencies_and_lease_conflicts() {
    let plan = test_work_graph_plan(
        "adaptive_work_graph",
        vec![
            WorkGraphWorkItem {
                id: "planner".to_string(),
                title: "Planner".to_string(),
                role: WorkGraphWorkerRole::Planner,
                summary: "Plan".to_string(),
                spawned_from_id: None,
                read_paths: Vec::new(),
                write_paths: Vec::new(),
                write_regions: Vec::new(),
                lease_requirements: Vec::new(),
                acceptance_criteria: Vec::new(),
                dependency_ids: Vec::new(),
                blocked_on_ids: Vec::new(),
                verification_policy: None,
                retry_budget: None,
                status: WorkGraphWorkItemStatus::Succeeded,
            },
            WorkGraphWorkItem {
                id: "skeleton".to_string(),
                title: "Skeleton".to_string(),
                role: WorkGraphWorkerRole::Skeleton,
                summary: "Create scaffold".to_string(),
                spawned_from_id: None,
                read_paths: vec!["index.html".to_string()],
                write_paths: vec!["index.html".to_string()],
                write_regions: vec!["section:hero".to_string()],
                lease_requirements: vec![exclusive_write_lease_for_path("index.html")],
                acceptance_criteria: Vec::new(),
                dependency_ids: vec!["planner".to_string()],
                blocked_on_ids: Vec::new(),
                verification_policy: None,
                retry_budget: None,
                status: WorkGraphWorkItemStatus::Pending,
            },
            WorkGraphWorkItem {
                id: "hero".to_string(),
                title: "Hero".to_string(),
                role: WorkGraphWorkerRole::SectionContent,
                summary: "Patch hero".to_string(),
                spawned_from_id: None,
                read_paths: vec!["index.html".to_string()],
                write_paths: vec!["index.html".to_string()],
                write_regions: vec!["section:hero".to_string()],
                lease_requirements: vec![exclusive_write_lease_for_region("section:hero")],
                acceptance_criteria: Vec::new(),
                dependency_ids: vec!["skeleton".to_string()],
                blocked_on_ids: Vec::new(),
                verification_policy: None,
                retry_budget: None,
                status: WorkGraphWorkItemStatus::Pending,
            },
            WorkGraphWorkItem {
                id: "style".to_string(),
                title: "Style".to_string(),
                role: WorkGraphWorkerRole::StyleSystem,
                summary: "Patch style".to_string(),
                spawned_from_id: None,
                read_paths: vec!["index.html".to_string()],
                write_paths: vec!["index.html".to_string()],
                write_regions: vec!["section:hero".to_string()],
                lease_requirements: vec![exclusive_write_lease_for_region("section:hero")],
                acceptance_criteria: Vec::new(),
                dependency_ids: vec!["skeleton".to_string()],
                blocked_on_ids: Vec::new(),
                verification_policy: None,
                retry_budget: None,
                status: WorkGraphWorkItemStatus::Pending,
            },
        ],
    );

    let batches = plan_work_graph_dispatch_batches(&plan);

    assert_eq!(batches.len(), 3);
    assert_eq!(batches[0].work_item_ids, vec!["skeleton".to_string()]);
    assert_eq!(batches[1].work_item_ids, vec!["hero".to_string()]);
    assert_eq!(batches[1].deferred_work_item_ids, vec!["style".to_string()]);
    assert_eq!(batches[2].work_item_ids, vec!["style".to_string()]);
}

#[test]
fn dispatch_batch_parallelism_cap_defers_overflow() {
    let mut batch = ExecutionDispatchBatch {
        id: "dispatch-batch-1".to_string(),
        sequence: 1,
        status: "ready".to_string(),
        work_item_ids: vec![
            "section-1".to_string(),
            "section-2".to_string(),
            "section-3".to_string(),
        ],
        deferred_work_item_ids: Vec::new(),
        blocked_work_item_ids: Vec::new(),
        details: Vec::new(),
    };

    constrain_dispatch_batch_by_parallelism(&mut batch, 2);

    assert_eq!(
        batch.work_item_ids,
        vec!["section-1".to_string(), "section-2".to_string()]
    );
    assert_eq!(batch.deferred_work_item_ids, vec!["section-3".to_string()]);
    assert_eq!(batch.status, "budget_limited");
    assert!(batch
        .details
        .iter()
        .any(|detail| detail.contains("Budget capped this dispatch wave")));
}

#[test]
fn build_execution_envelope_preserves_graph_and_repair_receipts() {
    let dispatch_batches = vec![ExecutionDispatchBatch {
        id: "dispatch-batch-1".to_string(),
        sequence: 1,
        status: "planned".to_string(),
        work_item_ids: vec!["planner".to_string()],
        deferred_work_item_ids: Vec::new(),
        blocked_work_item_ids: Vec::new(),
        details: vec!["planner is ready".to_string()],
    }];
    let graph_receipts = vec![ExecutionGraphMutationReceipt {
        id: "repair-requested".to_string(),
        mutation_kind: "repair_requested".to_string(),
        status: "applied".to_string(),
        summary: "Validation requested a repair.".to_string(),
        triggered_by_work_item_id: Some("validation".to_string()),
        affected_work_item_ids: vec!["repair".to_string()],
        details: vec!["Tighten layout".to_string()],
    }];
    let repair_receipts = vec![ExecutionRepairReceipt {
        id: "repair-pass-1".to_string(),
        status: "repairable".to_string(),
        summary: "Applied a scoped repair.".to_string(),
        triggered_by_verification_id: Some("artifact-validation".to_string()),
        work_item_ids: vec!["repair".to_string()],
        details: vec!["Fix hierarchy".to_string()],
    }];
    let replan_receipts = vec![ExecutionReplanReceipt {
        id: "repair-replan".to_string(),
        status: "blocked".to_string(),
        summary: "Repair requested a broader replan.".to_string(),
        triggered_by_work_item_id: Some("repair".to_string()),
        spawned_work_item_ids: vec!["repair-pass-1".to_string()],
        blocked_work_item_ids: vec!["integrator".to_string()],
        details: vec!["Widen section ownership".to_string()],
    }];

    let envelope = build_execution_envelope_from_work_graph_with_receipts(
        Some(ChatExecutionStrategy::AdaptiveWorkGraph),
        Some("chat_artifact".to_string()),
        Some(ExecutionDomainKind::Artifact),
        None,
        None,
        &[],
        &[],
        &[],
        &[],
        &graph_receipts,
        &dispatch_batches,
        &repair_receipts,
        &replan_receipts,
        Some(ExecutionBudgetSummary {
            planned_worker_count: Some(4),
            dispatched_worker_count: Some(4),
            token_budget: Some(4096),
            token_usage: Some(3072),
            wall_clock_ms: Some(1500),
            coordination_overhead_ms: Some(210),
            status: "within_budget".to_string(),
        }),
        &[],
    )
    .expect("expected execution envelope");

    assert_eq!(envelope.graph_mutation_receipts, graph_receipts);
    assert_eq!(envelope.dispatch_batches, dispatch_batches);
    assert_eq!(envelope.repair_receipts, repair_receipts);
    assert_eq!(envelope.replan_receipts, replan_receipts);
    assert_eq!(
        envelope
            .budget_summary
            .as_ref()
            .and_then(|entry| entry.token_budget),
        Some(4096)
    );
}
