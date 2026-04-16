use super::*;

#[test]
fn pipeline_steps_for_ready_markdown_artifact_are_complete() {
    let request = test_outcome_request().artifact.expect("artifact request");
    let manifest = test_manifest(StudioArtifactVerificationStatus::Ready);
    let mut materialization = materialization_contract_for_request(
        "Create a release artifact",
        &request,
        "Studio created the artifact.",
        None,
        StudioExecutionStrategy::PlanExecute,
    );
    materialization.artifact_brief = Some(StudioArtifactBrief {
        audience: "operators".to_string(),
        job_to_be_done: "ship a concise release artifact".to_string(),
        subject_domain: "release operations".to_string(),
        artifact_thesis: "Summarize release state with enough structure to stand alone."
            .to_string(),
        required_concepts: vec!["status".to_string(), "risks".to_string()],
        required_interactions: Vec::new(),
        query_profile: None,
        visual_tone: vec!["clear".to_string()],
        factual_anchors: vec!["release train".to_string()],
        style_directives: vec!["tight hierarchy".to_string()],
        reference_hints: Vec::new(),
    });
    materialization.prepared_context_resolution =
        Some(ioi_api::studio::StudioArtifactPreparedContextResolution {
            status: "resolved".to_string(),
            renderer: request.renderer,
            require_blueprint: false,
            require_artifact_ir: false,
            skill_need_count: 0,
            selected_skill_count: 0,
            exemplar_count: 0,
            selected_skill_names: Vec::new(),
        });
    materialization.skill_discovery_resolution =
        Some(ioi_api::studio::StudioArtifactSkillDiscoveryResolution {
            status: "resolved".to_string(),
            guidance_status: "not_needed".to_string(),
            guidance_evaluated: true,
            guidance_recommended: false,
            guidance_found: false,
            guidance_attached: false,
            skill_need_count: 0,
            selected_skill_count: 0,
            selected_skill_names: Vec::new(),
            search_scope: "published_runtime_skills".to_string(),
            rationale: "The markdown release artifact does not require extra runtime guidance."
                .to_string(),
            failure_reason: None,
        });
    let steps = pipeline_steps_for_state(
        "Create a release artifact",
        &request,
        &manifest,
        &materialization,
        StudioArtifactLifecycleState::Ready,
        None,
        None,
    );

    assert_eq!(steps.len(), 10);
    assert!(steps.iter().all(|step| step.status == "complete"));
    assert!(steps
        .iter()
        .find(|step| step.id == "skill_discovery")
        .is_some_and(|step| step
            .outputs
            .iter()
            .any(|output| output == "guidance_status:not_needed")));
    assert!(!steps.iter().any(|step| step.id == "execution"));
    assert!(!steps.iter().any(|step| step.id == "repair"));
}

#[test]
fn pipeline_steps_surface_swarm_execution_merge_and_repair() {
    let request = test_outcome_request().artifact.expect("artifact request");
    let manifest = test_manifest(StudioArtifactVerificationStatus::Ready);
    let mut materialization = test_materialization_contract();
    materialization.swarm_plan = Some(StudioArtifactSwarmPlan {
        version: 1,
        strategy: "markdown_adaptive_work_graph".to_string(),
        execution_domain: "studio_artifact".to_string(),
        adapter_label: "markdown_coarse_v1".to_string(),
        parallelism_mode: "sequential_by_default".to_string(),
        top_level_objective: Some("Create the markdown artifact.".to_string()),
        decomposition_hypothesis: Some(
            "A bounded shared-state graph is enough for markdown artifact delivery.".to_string(),
        ),
        decomposition_type: Some("functional_decomposition".to_string()),
        first_frontier_ids: vec!["planner".to_string()],
        spawn_conditions: vec!["Spawn repair only if judge blocks.".to_string()],
        prune_conditions: vec!["Prune repair when verification clears.".to_string()],
        merge_strategy: Some("deterministic_patch_merge".to_string()),
        verification_strategy: Some("judge_then_verify".to_string()),
        fallback_collapse_strategy: Some("collapse_to_remaining_frontier".to_string()),
        completion_invariant: Some(ioi_api::execution::ExecutionCompletionInvariant {
            summary: "Complete once the markdown graph is satisfied.".to_string(),
            status: ioi_api::execution::ExecutionCompletionInvariantStatus::Pending,
            required_work_item_ids: vec!["planner".to_string()],
            satisfied_work_item_ids: vec!["planner".to_string()],
            speculative_work_item_ids: vec!["repair".to_string()],
            pruned_work_item_ids: Vec::new(),
            required_verification_ids: vec!["acceptance-judge".to_string()],
            satisfied_verification_ids: Vec::new(),
            required_artifact_paths: vec!["artifact.md".to_string()],
            remaining_obligations: vec!["verification:acceptance-judge".to_string()],
            allows_early_exit: true,
        }),
        work_items: vec![
            StudioArtifactWorkItem {
                id: "planner".to_string(),
                title: "Planner".to_string(),
                role: StudioArtifactWorkerRole::Planner,
                summary: "Lock the artifact plan.".to_string(),
                spawned_from_id: None,
                read_paths: Vec::new(),
                write_paths: Vec::new(),
                write_regions: Vec::new(),
                lease_requirements: Vec::new(),
                acceptance_criteria: vec!["ordered".to_string()],
                dependency_ids: Vec::new(),
                blocked_on_ids: Vec::new(),
                verification_policy: Some(ioi_api::studio::SwarmVerificationPolicy::Normal),
                retry_budget: Some(0),
                status: StudioArtifactWorkItemStatus::Succeeded,
            },
            StudioArtifactWorkItem {
                id: "repair".to_string(),
                title: "Repair".to_string(),
                role: StudioArtifactWorkerRole::Repair,
                summary: "Patch cited failures.".to_string(),
                spawned_from_id: None,
                read_paths: Vec::new(),
                write_paths: Vec::new(),
                write_regions: Vec::new(),
                lease_requirements: Vec::new(),
                acceptance_criteria: vec!["bounded".to_string()],
                dependency_ids: vec!["judge".to_string()],
                blocked_on_ids: Vec::new(),
                verification_policy: Some(ioi_api::studio::SwarmVerificationPolicy::Blocking),
                retry_budget: Some(1),
                status: StudioArtifactWorkItemStatus::Rejected,
            },
        ],
    });
    materialization.swarm_execution = Some(StudioArtifactSwarmExecutionSummary {
        enabled: true,
        current_stage: "repair".to_string(),
        execution_stage: Some(ExecutionStage::Mutate),
        active_worker_role: Some(StudioArtifactWorkerRole::Repair),
        total_work_items: 5,
        completed_work_items: 4,
        failed_work_items: 0,
        verification_status: "blocked".to_string(),
        strategy: "markdown_coarse_patch_swarm".to_string(),
        execution_domain: "studio_artifact".to_string(),
        adapter_label: "markdown_coarse_v1".to_string(),
        parallelism_mode: "sequential_by_default".to_string(),
    });
    materialization.swarm_worker_receipts = vec![StudioArtifactWorkerReceipt {
        work_item_id: "repair".to_string(),
        role: StudioArtifactWorkerRole::Repair,
        status: StudioArtifactWorkItemStatus::Rejected,
        result_kind: Some(ioi_api::studio::SwarmWorkerResultKind::Conflict),
        summary: "Rejected the out-of-scope patch.".to_string(),
        started_at: now_iso(),
        finished_at: Some(now_iso()),
        runtime: crate::models::StudioRuntimeProvenance {
            kind: crate::models::StudioRuntimeProvenanceKind::FixtureRuntime,
            label: "fixture".to_string(),
            model: None,
            endpoint: None,
        },
        read_paths: vec!["artifact.md".to_string()],
        write_paths: vec!["artifact.md".to_string()],
        write_regions: Vec::new(),
        spawned_work_item_ids: Vec::new(),
        blocked_on_ids: Vec::new(),
        prompt_bytes: None,
        output_bytes: None,
        output_preview: None,
        preview_language: None,
        notes: vec!["bounded scope enforced".to_string()],
        failure: Some("out-of-scope path".to_string()),
    }];
    materialization.swarm_change_receipts = vec![StudioArtifactPatchReceipt {
        work_item_id: "repair".to_string(),
        status: StudioArtifactWorkItemStatus::Rejected,
        summary: "Rejected repair patch".to_string(),
        operation_count: 1,
        touched_paths: vec!["artifact.md".to_string()],
        touched_regions: Vec::new(),
        operation_kinds: vec!["replace_file".to_string()],
        preview: None,
        preview_language: None,
        failure: Some("out-of-scope path".to_string()),
    }];
    materialization.swarm_merge_receipts = vec![StudioArtifactMergeReceipt {
        work_item_id: "repair".to_string(),
        status: StudioArtifactWorkItemStatus::Rejected,
        summary: "Rejected out-of-scope patch".to_string(),
        applied_operation_count: 0,
        touched_paths: Vec::new(),
        touched_regions: Vec::new(),
        rejected_reason: Some("out-of-scope path".to_string()),
    }];
    materialization.swarm_verification_receipts = vec![StudioArtifactVerificationReceipt {
        id: "acceptance-judge".to_string(),
        kind: "acceptance_judge".to_string(),
        status: "blocked".to_string(),
        summary: "Judge blocked the merged artifact.".to_string(),
        details: vec!["interaction gap".to_string()],
    }];

    let steps = pipeline_steps_for_state(
        "Create a release artifact",
        &request,
        &manifest,
        &materialization,
        StudioArtifactLifecycleState::Ready,
        None,
        None,
    );

    let planner_step = steps
        .iter()
        .find(|step| step.id == "planner")
        .expect("planner step");
    let swarm_execution_step = steps
        .iter()
        .find(|step| step.id == "swarm_execution")
        .expect("swarm execution step");
    let merge_step = steps
        .iter()
        .find(|step| step.id == "merge")
        .expect("merge step");
    let repair_step = steps
        .iter()
        .find(|step| step.id == "repair")
        .expect("repair step");

    assert!(planner_step
        .outputs
        .iter()
        .any(|output| output == "markdown_adaptive_work_graph"));
    assert!(planner_step
        .outputs
        .iter()
        .any(|output| output == "work_items:2"));
    assert!(swarm_execution_step
        .outputs
        .iter()
        .any(|output| output == "worker_receipts:1"));
    assert!(swarm_execution_step
        .outputs
        .iter()
        .any(|output| output == "progress:4/5"));
    assert!(merge_step
        .outputs
        .iter()
        .any(|output| output == "repair (Rejected)"));
    assert!(repair_step
        .outputs
        .iter()
        .any(|output| output == "repair_ops:1"));
}

#[test]
fn materialization_contract_carries_micro_swarm_mode_decision_and_budget() {
    let request = test_outcome_request().artifact.expect("artifact request");
    let decision = ioi_types::app::StudioExecutionModeDecision {
        requested_strategy: StudioExecutionStrategy::PlanExecute,
        resolved_strategy: StudioExecutionStrategy::MicroSwarm,
        mode_confidence: 0.84,
        one_shot_sufficiency: 0.42,
        ambiguity: 0.08,
        work_graph_size_estimate: 3,
        hidden_dependency_likelihood: 0.32,
        verification_pressure: 0.4,
        revision_cost: 0.2,
        evidence_breadth: 0.3,
        merge_burden: 0.35,
        decomposition_payoff: 0.57,
        work_graph_required: true,
        decomposition_reason:
            "A bounded work graph is justified without needing adaptive expansion.".to_string(),
        budget_envelope: ioi_types::app::StudioExecutionBudgetEnvelope {
            max_workers: 3,
            max_parallel_depth: 2,
            max_replans: 1,
            max_wall_clock_ms: 300_000,
            max_tokens: 12_000,
            max_tool_calls: 6,
            max_repairs: 1,
            expansion_policy: ioi_types::app::StudioExecutionBudgetExpansionPolicy::ConfidenceGated,
        },
    };

    let materialization = materialization_contract_for_request(
        "Create a release artifact",
        &request,
        "Studio is preparing the artifact.",
        Some(decision.clone()),
        StudioExecutionStrategy::MicroSwarm,
    );
    let envelope = materialization
        .execution_envelope
        .as_ref()
        .expect("execution envelope");

    assert_eq!(envelope.strategy, Some(StudioExecutionStrategy::MicroSwarm));
    assert_eq!(envelope.mode_decision, Some(decision.clone()));
    assert_eq!(
        envelope.budget_envelope,
        Some(decision.budget_envelope.clone())
    );
    assert_eq!(
        envelope
            .completion_invariant
            .as_ref()
            .map(|entry| entry.status),
        Some(ioi_api::execution::ExecutionCompletionInvariantStatus::Pending)
    );
    assert_eq!(
        envelope
            .completion_invariant
            .as_ref()
            .map(|entry| entry.allows_early_exit),
        Some(false)
    );
}

#[test]
fn pipeline_steps_label_micro_swarm_and_surface_completion_progress() {
    let request = StudioOutcomeArtifactRequest {
        artifact_class: StudioArtifactClass::InteractiveSingleFile,
        deliverable_shape: StudioArtifactDeliverableShape::SingleFile,
        renderer: StudioRendererKind::HtmlIframe,
        presentation_surface: StudioPresentationSurface::SidePanel,
        persistence: StudioArtifactPersistenceMode::ArtifactScoped,
        execution_substrate: StudioExecutionSubstrate::ClientSandbox,
        workspace_recipe_id: None,
        presentation_variant_id: None,
        scope: crate::models::StudioOutcomeArtifactScope {
            target_project: None,
            create_new_workspace: false,
            mutation_boundary: vec!["artifact".to_string()],
        },
        verification: crate::models::StudioOutcomeArtifactVerificationRequest {
            require_render: true,
            require_build: false,
            require_preview: false,
            require_export: true,
            require_diff_review: false,
        },
    };
    let manifest = artifact_manifest_for_request(
        "Release artifact",
        &request,
        &["artifact-1".to_string()],
        None,
        None,
        StudioArtifactLifecycleState::Partial,
    );
    let mut materialization = test_materialization_contract();
    materialization.execution_envelope = Some(ioi_api::execution::ExecutionEnvelope {
        version: 1,
        execution_domain: "studio_artifact".to_string(),
        domain_kind: Some(ioi_api::execution::ExecutionDomainKind::Artifact),
        strategy: Some(StudioExecutionStrategy::MicroSwarm),
        mode_decision: Some(ioi_types::app::StudioExecutionModeDecision {
            requested_strategy: StudioExecutionStrategy::PlanExecute,
            resolved_strategy: StudioExecutionStrategy::MicroSwarm,
            mode_confidence: 0.84,
            one_shot_sufficiency: 0.42,
            ambiguity: 0.08,
            work_graph_size_estimate: 3,
            hidden_dependency_likelihood: 0.32,
            verification_pressure: 0.4,
            revision_cost: 0.2,
            evidence_breadth: 0.3,
            merge_burden: 0.35,
            decomposition_payoff: 0.57,
            work_graph_required: true,
            decomposition_reason: "A bounded work graph is justified without adaptive expansion."
                .to_string(),
            budget_envelope: ioi_types::app::StudioExecutionBudgetEnvelope {
                max_workers: 3,
                max_parallel_depth: 2,
                max_replans: 1,
                max_wall_clock_ms: 300_000,
                max_tokens: 12_000,
                max_tool_calls: 6,
                max_repairs: 1,
                expansion_policy:
                    ioi_types::app::StudioExecutionBudgetExpansionPolicy::ConfidenceGated,
            },
        }),
        budget_envelope: Some(ioi_types::app::StudioExecutionBudgetEnvelope {
            max_workers: 3,
            max_parallel_depth: 2,
            max_replans: 1,
            max_wall_clock_ms: 300_000,
            max_tokens: 12_000,
            max_tool_calls: 6,
            max_repairs: 1,
            expansion_policy: ioi_types::app::StudioExecutionBudgetExpansionPolicy::ConfidenceGated,
        }),
        completion_invariant: Some(ioi_api::execution::ExecutionCompletionInvariant {
            summary: "Complete when the bounded HTML graph and verification pass.".to_string(),
            status: ioi_api::execution::ExecutionCompletionInvariantStatus::Pending,
            required_work_item_ids: vec![
                "planner".to_string(),
                "draft".to_string(),
                "merge".to_string(),
            ],
            satisfied_work_item_ids: vec!["planner".to_string()],
            speculative_work_item_ids: vec!["repair".to_string()],
            pruned_work_item_ids: Vec::new(),
            required_verification_ids: vec!["acceptance-judge".to_string()],
            satisfied_verification_ids: Vec::new(),
            required_artifact_paths: vec!["index.html".to_string()],
            remaining_obligations: vec![
                "work_item:draft".to_string(),
                "verification:acceptance-judge".to_string(),
            ],
            allows_early_exit: false,
        }),
        plan: None,
        execution_summary: None,
        worker_receipts: Vec::new(),
        change_receipts: Vec::new(),
        merge_receipts: Vec::new(),
        verification_receipts: Vec::new(),
        graph_mutation_receipts: Vec::new(),
        dispatch_batches: Vec::new(),
        repair_receipts: Vec::new(),
        replan_receipts: Vec::new(),
        budget_summary: None,
        live_previews: Vec::new(),
    });
    materialization.swarm_plan = Some(StudioArtifactSwarmPlan {
        version: 1,
        strategy: "html_micro_swarm".to_string(),
        execution_domain: "studio_artifact".to_string(),
        adapter_label: "html_micro_v1".to_string(),
        parallelism_mode: "bounded_frontier".to_string(),
        top_level_objective: Some("Create the HTML explainer.".to_string()),
        decomposition_hypothesis: Some(
            "A three-node graph is enough for the HTML explainer.".to_string(),
        ),
        decomposition_type: Some("small_graph".to_string()),
        first_frontier_ids: vec!["planner".to_string(), "draft".to_string()],
        spawn_conditions: vec!["Spawn repair only if verification blocks.".to_string()],
        prune_conditions: vec!["Prune repair when verification passes.".to_string()],
        merge_strategy: Some("deterministic_patch_merge".to_string()),
        verification_strategy: Some("judge_then_verify".to_string()),
        fallback_collapse_strategy: Some("collapse_to_remaining_frontier".to_string()),
        completion_invariant: materialization
            .execution_envelope
            .as_ref()
            .and_then(|entry| entry.completion_invariant.clone()),
        work_items: vec![
            StudioArtifactWorkItem {
                id: "planner".to_string(),
                title: "Planner".to_string(),
                role: StudioArtifactWorkerRole::Planner,
                summary: "Lock the brief and graph.".to_string(),
                spawned_from_id: None,
                read_paths: Vec::new(),
                write_paths: Vec::new(),
                write_regions: Vec::new(),
                lease_requirements: Vec::new(),
                acceptance_criteria: vec!["bounded".to_string()],
                dependency_ids: Vec::new(),
                blocked_on_ids: Vec::new(),
                verification_policy: Some(ioi_api::studio::SwarmVerificationPolicy::Normal),
                retry_budget: Some(0),
                status: StudioArtifactWorkItemStatus::Succeeded,
            },
            StudioArtifactWorkItem {
                id: "draft".to_string(),
                title: "Draft".to_string(),
                role: StudioArtifactWorkerRole::SectionContent,
                summary: "Draft the main HTML artifact.".to_string(),
                spawned_from_id: None,
                read_paths: vec!["index.html".to_string()],
                write_paths: vec!["index.html".to_string()],
                write_regions: vec!["main".to_string()],
                lease_requirements: Vec::new(),
                acceptance_criteria: vec!["renderable".to_string()],
                dependency_ids: vec!["planner".to_string()],
                blocked_on_ids: Vec::new(),
                verification_policy: Some(ioi_api::studio::SwarmVerificationPolicy::Normal),
                retry_budget: Some(0),
                status: StudioArtifactWorkItemStatus::Running,
            },
        ],
    });
    materialization.swarm_execution = Some(StudioArtifactSwarmExecutionSummary {
        enabled: true,
        current_stage: "draft".to_string(),
        execution_stage: Some(ExecutionStage::Mutate),
        active_worker_role: Some(StudioArtifactWorkerRole::SectionContent),
        total_work_items: 3,
        completed_work_items: 1,
        failed_work_items: 0,
        verification_status: "pending".to_string(),
        strategy: "html_micro_swarm".to_string(),
        execution_domain: "studio_artifact".to_string(),
        adapter_label: "html_micro_v1".to_string(),
        parallelism_mode: "bounded_frontier".to_string(),
    });

    let steps = pipeline_steps_for_state(
        "Create a release artifact",
        &request,
        &manifest,
        &materialization,
        StudioArtifactLifecycleState::Materializing,
        None,
        None,
    );
    let planner_step = steps
        .iter()
        .find(|step| step.id == "planner")
        .expect("planner step");
    let execution_step = steps
        .iter()
        .find(|step| step.id == "swarm_execution")
        .expect("swarm execution step");
    let verification_step = steps
        .iter()
        .find(|step| step.id == "verification")
        .expect("verification step");

    assert_eq!(execution_step.label, "Micro swarm");
    assert!(planner_step
        .outputs
        .iter()
        .any(|output| output == "small_graph"));
    assert!(execution_step
        .outputs
        .iter()
        .any(|output| output == "progress:1/3"));
    assert!(execution_step
        .outputs
        .iter()
        .any(|output| output == "invariant:pending"));
    assert!(execution_step
        .outputs
        .iter()
        .any(|output| output == "remaining:2"));
    assert!(verification_step
        .outputs
        .iter()
        .any(|output| output == "completion:pending"));
}
