use super::*;

pub(super) fn coalesce_html_work_graph_section_plans(
    sections: Vec<ChatArtifactSectionPlan>,
    max_sections: usize,
) -> Vec<ChatArtifactSectionPlan> {
    if sections.len() <= max_sections.max(1) {
        return sections;
    }

    let chunk_size = sections.len().div_ceil(max_sections.max(1));
    sections
        .chunks(chunk_size)
        .enumerate()
        .map(|(index, chunk)| {
            let mut content_requirements = Vec::new();
            let mut interaction_hooks = Vec::new();
            let mut first_paint_requirements = Vec::new();
            for section in chunk {
                push_unique_focus_strings(
                    &mut content_requirements,
                    section.content_requirements.clone(),
                    5,
                );
                push_unique_focus_strings(
                    &mut interaction_hooks,
                    section.interaction_hooks.clone(),
                    4,
                );
                push_unique_focus_strings(
                    &mut first_paint_requirements,
                    section.first_paint_requirements.clone(),
                    5,
                );
            }
            let id = chunk
                .first()
                .map(|section| section.id.clone())
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| format!("section-{}", index + 1));
            let role = if chunk.len() == 1 {
                chunk[0].role.clone()
            } else {
                format!("composite-{}", index + 1)
            };
            let visible_purpose = chunk
                .iter()
                .take(2)
                .map(|section| truncate_materialization_focus_text(&section.visible_purpose, 96))
                .collect::<Vec<_>>()
                .join(" Then ");
            ChatArtifactSectionPlan {
                id,
                role,
                visible_purpose,
                content_requirements,
                interaction_hooks,
                first_paint_requirements,
            }
        })
        .collect()
}

pub(super) fn fallback_section_plans() -> Vec<ChatArtifactSectionPlan> {
    vec![
        ChatArtifactSectionPlan {
            id: "lead".to_string(),
            role: "lead".to_string(),
            visible_purpose: "Establish the request thesis and the first useful state.".to_string(),
            content_requirements: vec!["First-paint framing".to_string()],
            interaction_hooks: Vec::new(),
            first_paint_requirements: vec!["Visible opening state".to_string()],
        },
        ChatArtifactSectionPlan {
            id: "evidence".to_string(),
            role: "evidence".to_string(),
            visible_purpose: "Surface the request-grounded evidence or explanation.".to_string(),
            content_requirements: vec!["Primary evidence view".to_string()],
            interaction_hooks: Vec::new(),
            first_paint_requirements: vec!["Visible evidence".to_string()],
        },
        ChatArtifactSectionPlan {
            id: "detail".to_string(),
            role: "detail".to_string(),
            visible_purpose: "Carry the supporting detail, comparison, or call to action."
                .to_string(),
            content_requirements: vec!["Secondary depth".to_string()],
            interaction_hooks: Vec::new(),
            first_paint_requirements: vec!["Secondary surfaced depth".to_string()],
        },
    ]
}

pub(crate) fn build_chat_artifact_work_graph_plan(
    request: &ChatOutcomeArtifactRequest,
    blueprint: Option<&ChatArtifactBlueprint>,
    brief: &ChatArtifactBrief,
    execution_strategy: ChatExecutionStrategy,
) -> ChatArtifactWorkGraphPlan {
    let (strategy, adapter_label) =
        chat_work_graph_strategy_for_request(request, execution_strategy);
    let is_micro_work_graph = execution_strategy == ChatExecutionStrategy::MicroWorkGraph;
    let mut work_items = vec![ChatArtifactWorkItem {
        id: "planner".to_string(),
        title: "Planner".to_string(),
        role: ChatArtifactWorkerRole::Planner,
        summary: "Lock the artifact outline, constraints, and worker ownership map once."
            .to_string(),
        spawned_from_id: None,
        read_paths: Vec::new(),
        write_paths: Vec::new(),
        write_regions: Vec::new(),
        lease_requirements: Vec::new(),
        acceptance_criteria: vec![
            "Work graph is dependency ordered.".to_string(),
            "Writable scopes are explicit.".to_string(),
        ],
        dependency_ids: Vec::new(),
        blocked_on_ids: Vec::new(),
        verification_policy: Some(WorkGraphVerificationPolicy::Normal),
        retry_budget: Some(0),
        status: ChatArtifactWorkItemStatus::Pending,
    }];

    match request.renderer {
        ChatRendererKind::HtmlIframe => {
            let sections = blueprint
                .map(|value| value.section_plan.clone())
                .filter(|value| !value.is_empty())
                .unwrap_or_else(fallback_section_plans);
            let sections = coalesce_html_work_graph_section_plans(
                sections,
                if is_micro_work_graph { 1 } else { 3 },
            );
            let section_regions = sections
                .iter()
                .enumerate()
                .map(|(index, section)| format!("section:{}", section_region_id(section, index)))
                .collect::<Vec<_>>();
            work_items.push(ChatArtifactWorkItem {
                id: "skeleton".to_string(),
                title: "HTML skeleton".to_string(),
                role: ChatArtifactWorkerRole::Skeleton,
                summary: "Author the canonical HTML shell and region map.".to_string(),
                spawned_from_id: None,
                read_paths: Vec::new(),
                write_paths: vec!["index.html".to_string()],
                write_regions: {
                    let mut regions = vec!["style-system".to_string(), "interaction".to_string()];
                    regions.extend(section_regions.clone());
                    regions
                },
                lease_requirements: {
                    let mut leases = vec![exclusive_write_lease_for_path("index.html")];
                    leases.extend(
                        std::iter::once("style-system".to_string())
                            .chain(std::iter::once("interaction".to_string()))
                            .chain(section_regions.clone().into_iter())
                            .map(exclusive_write_lease_for_region),
                    );
                    leases
                },
                acceptance_criteria: vec![
                    "The shell includes <main> and the section region markers.".to_string(),
                    "Style and interaction regions are reserved once.".to_string(),
                ],
                dependency_ids: vec!["planner".to_string()],
                blocked_on_ids: Vec::new(),
                verification_policy: Some(WorkGraphVerificationPolicy::Normal),
                retry_budget: Some(0),
                status: ChatArtifactWorkItemStatus::Pending,
            });
            for (index, section) in sections.iter().enumerate() {
                let region_id = format!("section:{}", section_region_id(section, index));
                work_items.push(ChatArtifactWorkItem {
                    id: format!("section-{}", index + 1),
                    title: format!("Section {}", index + 1),
                    role: ChatArtifactWorkerRole::SectionContent,
                    summary: format!(
                        "Own the {} section content without rewriting global shell.",
                        section.role
                    ),
                    spawned_from_id: None,
                    read_paths: vec!["index.html".to_string()],
                    write_paths: vec!["index.html".to_string()],
                    write_regions: vec![region_id.clone()],
                    lease_requirements: vec![
                        shared_read_lease_for_path("index.html"),
                        exclusive_write_lease_for_region(region_id),
                    ],
                    acceptance_criteria: {
                        let mut criteria = vec![section.visible_purpose.clone()];
                        criteria.extend(section.first_paint_requirements.clone());
                        criteria
                    },
                    dependency_ids: vec!["skeleton".to_string()],
                    blocked_on_ids: Vec::new(),
                    verification_policy: Some(WorkGraphVerificationPolicy::Normal),
                    retry_budget: Some(0),
                    status: ChatArtifactWorkItemStatus::Pending,
                });
            }
            let section_dependency_ids = work_items
                .iter()
                .filter(|item| item.role == ChatArtifactWorkerRole::SectionContent)
                .map(|item| item.id.clone())
                .collect::<Vec<_>>();
            if !is_micro_work_graph {
                work_items.push(ChatArtifactWorkItem {
                    id: "style-system".to_string(),
                    title: "Style system".to_string(),
                    role: ChatArtifactWorkerRole::StyleSystem,
                    summary: "Own shared tokens, hierarchy, and palette coherence.".to_string(),
                    spawned_from_id: None,
                    read_paths: vec!["index.html".to_string()],
                    write_paths: vec!["index.html".to_string()],
                    write_regions: vec!["style-system".to_string()],
                    lease_requirements: vec![
                        shared_read_lease_for_path("index.html"),
                        exclusive_write_lease_for_region("style-system"),
                    ],
                    acceptance_criteria: vec![
                        "Slate/graphite shell with one cool accent family.".to_string(),
                        "Dense but readable hierarchy.".to_string(),
                    ],
                    dependency_ids: {
                        let mut deps = vec!["skeleton".to_string()];
                        deps.extend(section_dependency_ids.clone());
                        deps
                    },
                    blocked_on_ids: Vec::new(),
                    verification_policy: Some(WorkGraphVerificationPolicy::Elevated),
                    retry_budget: Some(0),
                    status: ChatArtifactWorkItemStatus::Pending,
                });
                work_items.push(ChatArtifactWorkItem {
                    id: "interaction".to_string(),
                    title: "Interaction".to_string(),
                    role: ChatArtifactWorkerRole::Interaction,
                    summary: "Wire the chosen interaction grammar against authored DOM."
                        .to_string(),
                    spawned_from_id: None,
                    read_paths: vec!["index.html".to_string()],
                    write_paths: vec!["index.html".to_string()],
                    write_regions: vec!["interaction".to_string()],
                    lease_requirements: vec![
                        shared_read_lease_for_path("index.html"),
                        exclusive_write_lease_for_region("interaction"),
                    ],
                    acceptance_criteria: {
                        let mut criteria = brief.required_interaction_summaries();
                        if criteria.is_empty() {
                            criteria.push(
                                "Keep authored state changes truthful and inline.".to_string(),
                            );
                        }
                        criteria
                    },
                    dependency_ids: {
                        let mut deps = section_dependency_ids.clone();
                        deps.push("skeleton".to_string());
                        deps
                    },
                    blocked_on_ids: Vec::new(),
                    verification_policy: Some(WorkGraphVerificationPolicy::Elevated),
                    retry_budget: Some(0),
                    status: ChatArtifactWorkItemStatus::Pending,
                });
                work_items.push(ChatArtifactWorkItem {
                    id: "integrator".to_string(),
                    title: "Integrator".to_string(),
                    role: ChatArtifactWorkerRole::Integrator,
                    summary: "Reconcile cross-section seams without restarting the document."
                        .to_string(),
                    spawned_from_id: None,
                    read_paths: vec!["index.html".to_string()],
                    write_paths: vec!["index.html".to_string()],
                    write_regions: {
                        let mut regions =
                            vec!["style-system".to_string(), "interaction".to_string()];
                        regions.extend(section_regions);
                        regions
                    },
                    lease_requirements: {
                        let mut leases = vec![shared_read_lease_for_path("index.html")];
                        leases.extend(
                            work_items
                                .iter()
                                .filter(|item| item.role == ChatArtifactWorkerRole::SectionContent)
                                .flat_map(|item| item.write_regions.clone())
                                .chain(vec!["style-system".to_string(), "interaction".to_string()])
                                .map(exclusive_write_lease_for_region),
                        );
                        leases
                    },
                    acceptance_criteria: vec![
                        "Cross-section copy and utility hierarchy agree.".to_string(),
                        "The first paint reads as one cohesive artifact.".to_string(),
                    ],
                    dependency_ids: {
                        let mut deps = vec!["style-system".to_string(), "interaction".to_string()];
                        deps.extend(section_dependency_ids);
                        deps
                    },
                    blocked_on_ids: Vec::new(),
                    verification_policy: Some(WorkGraphVerificationPolicy::Elevated),
                    retry_budget: Some(0),
                    status: ChatArtifactWorkItemStatus::Pending,
                });
            }
        }
        _ => {
            let primary_file = default_generated_artifact_file_for_renderer(request.renderer);
            work_items.push(ChatArtifactWorkItem {
                id: "skeleton".to_string(),
                title: "Coarse implementer".to_string(),
                role: ChatArtifactWorkerRole::Skeleton,
                summary:
                    "Materialize the initial renderer-native file set under one bounded worker."
                        .to_string(),
                spawned_from_id: None,
                read_paths: Vec::new(),
                write_paths: vec![primary_file.path.clone()],
                write_regions: Vec::new(),
                lease_requirements: vec![exclusive_write_lease_for_path(primary_file.path.clone())],
                acceptance_criteria: vec![
                    "Create the canonical primary file set once.".to_string(),
                    "Stay inside the renderer contract.".to_string(),
                ],
                dependency_ids: vec!["planner".to_string()],
                blocked_on_ids: Vec::new(),
                verification_policy: Some(WorkGraphVerificationPolicy::Normal),
                retry_budget: Some(0),
                status: ChatArtifactWorkItemStatus::Pending,
            });
            if !is_micro_work_graph {
                work_items.push(ChatArtifactWorkItem {
                    id: "integrator".to_string(),
                    title: "Integrator".to_string(),
                    role: ChatArtifactWorkerRole::Integrator,
                    summary: "Apply bounded reconciliation only when the coarse adapter needs it."
                        .to_string(),
                    spawned_from_id: None,
                    read_paths: vec![primary_file.path],
                    write_paths: Vec::new(),
                    write_regions: Vec::new(),
                    lease_requirements: Vec::new(),
                    acceptance_criteria: vec![
                        "Do not rewrite the artifact without a cited verification reason."
                            .to_string(),
                    ],
                    dependency_ids: vec!["skeleton".to_string()],
                    blocked_on_ids: Vec::new(),
                    verification_policy: Some(WorkGraphVerificationPolicy::Elevated),
                    retry_budget: Some(0),
                    status: ChatArtifactWorkItemStatus::Pending,
                });
            }
        }
    }

    let repair_write_paths = if request.renderer == ChatRendererKind::HtmlIframe {
        work_items
            .iter()
            .flat_map(|item| item.write_paths.iter().cloned())
            .fold(Vec::<String>::new(), |mut acc, path| {
                if !acc.iter().any(|existing| existing == &path) {
                    acc.push(path);
                }
                acc
            })
    } else {
        Vec::new()
    };
    let repair_write_regions = if request.renderer == ChatRendererKind::HtmlIframe {
        work_items
            .iter()
            .flat_map(|item| item.write_regions.iter().cloned())
            .fold(Vec::<String>::new(), |mut acc, region| {
                if !acc.iter().any(|existing| existing == &region) {
                    acc.push(region);
                }
                acc
            })
    } else {
        Vec::new()
    };

    let validation_dependency_ids = work_items
        .iter()
        .filter(|item| item.role == ChatArtifactWorkerRole::Integrator)
        .map(|item| item.id.clone())
        .collect::<Vec<_>>();
    work_items.push(ChatArtifactWorkItem {
        id: "validation".to_string(),
        title: "Validation".to_string(),
        role: ChatArtifactWorkerRole::Validation,
        summary: "Evaluate the merged artifact once against fidelity, utility, and coherence."
            .to_string(),
        spawned_from_id: None,
        read_paths: Vec::new(),
        write_paths: Vec::new(),
        write_regions: Vec::new(),
        lease_requirements: Vec::new(),
        acceptance_criteria: vec![
            "Validation the merged artifact, not competing universes.".to_string()
        ],
        dependency_ids: if validation_dependency_ids.is_empty() {
            work_items
                .iter()
                .filter(|item| {
                    matches!(
                        item.role,
                        ChatArtifactWorkerRole::Skeleton
                            | ChatArtifactWorkerRole::SectionContent
                            | ChatArtifactWorkerRole::StyleSystem
                            | ChatArtifactWorkerRole::Interaction
                            | ChatArtifactWorkerRole::Integrator
                    )
                })
                .map(|item| item.id.clone())
                .collect()
        } else {
            validation_dependency_ids
        },
        blocked_on_ids: Vec::new(),
        verification_policy: Some(WorkGraphVerificationPolicy::Blocking),
        retry_budget: Some(0),
        status: ChatArtifactWorkItemStatus::Pending,
    });
    work_items.push(ChatArtifactWorkItem {
        id: "repair".to_string(),
        title: "Repair".to_string(),
        role: ChatArtifactWorkerRole::Repair,
        summary:
            "Patch only cited failures against the canonical artifact when verification blocks."
                .to_string(),
        spawned_from_id: None,
        read_paths: Vec::new(),
        write_paths: repair_write_paths.clone(),
        write_regions: repair_write_regions.clone(),
        lease_requirements: {
            let mut leases = repair_write_paths
                .iter()
                .cloned()
                .map(exclusive_write_lease_for_path)
                .collect::<Vec<_>>();
            leases.extend(
                repair_write_regions
                    .iter()
                    .cloned()
                    .map(exclusive_write_lease_for_region),
            );
            leases
        },
        acceptance_criteria: vec!["Repair must stay bounded to cited failures.".to_string()],
        dependency_ids: vec!["validation".to_string()],
        blocked_on_ids: Vec::new(),
        verification_policy: Some(WorkGraphVerificationPolicy::Blocking),
        retry_budget: Some(2),
        status: ChatArtifactWorkItemStatus::Pending,
    });

    ChatArtifactWorkGraphPlan {
        version: 1,
        strategy: strategy.to_string(),
        execution_domain: "chat_artifact".to_string(),
        adapter_label: adapter_label.to_string(),
        parallelism_mode: "sequential_by_default".to_string(),
        top_level_objective: Some(brief.artifact_thesis.clone()),
        decomposition_hypothesis: Some(if is_micro_work_graph {
            "A small known work graph is sufficient; keep decomposition bounded and avoid full adaptive expansion."
                .to_string()
        } else {
            "The request merits a mutable shared-state work graph with bounded worker scopes."
                .to_string()
        }),
        decomposition_type: Some(if request.renderer == ChatRendererKind::HtmlIframe {
            if is_micro_work_graph {
                "small_graph_content_decomposition".to_string()
            } else {
                "adaptive_shared_state_content_decomposition".to_string()
            }
        } else if is_micro_work_graph {
            "small_graph_functional_decomposition".to_string()
        } else {
            "adaptive_functional_decomposition".to_string()
        }),
        first_frontier_ids: vec!["planner".to_string()],
        spawn_conditions: if is_micro_work_graph {
            vec!["Spawn a bounded repair node only if verification fails.".to_string()]
        } else {
            vec![
                "Spawn bounded repair nodes only when verification cites concrete failures."
                    .to_string(),
                "Allow follow-up repair nodes when earlier repair passes leave unresolved obligations."
                    .to_string(),
            ]
        },
        prune_conditions: vec![
            "Prune repair or integration work when the completion invariant is already satisfied."
                .to_string(),
            "Collapse remaining branches when earlier receipts eliminate downstream obligations."
                .to_string(),
        ],
        merge_strategy: Some(if is_micro_work_graph {
            "bounded_direct_merge".to_string()
        } else {
            "bounded_shared_state_patch_merge".to_string()
        }),
        verification_strategy: Some("validate_merged_state_then_repair_if_needed".to_string()),
        fallback_collapse_strategy: Some(
            "Collapse to the smallest remaining frontier that can satisfy the completion invariant."
                .to_string(),
        ),
        completion_invariant: Some(crate::execution::ExecutionCompletionInvariant {
            summary: if is_micro_work_graph {
                "Complete once the small mandatory graph lands one valid artifact and verification passes."
                    .to_string()
            } else {
                "Complete once the mandatory shared-state graph and verification obligations are satisfied."
                    .to_string()
            },
            status: crate::execution::ExecutionCompletionInvariantStatus::Pending,
            required_work_item_ids: work_items
                .iter()
                .filter(|item| {
                    item.role != ChatArtifactWorkerRole::Repair
                        && !item.id.starts_with("repair-pass-")
                })
                .map(|item| item.id.clone())
                .collect(),
            satisfied_work_item_ids: Vec::new(),
            speculative_work_item_ids: vec!["repair".to_string()],
            pruned_work_item_ids: Vec::new(),
            required_verification_ids: vec![
                "schema-validation".to_string(),
                "render-evaluation".to_string(),
                "artifact-validation".to_string(),
            ],
            satisfied_verification_ids: Vec::new(),
            required_artifact_paths: Vec::new(),
            remaining_obligations: Vec::new(),
            allows_early_exit: true,
        }),
        work_items,
    }
}
