use super::*;

#[test]
fn html_swarm_plan_is_stable_and_scoped() {
    let request = request_for(
        ChatArtifactClass::InteractiveSingleFile,
        ChatRendererKind::HtmlIframe,
    );
    let brief = ChatArtifactBrief {
        audience: "operators".to_string(),
        job_to_be_done: "compare launch evidence".to_string(),
        subject_domain: "release operations".to_string(),
        artifact_thesis: "Show one interactive release review artifact.".to_string(),
        required_concepts: vec![
            "timeline".to_string(),
            "owners".to_string(),
            "metrics".to_string(),
        ],
        required_interactions: vec![
            "view switching".to_string(),
            "detail comparison".to_string(),
        ],
        visual_tone: vec!["grounded".to_string(), "technical".to_string()],
        factual_anchors: vec!["launch review".to_string()],
        style_directives: vec!["dense but readable".to_string()],
        reference_hints: Vec::new(),
        query_profile: None,
    };
    let blueprint = derive_chat_artifact_blueprint(&request, &brief);

    let first_plan = super::generation::build_chat_artifact_swarm_plan(
        &request,
        Some(&blueprint),
        &brief,
        ChatExecutionStrategy::AdaptiveWorkGraph,
    );
    let second_plan = super::generation::build_chat_artifact_swarm_plan(
        &request,
        Some(&blueprint),
        &brief,
        ChatExecutionStrategy::AdaptiveWorkGraph,
    );

    assert_eq!(first_plan, second_plan);
    assert_eq!(first_plan.strategy, "html_adaptive_work_graph");
    assert_eq!(first_plan.parallelism_mode, "sequential_by_default");
    assert_eq!(
        first_plan.work_items.first().map(|item| item.id.as_str()),
        Some("planner")
    );
    assert!(first_plan
        .work_items
        .iter()
        .any(|item| item.id == "skeleton" && item.role == ChatArtifactWorkerRole::Skeleton));
    assert!(first_plan.work_items.iter().any(
        |item| item.id == "style-system" && item.role == ChatArtifactWorkerRole::StyleSystem
    ));
    assert!(
        first_plan
            .work_items
            .iter()
            .any(|item| item.id == "interaction"
                && item.role == ChatArtifactWorkerRole::Interaction)
    );
    assert!(first_plan
        .work_items
        .iter()
        .any(|item| item.id == "integrator" && item.role == ChatArtifactWorkerRole::Integrator));
    assert!(first_plan.work_items.iter().any(
        |item| item.id == "validation" && item.dependency_ids == vec!["integrator".to_string()]
    ));
    assert!(first_plan.work_items.iter().any(|item| item.id == "repair"
        && item.dependency_ids == vec!["validation".to_string()]
        && item.verification_policy == Some(SwarmVerificationPolicy::Blocking)
        && item.retry_budget == Some(2)));

    let section_items = first_plan
        .work_items
        .iter()
        .filter(|item| item.role == ChatArtifactWorkerRole::SectionContent)
        .collect::<Vec<_>>();
    assert!(!section_items.is_empty());
    assert!(section_items.iter().all(|item| {
        item.write_paths == vec!["index.html".to_string()]
            && item.dependency_ids == vec!["skeleton".to_string()]
            && item.write_regions.len() == 1
            && item
                .lease_requirements
                .iter()
                .any(|lease| lease.mode == SwarmLeaseMode::ExclusiveWrite)
    }));
}

#[test]
fn markdown_swarm_plan_uses_coarse_adapter_workers() {
    let request = request_for(ChatArtifactClass::Document, ChatRendererKind::Markdown);
    let brief = ChatArtifactBrief {
        audience: "operators".to_string(),
        job_to_be_done: "publish a brief".to_string(),
        subject_domain: "status reporting".to_string(),
        artifact_thesis: "Summarize the rollout cleanly.".to_string(),
        required_concepts: vec!["summary".to_string()],
        required_interactions: Vec::new(),
        visual_tone: vec!["clear".to_string()],
        factual_anchors: Vec::new(),
        style_directives: Vec::new(),
        reference_hints: Vec::new(),
        query_profile: None,
    };

    let plan = super::generation::build_chat_artifact_swarm_plan(
        &request,
        None,
        &brief,
        ChatExecutionStrategy::AdaptiveWorkGraph,
    );

    assert_eq!(plan.strategy, "markdown_adaptive_work_graph");
    assert_eq!(plan.parallelism_mode, "sequential_by_default");
    assert!(plan
        .work_items
        .iter()
        .any(|item| item.id == "skeleton" && item.role == ChatArtifactWorkerRole::Skeleton));
    assert!(
        plan.work_items
            .iter()
            .any(|item| item.id == "integrator"
                && item.dependency_ids == vec!["skeleton".to_string()])
    );
    assert!(!plan
        .work_items
        .iter()
        .any(|item| item.role == ChatArtifactWorkerRole::SectionContent));
}
