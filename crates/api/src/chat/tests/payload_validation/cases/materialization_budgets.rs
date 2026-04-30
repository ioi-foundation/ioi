#[test]
fn modal_first_html_local_runtime_candidate_generation_uses_single_candidate() {
    with_modal_first_html_env(|| {
        let (count, temperature, strategy) = candidate_generation_config(
            ChatRendererKind::HtmlIframe,
            ChatRuntimeProvenanceKind::RealLocalRuntime,
        );
        assert_eq!(count, 1);
        assert!(temperature >= 0.68);
        assert_eq!(strategy, "request-grounded_html");
    });
}

#[test]
fn modal_first_html_local_runtime_materialization_token_budget_expands_completion_room() {
    with_modal_first_html_env(|| {
        assert_eq!(
            super::generation::materialization_max_tokens_for_runtime(
                ChatRendererKind::HtmlIframe,
                ChatRuntimeProvenanceKind::RealLocalRuntime,
            ),
            2800
        );
    });
}

#[test]
fn local_html_direct_author_budget_matches_local_materialization_budget() {
    super::with_chat_modal_first_html_override(false, || {
        assert_eq!(
            super::generation::materialization_max_tokens_for_execution_strategy(
                ChatRendererKind::HtmlIframe,
                ChatExecutionStrategy::DirectAuthor,
                ChatRuntimeProvenanceKind::RealLocalRuntime,
            ),
            super::generation::materialization_max_tokens_for_runtime(
                ChatRendererKind::HtmlIframe,
                ChatRuntimeProvenanceKind::RealLocalRuntime,
            ),
        );
    });
}

#[test]
fn modal_first_html_direct_author_budget_stays_bounded_for_local_gpu_runs() {
    with_modal_first_html_env(|| {
        assert_eq!(
            super::generation::materialization_max_tokens_for_execution_strategy(
                ChatRendererKind::HtmlIframe,
                ChatExecutionStrategy::DirectAuthor,
                ChatRuntimeProvenanceKind::RealLocalRuntime,
            ),
            2400
        );
    });
}

#[test]
fn simple_local_runtime_renderers_use_single_candidate_budgets() {
    for (renderer, expected_temperature, expected_strategy) in [
        (ChatRendererKind::Markdown, 0.22, "outline-first_markdown"),
        (ChatRendererKind::Mermaid, 0.18, "pipeline-first_mermaid"),
        (ChatRendererKind::PdfEmbed, 0.2, "brief-first_pdf"),
        (
            ChatRendererKind::DownloadCard,
            0.12,
            "bundle-first_download",
        ),
        (
            ChatRendererKind::BundleManifest,
            0.12,
            "bundle-first_download",
        ),
    ] {
        let (count, temperature, strategy) =
            candidate_generation_config(renderer, ChatRuntimeProvenanceKind::RealLocalRuntime);
        assert_eq!(count, 1);
        assert!((temperature - expected_temperature).abs() < f32::EPSILON);
        assert_eq!(strategy, expected_strategy);
    }
}

#[test]
fn modal_first_html_local_runtime_refinement_budget_allows_one_pass() {
    with_modal_first_html_env(|| {
        assert_eq!(
            super::validation::semantic_refinement_pass_limit(
                ChatRendererKind::HtmlIframe,
                ChatRuntimeProvenanceKind::RealLocalRuntime,
            ),
            1
        );
    });
}

#[test]
fn modal_first_quantum_html_budget_stays_user_viable() {
    with_modal_first_html_env(|| {
        let request = request_for(ChatArtifactClass::Document, ChatRendererKind::HtmlIframe);
        let brief = sample_quantum_explainer_brief();
        let blueprint = derive_chat_artifact_blueprint(&request, &brief);
        let artifact_ir = compile_chat_artifact_ir(&request, &brief, &blueprint);

        let budget = super::generation::derive_chat_adaptive_search_budget(
            &request,
            &brief,
            Some(&blueprint),
            Some(&artifact_ir),
            &[],
            &[],
            None,
            ChatRuntimeProvenanceKind::RealLocalRuntime,
            ChatArtifactRuntimePolicyProfile::FullyLocal,
            false,
        );

        assert_eq!(budget.initial_candidate_count, 1);
        assert_eq!(budget.max_candidate_count, 1);
        assert_eq!(budget.shortlist_limit, 1);
        assert_eq!(budget.max_semantic_refinement_passes, 1);
        assert!(budget
            .signals
            .contains(&ChatAdaptiveSearchSignal::LocalGenerationConstraint));
    });
}

#[test]
fn modal_first_quantum_html_budget_reopens_for_validation_backed_runtime_profile() {
    with_modal_first_html_env(|| {
        let request = request_for(
            ChatArtifactClass::InteractiveSingleFile,
            ChatRendererKind::HtmlIframe,
        );
        let brief = sample_quantum_explainer_brief();
        let blueprint = derive_chat_artifact_blueprint(&request, &brief);
        let artifact_ir = compile_chat_artifact_ir(&request, &brief, &blueprint);

        let budget = super::generation::derive_chat_adaptive_search_budget(
            &request,
            &brief,
            Some(&blueprint),
            Some(&artifact_ir),
            &[],
            &[],
            None,
            ChatRuntimeProvenanceKind::RealLocalRuntime,
            ChatArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance,
            false,
        );

        assert_eq!(budget.initial_candidate_count, 1);
        assert!(budget.max_candidate_count >= 3);
        assert!(budget.shortlist_limit >= 3);
        assert_eq!(budget.max_semantic_refinement_passes, 3);
        assert!(budget
            .signals
            .contains(&ChatAdaptiveSearchSignal::LocalGenerationConstraint));
    });
}

#[test]
fn modal_first_local_html_prompt_pushes_authored_interactive_explainers() {
    with_modal_first_html_env(|| {
        let request = request_for(
            ChatArtifactClass::InteractiveSingleFile,
            ChatRendererKind::HtmlIframe,
        );
        let brief = sample_quantum_explainer_brief();

        let prompt = build_chat_artifact_materialization_prompt_for_runtime(
            "Quantum computing explainer",
            "Create an interactive HTML artifact that explains quantum computers",
            &request,
            &brief,
            None,
            None,
            &[],
            &[],
            None,
            None,
            "candidate-1",
            42,
            ChatRuntimeProvenanceKind::RealLocalRuntime,
        )
        .expect("modal-first local prompt");

        let prompt_bytes = serde_json::to_vec(&prompt).expect("prompt bytes");
        let prompt_text = decode_chat_test_prompt(&prompt_bytes);

        assert!(prompt_text.contains(
            "prefer a living model, scenario walkthrough, inspectable diagram, or guided comparison"
        ));
        assert!(prompt_text
            .contains("one isolated button or slider does not satisfy an interactive artifact"));
        assert!(prompt_text.contains("avoid default browser-white document styling"));
    });
}

#[test]
fn modal_first_local_html_materialization_prompt_stays_compact_for_landing_pages() {
    with_modal_first_html_env(|| {
        let request = request_for(
            ChatArtifactClass::InteractiveSingleFile,
            ChatRendererKind::HtmlIframe,
        );
        let brief = ChatArtifactBrief {
            audience: "SaaS teams evaluating collaboration tooling".to_string(),
            job_to_be_done:
                "understand CloudSync pricing, features, and reasons to switch".to_string(),
            subject_domain: "B2B SaaS landing page".to_string(),
            artifact_thesis:
                "Present CloudSync as a polished landing page with pricing comparison and feature proof."
                    .to_string(),
            required_concepts: vec![
                "CloudSync".to_string(),
                "pricing tiers".to_string(),
                "feature proof".to_string(),
                "team collaboration".to_string(),
            ],
            required_interactions: vec![
                "plan switching".to_string(),
                "feature inspection".to_string(),
            ],
            visual_tone: vec!["editorial".to_string(), "confident".to_string()],
            factual_anchors: vec!["pricing comparison".to_string()],
            style_directives: vec!["bold product storytelling".to_string()],
            reference_hints: vec!["hero, proof, pricing, footer".to_string()],
            query_profile: None,
        };

        let remote_prompt = build_chat_artifact_materialization_prompt_for_runtime(
            "CloudSync landing page",
            "Build a beautiful landing page for a SaaS product called CloudSync with a hero section, feature cards, pricing table, and a footer",
            &request,
            &brief,
            None,
            None,
            &[],
            &[],
            None,
            None,
            "candidate-1",
            7,
            ChatRuntimeProvenanceKind::RealRemoteModelRuntime,
        )
        .expect("remote modal-first prompt");
        let local_prompt = build_chat_artifact_materialization_prompt_for_runtime(
            "CloudSync landing page",
            "Build a beautiful landing page for a SaaS product called CloudSync with a hero section, feature cards, pricing table, and a footer",
            &request,
            &brief,
            None,
            None,
            &[],
            &[],
            None,
            None,
            "candidate-1",
            7,
            ChatRuntimeProvenanceKind::RealLocalRuntime,
        )
        .expect("local modal-first prompt");

        let remote_prompt_bytes = serde_json::to_vec(&remote_prompt).expect("remote prompt bytes");
        let local_prompt_bytes = serde_json::to_vec(&local_prompt).expect("local prompt bytes");
        let local_prompt_text = decode_chat_test_prompt(&local_prompt_bytes);

        assert!(local_prompt_bytes.len() < remote_prompt_bytes.len());
        assert!(local_prompt_bytes.len() < 11_000);
        assert!(local_prompt_text.contains(
            "Keep CSS and JS concise enough to finish the full document in one local-model pass."
        ));
        assert!(local_prompt_text.contains(
            "Ship one self-contained .html file with inline CSS/JS, <main>, and meaningful surfaced structure."
        ));
        assert!(!local_prompt_text.contains("Build the first paint around this section blueprint:"));
    });
}

#[test]
fn shortlist_widens_for_near_tied_primary_view_candidates() {
    let mut budget = ChatAdaptiveSearchBudget {
        initial_candidate_count: 2,
        max_candidate_count: 3,
        shortlist_limit: 1,
        max_semantic_refinement_passes: 1,
        plateau_limit: 1,
        min_score_delta: 1,
        target_validation_score_for_early_stop: 356,
        expansion_score_margin: 12,
        signals: Vec::new(),
    };
    let candidate_summaries = vec![
        chat_test_candidate_summary(
            "candidate-1",
            chat_test_validation(ChatArtifactValidationStatus::Pass, true, 5, 5, 5, 5, 5, 5),
        ),
        chat_test_candidate_summary(
            "candidate-2",
            chat_test_validation(ChatArtifactValidationStatus::Pass, true, 5, 5, 5, 5, 5, 4),
        ),
        chat_test_candidate_summary(
            "candidate-3",
            chat_test_validation(
                ChatArtifactValidationStatus::Repairable,
                false,
                3,
                3,
                3,
                3,
                3,
                3,
            ),
        ),
    ];
    let ranked = super::generation::ranked_candidate_indices_by_score(&candidate_summaries);
    let shortlist = super::generation::shortlisted_candidate_indices_for_budget(
        &mut budget,
        &ranked,
        &candidate_summaries,
    );

    assert_eq!(shortlist, vec![0, 1]);
    assert_eq!(budget.shortlist_limit, 2);
    assert!(budget
        .signals
        .contains(&ChatAdaptiveSearchSignal::LowCandidateVariance));
}

#[test]
fn html_local_runtime_materialization_repair_budget_limits_to_single_pass() {
    assert_eq!(
        super::generation::materialization_repair_pass_limit(
            ChatRendererKind::HtmlIframe,
            ChatRuntimeProvenanceKind::RealLocalRuntime,
        ),
        1
    );
}

#[test]
fn html_remote_runtime_materialization_repair_budget_allows_three_passes() {
    assert_eq!(
        super::generation::materialization_repair_pass_limit(
            ChatRendererKind::HtmlIframe,
            ChatRuntimeProvenanceKind::RealRemoteModelRuntime,
        ),
        3
    );
}

#[test]
fn pdf_materialization_repair_budget_allows_three_passes() {
    assert_eq!(
        super::generation::materialization_repair_pass_limit(
            ChatRendererKind::PdfEmbed,
            ChatRuntimeProvenanceKind::RealLocalRuntime,
        ),
        3
    );
}

