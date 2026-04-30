#[test]
fn local_generation_remote_acceptance_policy_falls_back_truthfully_when_acceptance_is_unavailable()
{
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let production_runtime: Arc<dyn InferenceRuntime> = Arc::new(ChatTestRuntime::new(
        ChatRuntimeProvenanceKind::RealLocalRuntime,
        "local producer",
        "qwen2.5:7b",
        "http://127.0.0.1:11434/v1/chat/completions",
        "production",
        calls.clone(),
    ));
    let unavailable_acceptance: Arc<dyn InferenceRuntime> = Arc::new(ChatTestRuntime::new(
        ChatRuntimeProvenanceKind::InferenceUnavailable,
        "acceptance unavailable",
        "unavailable",
        "unavailable://acceptance",
        "acceptance",
        calls,
    ));

    let runtime_plan = resolve_chat_artifact_runtime_plan(
        &request_for(
            ChatArtifactClass::InteractiveSingleFile,
            ChatRendererKind::HtmlIframe,
        ),
        production_runtime,
        Some(unavailable_acceptance),
        ChatArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance,
    );

    assert_eq!(
        runtime_plan.policy.profile,
        ChatArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance
    );
    let acceptance_binding = runtime_plan
        .policy
        .bindings
        .iter()
        .find(|binding| binding.step == ChatArtifactRuntimeStep::ArtifactValidation)
        .expect("acceptance binding");
    assert!(acceptance_binding.fallback_applied);
    assert_eq!(
        acceptance_binding.degradation_reason.as_deref(),
        Some("acceptance_runtime_unavailable")
    );
    assert_eq!(acceptance_binding.provenance.label, "local producer");
    let planning_binding = runtime_plan
        .policy
        .bindings
        .iter()
        .find(|binding| binding.step == ChatArtifactRuntimeStep::BlueprintPlanning)
        .expect("planning binding");
    assert!(!planning_binding.fallback_applied);
    assert_eq!(planning_binding.provenance.label, "local producer");
}

#[test]
fn local_generation_remote_acceptance_prefers_local_specialist_for_markdown_generation_and_acceptance(
) {
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let production_runtime: Arc<dyn InferenceRuntime> = Arc::new(ChatTestRuntime::new(
        ChatRuntimeProvenanceKind::RealLocalRuntime,
        "local producer",
        "qwen2.5:14b",
        "http://127.0.0.1:11434/v1/chat/completions",
        "production",
        calls.clone(),
    ));
    let acceptance_runtime: Arc<dyn InferenceRuntime> = Arc::new(ChatTestRuntime::new(
        ChatRuntimeProvenanceKind::RealLocalRuntime,
        "local specialist",
        "qwen2.5:7b",
        "http://127.0.0.1:11434/v1/chat/completions",
        "acceptance",
        calls,
    ));

    let runtime_plan = resolve_chat_artifact_runtime_plan(
        &request_for(ChatArtifactClass::Document, ChatRendererKind::Markdown),
        production_runtime,
        Some(acceptance_runtime),
        ChatArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance,
    );

    let planning_binding = runtime_plan
        .policy
        .bindings
        .iter()
        .find(|binding| binding.step == ChatArtifactRuntimeStep::BlueprintPlanning)
        .expect("planning binding");
    assert_eq!(planning_binding.provenance.label, "local specialist");
    assert!(!planning_binding.fallback_applied);

    let generation_binding = runtime_plan
        .policy
        .bindings
        .iter()
        .find(|binding| binding.step == ChatArtifactRuntimeStep::CandidateGeneration)
        .expect("generation binding");
    assert_eq!(generation_binding.provenance.label, "local specialist");
    assert!(!generation_binding.fallback_applied);

    let acceptance_binding = runtime_plan
        .policy
        .bindings
        .iter()
        .find(|binding| binding.step == ChatArtifactRuntimeStep::ArtifactValidation)
        .expect("acceptance binding");
    assert_eq!(acceptance_binding.provenance.label, "local specialist");
    assert!(acceptance_binding.fallback_applied);
    assert_eq!(
        acceptance_binding.degradation_reason.as_deref(),
        Some("compact_local_specialist_acceptance")
    );
}

#[test]
fn local_generation_remote_acceptance_prefers_local_specialist_for_download_bundle_acceptance() {
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let production_runtime: Arc<dyn InferenceRuntime> = Arc::new(ChatTestRuntime::new(
        ChatRuntimeProvenanceKind::RealLocalRuntime,
        "local producer",
        "qwen2.5:14b",
        "http://127.0.0.1:11434/v1/chat/completions",
        "production",
        calls.clone(),
    ));
    let acceptance_runtime: Arc<dyn InferenceRuntime> = Arc::new(ChatTestRuntime::new(
        ChatRuntimeProvenanceKind::RealLocalRuntime,
        "local specialist",
        "qwen2.5:7b",
        "http://127.0.0.1:11434/v1/chat/completions",
        "acceptance",
        calls,
    ));

    let runtime_plan = resolve_chat_artifact_runtime_plan(
        &request_for(
            ChatArtifactClass::DownloadableFile,
            ChatRendererKind::DownloadCard,
        ),
        production_runtime,
        Some(acceptance_runtime),
        ChatArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance,
    );

    let acceptance_binding = runtime_plan
        .policy
        .bindings
        .iter()
        .find(|binding| binding.step == ChatArtifactRuntimeStep::ArtifactValidation)
        .expect("acceptance binding");
    assert_eq!(acceptance_binding.provenance.label, "local specialist");
    assert!(acceptance_binding.fallback_applied);
    assert_eq!(
        acceptance_binding.degradation_reason.as_deref(),
        Some("compact_local_specialist_acceptance")
    );
}

#[test]
fn local_generation_remote_acceptance_keeps_html_generation_on_primary_runtime() {
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let production_runtime: Arc<dyn InferenceRuntime> = Arc::new(ChatTestRuntime::new(
        ChatRuntimeProvenanceKind::RealLocalRuntime,
        "local producer",
        "qwen2.5:14b",
        "http://127.0.0.1:11434/v1/chat/completions",
        "production",
        calls.clone(),
    ));
    let acceptance_runtime: Arc<dyn InferenceRuntime> = Arc::new(ChatTestRuntime::new(
        ChatRuntimeProvenanceKind::RealLocalRuntime,
        "local specialist",
        "qwen2.5:7b",
        "http://127.0.0.1:11434/v1/chat/completions",
        "acceptance",
        calls,
    ));

    let runtime_plan = resolve_chat_artifact_runtime_plan(
        &request_for(
            ChatArtifactClass::InteractiveSingleFile,
            ChatRendererKind::HtmlIframe,
        ),
        production_runtime,
        Some(acceptance_runtime),
        ChatArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance,
    );

    let generation_binding = runtime_plan
        .policy
        .bindings
        .iter()
        .find(|binding| binding.step == ChatArtifactRuntimeStep::CandidateGeneration)
        .expect("generation binding");
    assert_eq!(generation_binding.provenance.label, "local producer");
    assert!(!generation_binding.fallback_applied);

    let planning_binding = runtime_plan
        .policy
        .bindings
        .iter()
        .find(|binding| binding.step == ChatArtifactRuntimeStep::BlueprintPlanning)
        .expect("planning binding");
    assert_eq!(planning_binding.provenance.label, "local producer");
    assert!(!planning_binding.fallback_applied);

    let acceptance_binding = runtime_plan
        .policy
        .bindings
        .iter()
        .find(|binding| binding.step == ChatArtifactRuntimeStep::ArtifactValidation)
        .expect("acceptance binding");
    assert_eq!(acceptance_binding.provenance.label, "local specialist");
    assert!(!acceptance_binding.fallback_applied);

    let repair_binding = runtime_plan
        .policy
        .bindings
        .iter()
        .find(|binding| binding.step == ChatArtifactRuntimeStep::RepairPlanning)
        .expect("repair binding");
    assert_eq!(repair_binding.provenance.label, "local specialist");
    assert!(!repair_binding.fallback_applied);
}

#[test]
fn modal_first_local_generation_remote_acceptance_keeps_html_generation_on_primary_runtime() {
    with_modal_first_html_env(|| {
        let calls = Arc::new(Mutex::new(Vec::<String>::new()));
        let production_runtime: Arc<dyn InferenceRuntime> = Arc::new(ChatTestRuntime::new(
            ChatRuntimeProvenanceKind::RealLocalRuntime,
            "local producer",
            "qwen2.5:14b",
            "http://127.0.0.1:11434/v1/chat/completions",
            "production",
            calls.clone(),
        ));
        let acceptance_runtime: Arc<dyn InferenceRuntime> = Arc::new(ChatTestRuntime::new(
            ChatRuntimeProvenanceKind::RealLocalRuntime,
            "local specialist",
            "qwen3.5:9b",
            "http://127.0.0.1:11434/v1/chat/completions",
            "acceptance",
            calls,
        ));

        let runtime_plan = resolve_chat_artifact_runtime_plan(
            &request_for(
                ChatArtifactClass::InteractiveSingleFile,
                ChatRendererKind::HtmlIframe,
            ),
            production_runtime,
            Some(acceptance_runtime),
            ChatArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance,
        );

        let planning_binding = runtime_plan
            .policy
            .bindings
            .iter()
            .find(|binding| binding.step == ChatArtifactRuntimeStep::BlueprintPlanning)
            .expect("planning binding");
        assert_eq!(planning_binding.provenance.label, "local producer");
        assert!(!planning_binding.fallback_applied);

        let generation_binding = runtime_plan
            .policy
            .bindings
            .iter()
            .find(|binding| binding.step == ChatArtifactRuntimeStep::CandidateGeneration)
            .expect("generation binding");
        assert_eq!(generation_binding.provenance.label, "local producer");
        assert!(!generation_binding.fallback_applied);

        let acceptance_binding = runtime_plan
            .policy
            .bindings
            .iter()
            .find(|binding| binding.step == ChatArtifactRuntimeStep::ArtifactValidation)
            .expect("acceptance binding");
        assert_eq!(acceptance_binding.provenance.label, "local specialist");
        assert!(!acceptance_binding.fallback_applied);

        let repair_binding = runtime_plan
            .policy
            .bindings
            .iter()
            .find(|binding| binding.step == ChatArtifactRuntimeStep::RepairPlanning)
            .expect("repair binding");
        assert_eq!(repair_binding.provenance.label, "local specialist");
        assert!(!repair_binding.fallback_applied);
    });
}

#[test]
fn local_html_materialization_repair_prefers_local_specialist_runtime() {
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let production_runtime: Arc<dyn InferenceRuntime> = Arc::new(ChatTestRuntime::new(
        ChatRuntimeProvenanceKind::RealLocalRuntime,
        "local producer",
        "qwen2.5:14b",
        "http://127.0.0.1:11434/v1/chat/completions",
        "production",
        calls.clone(),
    ));
    let repair_runtime: Arc<dyn InferenceRuntime> = Arc::new(ChatTestRuntime::new(
        ChatRuntimeProvenanceKind::RealLocalRuntime,
        "local specialist",
        "qwen2.5:7b",
        "http://127.0.0.1:11434/v1/chat/completions",
        "repair",
        calls,
    ));

    let selected_runtime = super::generation::materialization_repair_runtime_for_request(
        &request_for(
            ChatArtifactClass::InteractiveSingleFile,
            ChatRendererKind::HtmlIframe,
        ),
        &production_runtime,
        Some(&repair_runtime),
    );

    assert_eq!(
        selected_runtime.chat_runtime_provenance().label,
        "local specialist"
    );
}

