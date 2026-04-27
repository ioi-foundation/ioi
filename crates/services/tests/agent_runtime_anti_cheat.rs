#[test]
fn circ_resolver_has_no_lexical_forced_winner_shortcuts() {
    let source = include_str!("../src/agentic/runtime/service/step/intent_resolver/resolve.rs");
    for forbidden in [
        "obvious_casual_conversation_query",
        "obvious_expository_reply_query",
        "forced_intent_id",
        "action_verbs",
        "temporal_terms",
    ] {
        assert!(
            !source.contains(forbidden),
            "resolver must not contain lexical shortcut '{}'",
            forbidden
        );
    }
}

#[test]
fn circ_policy_has_no_query_facet_backstop() {
    let source = include_str!("../src/agentic/runtime/service/step/intent_resolver/policy.rs");
    for forbidden in [
        "analyze_query_facets",
        "backstop",
        "apply_query_facet_overrides",
    ] {
        assert!(
            !source.contains(forbidden),
            "resolver policy must not contain query facet fallback '{}'",
            forbidden
        );
    }
}

#[test]
fn circ_instruction_contract_has_no_seeded_fallback_contract() {
    let source =
        include_str!("../src/agentic/runtime/service/step/intent_resolver/instruction_contract.rs");
    assert!(!source.contains("fallback_instruction_contract"));
}

#[test]
fn circ_ranker_descriptor_function_excludes_metadata_fields() {
    let source = include_str!("../src/agentic/runtime/service/step/intent_resolver/ranking.rs");
    let descriptor_fn = source
        .split("pub(super) fn canonical_descriptor_for_entry")
        .nth(1)
        .and_then(|rest| rest.split("async fn build_intent_prototypes").next())
        .expect("canonical descriptor function should be present");

    for forbidden in [
        "aliases",
        "exemplars",
        "risk_class",
        "preferred_tier",
        "required_capabilities",
        "scope",
        "provider_selection",
        "tool_name",
        "domain",
    ] {
        assert!(
            !descriptor_fn.contains(forbidden),
            "ranking descriptor must not depend on '{}'",
            forbidden
        );
    }
}

#[test]
fn circ_model_rank_payload_excludes_routing_metadata() {
    let source = include_str!("../src/agentic/runtime/service/step/intent_resolver/ranking.rs");
    let model_rank_fn = source
        .split("async fn rank_with_inference_model")
        .nth(1)
        .and_then(|rest| rest.split("fn parse_model_rank_scores").next())
        .expect("model rank function should be present");
    let intent_rows_block = model_rank_fn
        .split("let intent_rows = intent_catalog")
        .nth(1)
        .and_then(|rest| rest.split("let payload = json!").next())
        .expect("intent row projection should be present");

    assert!(intent_rows_block.contains("\"intent_id\""));
    assert!(intent_rows_block.contains("\"semantic_descriptor\""));
    for forbidden in [
        "aliases",
        "exemplars",
        "required_capabilities",
        "risk_class",
        "preferred_tier",
        "scope",
        "provider_selection",
        "requires_host_discovery",
        "tool_name",
    ] {
        assert!(
            !intent_rows_block.contains(forbidden),
            "model rank payload must not expose routing metadata '{}'",
            forbidden
        );
    }
}

#[test]
fn parity_generic_web_source_selection_is_centralized_and_typed() {
    let routing_source = include_str!("../../api/src/chat/planning/routing.rs");
    let topology_source = include_str!("../../api/src/chat/domain_topology/mod.rs");
    let source_selection_fn = topology_source
        .split("fn derive_source_decision(")
        .nth(1)
        .and_then(|rest| rest.split("fn derive_lane_transitions(").next())
        .expect("typed source selection function should be present");

    assert!(
        !routing_source.contains("ChatSourceFamily::WebSearch"),
        "routing must not contain hidden generic web fallback selection"
    );
    assert!(source_selection_fn.contains("ChatSourceDecision"));
    assert!(source_selection_fn.contains("selected_source"));
    assert!(source_selection_fn.contains("degradation_reason"));
    assert!(source_selection_fn.contains("ChatSourceFamily::SpecializedTool"));
    assert!(source_selection_fn.contains("ChatSourceFamily::WebSearch"));
}

#[test]
fn runtime_authority_paths_use_behavior_first_vocabulary() {
    let checked_sources = [
        include_str!("../src/agentic/runtime/types.rs"),
        include_str!("../src/agentic/runtime/service/step/action/command_contract.rs"),
        include_str!(
            "../src/agentic/runtime/service/step/action/command_contract/contract_resolution.rs"
        ),
        include_str!("../src/agentic/runtime/service/step/intent_resolver/resolve.rs"),
        include_str!("../src/agentic/runtime/service/step/intent_resolver/ranking.rs"),
        include_str!("../../api/src/chat/domain_topology/mod.rs"),
        include_str!("../../api/src/chat/planning/routing.rs"),
        include_str!("../../types/src/app/chat.rs"),
        include_str!(
            "../../../apps/autopilot/src-tauri/src/kernel/chat/content_session/decision_record.rs"
        ),
    ];
    let forbidden = [
        "CecExecution",
        "CecAttempt",
        "receipt_marker",
        "postcondition_marker",
        "IntentMatrix",
        "routing_hints",
        "request_frame",
        "lane_frame",
        "source_selection",
        "ChatSourceSelection",
        "fallback_reason",
    ];

    for source in checked_sources {
        for token in forbidden {
            assert!(
                !source.contains(token),
                "runtime authority source must not keep obsolete vocabulary '{}'",
                token
            );
        }
    }
}

#[test]
fn inline_answer_surface_does_not_render_trace_vocabulary() {
    let source = include_str!(
        "../../../apps/autopilot/src-tauri/src/kernel/chat/content_session/inline_answer_surface.rs"
    );
    for forbidden in [
        "Source ranking",
        "Route:",
        "Route contract",
        "receipt",
        "postcondition",
        "CIRC",
        "CEC",
        "ledger",
        "completion gate",
        "Retained widget state",
    ] {
        assert!(
            !source.contains(forbidden),
            "inline answer surface must not expose trace vocabulary '{}'",
            forbidden
        );
    }
}

#[test]
fn artifact_source_retrieval_has_no_prompt_keyword_or_fallback_plan_authority() {
    let source_pack = include_str!(
        "../../../apps/autopilot/src-tauri/src/kernel/chat/operator_run/source_pack.rs"
    );
    let source_research =
        include_str!("../../../apps/autopilot/src-tauri/src/kernel/chat/source_research.rs");

    assert!(
        !source_pack.contains("prompt.contains"),
        "artifact source pack visibility must not be driven by prompt keyword checks"
    );
    for forbidden in [
        "\"explainer\"",
        "\"latest\"",
        "\"source-backed\"",
        "\"sources\"",
    ] {
        assert!(
            !source_pack.contains(forbidden),
            "artifact source pack must not preserve keyword trigger '{}'",
            forbidden
        );
    }

    assert!(
        !source_research.contains("fallback_retrieval_plan"),
        "artifact retrieval must not keep a generic fallback retrieval plan"
    );
    assert!(
        !source_research.contains("Fallback retrieval"),
        "artifact retrieval must not describe fallback source authority"
    );
    assert!(source_research.contains("brief_allows_external_retrieval"));
}

#[test]
fn cec_contract_error_uses_single_primary_error_class() {
    let source = include_str!(
        "../src/agentic/runtime/service/step/action/command_contract/contract_resolution.rs"
    );
    let error_fn = source
        .split("pub fn execution_contract_violation_error")
        .nth(1)
        .and_then(|rest| {
            rest.split("pub fn requires_timer_notification_contract")
                .next()
        })
        .expect("execution contract error function should be present");

    assert!(error_fn.contains("ERROR_CLASS=ExecutionContractViolation"));
    assert!(!error_fn.contains("base_error_class=ExecutionContractViolation"));
    assert!(!error_fn.contains("ERROR_CLASS={}"));
}

#[test]
fn cec_terminal_paths_use_shared_completion_gate() {
    let source = include_str!("../src/agentic/runtime/service/step/queue/processing/completion.rs");
    assert!(source.contains("fn completion_gate_blocks"));
    assert!(
        source.matches("completion_gate_blocks(").count() >= 7,
        "queue terminal paths should call the shared typed CEC gate"
    );
    assert!(!source.contains("missing_execution_contract_markers"));
    assert!(source.contains("evaluate_completion_requirements"));
}

#[test]
fn cec_marker_only_completion_authority_is_deleted() {
    let contract_source = include_str!(
        "../src/agentic/runtime/service/step/action/command_contract/contract_resolution.rs"
    );
    let terminal_sources = [
        include_str!("../src/agentic/runtime/service/step/queue/processing/completion.rs"),
        include_str!(
            "../src/agentic/runtime/service/step/action/processing/phases/execute_tool_phase/tool_outcome.rs"
        ),
        include_str!(
            "../src/agentic/runtime/service/step/action/processing/phases/execute_tool_phase/duplicate.rs"
        ),
        include_str!(
            "../src/agentic/runtime/service/actions/resume/phases/lifecycle_status.rs"
        ),
    ];

    assert!(!contract_source.contains("missing_execution_contract_markers"));
    assert!(!contract_source.contains("capability_contract_fallback_from_matrix"));
    assert!(contract_source.contains("missing_completion_evidence_with_rules"));
    assert!(contract_source.contains("execution_evidence_key(\"verification_evidence\")"));
    for source in terminal_sources {
        assert!(!source.contains("missing_execution_contract_markers"));
        assert!(source.contains("evaluate_completion_requirements"));
    }
}
