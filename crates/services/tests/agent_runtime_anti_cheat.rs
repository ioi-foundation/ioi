#[test]
fn web_synthesis_has_no_deterministic_product_draft_entrypoints() {
    let synthesis_mod =
        include_str!("../src/agentic/runtime/service/queue/support/synthesis/mod.rs");
    let grounded_answer_source =
        include_str!("../src/agentic/runtime/service/queue/support/synthesis/grounded_answer.rs");

    for forbidden in [
        "build_deterministic_story_draft",
        "render_synthesis_draft",
        "render_user_synthesis_draft",
        "render_multi_story_layout",
        "render_document_report_layout",
        "synthesize_web_pipeline_reply(",
    ] {
        assert!(
            !synthesis_mod.contains(forbidden) && !grounded_answer_source.contains(forbidden),
            "web synthesis must not expose deprecated deterministic product draft entrypoint `{forbidden}`"
        );
    }
}

#[test]
fn model_finalization_contract_keeps_determinism_at_validation_boundary() {
    let grounded_answer_source =
        include_str!("../src/agentic/runtime/service/queue/support/synthesis/grounded_answer.rs");

    assert!(grounded_answer_source.contains("Use the retrieved source notes"));
    assert!(grounded_answer_source.contains("Return only the final user-facing Markdown answer"));
    assert!(grounded_answer_source.contains("Do not expose tool payloads"));
    assert!(grounded_answer_source.contains("Do not print run dates"));
    assert!(grounded_answer_source.contains("visible_direct_answer_from_raw"));
    assert!(grounded_answer_source.contains("final_web_completion_contract_ready"));
}

#[test]
fn pre_read_recovery_uses_candidate_recovery_vocabulary() {
    let planning_source = include_str!(
        "../src/agentic/runtime/service/queue/processing/web_pipeline/search/planning.rs"
    );
    let support_source = include_str!(
        "../src/agentic/runtime/service/queue/processing/web_pipeline/search/planning/support.rs"
    );
    let pre_read_source = include_str!(
        "../src/agentic/runtime/service/queue/processing/web_pipeline/pre_read_selection.rs"
    );

    assert!(planning_source.contains("candidate_recovery_plan"));
    assert!(support_source.contains("merge_candidate_recovery_plan_with_pending_inventory"));
    assert!(pre_read_source.contains("candidate_recovery_pre_read_selection"));

    for forbidden in [
        "deterministic_plan",
        "merge_deterministic_plan_with_pending_inventory",
        "deterministic_pre_read_selection",
        "deterministic selection",
    ] {
        assert!(
            !planning_source.contains(forbidden)
                && !support_source.contains(forbidden)
                && !pre_read_source.contains(forbidden),
            "web pre-read recovery should not preserve obsolete deterministic vocabulary `{forbidden}`"
        );
    }
}

#[test]
fn product_chat_guards_keep_trace_and_fixture_scaffolding_out_of_transcript() {
    let extension_source = include_str!("../../../workbench-adapters/ioi-workbench/extension.js");
    let panel_source =
        include_str!("../../../workbench-adapters/ioi-workbench/studio/studio-panel-html.js");

    assert!(extension_source.contains("studioAgentTurnResultText"));
    assert!(extension_source.contains("studioResultTextLooksRetrievalGrounded"));
    assert!(panel_source.contains("humanizeProjectedTurnText"));
    assert!(panel_source.contains("renderMarkdownInto"));
    for forbidden in [
        "Story 1:",
        "Briefing for '",
        "Run date (UTC):",
        "Run timestamp (UTC):",
        "Overall confidence:",
    ] {
        assert!(
            !extension_source.contains(forbidden) && !panel_source.contains(forbidden),
            "product chat code should not hard-code deprecated transcript scaffold `{forbidden}`"
        );
    }
}
