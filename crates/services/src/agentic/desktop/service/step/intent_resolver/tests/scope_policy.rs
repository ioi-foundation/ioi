use super::*;
use crate::agentic::desktop::service::step::intent_resolver::required_capabilities_with_instruction_contract;
use ioi_types::app::agentic::{
    ArgumentOrigin, InstructionBindingKind, InstructionContract, InstructionSlotBinding,
    ProtectedSlotKind,
};

#[test]
fn conversation_scope_blocks_browser() {
    let state = ResolvedIntentState {
        intent_id: "conversation.reply".to_string(),
        scope: IntentScopeProfile::Conversation,
        band: IntentConfidenceBand::High,
        score: 0.95,
        top_k: vec![],
        required_capabilities: vec![CapabilityId::from("conversation.reply")],
        required_receipts: vec![],
        required_postconditions: vec![],
        risk_class: "low".to_string(),
        preferred_tier: "tool_first".to_string(),
        matrix_version: "v1".to_string(),
        embedding_model_id: "test".to_string(),
        embedding_model_version: "test".to_string(),
        similarity_function_id: "cosine".to_string(),
        intent_set_hash: [0u8; 32],
        tool_registry_hash: [0u8; 32],
        capability_ontology_hash: [0u8; 32],
        query_normalization_version: "v1".to_string(),
        matrix_source_hash: [1u8; 32],
        receipt_hash: [2u8; 32],
        provider_selection: None,
        instruction_contract: None,
        constrained: false,
    };
    assert!(!is_tool_allowed_for_resolution(
        Some(&state),
        "browser__navigate"
    ));
    assert!(!is_tool_allowed_for_resolution(Some(&state), "os__copy"));
    assert!(!is_tool_allowed_for_resolution(Some(&state), "os__paste"));
    assert!(is_tool_allowed_for_resolution(Some(&state), "chat__reply"));
    assert!(is_tool_allowed_for_resolution(
        Some(&state),
        "wallet_network__mail_reply"
    ));
    assert!(!is_tool_allowed_for_resolution(
        Some(&state),
        "connector__google__calendar_create_event"
    ));
    assert!(!is_tool_allowed_for_resolution(
        Some(&state),
        "wallet_network__mail_connector_upsert"
    ));
    assert!(!is_tool_allowed_for_resolution(None, "browser__navigate"));
}

#[test]
fn math_intent_allows_math_eval_and_chat_reply_only() {
    let state = ResolvedIntentState {
        intent_id: "math.eval".to_string(),
        scope: IntentScopeProfile::Conversation,
        band: IntentConfidenceBand::High,
        score: 0.97,
        top_k: vec![],
        required_capabilities: vec![CapabilityId::from("conversation.reply")],
        required_receipts: vec![],
        required_postconditions: vec![],
        risk_class: "low".to_string(),
        preferred_tier: "tool_first".to_string(),
        matrix_version: "v1".to_string(),
        embedding_model_id: "test".to_string(),
        embedding_model_version: "test".to_string(),
        similarity_function_id: "cosine".to_string(),
        intent_set_hash: [0u8; 32],
        tool_registry_hash: [0u8; 32],
        capability_ontology_hash: [0u8; 32],
        query_normalization_version: "v1".to_string(),
        matrix_source_hash: [1u8; 32],
        receipt_hash: [2u8; 32],
        provider_selection: None,
        instruction_contract: None,
        constrained: false,
    };
    assert!(is_tool_allowed_for_resolution(Some(&state), "math__eval"));
    assert!(is_tool_allowed_for_resolution(Some(&state), "chat__reply"));
    assert!(!is_tool_allowed_for_resolution(Some(&state), "sys__exec"));
}

#[test]
fn math_eval_tool_stays_on_primitive_capability_surface() {
    let caps = super::tool_capabilities("math__eval");
    assert_eq!(caps, vec![CapabilityId::from("conversation.reply")]);
    assert!(!caps.iter().any(|cap| cap.as_str() == "math.eval"));
}

#[test]
fn mail_connector_setup_tools_do_not_inherit_conversation_capability() {
    let caps = super::tool_capabilities("wallet_network__mail_connector_upsert");
    assert!(caps.is_empty());
}

#[test]
fn memory_access_scope_allows_native_model_memory_tools() {
    let state = ResolvedIntentState {
        intent_id: "memory.recall".to_string(),
        scope: IntentScopeProfile::Conversation,
        band: IntentConfidenceBand::High,
        score: 0.95,
        top_k: vec![],
        required_capabilities: vec![CapabilityId::from("memory.access")],
        required_receipts: vec![],
        required_postconditions: vec![],
        risk_class: "low".to_string(),
        preferred_tier: "tool_first".to_string(),
        matrix_version: "v1".to_string(),
        embedding_model_id: "test".to_string(),
        embedding_model_version: "test".to_string(),
        similarity_function_id: "cosine".to_string(),
        intent_set_hash: [0u8; 32],
        tool_registry_hash: [0u8; 32],
        capability_ontology_hash: [0u8; 32],
        query_normalization_version: "v1".to_string(),
        matrix_source_hash: [1u8; 32],
        receipt_hash: [2u8; 32],
        provider_selection: None,
        instruction_contract: None,
        constrained: false,
    };
    assert!(is_tool_allowed_for_resolution(
        Some(&state),
        "model__embeddings"
    ));
    assert!(is_tool_allowed_for_resolution(
        Some(&state),
        "model__rerank"
    ));
    assert!(is_tool_allowed_for_resolution(
        Some(&state),
        "memory__search"
    ));
    assert!(!is_tool_allowed_for_resolution(
        Some(&state),
        "model_registry__load"
    ));
}

#[test]
fn model_registry_scope_allows_native_control_tools_without_shell_exec() {
    let state = ResolvedIntentState {
        intent_id: "model.registry.load".to_string(),
        scope: IntentScopeProfile::CommandExecution,
        band: IntentConfidenceBand::High,
        score: 0.95,
        top_k: vec![],
        required_capabilities: vec![CapabilityId::from("model.registry.manage")],
        required_receipts: vec![],
        required_postconditions: vec![],
        risk_class: "medium".to_string(),
        preferred_tier: "tool_first".to_string(),
        matrix_version: "v1".to_string(),
        embedding_model_id: "test".to_string(),
        embedding_model_version: "test".to_string(),
        similarity_function_id: "cosine".to_string(),
        intent_set_hash: [0u8; 32],
        tool_registry_hash: [0u8; 32],
        capability_ontology_hash: [0u8; 32],
        query_normalization_version: "v1".to_string(),
        matrix_source_hash: [1u8; 32],
        receipt_hash: [2u8; 32],
        provider_selection: None,
        instruction_contract: None,
        constrained: false,
    };
    assert!(is_tool_allowed_for_resolution(
        Some(&state),
        "model_registry__load"
    ));
    assert!(is_tool_allowed_for_resolution(
        Some(&state),
        "model_registry__unload"
    ));
    assert!(is_tool_allowed_for_resolution(
        Some(&state),
        "model_registry__install"
    ));
    assert!(is_tool_allowed_for_resolution(
        Some(&state),
        "backend__install"
    ));
    assert!(is_tool_allowed_for_resolution(
        Some(&state),
        "gallery__sync"
    ));
    assert!(!is_tool_allowed_for_resolution(Some(&state), "sys__exec"));
    assert!(!is_tool_allowed_for_resolution(
        Some(&state),
        "model__responses"
    ));
}

#[test]
fn media_extract_tools_use_specific_action_targets() {
    let transcript_binding = super::tool_capability_bindings()
        .into_iter()
        .find(|binding| binding.tool_name == "media__extract_transcript")
        .expect("media__extract_transcript binding should exist");
    assert_eq!(
        transcript_binding.action_target,
        ioi_types::app::ActionTarget::MediaExtractTranscript
    );
    assert!(transcript_binding
        .capabilities
        .iter()
        .any(|capability| capability.as_str() == "media.extract"));

    let multimodal_binding = super::tool_capability_bindings()
        .into_iter()
        .find(|binding| binding.tool_name == "media__extract_multimodal_evidence")
        .expect("media__extract_multimodal_evidence binding should exist");
    assert_eq!(
        multimodal_binding.action_target,
        ioi_types::app::ActionTarget::MediaExtractMultimodalEvidence
    );
    assert!(multimodal_binding
        .capabilities
        .iter()
        .any(|capability| capability.as_str() == "media.extract"));
}

#[test]
fn media_generation_and_analysis_tools_bind_to_kernel_media_capabilities() {
    let bindings = super::tool_capability_bindings();
    for (tool_name, capability) in [
        ("media__transcribe_audio", "media.transcribe"),
        ("media__synthesize_speech", "media.synthesize"),
        ("media__vision_read", "media.vision"),
        ("media__generate_image", "media.generate.image"),
        ("media__edit_image", "media.generate.image"),
        ("media__generate_video", "media.generate.video"),
    ] {
        let binding = bindings
            .iter()
            .find(|binding| binding.tool_name == tool_name)
            .unwrap_or_else(|| panic!("{tool_name} binding should exist"));
        assert_eq!(
            binding.action_target,
            ioi_types::app::ActionTarget::Custom(tool_name.to_string())
        );
        assert!(binding
            .capabilities
            .iter()
            .any(|required| required.as_str() == capability));
    }
}

#[test]
fn google_gmail_send_tool_satisfies_mail_reply_intent() {
    let state = ResolvedIntentState {
        intent_id: "mail.reply".to_string(),
        scope: IntentScopeProfile::Conversation,
        band: IntentConfidenceBand::High,
        score: 0.95,
        top_k: vec![],
        required_capabilities: vec![CapabilityId::from("mail.reply")],
        required_receipts: vec![],
        required_postconditions: vec![],
        risk_class: "high".to_string(),
        preferred_tier: "tool_first".to_string(),
        matrix_version: "v1".to_string(),
        embedding_model_id: "test".to_string(),
        embedding_model_version: "test".to_string(),
        similarity_function_id: "cosine".to_string(),
        intent_set_hash: [0u8; 32],
        tool_registry_hash: [0u8; 32],
        capability_ontology_hash: [0u8; 32],
        query_normalization_version: "v1".to_string(),
        matrix_source_hash: [1u8; 32],
        receipt_hash: [2u8; 32],
        provider_selection: None,
        instruction_contract: None,
        constrained: false,
    };
    assert!(is_tool_allowed_for_resolution(
        Some(&state),
        "connector__google__gmail_send_email"
    ));
}

#[test]
fn unregistered_prefixed_tools_do_not_gain_capabilities_by_name_shape() {
    let state = ResolvedIntentState {
        intent_id: "command.exec".to_string(),
        scope: IntentScopeProfile::CommandExecution,
        band: IntentConfidenceBand::High,
        score: 0.95,
        top_k: vec![],
        required_capabilities: vec![CapabilityId::from("command.exec")],
        required_receipts: vec![],
        required_postconditions: vec![],
        risk_class: "low".to_string(),
        preferred_tier: "tool_first".to_string(),
        matrix_version: "v1".to_string(),
        embedding_model_id: "test".to_string(),
        embedding_model_version: "test".to_string(),
        similarity_function_id: "cosine".to_string(),
        intent_set_hash: [0u8; 32],
        tool_registry_hash: [0u8; 32],
        capability_ontology_hash: [0u8; 32],
        query_normalization_version: "v1".to_string(),
        matrix_source_hash: [1u8; 32],
        receipt_hash: [2u8; 32],
        provider_selection: None,
        instruction_contract: None,
        constrained: false,
    };
    assert!(!is_tool_allowed_for_resolution(
        Some(&state),
        "sys__nonexistent_custom_tool"
    ));
    assert!(!is_tool_allowed_for_resolution(
        Some(&state),
        "browser__unregistered_op"
    ));
}

#[test]
fn ui_interaction_scope_allows_clipboard() {
    let state = ResolvedIntentState {
        intent_id: "ui.interact".to_string(),
        scope: IntentScopeProfile::UiInteraction,
        band: IntentConfidenceBand::High,
        score: 0.95,
        top_k: vec![],
        required_capabilities: vec![
            CapabilityId::from("clipboard.read"),
            CapabilityId::from("clipboard.write"),
        ],
        required_receipts: vec![],
        required_postconditions: vec![],
        risk_class: "low".to_string(),
        preferred_tier: "visual_last".to_string(),
        matrix_version: "v1".to_string(),
        embedding_model_id: "test".to_string(),
        embedding_model_version: "test".to_string(),
        similarity_function_id: "cosine".to_string(),
        intent_set_hash: [0u8; 32],
        tool_registry_hash: [0u8; 32],
        capability_ontology_hash: [0u8; 32],
        query_normalization_version: "v1".to_string(),
        matrix_source_hash: [1u8; 32],
        receipt_hash: [2u8; 32],
        provider_selection: None,
        instruction_contract: None,
        constrained: false,
    };
    assert!(is_tool_allowed_for_resolution(Some(&state), "os__copy"));
    assert!(is_tool_allowed_for_resolution(Some(&state), "os__paste"));
}

#[test]
fn ui_interaction_scope_allows_browser_safe_followups() {
    let state = ResolvedIntentState {
        intent_id: "ui.interaction".to_string(),
        scope: IntentScopeProfile::UiInteraction,
        band: IntentConfidenceBand::High,
        score: 0.95,
        top_k: vec![],
        required_capabilities: vec![CapabilityId::from("ui.interact")],
        required_receipts: vec![],
        required_postconditions: vec![],
        risk_class: "low".to_string(),
        preferred_tier: "visual_last".to_string(),
        matrix_version: "v1".to_string(),
        embedding_model_id: "test".to_string(),
        embedding_model_version: "test".to_string(),
        similarity_function_id: "cosine".to_string(),
        intent_set_hash: [0u8; 32],
        tool_registry_hash: [0u8; 32],
        capability_ontology_hash: [0u8; 32],
        query_normalization_version: "v1".to_string(),
        matrix_source_hash: [1u8; 32],
        receipt_hash: [2u8; 32],
        provider_selection: None,
        instruction_contract: None,
        constrained: false,
    };

    assert!(is_tool_allowed_for_resolution(
        Some(&state),
        "browser__snapshot"
    ));
    assert!(is_tool_allowed_for_resolution(
        Some(&state),
        "browser__click_element"
    ));
    assert!(is_tool_allowed_for_resolution(
        Some(&state),
        "browser__type"
    ));
    assert!(is_tool_allowed_for_resolution(
        Some(&state),
        "agent__complete"
    ));
    assert!(is_tool_allowed_for_resolution(Some(&state), "agent__pause"));
    assert!(is_tool_allowed_for_resolution(
        Some(&state),
        "agent__await_result"
    ));
}

#[test]
fn command_execution_scope_allows_clipboard() {
    let state = ResolvedIntentState {
        intent_id: "command.exec".to_string(),
        scope: IntentScopeProfile::CommandExecution,
        band: IntentConfidenceBand::High,
        score: 0.95,
        top_k: vec![],
        required_capabilities: vec![
            CapabilityId::from("clipboard.read"),
            CapabilityId::from("clipboard.write"),
        ],
        required_receipts: vec![],
        required_postconditions: vec![],
        risk_class: "low".to_string(),
        preferred_tier: "tool_first".to_string(),
        matrix_version: "v1".to_string(),
        embedding_model_id: "test".to_string(),
        embedding_model_version: "test".to_string(),
        similarity_function_id: "cosine".to_string(),
        intent_set_hash: [0u8; 32],
        tool_registry_hash: [0u8; 32],
        capability_ontology_hash: [0u8; 32],
        query_normalization_version: "v1".to_string(),
        matrix_source_hash: [1u8; 32],
        receipt_hash: [2u8; 32],
        provider_selection: None,
        instruction_contract: None,
        constrained: false,
    };
    assert!(is_tool_allowed_for_resolution(Some(&state), "os__copy"));
    assert!(is_tool_allowed_for_resolution(Some(&state), "os__paste"));
}

#[test]
fn workspace_ops_scope_allows_clipboard() {
    let state = ResolvedIntentState {
        intent_id: "workspace.ops".to_string(),
        scope: IntentScopeProfile::WorkspaceOps,
        band: IntentConfidenceBand::High,
        score: 0.95,
        top_k: vec![],
        required_capabilities: vec![
            CapabilityId::from("clipboard.read"),
            CapabilityId::from("clipboard.write"),
        ],
        required_receipts: vec![],
        required_postconditions: vec![],
        risk_class: "low".to_string(),
        preferred_tier: "tool_first".to_string(),
        matrix_version: "v1".to_string(),
        embedding_model_id: "test".to_string(),
        embedding_model_version: "test".to_string(),
        similarity_function_id: "cosine".to_string(),
        intent_set_hash: [0u8; 32],
        tool_registry_hash: [0u8; 32],
        capability_ontology_hash: [0u8; 32],
        query_normalization_version: "v1".to_string(),
        matrix_source_hash: [1u8; 32],
        receipt_hash: [2u8; 32],
        provider_selection: None,
        instruction_contract: None,
        constrained: false,
    };
    assert!(is_tool_allowed_for_resolution(Some(&state), "os__copy"));
    assert!(is_tool_allowed_for_resolution(Some(&state), "os__paste"));
}

#[test]
fn workspace_parent_playbook_scope_allows_agent_delegate() {
    let instruction_contract = InstructionContract {
        slot_bindings: vec![InstructionSlotBinding {
            slot: "playbook_id".to_string(),
            binding_kind: InstructionBindingKind::UserLiteral,
            value: Some("evidence_audited_patch".to_string()),
            origin: ArgumentOrigin::ModelInferred,
            protected_slot_kind: ProtectedSlotKind::Unknown,
        }],
        ..InstructionContract::default()
    };
    let state = ResolvedIntentState {
        intent_id: "workspace.ops".to_string(),
        scope: IntentScopeProfile::WorkspaceOps,
        band: IntentConfidenceBand::High,
        score: 0.95,
        top_k: vec![],
        required_capabilities: required_capabilities_with_instruction_contract(
            &[
                CapabilityId::from("filesystem.read"),
                CapabilityId::from("filesystem.write"),
            ],
            Some(&instruction_contract),
        ),
        required_receipts: vec![],
        required_postconditions: vec![],
        risk_class: "low".to_string(),
        preferred_tier: "tool_first".to_string(),
        matrix_version: "v1".to_string(),
        embedding_model_id: "test".to_string(),
        embedding_model_version: "test".to_string(),
        similarity_function_id: "cosine".to_string(),
        intent_set_hash: [0u8; 32],
        tool_registry_hash: [0u8; 32],
        capability_ontology_hash: [0u8; 32],
        query_normalization_version: "v1".to_string(),
        matrix_source_hash: [1u8; 32],
        receipt_hash: [2u8; 32],
        provider_selection: None,
        instruction_contract: Some(instruction_contract),
        constrained: false,
    };

    assert!(is_tool_allowed_for_resolution(
        Some(&state),
        "agent__delegate"
    ));
}

#[test]
fn browser_interaction_scope_allows_pointer_followups() {
    let state = ResolvedIntentState {
        intent_id: "browser.interact".to_string(),
        scope: IntentScopeProfile::UiInteraction,
        band: IntentConfidenceBand::High,
        score: 0.95,
        top_k: vec![],
        required_capabilities: vec![CapabilityId::from("browser.interact")],
        required_receipts: vec![],
        required_postconditions: vec![],
        risk_class: "low".to_string(),
        preferred_tier: "tool_first".to_string(),
        matrix_version: "v1".to_string(),
        embedding_model_id: "test".to_string(),
        embedding_model_version: "test".to_string(),
        similarity_function_id: "cosine".to_string(),
        intent_set_hash: [0u8; 32],
        tool_registry_hash: [0u8; 32],
        capability_ontology_hash: [0u8; 32],
        query_normalization_version: "v1".to_string(),
        matrix_source_hash: [1u8; 32],
        receipt_hash: [2u8; 32],
        provider_selection: None,
        instruction_contract: None,
        constrained: false,
    };

    assert!(is_tool_allowed_for_resolution(
        Some(&state),
        "browser__hover"
    ));
    assert!(is_tool_allowed_for_resolution(
        Some(&state),
        "browser__move_mouse"
    ));
    assert!(is_tool_allowed_for_resolution(
        Some(&state),
        "browser__mouse_down"
    ));
    assert!(is_tool_allowed_for_resolution(
        Some(&state),
        "browser__mouse_up"
    ));
}

#[test]
fn browser_interaction_scope_allows_inspection_followups() {
    let state = ResolvedIntentState {
        intent_id: "browser.interact".to_string(),
        scope: IntentScopeProfile::UiInteraction,
        band: IntentConfidenceBand::High,
        score: 0.95,
        top_k: vec![],
        required_capabilities: vec![CapabilityId::from("browser.interact")],
        required_receipts: vec![],
        required_postconditions: vec![],
        risk_class: "low".to_string(),
        preferred_tier: "tool_first".to_string(),
        matrix_version: "v1".to_string(),
        embedding_model_id: "test".to_string(),
        embedding_model_version: "test".to_string(),
        similarity_function_id: "cosine".to_string(),
        intent_set_hash: [0u8; 32],
        tool_registry_hash: [0u8; 32],
        capability_ontology_hash: [0u8; 32],
        query_normalization_version: "v1".to_string(),
        matrix_source_hash: [1u8; 32],
        receipt_hash: [2u8; 32],
        provider_selection: None,
        instruction_contract: None,
        constrained: false,
    };

    assert!(is_tool_allowed_for_resolution(
        Some(&state),
        "browser__snapshot"
    ));
    assert!(is_tool_allowed_for_resolution(
        Some(&state),
        "browser__canvas_summary"
    ));
}

#[test]
fn confidence_thresholds_map_bands() {
    let mut policy = IntentRoutingPolicy::default();
    policy.confidence = IntentConfidenceBandPolicy {
        high_threshold_bps: 7_000,
        medium_threshold_bps: 4_500,
    };
    assert_eq!(resolve_band(0.91, &policy), IntentConfidenceBand::High);
    assert_eq!(resolve_band(0.52, &policy), IntentConfidenceBand::Medium);
    assert_eq!(resolve_band(0.2, &policy), IntentConfidenceBand::Low);
}

#[test]
fn pause_policy_applies_to_medium_confidence_band() {
    let mut policy = IntentRoutingPolicy::default();
    policy.ambiguity.low_confidence_action = IntentAmbiguityAction::Proceed;
    policy.ambiguity.medium_confidence_action = IntentAmbiguityAction::PauseForClarification;

    let resolved = ResolvedIntentState {
        intent_id: "command.exec".to_string(),
        scope: IntentScopeProfile::CommandExecution,
        band: IntentConfidenceBand::Medium,
        score: 0.61,
        top_k: vec![],
        required_capabilities: vec![CapabilityId::from("command.exec")],
        required_receipts: vec![],
        required_postconditions: vec![],
        risk_class: "low".to_string(),
        preferred_tier: "tool_first".to_string(),
        matrix_version: "v1".to_string(),
        embedding_model_id: "test".to_string(),
        embedding_model_version: "test".to_string(),
        similarity_function_id: "cosine".to_string(),
        intent_set_hash: [0u8; 32],
        tool_registry_hash: [0u8; 32],
        capability_ontology_hash: [0u8; 32],
        query_normalization_version: "v1".to_string(),
        matrix_source_hash: [0u8; 32],
        receipt_hash: [0u8; 32],
        provider_selection: None,
        instruction_contract: None,
        constrained: false,
    };

    assert!(should_pause_for_clarification(&resolved, &policy));
}

#[test]
fn ambiguity_abstain_exemption_is_policy_driven() {
    let mut policy = IntentRoutingPolicy::default();
    policy.ambiguity_abstain_exempt_intents = vec![
        "app.launch".to_string(),
        "command.exec".to_string(),
        "system.clock.read".to_string(),
    ];
    assert!(is_ambiguity_abstain_exempt(&policy, "app.launch"));
    assert!(is_ambiguity_abstain_exempt(&policy, "command.exec"));
    assert!(is_ambiguity_abstain_exempt(&policy, "system.clock.read"));
    assert!(!is_ambiguity_abstain_exempt(&policy, "ui.interaction"));
}

#[test]
fn default_policy_exempts_command_exec_from_ambiguity_abstain() {
    let policy = IntentRoutingPolicy::default();
    assert!(is_ambiguity_abstain_exempt(&policy, "command.exec"));
}

#[test]
fn policy_exemption_overrides_ambiguity_abstain_gate() {
    let mut policy = IntentRoutingPolicy::default();
    policy.ambiguity_margin_bps = 50;
    policy.ambiguity_abstain_exempt_intents = vec!["app.launch".to_string()];
    let ranked = vec![
        IntentCandidateScore {
            intent_id: "app.launch".to_string(),
            score: 0.646,
        },
        IntentCandidateScore {
            intent_id: "ui.interaction".to_string(),
            score: 0.642,
        },
    ];
    let winner = ranked[0].clone();
    assert!(should_abstain_for_ambiguity(&ranked, &winner, &policy));
    let abstain = should_abstain_for_ambiguity(&ranked, &winner, &policy)
        && !is_ambiguity_abstain_exempt(&policy, &winner.intent_id);
    assert!(!abstain);
}
