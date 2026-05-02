use super::*;

#[test]
fn conversation_reply_does_not_inherit_mail_grounding_contract() {
    let entry = default_intent_catalog()
        .into_iter()
        .find(|entry| entry.intent_id == "conversation.reply")
        .expect("conversation.reply entry should exist");

    assert!(
        !entry
            .required_evidence
            .iter()
            .any(|receipt| receipt == "grounding"),
        "conversation.reply should not require connector grounding receipts"
    );
    assert!(
        !entry
            .success_conditions
            .iter()
            .any(|postcondition| postcondition == "mail.reply.completed"),
        "conversation.reply should not require mail completion postconditions"
    );
}

#[test]
fn generic_mail_reply_defaults_to_dynamic_provider_selection() {
    let entry = default_intent_catalog()
        .into_iter()
        .find(|entry| entry.intent_id == "mail.reply")
        .expect("mail.reply entry should exist");

    assert_eq!(
        entry.provider_selection_mode,
        Some(ProviderSelectionMode::DynamicSynthesis)
    );
    assert!(
        entry
            .required_evidence
            .iter()
            .any(|receipt| receipt == "provider_selection"),
        "mail.reply should require provider selection receipts"
    );
    assert!(
        entry
            .required_evidence
            .iter()
            .any(|receipt| receipt == "provider_selection_commit"),
        "mail.reply should require provider selection commit receipts"
    );
    assert!(
        entry
            .required_evidence
            .iter()
            .any(|receipt| receipt == "grounding"),
        "mail.reply should require grounding receipts"
    );
    assert!(
        entry
            .success_conditions
            .iter()
            .any(|postcondition| postcondition == "mail.reply.completed"),
        "mail.reply should require verified completion postconditions"
    );
}

#[test]
fn memory_recall_defaults_to_local_memory_capability_surface() {
    let entry = default_intent_catalog()
        .into_iter()
        .find(|entry| entry.intent_id == "memory.recall")
        .expect("memory.recall entry should exist");

    assert_eq!(entry.scope, IntentScopeProfile::Conversation);
    assert!(
        entry
            .required_capabilities
            .iter()
            .any(|capability| capability.as_str() == "memory.access"),
        "memory.recall should require memory.access"
    );
    assert!(
        entry
            .required_capabilities
            .iter()
            .any(|capability| capability.as_str() == "conversation.reply"),
        "memory.recall should preserve chat completion capability"
    );
    assert_eq!(
        entry.verification_mode,
        Some(VerificationMode::DeterministicCheck)
    );
}

#[test]
fn model_registry_control_intents_use_kernel_managed_capability_surface() {
    let entries = default_intent_catalog();
    for intent_id in [
        "model.registry.load",
        "model.registry.unload",
        "model.registry.install",
        "backend.registry.manage",
        "gallery.sync",
    ] {
        let entry = entries
            .iter()
            .find(|entry| entry.intent_id == intent_id)
            .unwrap_or_else(|| panic!("{intent_id} entry should exist"));

        assert_eq!(entry.scope, IntentScopeProfile::CommandExecution);
        assert_eq!(
            entry.query_binding,
            IntentQueryBindingClass::ModelRegistryControl
        );
        assert!(
            entry
                .required_capabilities
                .iter()
                .any(|capability| capability.as_str() == "model.registry.manage"),
            "{intent_id} should require model.registry.manage"
        );
        assert!(
            entry
                .required_capabilities
                .iter()
                .any(|capability| capability.as_str() == "conversation.reply"),
            "{intent_id} should preserve chat completion capability"
        );
        assert_eq!(
            entry.provider_selection_mode,
            Some(ProviderSelectionMode::CapabilityOnly)
        );
    }
}

#[test]
fn media_generation_and_analysis_intents_use_kernel_media_capabilities() {
    let entries = default_intent_catalog();
    for (intent_id, capability) in [
        ("media.transcribe", "media.transcribe"),
        ("media.synthesize", "media.synthesize"),
        ("media.vision", "media.vision"),
        ("media.generate.image", "media.generate.image"),
        ("media.generate.video", "media.generate.video"),
    ] {
        let entry = entries
            .iter()
            .find(|entry| entry.intent_id == intent_id)
            .unwrap_or_else(|| panic!("{intent_id} entry should exist"));

        assert_eq!(entry.scope, IntentScopeProfile::CommandExecution);
        assert!(
            entry
                .required_capabilities
                .iter()
                .any(|required| required.as_str() == capability),
            "{intent_id} should require {capability}"
        );
        assert!(
            entry
                .required_capabilities
                .iter()
                .any(|required| required.as_str() == "conversation.reply"),
            "{intent_id} should preserve chat completion capability"
        );
        assert_eq!(
            entry.provider_selection_mode,
            Some(ProviderSelectionMode::CapabilityOnly)
        );
    }
}

#[test]
fn desktop_app_install_intent_requires_host_discovery_and_verification() {
    let entry = default_intent_catalog()
        .into_iter()
        .find(|entry| entry.intent_id == "software.install.desktop_app")
        .expect("software.install.desktop_app entry should exist");

    assert_eq!(entry.scope, IntentScopeProfile::CommandExecution);
    assert_eq!(entry.requires_host_discovery, Some(true));
    assert!(entry
        .required_capabilities
        .iter()
        .any(|capability| capability.as_str() == "software.install.execute"));
    assert!(entry
        .required_evidence
        .iter()
        .any(|receipt| receipt == "software_install_resolution"));
    assert!(entry
        .required_evidence
        .iter()
        .any(|receipt| receipt == "approval"));
    assert!(entry
        .success_conditions
        .iter()
        .any(|condition| condition == "verified_local_app_available"));
}
