use super::*;
use ioi_api::state::StateAccess;
use ioi_state::primitives::hash::HashCommitmentScheme;
use ioi_state::tree::iavl::IAVLTree;
use ioi_types::app::agentic::InstructionBindingKind;
use ioi_types::app::wallet_network::{
    MailConnectorAuthMode, MailConnectorConfig, MailConnectorEndpoint, MailConnectorProvider,
    MailConnectorRecord, MailConnectorSecretAliases, MailConnectorTlsMode,
};
use ioi_types::codec;
use std::collections::BTreeMap;

#[tokio::test(flavor = "current_thread")]
async fn resolver_never_emits_constrained_true() {
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());
    let inference: Arc<dyn InferenceRuntime> = Arc::new(MockInferenceRuntime);
    let service = DesktopAgentService::new(gui, terminal, browser, inference);

    let agent_state = test_agent_state();

    let mut rules = ActionRules::default();
    rules
        .ontology_policy
        .intent_routing
        .ambiguity
        .medium_confidence_action = IntentAmbiguityAction::ConstrainedProceed;
    rules
        .ontology_policy
        .intent_routing
        .ambiguity
        .low_confidence_action = IntentAmbiguityAction::ConstrainedProceed;

    let resolved = resolve_step_intent(&service, &agent_state, &rules, "terminal")
        .await
        .unwrap();
    assert!(!resolved.constrained);
}

#[tokio::test(flavor = "current_thread")]
async fn resolver_routes_clock_queries_to_system_clock_read() {
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());
    let inference: Arc<dyn InferenceRuntime> = Arc::new(ClockIntentRuntime);
    let service = DesktopAgentService::new(gui, terminal, browser, inference);

    let mut agent_state = test_agent_state();
    agent_state.goal = "What time is it right now on this machine?".to_string();

    let mut rules = ActionRules::default();
    rules.ontology_policy.intent_routing.matrix_version = "intent-matrix-v2-clock-test".into();
    let resolved = resolve_step_intent(&service, &agent_state, &rules, "terminal")
        .await
        .unwrap();
    assert_eq!(resolved.scope, IntentScopeProfile::CommandExecution);
    assert_eq!(resolved.intent_id, "system.clock.read");
    assert_eq!(
        resolved
            .top_k
            .first()
            .map(|candidate| candidate.intent_id.as_str()),
        Some("system.clock.read")
    );
}

#[tokio::test(flavor = "current_thread")]
async fn resolver_routes_weather_queries_to_web_research_not_clock_read() {
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());
    let inference: Arc<dyn InferenceRuntime> = Arc::new(WeatherVsClockRuntime);
    let service = DesktopAgentService::new(gui, terminal, browser, inference);

    let mut agent_state = test_agent_state();
    agent_state.goal = "What's the weather like right now?".to_string();

    let mut rules = ActionRules::default();
    rules.ontology_policy.intent_routing.matrix_version = "intent-matrix-v2-weather-test".into();
    let resolved = resolve_step_intent(&service, &agent_state, &rules, "terminal")
        .await
        .unwrap();

    assert_eq!(resolved.intent_id, "web.research");
    assert_eq!(resolved.scope, IntentScopeProfile::WebResearch);
}

#[tokio::test(flavor = "current_thread")]
async fn resolver_routes_latest_headlines_queries_to_web_research_via_descriptor() {
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());
    let inference: Arc<dyn InferenceRuntime> = Arc::new(HeadlinesDescriptorRuntime);
    let service = DesktopAgentService::new(gui, terminal, browser, inference);

    let mut agent_state = test_agent_state();
    agent_state.goal = "Give me the latest news headlines right now.".to_string();

    let mut rules = ActionRules::default();
    rules.ontology_policy.intent_routing.matrix_version = "intent-matrix-v11-headlines-test".into();
    let resolved = resolve_step_intent(&service, &agent_state, &rules, "terminal")
        .await
        .unwrap();

    assert_eq!(resolved.intent_id, "web.research");
    assert_eq!(resolved.scope, IntentScopeProfile::WebResearch);
    assert_eq!(
        resolved
            .top_k
            .first()
            .map(|candidate| candidate.intent_id.as_str()),
        Some("web.research")
    );
}

#[tokio::test(flavor = "current_thread")]
async fn resolver_seeds_researcher_template_for_web_research_intent() {
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());
    let inference: Arc<dyn InferenceRuntime> = Arc::new(WeatherVsClockRuntime);
    let service = DesktopAgentService::new(gui, terminal, browser, inference);

    let mut agent_state = test_agent_state();
    agent_state.goal = "What's the weather like right now?".to_string();

    let mut rules = ActionRules::default();
    rules.ontology_policy.intent_routing.matrix_version =
        "intent-matrix-v2-web-research-template-test".into();
    let resolved = resolve_step_intent(&service, &agent_state, &rules, "terminal")
        .await
        .unwrap();

    assert_eq!(resolved.intent_id, "web.research");
    let contract = resolved
        .instruction_contract
        .expect("web research should synthesize a contract");
    let template_binding = contract
        .slot_bindings
        .iter()
        .find(|binding| binding.slot == "template_id")
        .expect("web research contract should seed a template");
    assert_eq!(
        template_binding.binding_kind,
        InstructionBindingKind::UserLiteral
    );
    assert_eq!(template_binding.value.as_deref(), Some("researcher"));
    let workflow_binding = contract
        .slot_bindings
        .iter()
        .find(|binding| binding.slot == "workflow_id")
        .expect("web research contract should seed a workflow");
    assert_eq!(
        workflow_binding.value.as_deref(),
        Some("live_research_brief")
    );
}

#[tokio::test(flavor = "current_thread")]
async fn resolver_routes_open_calculator_to_app_launch_scope() {
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());
    let inference: Arc<dyn InferenceRuntime> = Arc::new(LaunchVsUiRuntime);
    let service = DesktopAgentService::new(gui, terminal, browser, inference);

    let mut agent_state = test_agent_state();
    agent_state.goal = "open calculator".to_string();

    let mut rules = ActionRules::default();
    rules.ontology_policy.intent_routing.matrix_version =
        "intent-matrix-v10-app-launch-disambiguation-test".into();
    let resolved = resolve_step_intent(&service, &agent_state, &rules, "terminal")
        .await
        .unwrap();

    assert_eq!(resolved.intent_id, "app.launch");
    assert_eq!(resolved.scope, IntentScopeProfile::AppLaunch);
    assert_ne!(resolved.intent_id, "math.eval");
}

#[tokio::test(flavor = "current_thread")]
async fn resolver_routes_desktop_folder_creation_to_command_exec_not_app_launch() {
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());
    let inference: Arc<dyn InferenceRuntime> = Arc::new(DesktopFolderSkewedRuntime);
    let service = DesktopAgentService::new(gui, terminal, browser, inference);

    let mut agent_state = test_agent_state();
    agent_state.goal =
        "Create a new folder on my desktop called \"Project <some_number>\"".to_string();

    let mut rules = ActionRules::default();
    rules.ontology_policy.intent_routing.matrix_version =
        "intent-matrix-v13-desktop-folder-command-exec-test".into();
    rules.ontology_policy.intent_routing.matrix = rules
        .ontology_policy
        .intent_routing
        .matrix
        .iter()
        .filter(|entry| matches!(entry.intent_id.as_str(), "app.launch" | "command.exec"))
        .cloned()
        .collect();
    let resolved = resolve_step_intent(&service, &agent_state, &rules, "terminal")
        .await
        .unwrap();

    assert_eq!(resolved.intent_id, "command.exec");
    assert_eq!(resolved.scope, IntentScopeProfile::CommandExecution);
    assert_ne!(resolved.intent_id, "app.launch");
}

#[tokio::test(flavor = "current_thread")]
async fn resolver_routes_downloads_lowercase_rename_to_command_exec() {
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());
    let inference: Arc<dyn InferenceRuntime> = Arc::new(DesktopFolderSkewedRuntime);
    let service = DesktopAgentService::new(gui, terminal, browser, inference);

    let mut agent_state = test_agent_state();
    agent_state.goal = "Rename every file in my Downloads folder to lowercase.".to_string();

    let mut rules = ActionRules::default();
    rules.ontology_policy.intent_routing.matrix_version =
        "intent-matrix-v13-downloads-rename-command-exec-test".into();
    rules.ontology_policy.intent_routing.matrix = rules
        .ontology_policy
        .intent_routing
        .matrix
        .iter()
        .filter(|entry| {
            matches!(
                entry.intent_id.as_str(),
                "app.launch" | "workspace.ops" | "command.exec"
            )
        })
        .cloned()
        .collect();
    let resolved = resolve_step_intent(&service, &agent_state, &rules, "terminal")
        .await
        .unwrap();

    assert_eq!(resolved.intent_id, "command.exec");
    assert_eq!(resolved.scope, IntentScopeProfile::CommandExecution);
    assert_ne!(resolved.intent_id, "app.launch");
}

#[tokio::test(flavor = "current_thread")]
async fn resolver_routes_vlc_install_query_to_install_dependency_intent() {
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());
    let inference: Arc<dyn InferenceRuntime> = Arc::new(InstallVsWebRuntime);
    let service = DesktopAgentService::new(gui, terminal, browser, inference);

    let mut agent_state = test_agent_state();
    agent_state.goal = "Download and install VLC media player.".to_string();

    let mut rules = ActionRules::default();
    rules.ontology_policy.intent_routing.matrix_version =
        "intent-matrix-v14-vlc-install-intent-test".into();
    rules.ontology_policy.intent_routing.matrix = rules
        .ontology_policy
        .intent_routing
        .matrix
        .iter()
        .filter(|entry| {
            matches!(
                entry.intent_id.as_str(),
                "web.research" | "command.exec" | "command.exec.install_dependency"
            )
        })
        .cloned()
        .collect();
    let resolved = resolve_step_intent(&service, &agent_state, &rules, "terminal")
        .await
        .unwrap();

    assert_eq!(resolved.intent_id, "command.exec.install_dependency");
    assert_eq!(resolved.scope, IntentScopeProfile::CommandExecution);
    assert!(resolved
        .required_capabilities
        .iter()
        .any(|capability| { capability.as_str() == "system.install_package" }));
}

#[tokio::test(flavor = "current_thread")]
async fn resolver_routes_model_load_queries_to_model_registry_load_intent() {
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());
    let inference: Arc<dyn InferenceRuntime> = Arc::new(ModelRegistryIntentRuntime);
    let service = DesktopAgentService::new(gui, terminal, browser, inference);

    let mut agent_state = test_agent_state();
    agent_state.goal = "Load the codex-oss model into the local kernel runtime.".to_string();

    let mut rules = ActionRules::default();
    rules.ontology_policy.intent_routing.matrix_version =
        "intent-matrix-v16-model-registry-load-test".into();
    rules.ontology_policy.intent_routing.matrix = rules
        .ontology_policy
        .intent_routing
        .matrix
        .iter()
        .filter(|entry| {
            matches!(
                entry.intent_id.as_str(),
                "model.registry.load" | "model.registry.unload" | "command.exec"
            )
        })
        .cloned()
        .collect();

    let resolved = resolve_step_intent(&service, &agent_state, &rules, "terminal")
        .await
        .unwrap();

    assert_eq!(resolved.intent_id, "model.registry.load");
    assert_eq!(resolved.scope, IntentScopeProfile::CommandExecution);
    assert!(resolved
        .required_capabilities
        .iter()
        .any(|capability| capability.as_str() == "model.registry.manage"));
}

#[tokio::test(flavor = "current_thread")]
async fn resolver_routes_model_unload_queries_to_model_registry_unload_intent() {
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());
    let inference: Arc<dyn InferenceRuntime> = Arc::new(ModelRegistryIntentRuntime);
    let service = DesktopAgentService::new(gui, terminal, browser, inference);

    let mut agent_state = test_agent_state();
    agent_state.goal = "Unload the whisper model to free memory.".to_string();

    let mut rules = ActionRules::default();
    rules.ontology_policy.intent_routing.matrix_version =
        "intent-matrix-v16-model-registry-unload-test".into();
    rules.ontology_policy.intent_routing.matrix = rules
        .ontology_policy
        .intent_routing
        .matrix
        .iter()
        .filter(|entry| {
            matches!(
                entry.intent_id.as_str(),
                "model.registry.load" | "model.registry.unload" | "command.exec"
            )
        })
        .cloned()
        .collect();

    let resolved = resolve_step_intent(&service, &agent_state, &rules, "terminal")
        .await
        .unwrap();

    assert_eq!(resolved.intent_id, "model.registry.unload");
    assert_eq!(resolved.scope, IntentScopeProfile::CommandExecution);
    assert!(resolved
        .required_capabilities
        .iter()
        .any(|capability| capability.as_str() == "model.registry.manage"));
}

#[tokio::test(flavor = "current_thread")]
async fn resolver_promotes_exempt_low_confidence_winner_to_medium_band() {
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());
    let inference: Arc<dyn InferenceRuntime> = Arc::new(LowConfidenceExemptRuntime);
    let service = DesktopAgentService::new(gui, terminal, browser, inference);

    let mut agent_state = test_agent_state();
    agent_state.goal = "Rename every file in my Downloads folder to lowercase.".to_string();

    let mut rules = ActionRules::default();
    rules.ontology_policy.intent_routing.matrix_version =
        "intent-matrix-v13-exempt-low-band-promotion-test".into();
    rules.ontology_policy.intent_routing.matrix = rules
        .ontology_policy
        .intent_routing
        .matrix
        .iter()
        .filter(|entry| matches!(entry.intent_id.as_str(), "workspace.ops" | "command.exec"))
        .cloned()
        .collect();
    let resolved = resolve_step_intent(&service, &agent_state, &rules, "terminal")
        .await
        .unwrap();

    assert_eq!(resolved.intent_id, "command.exec");
    assert_eq!(resolved.band, IntentConfidenceBand::Medium);
    assert!(!should_pause_for_clarification(
        &resolved,
        &rules.ontology_policy.intent_routing
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn resolver_routes_click_queries_to_ui_interaction_scope() {
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());
    let inference: Arc<dyn InferenceRuntime> = Arc::new(LaunchVsUiRuntime);
    let service = DesktopAgentService::new(gui, terminal, browser, inference);

    let mut agent_state = test_agent_state();
    agent_state.goal = "click the login button".to_string();

    let mut rules = ActionRules::default();
    rules.ontology_policy.intent_routing.matrix_version =
        "intent-matrix-v10-ui-interaction-disambiguation-test".into();
    let resolved = resolve_step_intent(&service, &agent_state, &rules, "terminal")
        .await
        .unwrap();

    assert_eq!(resolved.intent_id, "ui.interaction");
    assert_eq!(resolved.scope, IntentScopeProfile::UiInteraction);
}

#[tokio::test(flavor = "current_thread")]
async fn resolver_routes_timer_queries_to_command_exec() {
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());
    let inference: Arc<dyn InferenceRuntime> = Arc::new(TimerIntentRuntime);
    let service = DesktopAgentService::new(gui, terminal, browser, inference);

    let mut agent_state = test_agent_state();
    agent_state.goal = "Set a timer for 15 minutes".to_string();

    let mut rules = ActionRules::default();
    rules.ontology_policy.intent_routing.matrix_version = "intent-matrix-v4-timer-test".into();
    let resolved = resolve_step_intent(&service, &agent_state, &rules, "terminal")
        .await
        .unwrap();

    assert_eq!(resolved.intent_id, "command.exec");
    assert_ne!(resolved.intent_id, "system.clock.read");
}

#[tokio::test(flavor = "current_thread")]
async fn resolver_routes_mail_send_queries_to_mail_reply_not_clock() {
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());
    let inference: Arc<dyn InferenceRuntime> = Arc::new(MailReplyIntentRuntime);
    let service = DesktopAgentService::new(gui, terminal, browser, inference);

    let mut agent_state = test_agent_state();
    agent_state.goal =
        "Draft an email to team@ioi.network saying tomorrow's standup is moved to 2 PM and send it."
            .to_string();

    let mut rules = ActionRules::default();
    rules.ontology_policy.intent_routing.matrix_version = "intent-matrix-v15-mail-send-test".into();
    let resolved = resolve_step_intent(&service, &agent_state, &rules, "terminal")
        .await
        .unwrap();

    assert_eq!(resolved.intent_id, "mail.reply");
    assert_eq!(resolved.scope, IntentScopeProfile::Conversation);
    assert_ne!(resolved.intent_id, "system.clock.read");
    assert!(resolved
        .required_capabilities
        .iter()
        .any(|capability| capability.as_str() == "mail.reply"));
}

#[tokio::test(flavor = "current_thread")]
async fn resolver_auto_selects_single_available_mail_provider_family() {
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());
    let inference: Arc<dyn InferenceRuntime> = Arc::new(MailReplyIntentRuntime);
    let service = DesktopAgentService::new(gui, terminal, browser, inference);

    let mut agent_state = test_agent_state();
    agent_state.goal =
        "Draft an email to team@ioi.network saying tomorrow's standup is moved to 2 PM and send it."
            .to_string();

    let mut rules = ActionRules::default();
    rules.ontology_policy.intent_routing.matrix_version = "intent-matrix-v15-mail-send-test".into();

    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let record = MailConnectorRecord {
        mailbox: "primary".to_string(),
        config: MailConnectorConfig {
            provider: MailConnectorProvider::ImapSmtp,
            auth_mode: MailConnectorAuthMode::Password,
            account_email: "local-mail@example.com".to_string(),
            sender_display_name: Some("Local Mail".to_string()),
            imap: MailConnectorEndpoint {
                host: "imap.example.com".to_string(),
                port: 993,
                tls_mode: MailConnectorTlsMode::Tls,
            },
            smtp: MailConnectorEndpoint {
                host: "smtp.example.com".to_string(),
                port: 465,
                tls_mode: MailConnectorTlsMode::Tls,
            },
            secret_aliases: MailConnectorSecretAliases {
                imap_username_alias: "imap_username".to_string(),
                imap_password_alias: "imap_password".to_string(),
                smtp_username_alias: "smtp_username".to_string(),
                smtp_password_alias: "smtp_password".to_string(),
            },
            metadata: BTreeMap::new(),
        },
        created_at_ms: 0,
        updated_at_ms: 0,
    };
    state
        .insert(
            b"mail_connector::primary",
            &codec::to_bytes_canonical(&record).expect("encode mail connector"),
        )
        .expect("insert mail connector");

    let resolved =
        resolve_step_intent_with_state(&service, Some(&state), &agent_state, &rules, "terminal")
            .await
            .unwrap();

    assert_eq!(resolved.intent_id, "mail.reply");
    let provider_selection = resolved
        .provider_selection
        .expect("provider selection should be synthesized");
    assert_eq!(
        provider_selection.mode,
        ProviderSelectionMode::DynamicSynthesis
    );
    assert!(
        provider_selection
            .candidates
            .iter()
            .any(
                |candidate| candidate.provider_family == "mail.wallet_network"
                    && candidate.route_label == "mail_connector"
            ),
        "generic mail provider candidates should include the wallet mail connector route"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn resolver_does_not_allow_clock_intent_when_host_clock_binding_is_false() {
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());
    let inference: Arc<dyn InferenceRuntime> = Arc::new(ClockSkewedCommandBindingRuntime);
    let service = DesktopAgentService::new(gui, terminal, browser, inference);

    let mut agent_state = test_agent_state();
    agent_state.goal = "Rename every file in my Downloads folder to lowercase.".to_string();

    let mut rules = ActionRules::default();
    rules.ontology_policy.intent_routing.matrix_version =
        "intent-matrix-v15-host-local-binding-gate-test".into();
    rules.ontology_policy.intent_routing.matrix = rules
        .ontology_policy
        .intent_routing
        .matrix
        .iter()
        .filter(|entry| {
            matches!(
                entry.intent_id.as_str(),
                "system.clock.read" | "command.exec"
            )
        })
        .cloned()
        .collect();

    let resolved = resolve_step_intent(&service, &agent_state, &rules, "terminal")
        .await
        .unwrap();

    assert_eq!(resolved.intent_id, "command.exec");
    assert_ne!(resolved.intent_id, "system.clock.read");
}

#[tokio::test(flavor = "current_thread")]
async fn resolver_routes_calculator_queries_to_math_eval_not_command_exec() {
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());
    let inference: Arc<dyn InferenceRuntime> = Arc::new(MathIntentRuntime);
    let service = DesktopAgentService::new(gui, terminal, browser, inference);

    let mut agent_state = test_agent_state();
    agent_state.goal = "What's 247 x 38?".to_string();

    let mut rules = ActionRules::default();
    rules.ontology_policy.intent_routing.matrix_version = "intent-matrix-v10-math-test".into();
    let resolved = resolve_step_intent(&service, &agent_state, &rules, "terminal")
        .await
        .unwrap();

    assert_eq!(resolved.intent_id, "math.eval");
    assert_eq!(resolved.scope, IntentScopeProfile::Conversation);
    assert_ne!(resolved.intent_id, "command.exec");
}

#[tokio::test(flavor = "current_thread")]
async fn resolver_routes_open_calculator_app_to_app_launch_not_math_eval() {
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());
    let inference: Arc<dyn InferenceRuntime> = Arc::new(MathIntentRuntime);
    let service = DesktopAgentService::new(gui, terminal, browser, inference);

    let mut agent_state = test_agent_state();
    agent_state.goal = "Open calculator app".to_string();

    let mut rules = ActionRules::default();
    rules.ontology_policy.intent_routing.matrix_version =
        "intent-matrix-v10-open-calculator-app-launch-test".into();
    let resolved = resolve_step_intent(&service, &agent_state, &rules, "terminal")
        .await
        .unwrap();

    assert_eq!(resolved.intent_id, "app.launch");
    assert_eq!(resolved.scope, IntentScopeProfile::AppLaunch);
    assert_ne!(resolved.intent_id, "math.eval");
}

#[tokio::test(flavor = "current_thread")]
async fn resolver_routes_open_the_calculator_app_sentence_to_app_launch() {
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());
    let inference: Arc<dyn InferenceRuntime> = Arc::new(MathIntentRuntime);
    let service = DesktopAgentService::new(gui, terminal, browser, inference);

    let mut agent_state = test_agent_state();
    agent_state.goal = "Open the Calculator app.".to_string();

    let mut rules = ActionRules::default();
    rules.ontology_policy.intent_routing.matrix_version =
        "intent-matrix-v10-open-the-calculator-app-launch-test".into();
    let resolved = resolve_step_intent(&service, &agent_state, &rules, "terminal")
        .await
        .unwrap();

    assert_eq!(resolved.intent_id, "app.launch");
    assert_eq!(resolved.scope, IntentScopeProfile::AppLaunch);
    assert_ne!(resolved.intent_id, "math.eval");
}

#[tokio::test(flavor = "current_thread")]
async fn resolver_keeps_app_launch_feasible_when_sys_exec_is_blocked() {
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());
    let inference: Arc<dyn InferenceRuntime> = Arc::new(LaunchVsUiRuntime);
    let service = DesktopAgentService::new(gui, terminal, browser, inference);

    let mut agent_state = test_agent_state();
    agent_state.goal = "Open the Calculator app.".to_string();

    let mut rules = ActionRules::default();
    rules.rules.push(Rule {
        rule_id: Some("block-sys-exec".to_string()),
        target: "sys::exec".to_string(),
        conditions: RuleConditions::default(),
        action: Verdict::Block,
    });
    rules.ontology_policy.intent_routing.matrix_version =
        "intent-matrix-v11-open-calculator-with-sys-blocked".into();
    let resolved = resolve_step_intent(&service, &agent_state, &rules, "terminal")
        .await
        .unwrap();

    assert_eq!(resolved.intent_id, "app.launch");
    assert_eq!(resolved.scope, IntentScopeProfile::AppLaunch);
}

#[tokio::test(flavor = "current_thread")]
async fn resolver_routing_is_not_driven_by_aliases_or_exemplars() {
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());
    let inference: Arc<dyn InferenceRuntime> = Arc::new(ClockIntentRuntime);
    let service = DesktopAgentService::new(gui, terminal, browser, inference);

    let mut agent_state = test_agent_state();
    agent_state.goal = "What time is it right now on this machine?".to_string();

    let mut rules = ActionRules::default();
    rules.ontology_policy.intent_routing.matrix_version =
        "intent-matrix-v2-metadata-independence-test".into();
    rules.ontology_policy.intent_routing.matrix = vec![
        IntentMatrixEntry {
            intent_id: "web.research".to_string(),
            semantic_descriptor: "retrieve web research results".to_string(),
            query_binding: IntentQueryBindingClass::RemotePublicFact,
            required_capabilities: vec![],
            risk_class: "medium".to_string(),
            scope: IntentScopeProfile::WebResearch,
            preferred_tier: "tool_first".to_string(),
            applicability_class: ExecutionApplicabilityClass::RemoteRetrieval,
            requires_host_discovery: Some(false),
            provider_selection_mode: Some(ProviderSelectionMode::CapabilityOnly),
            required_receipts: vec!["execution".to_string(), "verification".to_string()],
            required_postconditions: vec![],
            verification_mode: Some(VerificationMode::DeterministicCheck),
            aliases: vec!["clock".to_string(), "time".to_string()],
            exemplars: vec![
                "what time is it on this machine".to_string(),
                "read current utc clock timestamp".to_string(),
            ],
        },
        IntentMatrixEntry {
            intent_id: "system.clock.read".to_string(),
            semantic_descriptor: "read system clock timestamp".to_string(),
            query_binding: IntentQueryBindingClass::HostLocal,
            required_capabilities: vec![],
            risk_class: "low".to_string(),
            scope: IntentScopeProfile::CommandExecution,
            preferred_tier: "tool_first".to_string(),
            applicability_class: ExecutionApplicabilityClass::DeterministicLocal,
            requires_host_discovery: Some(false),
            provider_selection_mode: Some(ProviderSelectionMode::CapabilityOnly),
            required_receipts: vec!["execution".to_string(), "verification".to_string()],
            required_postconditions: vec![],
            verification_mode: Some(VerificationMode::DeterministicCheck),
            aliases: vec!["weather".to_string()],
            exemplars: vec![
                "what's the weather like right now".to_string(),
                "current temperature humidity and wind".to_string(),
            ],
        },
    ];

    let resolved = resolve_step_intent(&service, &agent_state, &rules, "terminal")
        .await
        .unwrap();
    assert_eq!(resolved.intent_id, "system.clock.read");
    assert_eq!(resolved.scope, IntentScopeProfile::CommandExecution);
}

#[tokio::test(flavor = "current_thread")]
async fn resolver_enforces_remote_public_fact_binding_when_embeddings_disagree() {
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());
    let inference: Arc<dyn InferenceRuntime> = Arc::new(LocalitySkewedRuntime);
    let service = DesktopAgentService::new(gui, terminal, browser, inference);

    let mut agent_state = test_agent_state();
    agent_state.goal = "What's the weather like right now?".to_string();

    let mut rules = ActionRules::default();
    rules.ontology_policy.intent_routing.matrix_version =
        "intent-matrix-v2-runtime-locality-no-forced-override-test".into();
    let resolved = resolve_step_intent(&service, &agent_state, &rules, "terminal")
        .await
        .unwrap();
    assert_eq!(resolved.intent_id, "web.research");
    assert_eq!(resolved.scope, IntentScopeProfile::WebResearch);
}

#[tokio::test(flavor = "current_thread")]
async fn resolver_keeps_host_local_clock_queries_on_system_clock_read() {
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());
    let inference: Arc<dyn InferenceRuntime> = Arc::new(LocalitySkewedRuntime);
    let service = DesktopAgentService::new(gui, terminal, browser, inference);

    let mut agent_state = test_agent_state();
    agent_state.goal = "What time is it right now on this machine?".to_string();

    let mut rules = ActionRules::default();
    rules.ontology_policy.intent_routing.matrix_version =
        "intent-matrix-v2-host-local-clock-binding-test".into();
    let resolved = resolve_step_intent(&service, &agent_state, &rules, "terminal")
        .await
        .unwrap();
    assert_eq!(resolved.intent_id, "system.clock.read");
    assert_eq!(resolved.scope, IntentScopeProfile::CommandExecution);
}

#[tokio::test(flavor = "current_thread")]
async fn resolver_uses_model_ranking_when_embeddings_are_unavailable() {
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());
    let inference: Arc<dyn InferenceRuntime> = Arc::new(NoEmbeddingModelRankRuntime);
    let service = DesktopAgentService::new(gui, terminal, browser, inference);

    let mut agent_state = test_agent_state();
    agent_state.goal = "Rename every file in my Downloads folder to lowercase.".to_string();

    let mut rules = ActionRules::default();
    rules.ontology_policy.intent_routing.matrix_version =
        "intent-matrix-v13-no-embed-model-rank-test".into();
    rules.ontology_policy.intent_routing.matrix = rules
        .ontology_policy
        .intent_routing
        .matrix
        .iter()
        .filter(|entry| {
            matches!(
                entry.intent_id.as_str(),
                "app.launch" | "workspace.ops" | "command.exec"
            )
        })
        .cloned()
        .collect();

    let resolved = resolve_step_intent(&service, &agent_state, &rules, "terminal")
        .await
        .unwrap();
    assert_eq!(resolved.intent_id, "command.exec");
    assert_eq!(resolved.scope, IntentScopeProfile::CommandExecution);
    assert!(matches!(
        resolved.band,
        IntentConfidenceBand::High | IntentConfidenceBand::Medium
    ));
    assert!(!should_pause_for_clarification(
        &resolved,
        &rules.ontology_policy.intent_routing
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn resolver_routes_durable_monitor_queries_to_automation_monitor() {
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());
    let inference: Arc<dyn InferenceRuntime> = Arc::new(AutomationMonitorIntentRuntime);
    let service = DesktopAgentService::new(gui, terminal, browser, inference);

    let mut agent_state = test_agent_state();
    agent_state.goal = "Monitor Hacker News and notify me whenever a post about Web4 or post-quantum cryptography hits the front page.".to_string();

    let mut rules = ActionRules::default();
    rules.ontology_policy.intent_routing.matrix_version =
        "intent-matrix-v15-automation-monitor-test".into();
    rules.ontology_policy.intent_routing.matrix = rules
        .ontology_policy
        .intent_routing
        .matrix
        .iter()
        .filter(|entry| {
            matches!(
                entry.intent_id.as_str(),
                "automation.monitor" | "command.exec" | "web.research"
            )
        })
        .cloned()
        .collect();

    let resolved = resolve_step_intent(&service, &agent_state, &rules, "terminal")
        .await
        .unwrap();
    assert_eq!(resolved.intent_id, "automation.monitor");
    assert_eq!(resolved.scope, IntentScopeProfile::CommandExecution);
    assert!(resolved
        .required_capabilities
        .iter()
        .any(|capability| capability.as_str() == "automation.monitor.install"));
}

#[tokio::test(flavor = "current_thread")]
async fn resolver_prefers_automation_monitor_for_durable_queries_even_when_web_rank_is_higher() {
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());
    let inference: Arc<dyn InferenceRuntime> = Arc::new(AutomationMonitorVsWebResearchRuntime);
    let service = DesktopAgentService::new(gui, terminal, browser, inference);

    let mut agent_state = test_agent_state();
    agent_state.goal = "Monitor Hacker News and notify me whenever a post about Web4 or post-quantum cryptography hits the front page.".to_string();

    let mut rules = ActionRules::default();
    rules.ontology_policy.intent_routing.matrix_version =
        "intent-matrix-v15-automation-monitor-remote-source-test".into();
    rules.ontology_policy.intent_routing.matrix = rules
        .ontology_policy
        .intent_routing
        .matrix
        .iter()
        .filter(|entry| {
            matches!(
                entry.intent_id.as_str(),
                "automation.monitor" | "command.exec" | "web.research"
            )
        })
        .cloned()
        .collect();

    let resolved = resolve_step_intent(&service, &agent_state, &rules, "terminal")
        .await
        .unwrap();
    assert_eq!(resolved.intent_id, "automation.monitor");
    assert_eq!(resolved.scope, IntentScopeProfile::CommandExecution);
    assert!(matches!(
        resolved.band,
        IntentConfidenceBand::High | IntentConfidenceBand::Medium
    ));
    assert!(resolved
        .required_capabilities
        .iter()
        .any(|capability| capability.as_str() == "automation.monitor.install"));
    assert!(!should_pause_for_clarification(
        &resolved,
        &rules.ontology_policy.intent_routing
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn resolver_abstains_when_embeddings_and_model_ranking_fail() {
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());
    let inference: Arc<dyn InferenceRuntime> = Arc::new(NoEmbeddingRuntime);
    let service = DesktopAgentService::new(gui, terminal, browser, inference);

    let mut agent_state = test_agent_state();
    agent_state.goal = "What time is it right now?".to_string();

    let mut rules = ActionRules::default();
    rules.ontology_policy.intent_routing.matrix_version = "intent-matrix-v2-no-embed-test".into();
    let resolved = resolve_step_intent(&service, &agent_state, &rules, "terminal")
        .await
        .unwrap();
    assert_eq!(resolved.intent_id, "resolver.unclassified");
    assert_eq!(resolved.scope, IntentScopeProfile::Unknown);
    assert_eq!(resolved.score, 0.0);
    assert_eq!(resolved.band, IntentConfidenceBand::Low);
    assert!(!resolved.top_k.is_empty());
    assert!(resolved
        .top_k
        .iter()
        .any(|candidate| candidate.score <= f32::EPSILON));
    assert!(should_pause_for_clarification(
        &resolved,
        &rules.ontology_policy.intent_routing
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn resolver_fails_closed_for_mail_send_when_rank_backend_is_unavailable() {
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());
    let inference: Arc<dyn InferenceRuntime> = Arc::new(NoEmbeddingRuntime);
    let service = DesktopAgentService::new(gui, terminal, browser, inference);

    let mut agent_state = test_agent_state();
    agent_state.goal =
        "Draft an email to team@ioi.network saying tomorrow's standup is moved to 2 PM and send it."
            .to_string();

    let mut rules = ActionRules::default();
    rules.ontology_policy.intent_routing.matrix_version =
        "intent-matrix-v15-mail-no-rank-backend-test".into();
    rules.ontology_policy.intent_routing.matrix = rules
        .ontology_policy
        .intent_routing
        .matrix
        .iter()
        .filter(|entry| {
            matches!(
                entry.intent_id.as_str(),
                "mail.reply" | "conversation.reply" | "system.clock.read"
            )
        })
        .cloned()
        .collect();

    let resolved = resolve_step_intent(&service, &agent_state, &rules, "terminal")
        .await
        .unwrap();
    assert_eq!(resolved.intent_id, "resolver.unclassified");
    assert_eq!(resolved.scope, IntentScopeProfile::Unknown);
    assert_eq!(resolved.band, IntentConfidenceBand::Low);
    assert_eq!(resolved.score, 0.0);
    assert!(!resolved.top_k.is_empty());
    assert!(resolved
        .top_k
        .iter()
        .all(|candidate| candidate.score <= f32::EPSILON));
    assert_eq!(resolved.embedding_model_id, "resolver.unavailable");
    assert!(should_pause_for_clarification(
        &resolved,
        &rules.ontology_policy.intent_routing
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn resolver_abstains_when_top_candidates_are_ambiguous() {
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());
    let inference: Arc<dyn InferenceRuntime> = Arc::new(AmbiguousRuntime);
    let service = DesktopAgentService::new(gui, terminal, browser, inference);

    let mut agent_state = test_agent_state();
    agent_state.goal = "ambiguous clock command intent".to_string();

    let mut rules = ActionRules::default();
    rules.ontology_policy.intent_routing.matrix_version =
        "intent-matrix-v2-ambiguity-abstain-test".into();
    rules.ontology_policy.intent_routing.ambiguity_margin_bps = 10_000;
    rules
        .ontology_policy
        .intent_routing
        .ambiguity_abstain_exempt_intents = vec![];
    rules.ontology_policy.intent_routing.matrix = vec![
        IntentMatrixEntry {
            intent_id: "system.clock.read".to_string(),
            semantic_descriptor: "system clock timestamp".to_string(),
            query_binding: IntentQueryBindingClass::HostLocal,
            required_capabilities: vec![],
            risk_class: "low".to_string(),
            scope: IntentScopeProfile::CommandExecution,
            preferred_tier: "tool_first".to_string(),
            applicability_class: ExecutionApplicabilityClass::DeterministicLocal,
            requires_host_discovery: Some(false),
            provider_selection_mode: Some(ProviderSelectionMode::CapabilityOnly),
            required_receipts: vec!["execution".to_string(), "verification".to_string()],
            required_postconditions: vec![],
            verification_mode: Some(VerificationMode::DeterministicCheck),
            aliases: vec![],
            exemplars: vec![],
        },
        IntentMatrixEntry {
            intent_id: "command.exec".to_string(),
            semantic_descriptor: "shell or terminal command execute".to_string(),
            query_binding: IntentQueryBindingClass::CommandDirected,
            required_capabilities: vec![],
            risk_class: "low".to_string(),
            scope: IntentScopeProfile::CommandExecution,
            preferred_tier: "tool_first".to_string(),
            applicability_class: ExecutionApplicabilityClass::TopologyDependent,
            requires_host_discovery: Some(true),
            provider_selection_mode: Some(ProviderSelectionMode::DynamicSynthesis),
            required_receipts: vec![
                "host_discovery".to_string(),
                "provider_selection".to_string(),
                "execution".to_string(),
                "verification".to_string(),
            ],
            required_postconditions: vec![],
            verification_mode: Some(VerificationMode::DynamicSynthesis),
            aliases: vec![],
            exemplars: vec![],
        },
    ];
    let resolved = resolve_step_intent(&service, &agent_state, &rules, "terminal")
        .await
        .unwrap();

    assert_eq!(resolved.intent_id, "resolver.unclassified");
    assert_eq!(resolved.scope, IntentScopeProfile::Unknown);
    assert_eq!(resolved.band, IntentConfidenceBand::Low);
    assert!(resolved
        .top_k
        .iter()
        .any(|candidate| candidate.intent_id == "system.clock.read"));
    assert!(resolved
        .top_k
        .iter()
        .any(|candidate| candidate.intent_id == "command.exec"));
    assert!(should_pause_for_clarification(
        &resolved,
        &rules.ontology_policy.intent_routing
    ));
}
