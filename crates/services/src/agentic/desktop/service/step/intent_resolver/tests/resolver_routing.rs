use super::*;

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
