fn runtime_target_for_dynamic_tool(value: &serde_json::Value) -> RuntimeTarget {
    let Some(name) = value.get("name").and_then(|entry| entry.as_str()) else {
        return RuntimeTarget::Adapter;
    };

    match name {
        "model__responses" | "model__embeddings" | "model__rerank" => RuntimeTarget::Inference,
        name if name.starts_with("media__") => RuntimeTarget::Media,
        "browser__subagent" => RuntimeTarget::Browser,
        name if name.starts_with("model_registry__")
            || name.starts_with("backend__")
            || name.starts_with("gallery__") =>
        {
            RuntimeTarget::ModelRegistry
        }
        _ => RuntimeTarget::Adapter,
    }
}

fn runtime_target_for_tool(tool: &AgentTool) -> RuntimeTarget {
    match tool {
        AgentTool::FsWrite { .. }
        | AgentTool::FsPatch { .. }
        | AgentTool::FsMultiPatch { .. }
        | AgentTool::FsRead { .. }
        | AgentTool::FsView { .. }
        | AgentTool::FsList { .. }
        | AgentTool::FsSearch { .. }
        | AgentTool::FsStat { .. }
        | AgentTool::FsCreateDirectory { .. }
        | AgentTool::FsCreateZip { .. }
        | AgentTool::FsMove { .. }
        | AgentTool::FsCopy { .. }
        | AgentTool::FsDelete { .. } => RuntimeTarget::Filesystem,
        AgentTool::SysExec { .. }
        | AgentTool::SysExecSession { .. }
        | AgentTool::SysExecStatus { .. }
        | AgentTool::SysExecInput { .. }
        | AgentTool::SysExecTerminate { .. }
        | AgentTool::SysExecSessionReset {}
        | AgentTool::SoftwareInstallResolve { .. }
        | AgentTool::SoftwareInstallExecutePlan { .. }
        | AgentTool::SysChangeDir { .. }
        | AgentTool::OsLaunchApp { .. } => RuntimeTarget::System,
        AgentTool::Screen(_)
        | AgentTool::GuiClick { .. }
        | AgentTool::GuiType { .. }
        | AgentTool::GuiScroll { .. }
        | AgentTool::GuiSnapshot { .. }
        | AgentTool::GuiClickElement { .. }
        | AgentTool::UiFind { .. }
        | AgentTool::OsFocusWindow { .. }
        | AgentTool::OsCopy { .. }
        | AgentTool::OsPaste {} => RuntimeTarget::DesktopUi,
        AgentTool::BrowserNavigate { .. }
        | AgentTool::BrowserSnapshot { .. }
        | AgentTool::BrowserClick { .. }
        | AgentTool::BrowserHover { .. }
        | AgentTool::BrowserMoveMouse { .. }
        | AgentTool::BrowserMouseDown { .. }
        | AgentTool::BrowserMouseUp { .. }
        | AgentTool::BrowserSyntheticClick { .. }
        | AgentTool::BrowserScroll { .. }
        | AgentTool::BrowserType { .. }
        | AgentTool::BrowserSelectText { .. }
        | AgentTool::BrowserKey { .. }
        | AgentTool::BrowserCopySelection {}
        | AgentTool::BrowserPasteClipboard { .. }
        | AgentTool::BrowserFindText { .. }
        | AgentTool::BrowserCanvasSummary { .. }
        | AgentTool::BrowserScreenshot { .. }
        | AgentTool::BrowserWait { .. }
        | AgentTool::BrowserUploadFile { .. }
        | AgentTool::BrowserDropdownOptions { .. }
        | AgentTool::BrowserSelectDropdown { .. }
        | AgentTool::BrowserGoBack { .. }
        | AgentTool::BrowserTabList {}
        | AgentTool::BrowserTabSwitch { .. }
        | AgentTool::BrowserTabClose { .. } => RuntimeTarget::Browser,
        AgentTool::WebSearch { .. } | AgentTool::WebRead { .. } | AgentTool::NetFetch { .. } => {
            RuntimeTarget::Network
        }
        AgentTool::MediaExtractTranscript { .. }
        | AgentTool::MediaExtractMultimodalEvidence { .. } => RuntimeTarget::Media,
        AgentTool::MemorySearch { .. }
        | AgentTool::MemoryInspect { .. }
        | AgentTool::MemoryReplaceCore { .. }
        | AgentTool::MemoryAppendCore { .. }
        | AgentTool::MemoryClearCore { .. } => RuntimeTarget::Memory,
        AgentTool::Dynamic(value) => runtime_target_for_dynamic_tool(value),
        AgentTool::MathEval { .. }
        | AgentTool::ChatReply { .. }
        | AgentTool::AutomationCreateMonitor { .. }
        | AgentTool::AgentDelegate { .. }
        | AgentTool::AgentAwait { .. }
        | AgentTool::AgentPause { .. }
        | AgentTool::AgentComplete { .. }
        | AgentTool::CommerceCheckout { .. }
        | AgentTool::SystemFail { .. } => RuntimeTarget::ControlPlane,
    }
}

fn target_requires_network_lease(target: &ActionTarget) -> bool {
    match target {
        ActionTarget::NetFetch
        | ActionTarget::WebRetrieve
        | ActionTarget::MediaExtractTranscript
        | ActionTarget::MediaExtractMultimodalEvidence
        | ActionTarget::BrowserInteract
        | ActionTarget::BrowserInspect
        | ActionTarget::CommerceDiscovery
        | ActionTarget::CommerceCheckout => true,
        ActionTarget::Custom(label) => {
            let normalized = label.trim().to_ascii_lowercase();
            normalized.starts_with("net::")
                || normalized.starts_with("web::")
                || normalized.starts_with("browser::")
                || normalized.starts_with("connector__google__")
        }
        _ => false,
    }
}

fn normalize_domain_from_url(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    Url::parse(trimmed)
        .or_else(|_| Url::parse(&format!("https://{}", trimmed)))
        .ok()
        .and_then(|parsed| parsed.host_str().map(|value| value.to_ascii_lowercase()))
}

fn observed_domain_for_dynamic_tool(value: &serde_json::Value) -> Option<String> {
    let arguments = value.get("arguments")?;
    if let Some(url) = arguments.get("url").and_then(|entry| entry.as_str()) {
        return normalize_domain_from_url(url);
    }
    if let Some(url) = arguments.get("source_uri").and_then(|entry| entry.as_str()) {
        return normalize_domain_from_url(url);
    }
    if let Some(url) = arguments
        .get("artifact_url")
        .and_then(|entry| entry.as_str())
    {
        return normalize_domain_from_url(url);
    }
    if let Some(url) = arguments
        .get("download_url")
        .and_then(|entry| entry.as_str())
    {
        return normalize_domain_from_url(url);
    }
    if let Some(url) = arguments
        .get("registry_url")
        .and_then(|entry| entry.as_str())
    {
        return normalize_domain_from_url(url);
    }
    if let Some(url) = arguments
        .get("merchant_url")
        .and_then(|entry| entry.as_str())
    {
        return normalize_domain_from_url(url);
    }
    None
}

fn observed_domain_for_tool(tool: &AgentTool) -> Option<String> {
    match tool {
        AgentTool::NetFetch { url, .. }
        | AgentTool::WebRead { url, .. }
        | AgentTool::MediaExtractTranscript { url, .. }
        | AgentTool::MediaExtractMultimodalEvidence { url, .. }
        | AgentTool::BrowserNavigate { url }
        | AgentTool::CommerceCheckout {
            merchant_url: url, ..
        } => normalize_domain_from_url(url),
        AgentTool::WebSearch { url, .. } => url.as_deref().and_then(normalize_domain_from_url),
        AgentTool::Dynamic(value) => observed_domain_for_dynamic_tool(value),
        _ => None,
    }
}

fn build_workload_spec(
    tool: &AgentTool,
    target: &ActionTarget,
    request_hash: [u8; 32],
    window_binding: Option<u64>,
    target_app_hint: Option<String>,
    now_ms: u64,
) -> (WorkloadSpec, Option<String>) {
    let observed_domain = observed_domain_for_tool(tool);
    let net_mode = if target_requires_network_lease(target) || observed_domain.is_some() {
        if observed_domain.is_some() {
            NetMode::AllowListed
        } else {
            NetMode::AllowAny
        }
    } else {
        NetMode::Disabled
    };

    let mut domain_allowlist = Vec::new();
    if let Some(domain) = observed_domain.as_ref() {
        domain_allowlist.push(domain.clone());
    }

    let lease = CapabilityLease {
        lease_id: request_hash,
        issued_at_ms: now_ms,
        expires_at_ms: now_ms.saturating_add(5 * 60 * 1_000),
        mode: CapabilityLeaseMode::OneShot,
        capability_allowlist: vec![target.canonical_label()],
        domain_allowlist,
    };

    let requires_focused_window = target_requires_window_binding(target);
    let ui_surface = if requires_focused_window || target_app_hint.is_some() {
        Some(UiSurfaceSpec {
            window_id: window_binding,
            app_hint: target_app_hint,
            requires_focused_window,
        })
    } else {
        None
    };

    (
        WorkloadSpec {
            runtime_target: runtime_target_for_tool(tool),
            net_mode,
            capability_lease: Some(lease),
            ui_surface,
        },
        observed_domain,
    )
}

async fn prepare_tool_for_execution(
    service: &RuntimeAgentService,
    tool: &mut AgentTool,
    rules: &ActionRules,
    session_id: [u8; 32],
    agent_state: &AgentState,
    os_driver: &Arc<dyn OsDriver>,
    scoped_exception_hash: Option<[u8; 32]>,
) -> Result<(Option<ioi_api::vm::drivers::os::WindowInfo>, Option<String>), TransactionError> {
    let foreground_window = query_active_window_with_timeout(os_driver, session_id, "pre").await;
    let target_app_hint = agent_state.target.as_ref().and_then(|t| t.app_hint.clone());

    // Pre-policy normalization:
    // - Convert search-result browser navigation into governed `web__search` for WebResearch.
    // - Ensure `web__search` carries a computed SERP URL for deterministic policy hashing.
    normalize_web_research_tool_call(
        tool,
        agent_state.resolved_intent.as_ref(),
        &agent_state.goal,
    );
    let _ = reconcile_pending_web_research_tool_call(
        tool,
        agent_state.pending_search_completion.as_ref(),
    );

    // `web__search` carries a computed SERP URL for deterministic
    // policy enforcement + hashing (the model should only provide the query).
    if let AgentTool::WebSearch { query, url, .. } = tool {
        if url.as_ref().map(|u| u.trim().is_empty()).unwrap_or(true) {
            *url = Some(crate::agentic::web::build_default_search_url(query));
        }
    }

    // Stage D transform-first enforcement for egress-capable tools.
    pii::apply_pii_transform_first(service, rules, session_id, scoped_exception_hash, tool).await?;

    Ok((foreground_window, target_app_hint))
}

pub fn select_runtime(
    service: &RuntimeAgentService,
    state: &crate::agentic::runtime::types::AgentState,
) -> std::sync::Arc<dyn ioi_api::vm::inference::InferenceRuntime> {
    if state.consecutive_failures > 0 {
        return service.reasoning_inference.clone();
    }
    if state.step_count == 0 {
        return service.reasoning_inference.clone();
    }
    match state.last_action_type.as_deref() {
        Some("screen__click_at") | Some("screen__type") => {
            // Prefer fast inference if available for simple UI follow-ups
            service.fast_inference.clone()
        }
        _ => service.reasoning_inference.clone(),
    }
}
