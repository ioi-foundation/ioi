use serde_json::{json, Value};

#[derive(Clone)]
pub(super) struct ComputerUseProvider {
    pub(super) provider_id: &'static str,
    pub(super) provider_kind: &'static str,
    pub(super) lane: &'static str,
    pub(super) status: &'static str,
    pub(super) implementation_status: &'static str,
    pub(super) thread_tool_name: Option<&'static str>,
    pub(super) supported_session_modes: &'static [&'static str],
    pub(super) capabilities: &'static [&'static str],
    pub(super) authority_scopes: &'static [&'static str],
    pub(super) retention_modes: &'static [&'static str],
    pub(super) cleanup_required: bool,
    pub(super) fixture: bool,
    pub(super) unavailable_reason: Option<&'static str>,
}

pub(super) fn computer_use_provider_registry_report(
    selected: Option<&ComputerUseProvider>,
) -> Value {
    let providers = computer_use_providers();
    let available_provider_ids = providers
        .iter()
        .filter(|provider| provider.status == "available")
        .map(|provider| provider.provider_id)
        .collect::<Vec<_>>();
    let unavailable_provider_ids = providers
        .iter()
        .filter(|provider| provider.status != "available")
        .map(|provider| provider.provider_id)
        .collect::<Vec<_>>();
    json!({
        "schema_version": "ioi.computer-use.provider-registry.v1",
        "object": "ioi.computer_use.provider_registry_report",
        "providers": providers.iter().map(computer_use_provider_json).collect::<Vec<_>>(),
        "available_provider_ids": available_provider_ids,
        "unavailable_provider_ids": unavailable_provider_ids,
        "fail_closed_when_unavailable": true,
        "selected_provider_id": selected.map(|provider| provider.provider_id),
        "selected_provider_kind": selected.map(|provider| provider.provider_kind)
    })
}

pub(super) fn computer_use_provider_for_lane(
    lane: &str,
    provider_hint: Option<&str>,
    session_mode: &str,
) -> Option<ComputerUseProvider> {
    let providers = computer_use_providers()
        .into_iter()
        .filter(|provider| provider.lane == lane)
        .collect::<Vec<_>>();
    if let Some(hint) = provider_hint {
        if let Some(provider) = providers
            .iter()
            .find(|provider| computer_use_provider_matches_hint(provider, hint))
        {
            return Some(provider.clone());
        }
    }
    providers
        .iter()
        .find(|provider| {
            provider.status == "available"
                && (session_mode.is_empty()
                    || provider.supported_session_modes.contains(&session_mode))
        })
        .cloned()
        .or_else(|| {
            providers
                .iter()
                .find(|provider| provider.status == "available")
                .cloned()
        })
        .or_else(|| providers.first().cloned())
}

fn computer_use_providers() -> Vec<ComputerUseProvider> {
    vec![
        ComputerUseProvider {
            provider_id: "ioi.computer_use.native_browser.task_scoped_profile",
            provider_kind: "task_scoped_browser_profile",
            lane: "native_browser",
            status: "available",
            implementation_status: "concrete_with_fail_closed_adapters",
            thread_tool_name: Some("ioi.computer_use.native_browser"),
            supported_session_modes: &[
                "owned_hermetic_browser",
                "attached_browser",
                "controlled_relaunch",
            ],
            capabilities: &[
                "browser_discovery",
                "observation",
                "target_index",
                "action_proposal",
                "verification",
                "cleanup",
            ],
            authority_scopes: &["computer_use.native_browser.read", "computer_use.native_browser.act"],
            retention_modes: &[
                "prompt_visible_summary_only",
                "local_redacted_artifacts",
                "local_raw_artifacts",
            ],
            cleanup_required: true,
            fixture: false,
            unavailable_reason: None,
        },
        ComputerUseProvider {
            provider_id: "ioi.computer_use.visual_gui.local",
            provider_kind: "local_visual_gui",
            lane: "visual_gui",
            status: "available",
            implementation_status: "concrete_when_observation_or_executor_available",
            thread_tool_name: Some("ioi.computer_use.visual_gui"),
            supported_session_modes: &[
                "visual_fallback",
                "foreground_desktop",
                "background_desktop",
                "app_scoped_desktop",
            ],
            capabilities: &[
                "visual_observation",
                "target_index",
                "action_proposal",
                "verification",
                "cleanup",
            ],
            authority_scopes: &["computer_use.visual_gui.read", "computer_use.visual_gui.act"],
            retention_modes: &[
                "prompt_visible_summary_only",
                "local_redacted_artifacts",
                "local_raw_artifacts",
            ],
            cleanup_required: true,
            fixture: false,
            unavailable_reason: None,
        },
        ComputerUseProvider {
            provider_id: "ioi.computer_use.sandboxed_hosted.local_fixture",
            provider_kind: "local_fixture",
            lane: "sandboxed_hosted",
            status: "available",
            implementation_status: "fixture_adapter",
            thread_tool_name: Some("ioi.computer_use.sandboxed_hosted"),
            supported_session_modes: &["local_sandbox"],
            capabilities: &[
                "observation",
                "target_index",
                "action_proposal",
                "verification",
                "cleanup",
            ],
            authority_scopes: &[
                "computer_use.sandboxed_hosted.read",
                "computer_use.sandboxed_hosted.act",
            ],
            retention_modes: &["no_persistence", "prompt_visible_summary_only"],
            cleanup_required: true,
            fixture: true,
            unavailable_reason: None,
        },
        ComputerUseProvider {
            provider_id: "ioi.computer_use.sandboxed_hosted.local_container",
            provider_kind: "local_container",
            lane: "sandboxed_hosted",
            status: "unavailable",
            implementation_status: "planned_fail_closed",
            thread_tool_name: None,
            supported_session_modes: &["local_sandbox", "hosted_sandbox"],
            capabilities: &["provider_discovery", "lease_request"],
            authority_scopes: &[
                "computer_use.sandboxed_hosted.read",
                "computer_use.sandboxed_hosted.act",
            ],
            retention_modes: &["no_persistence", "local_redacted_artifacts"],
            cleanup_required: true,
            fixture: false,
            unavailable_reason: Some(
                "Local container provider is registered as a planned parity-plus provider; no container runtime adapter is mounted yet.",
            ),
        },
    ]
}

fn computer_use_provider_json(provider: &ComputerUseProvider) -> Value {
    let mut value = json!({
        "provider_id": provider.provider_id,
        "provider_kind": provider.provider_kind,
        "lane": provider.lane,
        "status": provider.status,
        "implementation_status": provider.implementation_status,
        "thread_tool_name": provider.thread_tool_name,
        "supported_session_modes": provider.supported_session_modes,
        "capabilities": provider.capabilities,
        "authority_scopes": provider.authority_scopes,
        "retention_modes": provider.retention_modes,
        "cleanup_required": provider.cleanup_required,
        "fixture": provider.fixture,
    });
    if let Some(unavailable_reason) = provider.unavailable_reason {
        value["unavailable_reason"] = json!(unavailable_reason);
    }
    value
}

fn computer_use_provider_matches_hint(provider: &ComputerUseProvider, hint: &str) -> bool {
    provider.provider_id == hint
        || provider.provider_kind == hint
        || provider.provider_id.ends_with(&format!(".{hint}"))
        || provider.provider_id.ends_with(&format!("_{hint}"))
}
