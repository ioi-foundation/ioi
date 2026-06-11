use serde_json::{json, Value};

const CODING_TOOL_RESULT_SCHEMA_VERSION: &str = "ioi.runtime.coding-tool-result.v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodingToolComputerUseError {
    code: &'static str,
    message: String,
}

impl CodingToolComputerUseError {
    fn new(code: &'static str, message: String) -> Self {
        Self { code, message }
    }

    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

#[derive(Clone)]
struct ComputerUseProvider {
    provider_id: &'static str,
    provider_kind: &'static str,
    lane: &'static str,
    status: &'static str,
    implementation_status: &'static str,
    thread_tool_name: Option<&'static str>,
    supported_session_modes: &'static [&'static str],
    capabilities: &'static [&'static str],
    authority_scopes: &'static [&'static str],
    retention_modes: &'static [&'static str],
    cleanup_required: bool,
    fixture: bool,
    unavailable_reason: Option<&'static str>,
}

pub fn build_computer_use_lease_request(
    workspace_root: &str,
    input: &Value,
) -> Result<Value, CodingToolComputerUseError> {
    let prompt = optional_json_string(input, &["prompt", "goal", "objective"])
        .unwrap_or_else(|| "Coding agent requested a governed computer-use lease.".to_string());
    let lane = computer_use_lane_for_input(input);
    let session_mode = computer_use_session_mode_for_input(input, &lane);
    let action_kind = computer_use_action_kind_for_input(input);
    let approval_ref = optional_json_string(input, &["approval_ref"]);
    let provider_hint =
        optional_json_string(input, &["provider_id", "provider_kind", "sandbox_provider"]);
    let provider = computer_use_provider_for_lane(&lane, provider_hint.as_deref(), &session_mode);
    let provider_registry = computer_use_provider_registry_report(provider.as_ref());
    let url = optional_json_string(input, &["url"]);
    let target_ref = optional_json_string(input, &["target_ref"]);
    let selector = optional_json_string(input, &["selector"]);
    let request_seed = computer_use_request_seed(
        workspace_root,
        &prompt,
        &lane,
        &session_mode,
        &action_kind,
        url.as_deref(),
        target_ref.as_deref(),
        selector.as_deref(),
    )?;
    let request_ref = format!(
        "computer_use_lease_request_{}",
        sha256_hex(request_seed.as_bytes())?
            .chars()
            .take(16)
            .collect::<String>()
    );
    let authority_scope = if computer_use_action_is_read_only(&action_kind) {
        format!("computer_use.{lane}.read")
    } else {
        format!("computer_use.{lane}.act")
    };
    let approval_required_before_execution =
        authority_scope.ends_with(".act") && approval_ref.is_none();
    let thread_tool_name = provider
        .as_ref()
        .and_then(|provider| provider.thread_tool_name);
    let observation_retention_mode = optional_json_string(input, &["observation_retention_mode"])
        .unwrap_or_else(|| {
            if lane == "sandboxed_hosted" {
                "no_persistence".to_string()
            } else {
                "prompt_visible_summary_only".to_string()
            }
        });

    let mut thread_tool_input = serde_json::Map::new();
    thread_tool_input.insert("prompt".to_string(), json!(prompt.clone()));
    thread_tool_input.insert("url".to_string(), json!(url.clone()));
    thread_tool_input.insert("action_kind".to_string(), json!(action_kind.clone()));
    thread_tool_input.insert("session_mode".to_string(), json!(session_mode.clone()));
    thread_tool_input.insert("target_ref".to_string(), json!(target_ref.clone()));
    thread_tool_input.insert("selector".to_string(), json!(selector.clone()));
    thread_tool_input.insert("approval_ref".to_string(), json!(approval_ref.clone()));
    thread_tool_input.insert(
        "observation_retention_mode".to_string(),
        json!(observation_retention_mode),
    );
    if lane == "sandboxed_hosted" {
        thread_tool_input.insert(
            "sandbox_provider".to_string(),
            json!(optional_json_string(input, &["sandbox_provider"])
                .unwrap_or_else(|| "local_fixture".to_string())),
        );
        thread_tool_input.insert("sandbox_fixture".to_string(), json!(true));
    }

    let unavailable_reason = if thread_tool_name.is_none() {
        provider
            .as_ref()
            .and_then(|provider| provider.unavailable_reason)
            .unwrap_or(
                "Requested lane is recorded as a governed lease request; no concrete provider adapter is mounted yet.",
            )
    } else {
        ""
    };
    let receipt_ref = format!(
        "receipt_computer_use_lease_request_{}",
        safe_ref_path(&request_ref)
    );
    let selected_provider_id = provider.as_ref().map(|provider| provider.provider_id);
    let selected_provider_kind = provider.as_ref().map(|provider| provider.provider_kind);
    let unavailable_reason_value = if unavailable_reason.is_empty() {
        Value::Null
    } else {
        json!(unavailable_reason)
    };
    let thread_tool_input_value = Value::Object(thread_tool_input);
    let mut evidence_refs = vec![request_ref.clone()];
    if let Some(provider_id) = selected_provider_id {
        evidence_refs.push(provider_id.to_string());
    }
    evidence_refs.extend(
        [
            "computer_use_lease_request_receipt",
            "coding_tool_receipt",
            "wallet.network.authority_boundary",
        ]
        .into_iter()
        .map(ToOwned::to_owned),
    );
    let receipt_refs = vec![receipt_ref.clone()];

    Ok(json!({
        "schema_version": CODING_TOOL_RESULT_SCHEMA_VERSION,
        "object": "ioi.coding_agent_computer_use_lease_request",
        "request_ref": request_ref,
        "workspace_root": workspace_root,
        "lease_request": {
            "prompt": prompt.clone(),
            "lane": lane.clone(),
            "session_mode": session_mode.clone(),
            "action_kind": action_kind,
            "authority_scope": authority_scope,
            "repo_authority_scope": "workspace.read",
            "shared_clipboard_policy": "disabled_until_explicit_approval",
            "artifact_policy": "redacted_trace_artifacts_only",
            "approval_ref": approval_ref,
            "fail_closed_when_unavailable": true,
            "provider_id": selected_provider_id,
            "provider_kind": selected_provider_kind,
            "wallet_network_authority_required_before_execution": approval_required_before_execution
        },
        "thread_tool": {
            "tool_pack": "computer_use",
            "tool_name": thread_tool_name,
            "unavailable_reason": unavailable_reason_value,
            "input": thread_tool_input_value
        },
        "provider_registry": provider_registry,
        "approval_required_before_execution": approval_required_before_execution,
        "wallet_network_authority_boundary": {
            "authority_layer": "wallet.network",
            "required_before_execution": approval_required_before_execution,
            "grant_refs": [],
            "receipt_refs": []
        },
        "evidence_refs": evidence_refs,
        "receipt_refs": receipt_refs,
        "shell_fallback_used": false
    }))
}

fn computer_use_lane_for_input(input: &Value) -> String {
    match optional_json_string(input, &["lane", "computer_use_lane"]).as_deref() {
        Some("visual_gui") => "visual_gui".to_string(),
        Some("sandboxed_hosted") => "sandboxed_hosted".to_string(),
        _ => "native_browser".to_string(),
    }
}

fn computer_use_session_mode_for_input(input: &Value, lane: &str) -> String {
    if let Some(value) = optional_json_string(input, &["session_mode"]) {
        return value;
    }
    match lane {
        "visual_gui" => "visual_fallback".to_string(),
        "sandboxed_hosted" => "local_sandbox".to_string(),
        _ => "owned_hermetic_browser".to_string(),
    }
}

fn computer_use_action_kind_for_input(input: &Value) -> String {
    let value = optional_json_string(input, &["action_kind"])
        .unwrap_or_default()
        .to_ascii_lowercase()
        .replace([' ', '-'], "_");
    match value.as_str() {
        "" => "inspect".to_string(),
        "type" | "input_text" => "type_text".to_string(),
        "keypress" => "key_press".to_string(),
        "click" | "type_text" | "key_press" | "scroll" | "drag" | "hover" | "select" | "upload"
        | "clipboard" | "wait" | "shell" | "mobile_gesture" | "navigate" | "inspect" => value,
        _ => "inspect".to_string(),
    }
}

fn computer_use_action_is_read_only(action_kind: &str) -> bool {
    matches!(action_kind, "inspect" | "hover" | "wait" | "scroll")
}

fn computer_use_provider_registry_report(selected: Option<&ComputerUseProvider>) -> Value {
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

fn computer_use_provider_for_lane(
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
            authority_scopes: &[
                "computer_use.native_browser.read",
                "computer_use.native_browser.act",
            ],
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

fn computer_use_request_seed(
    workspace_root: &str,
    prompt: &str,
    lane: &str,
    session_mode: &str,
    action_kind: &str,
    url: Option<&str>,
    target_ref: Option<&str>,
    selector: Option<&str>,
) -> Result<String, CodingToolComputerUseError> {
    Ok(format!(
        "{{\"workspace_root\":{},\"prompt\":{},\"lane\":{},\"session_mode\":{},\"action_kind\":{},\"url\":{},\"target_ref\":{},\"selector\":{}}}",
        json_literal(Some(workspace_root))?,
        json_literal(Some(prompt))?,
        json_literal(Some(lane))?,
        json_literal(Some(session_mode))?,
        json_literal(Some(action_kind))?,
        json_literal(url)?,
        json_literal(target_ref)?,
        json_literal(selector)?,
    ))
}

fn json_literal(value: Option<&str>) -> Result<String, CodingToolComputerUseError> {
    serde_json::to_string(&value)
        .map_err(|error| CodingToolComputerUseError::new("json_literal_failed", error.to_string()))
}

fn optional_json_string(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn sha256_hex(bytes: &[u8]) -> Result<String, CodingToolComputerUseError> {
    ioi_crypto::algorithms::hash::sha256(bytes)
        .map(hex::encode)
        .map_err(|error| CodingToolComputerUseError::new("sha256_failed", error.to_string()))
}

fn safe_ref_path(value: &str) -> String {
    let text = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '.' || ch == '_' || ch == '-' {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    if text.is_empty() {
        "ref".to_string()
    } else {
        text.chars().take(96).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn request_lease_records_wallet_gated_act_request() {
        let result = build_computer_use_lease_request(
            "/tmp/workspace",
            &json!({
                "prompt": "Open the browser and click the sign in button.",
                "lane": "native_browser",
                "session_mode": "controlled_relaunch",
                "action_kind": "click",
                "url": "https://example.test"
            }),
        )
        .expect("lease request");

        assert_eq!(result["lease_request"]["lane"], "native_browser");
        assert_eq!(
            result["lease_request"]["authority_scope"],
            "computer_use.native_browser.act"
        );
        assert_eq!(result["approval_required_before_execution"], true);
        assert_eq!(
            result["wallet_network_authority_boundary"]["authority_layer"],
            "wallet.network"
        );
        assert_eq!(
            result["thread_tool"]["tool_name"],
            "ioi.computer_use.native_browser"
        );
        assert!(result["request_ref"]
            .as_str()
            .expect("request ref")
            .starts_with("computer_use_lease_request_"));
        assert!(result["receipt_refs"][0]
            .as_str()
            .expect("receipt ref")
            .starts_with("receipt_computer_use_lease_request_"));
    }

    #[test]
    fn request_lease_ignores_retired_aliases() {
        let result = build_computer_use_lease_request(
            "/tmp/workspace",
            &json!({
                "prompt": "Try retired aliases.",
                "computerUseLane": "sandboxed_hosted",
                "actionKind": "click",
                "approvalRef": "approval_legacy",
                "targetRef": "target_retired",
                "sessionMode": "hosted_sandbox",
                "observationRetentionMode": "local_raw_artifacts"
            }),
        )
        .expect("lease request");

        assert_eq!(result["lease_request"]["lane"], "native_browser");
        assert_eq!(result["lease_request"]["action_kind"], "inspect");
        assert_eq!(result["lease_request"]["approval_ref"], Value::Null);
        assert_eq!(result["thread_tool"]["input"]["target_ref"], Value::Null);
        assert_eq!(
            result["thread_tool"]["input"]["session_mode"],
            "owned_hermetic_browser"
        );
        assert_eq!(
            result["thread_tool"]["input"]["observation_retention_mode"],
            "prompt_visible_summary_only"
        );
        assert_eq!(
            result["lease_request"]["authority_scope"],
            "computer_use.native_browser.read"
        );
    }

    #[test]
    fn request_lease_records_unavailable_provider_fail_closed() {
        let result = build_computer_use_lease_request(
            "/tmp/workspace",
            &json!({
                "prompt": "Open a hosted sandbox.",
                "lane": "sandboxed_hosted",
                "session_mode": "hosted_sandbox",
                "sandbox_provider": "local_container",
                "action_kind": "inspect"
            }),
        )
        .expect("lease request");

        assert_eq!(
            result["lease_request"]["provider_id"],
            "ioi.computer_use.sandboxed_hosted.local_container"
        );
        assert_eq!(result["thread_tool"]["tool_name"], Value::Null);
        assert!(result["thread_tool"]["unavailable_reason"]
            .as_str()
            .expect("unavailable reason")
            .contains("no container runtime adapter"));
        assert_eq!(result["approval_required_before_execution"], false);
    }
}
