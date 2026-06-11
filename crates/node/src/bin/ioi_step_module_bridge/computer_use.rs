use serde_json::{json, Value};

use super::computer_use_provider::{
    computer_use_provider_for_lane, computer_use_provider_registry_report,
};

const CODING_TOOL_RESULT_SCHEMA_VERSION: &str = "ioi.runtime.coding-tool-result.v1";

pub(super) fn build_computer_use_lease_request(
    workspace_root: &str,
    input: &Value,
) -> Result<Value, String> {
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

fn computer_use_request_seed(
    workspace_root: &str,
    prompt: &str,
    lane: &str,
    session_mode: &str,
    action_kind: &str,
    url: Option<&str>,
    target_ref: Option<&str>,
    selector: Option<&str>,
) -> Result<String, String> {
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

fn json_literal(value: Option<&str>) -> Result<String, String> {
    serde_json::to_string(&value).map_err(|error| error.to_string())
}

fn optional_json_string(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn sha256_hex(bytes: &[u8]) -> Result<String, String> {
    ioi_crypto::algorithms::hash::sha256(bytes)
        .map(hex::encode)
        .map_err(|error| error.to_string())
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
