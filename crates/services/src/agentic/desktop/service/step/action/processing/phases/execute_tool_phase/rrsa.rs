use super::events::emit_execution_contract_receipt_event;
use super::*;
use crate::agentic::web::build_default_search_url;
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::ActionTarget;
use serde_json::{json, Value};
use url::Url;

pub(super) struct RrsaContext<'a> {
    pub service: &'a DesktopAgentService,
    pub agent_state: &'a mut AgentState,
    pub tool: &'a AgentTool,
    pub tool_args: &'a Value,
    pub session_id: [u8; 32],
    pub step_index: u32,
    pub resolved_intent_id: &'a str,
    pub synthesized_payload_hash: Option<String>,
    pub req_hash_hex: &'a str,
    pub policy_decision: &'a str,
    pub success: bool,
    pub error_msg: Option<&'a str>,
    pub history_entry: Option<&'a str>,
    pub trace_visual_hash: Option<[u8; 32]>,
    pub verification_checks: &'a mut Vec<String>,
}

enum RrsaDomain {
    UiBrowser,
    Filesystem,
    Network,
    Wallet,
}

impl RrsaDomain {
    fn as_str(&self) -> &'static str {
        match self {
            Self::UiBrowser => "ui_browser",
            Self::Filesystem => "filesystem",
            Self::Network => "network_web",
            Self::Wallet => "wallet",
        }
    }
}

pub(super) fn record_rrsa_action_evidence(ctx: RrsaContext<'_>) -> Result<(), String> {
    if ctx.req_hash_hex.trim().is_empty() {
        return Ok(());
    }

    let Some(domain) = classify_domain(ctx.tool) else {
        return Ok(());
    };

    let request_binding = format!("sha256:{}", ctx.req_hash_hex);
    record_rrsa_receipt(
        ctx.service,
        ctx.agent_state,
        ctx.verification_checks,
        ctx.session_id,
        ctx.step_index,
        ctx.resolved_intent_id,
        ctx.synthesized_payload_hash.clone(),
        "rrsa_request_binding",
        &request_binding,
        true,
    );

    let firewall_payload = json!({
        "request_hash": request_binding,
        "policy_decision": ctx.policy_decision,
        "domain": domain.as_str(),
    });
    let firewall_binding = commitment_from_value(&firewall_payload)
        .ok_or_else(|| "rrsa firewall binding commitment failed".to_string())?;
    record_rrsa_receipt(
        ctx.service,
        ctx.agent_state,
        ctx.verification_checks,
        ctx.session_id,
        ctx.step_index,
        ctx.resolved_intent_id,
        ctx.synthesized_payload_hash.clone(),
        "rrsa_firewall_decision",
        &firewall_binding,
        true,
    );

    record_rrsa_receipt(
        ctx.service,
        ctx.agent_state,
        ctx.verification_checks,
        ctx.session_id,
        ctx.step_index,
        ctx.resolved_intent_id,
        ctx.synthesized_payload_hash.clone(),
        "rrsa_domain",
        domain.as_str(),
        true,
    );

    match domain {
        RrsaDomain::UiBrowser => {
            let (commitment, source) = if let Some(visual_hash) = ctx.trace_visual_hash {
                (
                    format!("sha256:{}", hex::encode(visual_hash)),
                    "visual_observation",
                )
            } else {
                let payload = json!({
                    "tool_args": ctx.tool_args,
                    "history_entry": ctx.history_entry.unwrap_or_default(),
                    "success": ctx.success,
                    "error": ctx.error_msg.unwrap_or_default(),
                });
                (
                    commitment_from_value(&payload)
                        .ok_or_else(|| "rrsa ui/browser output commitment failed".to_string())?,
                    "execution_output_fallback",
                )
            };

            record_rrsa_receipt(
                ctx.service,
                ctx.agent_state,
                ctx.verification_checks,
                ctx.session_id,
                ctx.step_index,
                ctx.resolved_intent_id,
                ctx.synthesized_payload_hash.clone(),
                "rrsa_output_commitment",
                &commitment,
                true,
            );
            ctx.verification_checks
                .push(format!("rrsa_output_commitment_source={}", source));
        }
        RrsaDomain::Filesystem => {
            let output_payload = json!({
                "tool_args": ctx.tool_args,
                "history_entry": ctx.history_entry.unwrap_or_default(),
                "success": ctx.success,
                "error": ctx.error_msg.unwrap_or_default(),
            });
            let output_commitment = commitment_from_value(&output_payload)
                .ok_or_else(|| "rrsa filesystem output commitment failed".to_string())?;
            record_rrsa_receipt(
                ctx.service,
                ctx.agent_state,
                ctx.verification_checks,
                ctx.session_id,
                ctx.step_index,
                ctx.resolved_intent_id,
                ctx.synthesized_payload_hash.clone(),
                "rrsa_output_commitment",
                &output_commitment,
                true,
            );

            let mut scope_paths = filesystem_scope_paths(ctx.tool_args);
            scope_paths.sort();
            scope_paths.dedup();
            if scope_paths.is_empty() {
                return Err("rrsa filesystem path scope binding missing".to_string());
            }
            let path_scope_commitment = commitment_from_value(&json!({ "paths": scope_paths }))
                .ok_or_else(|| "rrsa filesystem path scope commitment failed".to_string())?;
            record_rrsa_receipt(
                ctx.service,
                ctx.agent_state,
                ctx.verification_checks,
                ctx.session_id,
                ctx.step_index,
                ctx.resolved_intent_id,
                ctx.synthesized_payload_hash.clone(),
                "rrsa_path_scope_binding",
                &path_scope_commitment,
                true,
            );
        }
        RrsaDomain::Network => {
            let url = network_url(ctx.tool, ctx.tool_args)
                .ok_or_else(|| "rrsa network URL binding missing".to_string())?;
            let host = network_host(&url).ok_or_else(|| {
                format!(
                    "rrsa network domain binding failed: unable to resolve host from '{}'",
                    url
                )
            })?;
            let domain_binding = commitment_from_value(&json!({
                "host": host,
                "url": url,
            }))
            .ok_or_else(|| "rrsa network domain binding commitment failed".to_string())?;
            record_rrsa_receipt(
                ctx.service,
                ctx.agent_state,
                ctx.verification_checks,
                ctx.session_id,
                ctx.step_index,
                ctx.resolved_intent_id,
                ctx.synthesized_payload_hash.clone(),
                "rrsa_domain_binding",
                &domain_binding,
                true,
            );

            let output_commitment = commitment_from_value(&json!({
                "history_entry": ctx.history_entry.unwrap_or_default(),
                "success": ctx.success,
                "error": ctx.error_msg.unwrap_or_default(),
            }))
            .ok_or_else(|| "rrsa network output commitment failed".to_string())?;
            record_rrsa_receipt(
                ctx.service,
                ctx.agent_state,
                ctx.verification_checks,
                ctx.session_id,
                ctx.step_index,
                ctx.resolved_intent_id,
                ctx.synthesized_payload_hash.clone(),
                "rrsa_output_commitment",
                &output_commitment,
                true,
            );
        }
        RrsaDomain::Wallet => {
            let target = ctx.tool.target();
            let tx_hash = wallet_tx_hash(ctx.tool_args, ctx.history_entry)
                .ok_or_else(|| "rrsa wallet tx_hash binding missing".to_string())?;
            let tx_hash_binding = commitment_from_value(&json!({
                "tx_hash": tx_hash,
                "target": target.canonical_label(),
            }))
            .ok_or_else(|| "rrsa wallet tx_hash binding commitment failed".to_string())?;
            record_rrsa_receipt(
                ctx.service,
                ctx.agent_state,
                ctx.verification_checks,
                ctx.session_id,
                ctx.step_index,
                ctx.resolved_intent_id,
                ctx.synthesized_payload_hash.clone(),
                "rrsa_tx_hash_binding",
                &tx_hash_binding,
                true,
            );

            let approval_token_ref = wallet_approval_token_ref(ctx.tool_args, ctx.history_entry);
            let approval_required = matches!(target, ActionTarget::WalletSend)
                || ctx
                    .policy_decision
                    .to_ascii_lowercase()
                    .contains("approved");
            if approval_required && approval_token_ref.is_none() {
                return Err("rrsa wallet approval token reference missing".to_string());
            }
            if let Some(approval_token_ref) = approval_token_ref {
                record_rrsa_receipt(
                    ctx.service,
                    ctx.agent_state,
                    ctx.verification_checks,
                    ctx.session_id,
                    ctx.step_index,
                    ctx.resolved_intent_id,
                    ctx.synthesized_payload_hash.clone(),
                    "rrsa_approval_token_ref",
                    &approval_token_ref,
                    true,
                );
            }

            let eei_bundle = wallet_eei_bundle(ctx.tool_args, ctx.history_entry);
            if matches!(target, ActionTarget::WalletSend) && eei_bundle.is_none() {
                return Err("rrsa wallet eei bundle missing".to_string());
            }
            if let Some(eei_bundle) = eei_bundle {
                let eei_bundle_commitment = commitment_from_value(&eei_bundle)
                    .ok_or_else(|| "rrsa wallet eei bundle commitment failed".to_string())?;
                record_rrsa_receipt(
                    ctx.service,
                    ctx.agent_state,
                    ctx.verification_checks,
                    ctx.session_id,
                    ctx.step_index,
                    ctx.resolved_intent_id,
                    ctx.synthesized_payload_hash.clone(),
                    "rrsa_eei_bundle_commitment",
                    &eei_bundle_commitment,
                    true,
                );
            }

            let output_commitment = commitment_from_value(&json!({
                "history_entry": ctx.history_entry.unwrap_or_default(),
                "success": ctx.success,
                "error": ctx.error_msg.unwrap_or_default(),
            }))
            .ok_or_else(|| "rrsa wallet output commitment failed".to_string())?;
            record_rrsa_receipt(
                ctx.service,
                ctx.agent_state,
                ctx.verification_checks,
                ctx.session_id,
                ctx.step_index,
                ctx.resolved_intent_id,
                ctx.synthesized_payload_hash.clone(),
                "rrsa_output_commitment",
                &output_commitment,
                true,
            );
        }
    }

    Ok(())
}

fn classify_domain(tool: &AgentTool) -> Option<RrsaDomain> {
    match tool {
        AgentTool::GuiClick { .. }
        | AgentTool::GuiType { .. }
        | AgentTool::GuiScroll { .. }
        | AgentTool::GuiSnapshot {}
        | AgentTool::GuiClickElement { .. }
        | AgentTool::Computer(_)
        | AgentTool::BrowserNavigate { .. }
        | AgentTool::BrowserSnapshot {}
        | AgentTool::BrowserClick { .. }
        | AgentTool::BrowserClickElement { .. }
        | AgentTool::BrowserSyntheticClick { .. }
        | AgentTool::BrowserScroll { .. }
        | AgentTool::BrowserType { .. }
        | AgentTool::BrowserKey { .. }
        | AgentTool::BrowserFindText { .. }
        | AgentTool::BrowserScreenshot { .. }
        | AgentTool::BrowserWait { .. }
        | AgentTool::BrowserUploadFile { .. }
        | AgentTool::BrowserDropdownOptions { .. }
        | AgentTool::BrowserSelectDropdown { .. }
        | AgentTool::BrowserGoBack { .. }
        | AgentTool::BrowserTabList {}
        | AgentTool::BrowserTabSwitch { .. }
        | AgentTool::BrowserTabClose { .. } => Some(RrsaDomain::UiBrowser),

        AgentTool::FsWrite { .. }
        | AgentTool::FsPatch { .. }
        | AgentTool::FsMove { .. }
        | AgentTool::FsCopy { .. }
        | AgentTool::FsDelete { .. }
        | AgentTool::FsCreateDirectory { .. }
        | AgentTool::FsCreateZip { .. } => Some(RrsaDomain::Filesystem),

        AgentTool::NetFetch { .. }
        | AgentTool::WebSearch { .. }
        | AgentTool::WebRead { .. }
        | AgentTool::MediaExtractTranscript { .. }
        | AgentTool::MediaExtractMultimodalEvidence { .. } => {
            Some(RrsaDomain::Network)
        }

        _ => match tool.target() {
            ActionTarget::WalletSign | ActionTarget::WalletSend => Some(RrsaDomain::Wallet),
            _ => None,
        },
    }
}

fn commitment_from_value(value: &Value) -> Option<String> {
    let canonical = serde_jcs::to_vec(value).ok()?;
    let digest = sha256(&canonical).ok()?;
    Some(format!("sha256:{}", hex::encode(digest.as_ref())))
}

fn filesystem_scope_paths(tool_args: &Value) -> Vec<String> {
    const PATH_KEYS: [&str; 4] = [
        "path",
        "source_path",
        "destination_path",
        "destination_zip_path",
    ];
    let mut out = Vec::<String>::new();
    for key in PATH_KEYS {
        if let Some(value) = tool_args.get(key).and_then(|v| v.as_str()) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                out.push(trimmed.to_string());
            }
        }
    }
    out
}

fn network_url(tool: &AgentTool, tool_args: &Value) -> Option<String> {
    if let Some(url) = tool_args.get("url").and_then(|value| value.as_str()) {
        let trimmed = url.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    match tool {
        AgentTool::WebSearch { query, .. } => Some(build_default_search_url(query)),
        _ => None,
    }
}

fn network_host(raw_url: &str) -> Option<String> {
    let parsed = Url::parse(raw_url).ok()?;
    parsed
        .host_str()
        .map(|host| host.to_ascii_lowercase())
        .filter(|host| !host.trim().is_empty())
}

fn wallet_tx_hash(tool_args: &Value, history_entry: Option<&str>) -> Option<String> {
    const HASH_KEYS: [&str; 5] = [
        "tx_hash",
        "txHash",
        "transaction_hash",
        "transactionHash",
        "hash",
    ];
    extract_non_empty_string_field(tool_args, &HASH_KEYS).or_else(|| {
        history_entry_json(history_entry)
            .as_ref()
            .and_then(|entry| extract_non_empty_string_field(entry, &HASH_KEYS))
    })
}

fn wallet_approval_token_ref(tool_args: &Value, history_entry: Option<&str>) -> Option<String> {
    const REF_KEYS: [&str; 4] = [
        "approval_token_ref",
        "approvalTokenRef",
        "approval_ref",
        "approvalRef",
    ];
    extract_non_empty_string_field(tool_args, &REF_KEYS).or_else(|| {
        history_entry_json(history_entry)
            .as_ref()
            .and_then(|entry| extract_non_empty_string_field(entry, &REF_KEYS))
    })
}

fn wallet_eei_bundle(tool_args: &Value, history_entry: Option<&str>) -> Option<Value> {
    const EEI_KEYS: [&str; 4] = [
        "eei_bundle",
        "eeiBundle",
        "external_evidence_bundle",
        "externalEvidenceBundle",
    ];
    if let Some(value) = extract_field(tool_args, &EEI_KEYS) {
        if let Some(bundle) = normalize_eei_bundle(value) {
            return Some(bundle);
        }
    }
    history_entry_json(history_entry)
        .as_ref()
        .and_then(|entry| extract_field(entry, &EEI_KEYS))
        .and_then(normalize_eei_bundle)
}

fn history_entry_json(history_entry: Option<&str>) -> Option<Value> {
    let raw = history_entry?.trim();
    if raw.is_empty() {
        return None;
    }
    let parsed = serde_json::from_str::<Value>(raw).ok()?;
    if parsed.is_object() {
        Some(parsed)
    } else {
        None
    }
}

fn extract_field<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a Value> {
    for key in keys {
        if let Some(found) = value.get(*key) {
            return Some(found);
        }
    }
    None
}

fn extract_non_empty_string_field(value: &Value, keys: &[&str]) -> Option<String> {
    let field = extract_field(value, keys)?;
    let raw = field.as_str()?.trim();
    if raw.is_empty() {
        None
    } else {
        Some(raw.to_string())
    }
}

fn normalize_eei_bundle(value: &Value) -> Option<Value> {
    match value {
        Value::Object(_) | Value::Array(_) => Some(value.clone()),
        Value::String(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                None
            } else if let Ok(parsed) = serde_json::from_str::<Value>(trimmed) {
                Some(parsed)
            } else {
                Some(json!({ "reference": trimmed }))
            }
        }
        _ => None,
    }
}

fn record_rrsa_receipt(
    service: &DesktopAgentService,
    agent_state: &mut AgentState,
    verification_checks: &mut Vec<String>,
    session_id: [u8; 32],
    step_index: u32,
    resolved_intent_id: &str,
    synthesized_payload_hash: Option<String>,
    key: &str,
    value: &str,
    satisfied: bool,
) {
    mark_execution_receipt_with_value(&mut agent_state.tool_execution_log, key, value.to_string());
    verification_checks.push(receipt_marker(key));
    emit_execution_contract_receipt_event(
        service,
        session_id,
        step_index,
        resolved_intent_id,
        "execution",
        key,
        satisfied,
        value,
        None,
        None,
        synthesized_payload_hash,
    );
}

#[cfg(test)]
mod tests {
    use super::{
        classify_domain, filesystem_scope_paths, network_host, network_url,
        wallet_approval_token_ref, wallet_eei_bundle, wallet_tx_hash, RrsaDomain,
    };
    use ioi_types::app::agentic::AgentTool;
    use serde_json::json;

    #[test]
    fn classify_domain_maps_fs_write_to_filesystem() {
        let tool = AgentTool::FsWrite {
            path: "a.txt".to_string(),
            content: "hello".to_string(),
            line_number: None,
        };
        assert!(matches!(
            classify_domain(&tool),
            Some(RrsaDomain::Filesystem)
        ));
    }

    #[test]
    fn classify_domain_maps_net_fetch_to_network() {
        let tool = AgentTool::NetFetch {
            url: "https://example.com".to_string(),
            max_chars: None,
        };
        assert!(matches!(classify_domain(&tool), Some(RrsaDomain::Network)));
    }

    #[test]
    fn network_url_uses_tool_argument_when_present() {
        let tool = AgentTool::WebSearch {
            query: "internet of intelligence".to_string(),
            query_contract: None,
            retrieval_contract: None,
            limit: None,
            url: None,
        };
        let args = json!({ "url": "https://example.org/path?q=1" });
        assert_eq!(
            network_url(&tool, &args).as_deref(),
            Some("https://example.org/path?q=1")
        );
    }

    #[test]
    fn network_url_falls_back_to_web_search_serp_url() {
        let tool = AgentTool::WebSearch {
            query: "internet of intelligence".to_string(),
            query_contract: None,
            retrieval_contract: None,
            limit: Some(5),
            url: None,
        };
        let args = json!({});
        let resolved = network_url(&tool, &args).expect("web search fallback URL");
        assert!(resolved.starts_with("https://"));
        assert!(resolved.contains("internet+of+intelligence"));
    }

    #[test]
    fn network_host_normalizes_case() {
        let host = network_host("https://WWW.Example.COM/path").expect("host");
        assert_eq!(host, "www.example.com");
    }

    #[test]
    fn filesystem_scope_paths_extracts_primary_and_secondary_paths() {
        let args = json!({
            "path": "/tmp/a.txt",
            "source_path": "/tmp/src.txt",
            "destination_path": "/tmp/dst.txt",
            "destination_zip_path": "/tmp/archive.zip"
        });
        let mut paths = filesystem_scope_paths(&args);
        paths.sort();
        assert_eq!(
            paths,
            vec![
                "/tmp/a.txt".to_string(),
                "/tmp/archive.zip".to_string(),
                "/tmp/dst.txt".to_string(),
                "/tmp/src.txt".to_string()
            ]
        );
    }

    #[test]
    fn wallet_tx_hash_prefers_tool_args_then_history_json() {
        let args = json!({ "tx_hash": "0xabc123" });
        let history = Some(r#"{"tx_hash":"0xdef456"}"#);
        assert_eq!(wallet_tx_hash(&args, history).as_deref(), Some("0xabc123"));

        let args_without_hash = json!({});
        assert_eq!(
            wallet_tx_hash(&args_without_hash, history).as_deref(),
            Some("0xdef456")
        );
    }

    #[test]
    fn wallet_approval_ref_extracts_from_args() {
        let args = json!({ "approval_token_ref": "sha256:deadbeef" });
        assert_eq!(
            wallet_approval_token_ref(&args, None).as_deref(),
            Some("sha256:deadbeef")
        );
    }

    #[test]
    fn wallet_eei_bundle_accepts_object_and_json_string() {
        let args_obj = json!({
            "eei_bundle": {
                "chain": "ethereum",
                "block": 12345
            }
        });
        assert!(wallet_eei_bundle(&args_obj, None).is_some());

        let args_str = json!({
            "eei_bundle": "{\"chain\":\"solana\",\"slot\":99}"
        });
        let bundle = wallet_eei_bundle(&args_str, None).expect("bundle");
        assert_eq!(bundle.get("chain").and_then(|v| v.as_str()), Some("solana"));
    }
}
