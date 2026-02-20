use super::{DesktopAgentService, ServiceCallContext};
use crate::agentic::desktop::execution::ToolExecutor;
use crate::agentic::desktop::service::step::action::{
    is_search_results_url, search_query_from_url,
};
use crate::agentic::desktop::service::step::helpers::{
    is_live_external_research_goal, is_mailbox_connector_goal,
};
use crate::agentic::desktop::service::step::queue::WEB_PIPELINE_SEARCH_LIMIT;
use crate::agentic::desktop::types::{AgentState, RecordedMessage};
use crate::wallet_network::mail_ontology::{
    parse_confidence_band, parse_volume_band, spam_confidence_band, MAIL_ONTOLOGY_SIGNAL_VERSION,
    SPAM_HIGH_CONFIDENCE_THRESHOLD_BPS,
};
use crate::wallet_network::LeaseActionReplayWindowState;
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_api::vm::drivers::os::OsDriver;
use ioi_drivers::mcp::McpManager;
use ioi_scs::FrameType;
use ioi_types::app::agentic::{AgentTool, IntentScopeProfile, ResolvedIntentState};
use ioi_types::app::wallet_network::{
    MailDeleteSpamParams, MailDeleteSpamReceipt, MailListRecentParams, MailListRecentReceipt,
    MailReadLatestParams, MailReadLatestReceipt, MailReplyParams, MailReplyReceipt,
    SessionChannelRecord, SessionChannelState, SessionLease,
};
use ioi_types::codec;
use ioi_types::error::TransactionError;
use serde_json::{json, Map as JsonMap, Value as JsonValue};
use std::sync::Arc;

mod approvals;
mod focus;
mod pii;

pub(crate) use pii::{
    build_pii_review_request_for_tool, emit_pii_review_requested, persist_pii_review_request,
};

fn normalize_web_research_tool_call(
    tool: &mut AgentTool,
    resolved_intent: Option<&ResolvedIntentState>,
    fallback_query: &str,
) {
    let mailbox_connector_goal = is_mailbox_connector_goal(fallback_query);
    if mailbox_connector_goal {
        return;
    }
    let is_web_research_scope = resolved_intent
        .map(|resolved| resolved.scope == IntentScopeProfile::WebResearch)
        .unwrap_or(false);
    let is_live_external_research = is_live_external_research_goal(fallback_query);
    let is_effective_web_research = is_web_research_scope || is_live_external_research;
    if !is_effective_web_research {
        return;
    }

    match tool {
        AgentTool::BrowserNavigate { url } => {
            if !is_search_results_url(url) {
                return;
            }

            let query = search_query_from_url(url)
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| fallback_query.trim().to_string());
            if query.trim().is_empty() {
                return;
            }

            *tool = AgentTool::WebSearch {
                query: query.clone(),
                limit: Some(WEB_PIPELINE_SEARCH_LIMIT),
                url: Some(crate::agentic::web::build_default_search_url(&query)),
            };
        }
        AgentTool::WebSearch { query, limit, url } => {
            let normalized_query = if query.trim().is_empty() {
                fallback_query.trim().to_string()
            } else {
                query.trim().to_string()
            };
            if normalized_query.is_empty() {
                return;
            }
            *query = normalized_query.clone();
            *limit = Some(WEB_PIPELINE_SEARCH_LIMIT);
            if url
                .as_ref()
                .map(|value| value.trim().is_empty())
                .unwrap_or(true)
            {
                *url = Some(crate::agentic::web::build_default_search_url(
                    &normalized_query,
                ));
            }
        }
        AgentTool::MemorySearch { query } => {
            let normalized_query = if query.trim().is_empty() {
                fallback_query.trim().to_string()
            } else {
                query.trim().to_string()
            };
            if normalized_query.is_empty() {
                return;
            }

            // WebResearch is expected to gather fresh external evidence; avoid
            // memory-only retrieval loops by pivoting memory search to web search.
            *tool = AgentTool::WebSearch {
                query: normalized_query.clone(),
                limit: Some(WEB_PIPELINE_SEARCH_LIMIT),
                url: Some(crate::agentic::web::build_default_search_url(
                    &normalized_query,
                )),
            };
        }
        _ => {}
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WalletMailToolMethod {
    ReadLatest,
    ListRecent,
    DeleteSpam,
    Reply,
}

impl WalletMailToolMethod {
    fn method_name(self) -> &'static str {
        match self {
            Self::ReadLatest => "mail_read_latest@v1",
            Self::ListRecent => "mail_list_recent@v1",
            Self::DeleteSpam => "mail_delete_spam@v1",
            Self::Reply => "mail_reply@v1",
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct InferredMailBinding {
    channel_id: [u8; 32],
    lease_id: [u8; 32],
}

const CHANNEL_PREFIX: &[u8] = b"channel::";
const LEASE_PREFIX: &[u8] = b"lease::";
const LEASE_ACTION_WINDOW_PREFIX: &[u8] = b"lease_action_window::";
const MAIL_READ_RECEIPT_PREFIX: &[u8] = b"mail_read_receipt::";
const MAIL_LIST_RECEIPT_PREFIX: &[u8] = b"mail_list_receipt::";
const MAIL_DELETE_RECEIPT_PREFIX: &[u8] = b"mail_delete_receipt::";
const MAIL_REPLY_RECEIPT_PREFIX: &[u8] = b"mail_reply_receipt::";

const MAIL_READ_CAPABILITY_ALIASES: &[&str] =
    &["mail.read.latest", "mail:read", "mail.read", "email:read"];
const MAIL_LIST_CAPABILITY_ALIASES: &[&str] = &[
    "mail.list.recent",
    "mail:list",
    "mail.list",
    "email:list",
    "mail.read.latest",
    "mail:read",
    "mail.read",
    "email:read",
];
const MAIL_DELETE_CAPABILITY_ALIASES: &[&str] = &[
    "mail.delete.spam",
    "mail.delete",
    "mail.write",
    "mail:write",
    "email:write",
    "mail.modify",
    "email:modify",
];
const MAIL_REPLY_CAPABILITY_ALIASES: &[&str] = &[
    "mail.reply",
    "mail.send",
    "mail.write",
    "mail:write",
    "email:write",
    "mail.compose",
    "email:compose",
    "mail.modify",
    "email:modify",
];

fn wallet_mail_method_from_tool_name(name: &str) -> Option<WalletMailToolMethod> {
    let normalized = name.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "wallet_network__mail_read_latest" | "wallet_mail_read_latest" | "mail__read_latest" => {
            Some(WalletMailToolMethod::ReadLatest)
        }
        "wallet_network__mail_list_recent" | "wallet_mail_list_recent" | "mail__list_recent" => {
            Some(WalletMailToolMethod::ListRecent)
        }
        "wallet_network__mail_delete_spam" | "wallet_mail_delete_spam" | "mail__delete_spam" => {
            Some(WalletMailToolMethod::DeleteSpam)
        }
        "wallet_network__mail_reply" | "wallet_mail_reply" | "mail__reply" => {
            Some(WalletMailToolMethod::Reply)
        }
        _ => None,
    }
}

fn channel_storage_key(channel_id: &[u8; 32]) -> Vec<u8> {
    [CHANNEL_PREFIX, channel_id.as_slice()].concat()
}

fn lease_action_window_storage_key(channel_id: &[u8; 32], lease_id: &[u8; 32]) -> Vec<u8> {
    [
        LEASE_ACTION_WINDOW_PREFIX,
        channel_id.as_slice(),
        b"::",
        lease_id.as_slice(),
    ]
    .concat()
}

fn mail_read_receipt_storage_key(operation_id: &[u8; 32]) -> Vec<u8> {
    [MAIL_READ_RECEIPT_PREFIX, operation_id.as_slice()].concat()
}

fn mail_list_receipt_storage_key(operation_id: &[u8; 32]) -> Vec<u8> {
    [MAIL_LIST_RECEIPT_PREFIX, operation_id.as_slice()].concat()
}

fn mail_delete_receipt_storage_key(operation_id: &[u8; 32]) -> Vec<u8> {
    [MAIL_DELETE_RECEIPT_PREFIX, operation_id.as_slice()].concat()
}

fn mail_reply_receipt_storage_key(operation_id: &[u8; 32]) -> Vec<u8> {
    [MAIL_REPLY_RECEIPT_PREFIX, operation_id.as_slice()].concat()
}

fn capability_aliases(method: WalletMailToolMethod) -> &'static [&'static str] {
    match method {
        WalletMailToolMethod::ReadLatest => MAIL_READ_CAPABILITY_ALIASES,
        WalletMailToolMethod::ListRecent => MAIL_LIST_CAPABILITY_ALIASES,
        WalletMailToolMethod::DeleteSpam => MAIL_DELETE_CAPABILITY_ALIASES,
        WalletMailToolMethod::Reply => MAIL_REPLY_CAPABILITY_ALIASES,
    }
}

fn capability_matches(method: WalletMailToolMethod, capabilities: &[String]) -> bool {
    capabilities.iter().any(|capability| {
        let normalized = capability.trim().to_ascii_lowercase();
        capability_aliases(method)
            .iter()
            .any(|alias| normalized == *alias)
    })
}

fn normalize_mailbox(mailbox: &str) -> String {
    let trimmed = mailbox.trim();
    if trimmed.is_empty() {
        "primary".to_string()
    } else {
        trimmed.to_ascii_lowercase()
    }
}

fn mailbox_constraint_matches(constraint: Option<&String>, mailbox: &str) -> bool {
    constraint
        .map(|value| normalize_mailbox(value) == normalize_mailbox(mailbox))
        .unwrap_or(true)
}

fn extract_dynamic_args_object(arguments: &JsonValue) -> Result<JsonMap<String, JsonValue>, TransactionError> {
    let to_object = |value: JsonValue| -> Result<JsonMap<String, JsonValue>, TransactionError> {
        value.as_object().cloned().ok_or_else(|| {
            TransactionError::Invalid(
                "wallet mail tool arguments must encode a JSON object".to_string(),
            )
        })
    };

    if let Some(params_value) = arguments.get("params") {
        match params_value {
            JsonValue::Null => Ok(JsonMap::new()),
            JsonValue::Object(map) => Ok(map.clone()),
            JsonValue::String(raw) => {
                let trimmed = raw.trim();
                if trimmed.is_empty() {
                    return Ok(JsonMap::new());
                }
                let decoded: JsonValue = serde_json::from_str(trimmed).map_err(|e| {
                    TransactionError::Invalid(format!(
                        "wallet mail tool arguments.params must be valid JSON: {}",
                        e
                    ))
                })?;
                to_object(decoded)
            }
            _ => Err(TransactionError::Invalid(
                "wallet mail tool arguments.params must be object|string|null".to_string(),
            )),
        }
    } else if let Some(map) = arguments.as_object() {
        Ok(map.clone())
    } else {
        Ok(JsonMap::new())
    }
}

fn pick_string<'a>(args: &'a JsonMap<String, JsonValue>, keys: &[&str]) -> Option<&'a str> {
    keys.iter().find_map(|key| args.get(*key)?.as_str())
}

fn pick_u64(args: &JsonMap<String, JsonValue>, keys: &[&str]) -> Option<u64> {
    keys.iter().find_map(|key| {
        let value = args.get(*key)?;
        if let Some(parsed) = value.as_u64() {
            return Some(parsed);
        }
        if let Some(text) = value.as_str() {
            return text.trim().parse::<u64>().ok();
        }
        None
    })
}

fn pick_u32(args: &JsonMap<String, JsonValue>, keys: &[&str]) -> Option<u32> {
    pick_u64(args, keys).and_then(|value| u32::try_from(value).ok())
}

fn decode_hex_32(label: &str, raw: &str) -> Result<[u8; 32], TransactionError> {
    let trimmed = raw.trim().trim_start_matches("0x");
    let decoded = hex::decode(trimmed).map_err(|e| {
        TransactionError::Invalid(format!("{} must be 32-byte hex: {}", label, e))
    })?;
    if decoded.len() != 32 {
        return Err(TransactionError::Invalid(format!(
            "{} must be exactly 32 bytes (hex len 64)",
            label
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded);
    Ok(out)
}

fn pick_hex_32(
    args: &JsonMap<String, JsonValue>,
    keys: &[&str],
) -> Result<Option<[u8; 32]>, TransactionError> {
    for key in keys {
        let Some(value) = args.get(*key) else {
            continue;
        };
        if let Some(text) = value.as_str() {
            return decode_hex_32(key, text).map(Some);
        }
    }
    Ok(None)
}

fn compute_sha256_id(seed: &str) -> [u8; 32] {
    if let Ok(hash) = ioi_crypto::algorithms::hash::sha256(seed.as_bytes()) {
        let mut out = [0u8; 32];
        out.copy_from_slice(hash.as_ref());
        if out != [0u8; 32] {
            return out;
        }
    }
    let mut fallback = [0u8; 32];
    fallback[0] = 1;
    fallback
}

fn infer_next_op_seq(state: &dyn StateAccess, channel_id: [u8; 32], lease_id: [u8; 32]) -> u64 {
    let key = lease_action_window_storage_key(&channel_id, &lease_id);
    state
        .get(&key)
        .ok()
        .flatten()
        .and_then(|bytes| codec::from_bytes_canonical::<LeaseActionReplayWindowState>(&bytes).ok())
        .map(|window| window.highest_seq.saturating_add(1).max(1))
        .unwrap_or(1)
}

fn infer_mail_binding(
    state: &dyn StateAccess,
    method: WalletMailToolMethod,
    signer_account_id: [u8; 32],
    mailbox_hint: &str,
    now_ms: u64,
) -> Result<InferredMailBinding, TransactionError> {
    let mailbox = normalize_mailbox(mailbox_hint);
    let mut best: Option<(SessionLease, SessionChannelRecord)> = None;

    let scan = state
        .prefix_scan(LEASE_PREFIX)
        .map_err(|e| TransactionError::State(e))?;
    for row in scan {
        let Ok((_, value)) = row else {
            continue;
        };
        let Ok(lease) = codec::from_bytes_canonical::<SessionLease>(&value) else {
            continue;
        };
        if lease.audience != signer_account_id || now_ms > lease.expires_at_ms {
            continue;
        }
        if !capability_matches(method, &lease.capability_subset) {
            continue;
        }
        if !mailbox_constraint_matches(lease.constraints_subset.get("mailbox"), &mailbox) {
            continue;
        }

        let channel_key = channel_storage_key(&lease.channel_id);
        let Some(channel_bytes) = state.get(&channel_key).map_err(TransactionError::State)? else {
            continue;
        };
        let Ok(channel) = codec::from_bytes_canonical::<SessionChannelRecord>(&channel_bytes) else {
            continue;
        };
        if channel.state != SessionChannelState::Open || now_ms > channel.envelope.expires_at_ms {
            continue;
        }
        if !capability_matches(method, &channel.envelope.capability_set) {
            continue;
        }
        if !mailbox_constraint_matches(channel.envelope.constraints.get("mailbox"), &mailbox) {
            continue;
        }

        let replace = best
            .as_ref()
            .map(|(current_lease, _)| lease.issued_at_ms >= current_lease.issued_at_ms)
            .unwrap_or(true);
        if replace {
            best = Some((lease, channel));
        }
    }

    let Some((lease, _channel)) = best else {
        return Err(TransactionError::Invalid(format!(
            "no wallet mail lease binding available for method '{}' (mailbox='{}')",
            method.method_name(),
            mailbox
        )));
    };

    Ok(InferredMailBinding {
        channel_id: lease.channel_id,
        lease_id: lease.lease_id,
    })
}

fn op_nonce_from_operation(operation_id: [u8; 32], step_index: u32) -> [u8; 32] {
    let mut nonce = operation_id;
    nonce[0] ^= (step_index & 0xFF) as u8;
    nonce[1] ^= ((step_index >> 8) & 0xFF) as u8;
    if nonce == [0u8; 32] {
        nonce[0] = 1;
    }
    nonce
}

fn civil_date_from_days(days_since_epoch: i64) -> (i64, i64, i64) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if month <= 2 { 1 } else { 0 };
    (year, month, day)
}

fn iso_datetime_from_unix_ms(unix_ms: u64) -> String {
    let days_since_epoch = (unix_ms / 86_400_000) as i64;
    let (year, month, day) = civil_date_from_days(days_since_epoch);
    let ms_of_day = unix_ms % 86_400_000;
    let hour = ms_of_day / 3_600_000;
    let minute = (ms_of_day % 3_600_000) / 60_000;
    let second = (ms_of_day % 60_000) / 1_000;
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hour, minute, second
    )
}

fn truncate_chars(input: &str, max_chars: usize) -> String {
    if input.chars().count() <= max_chars {
        return input.to_string();
    }
    input.chars().take(max_chars).collect::<String>() + "..."
}

async fn try_execute_wallet_mail_dynamic_tool(
    state: &mut dyn StateAccess,
    call_context: ServiceCallContext<'_>,
    dynamic_tool: &JsonValue,
    session_id: [u8; 32],
    step_index: u32,
) -> Result<Option<(bool, Option<String>, Option<String>)>, TransactionError> {
    let Some(tool_name) = dynamic_tool.get("name").and_then(|value| value.as_str()) else {
        return Ok(None);
    };
    let Some(method) = wallet_mail_method_from_tool_name(tool_name) else {
        return Ok(None);
    };

    let wallet_service = call_context
        .services
        .services()
        .find(|service| service.id() == "wallet_network")
        .cloned()
        .ok_or_else(|| {
            TransactionError::Invalid(
                "wallet_network service is not active in the ServiceDirectory".to_string(),
            )
        })?;

    let arguments = dynamic_tool
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| JsonValue::Object(JsonMap::new()));
    let args = extract_dynamic_args_object(&arguments)?;

    let now_ms = call_context.block_timestamp / 1_000_000;
    let mailbox_hint = pick_string(&args, &["mailbox", "mailbox_name", "mailboxName"])
        .map(normalize_mailbox)
        .unwrap_or_else(|| {
            if matches!(method, WalletMailToolMethod::DeleteSpam) {
                "spam".to_string()
            } else {
                "primary".to_string()
            }
        });

    let channel_id = pick_hex_32(&args, &["channel_id", "channelId"])?;
    let lease_id = pick_hex_32(&args, &["lease_id", "leaseId"])?;
    let inferred = if channel_id.is_none() || lease_id.is_none() {
        Some(infer_mail_binding(
            state,
            method,
            call_context.signer_account_id.0,
            &mailbox_hint,
            now_ms,
        )?)
    } else {
        None
    };
    let channel_id = channel_id
        .or(inferred.map(|binding| binding.channel_id))
        .ok_or_else(|| {
            TransactionError::Invalid("unable to resolve wallet mail channel_id".to_string())
        })?;
    let lease_id = lease_id
        .or(inferred.map(|binding| binding.lease_id))
        .ok_or_else(|| {
            TransactionError::Invalid("unable to resolve wallet mail lease_id".to_string())
        })?;

    let op_seq = pick_u64(&args, &["op_seq", "opSeq"])
        .filter(|value| *value >= 1)
        .unwrap_or_else(|| infer_next_op_seq(state, channel_id, lease_id));
    let operation_id = pick_hex_32(&args, &["operation_id", "operationId"])?.unwrap_or_else(|| {
        compute_sha256_id(&format!(
            "{}:{}:{}:{}:{}",
            hex::encode(session_id),
            step_index,
            method.method_name(),
            op_seq,
            now_ms
        ))
    });
    let op_nonce =
        pick_hex_32(&args, &["op_nonce", "opNonce"])?.unwrap_or_else(|| op_nonce_from_operation(operation_id, step_index));
    let requested_at_ms = pick_u64(&args, &["requested_at_ms", "requestedAtMs"]).unwrap_or(now_ms);

    let (params_bytes, receipt_operation_id) = match method {
        WalletMailToolMethod::ReadLatest => {
            let params = MailReadLatestParams {
                operation_id,
                channel_id,
                lease_id,
                op_seq,
                op_nonce: Some(op_nonce),
                mailbox: mailbox_hint.clone(),
                requested_at_ms,
            };
            (codec::to_bytes_canonical(&params)?, params.operation_id)
        }
        WalletMailToolMethod::ListRecent => {
            let params = MailListRecentParams {
                operation_id,
                channel_id,
                lease_id,
                op_seq,
                op_nonce: Some(op_nonce),
                mailbox: mailbox_hint.clone(),
                limit: pick_u32(&args, &["limit"]).unwrap_or(25).clamp(1, 200),
                requested_at_ms,
            };
            (codec::to_bytes_canonical(&params)?, params.operation_id)
        }
        WalletMailToolMethod::DeleteSpam => {
            let params = MailDeleteSpamParams {
                operation_id,
                channel_id,
                lease_id,
                op_seq,
                op_nonce: Some(op_nonce),
                mailbox: mailbox_hint.clone(),
                max_delete: pick_u32(&args, &["max_delete", "maxDelete"]).unwrap_or(25),
                requested_at_ms,
            };
            (codec::to_bytes_canonical(&params)?, params.operation_id)
        }
        WalletMailToolMethod::Reply => {
            let to = pick_string(&args, &["to"])
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    TransactionError::Invalid(
                        "wallet_network__mail_reply requires non-empty 'to'".to_string(),
                    )
                })?
                .to_string();
            let subject = pick_string(&args, &["subject"])
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    TransactionError::Invalid(
                        "wallet_network__mail_reply requires non-empty 'subject'".to_string(),
                    )
                })?
                .to_string();
            let body = pick_string(&args, &["body"])
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    TransactionError::Invalid(
                        "wallet_network__mail_reply requires non-empty 'body'".to_string(),
                    )
                })?
                .to_string();
            let reply_to_message_id = pick_string(
                &args,
                &["reply_to_message_id", "replyToMessageId"],
            )
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string);

            let params = MailReplyParams {
                operation_id,
                channel_id,
                lease_id,
                op_seq,
                op_nonce: Some(op_nonce),
                mailbox: mailbox_hint.clone(),
                to,
                subject,
                body,
                reply_to_message_id,
                requested_at_ms,
            };
            (codec::to_bytes_canonical(&params)?, params.operation_id)
        }
    };

    let mut wallet_ctx = TxContext {
        block_height: call_context.block_height,
        block_timestamp: call_context.block_timestamp,
        chain_id: call_context.chain_id,
        signer_account_id: call_context.signer_account_id,
        services: call_context.services,
        simulation: call_context.simulation,
        is_internal: call_context.is_internal,
    };

    if let Err(error) = wallet_service
        .handle_service_call(
            state,
            method.method_name(),
            &params_bytes,
            &mut wallet_ctx,
        )
        .await
    {
        return Ok(Some((
            false,
            None,
            Some(format!(
                "ERROR_CLASS=UnexpectedState wallet_network dynamic call '{}' failed: {}",
                method.method_name(),
                error
            )),
        )));
    }

    let output = match method {
        WalletMailToolMethod::ReadLatest => {
            let receipt_key = mail_read_receipt_storage_key(&receipt_operation_id);
            let receipt_bytes = state.get(&receipt_key).map_err(TransactionError::State)?.ok_or_else(|| {
                TransactionError::Invalid("wallet_network read receipt missing after execution".to_string())
            })?;
            let receipt: MailReadLatestReceipt = codec::from_bytes_canonical(&receipt_bytes)?;
            let message_spam_band = if receipt.message.spam_confidence_band.trim().is_empty() {
                spam_confidence_band(receipt.message.spam_confidence_bps).to_string()
            } else {
                receipt.message.spam_confidence_band.clone()
            };
            json!({
                "operation": method.method_name(),
                "mailbox": receipt.mailbox,
                "executed_at_utc": iso_datetime_from_unix_ms(receipt.executed_at_ms),
                "message": {
                    "message_id": receipt.message.message_id,
                    "from": receipt.message.from,
                    "subject": receipt.message.subject,
                    "received_at_ms": receipt.message.received_at_ms,
                    "received_at_utc": iso_datetime_from_unix_ms(receipt.message.received_at_ms),
                    "preview": truncate_chars(&receipt.message.preview, 280),
                    "spam_confidence_bps": receipt.message.spam_confidence_bps,
                    "spam_confidence_band": message_spam_band,
                    "spam_signal_tags": receipt.message.spam_signal_tags,
                },
                "citation": format!(
                    "imap://{}/{}",
                    normalize_mailbox(&receipt.mailbox),
                    receipt.message.message_id
                ),
            })
            .to_string()
        }
        WalletMailToolMethod::ListRecent => {
            let receipt_key = mail_list_receipt_storage_key(&receipt_operation_id);
            let receipt_bytes = state.get(&receipt_key).map_err(TransactionError::State)?.ok_or_else(|| {
                TransactionError::Invalid("wallet_network list receipt missing after execution".to_string())
            })?;
            let receipt: MailListRecentReceipt = codec::from_bytes_canonical(&receipt_bytes)?;
            let mailbox = receipt.mailbox.clone();
            let requested_limit = if receipt.requested_limit == 0 {
                receipt.messages.len() as u32
            } else {
                receipt.requested_limit
            };
            let evaluated_count = if receipt.evaluated_count == 0 {
                receipt.messages.len() as u32
            } else {
                receipt.evaluated_count
            };
            let parse_confidence_bps = if receipt.parse_confidence_bps == 0 {
                if evaluated_count == 0 {
                    10_000
                } else {
                    ((receipt.messages.len() as u32).saturating_mul(10_000) / evaluated_count.max(1))
                        as u16
                }
            } else {
                receipt.parse_confidence_bps
            };
            let parse_volume_band_value = if receipt.parse_volume_band.trim().is_empty() {
                parse_volume_band(receipt.messages.len()).to_string()
            } else {
                receipt.parse_volume_band.clone()
            };
            let ontology_version = if receipt.ontology_version.trim().is_empty() {
                MAIL_ONTOLOGY_SIGNAL_VERSION.to_string()
            } else {
                receipt.ontology_version.clone()
            };
            let mut high_confidence_spam_candidates = 0u32;
            let mut high_confidence_non_spam_candidates = 0u32;
            let messages = receipt
                .messages
                .into_iter()
                .map(|message| {
                    let spam_band = if message.spam_confidence_band.trim().is_empty() {
                        spam_confidence_band(message.spam_confidence_bps).to_string()
                    } else {
                        message.spam_confidence_band.clone()
                    };
                    if message.spam_confidence_bps >= SPAM_HIGH_CONFIDENCE_THRESHOLD_BPS {
                        high_confidence_spam_candidates =
                            high_confidence_spam_candidates.saturating_add(1);
                    } else if spam_band == "high" {
                        high_confidence_non_spam_candidates =
                            high_confidence_non_spam_candidates.saturating_add(1);
                    }
                    json!({
                        "message_id": message.message_id.clone(),
                        "from": message.from,
                        "subject": message.subject,
                        "received_at_ms": message.received_at_ms,
                        "received_at_utc": iso_datetime_from_unix_ms(message.received_at_ms),
                        "preview": truncate_chars(&message.preview, 220),
                        "spam_confidence_bps": message.spam_confidence_bps,
                        "spam_confidence_band": spam_band,
                        "spam_signal_tags": message.spam_signal_tags,
                        "citation": format!(
                            "imap://{}/{}",
                            normalize_mailbox(&mailbox),
                            message.message_id
                        ),
                    })
                })
                .collect::<Vec<_>>();
            json!({
                "operation": method.method_name(),
                "mailbox": mailbox,
                "executed_at_utc": iso_datetime_from_unix_ms(receipt.executed_at_ms),
                "analysis": {
                    "ontology_version": ontology_version,
                    "requested_limit": requested_limit,
                    "evaluated_count": evaluated_count,
                    "returned_count": messages.len(),
                    "parse_error_count": receipt.parse_error_count,
                    "parse_confidence_bps": parse_confidence_bps,
                    "parse_confidence_band": parse_confidence_band(parse_confidence_bps),
                    "parse_volume_band": parse_volume_band_value,
                    "high_confidence_spam_candidates": high_confidence_spam_candidates,
                    "high_confidence_non_spam_candidates": high_confidence_non_spam_candidates,
                    "spam_high_confidence_threshold_bps": SPAM_HIGH_CONFIDENCE_THRESHOLD_BPS,
                },
                "messages": messages,
            })
            .to_string()
        }
        WalletMailToolMethod::DeleteSpam => {
            let receipt_key = mail_delete_receipt_storage_key(&receipt_operation_id);
            let receipt_bytes = state.get(&receipt_key).map_err(TransactionError::State)?.ok_or_else(|| {
                TransactionError::Invalid("wallet_network delete receipt missing after execution".to_string())
            })?;
            let receipt: MailDeleteSpamReceipt = codec::from_bytes_canonical(&receipt_bytes)?;
            let ontology_version = if receipt.ontology_version.trim().is_empty() {
                MAIL_ONTOLOGY_SIGNAL_VERSION.to_string()
            } else {
                receipt.ontology_version.clone()
            };
            let confidence_threshold_bps = if receipt.spam_confidence_threshold_bps == 0 {
                SPAM_HIGH_CONFIDENCE_THRESHOLD_BPS
            } else {
                receipt.spam_confidence_threshold_bps
            };
            let evaluated_count = if receipt.evaluated_count == 0 {
                receipt.deleted_count
            } else {
                receipt.evaluated_count
            };
            let high_confidence_deleted_count = if receipt.high_confidence_deleted_count == 0
                && receipt.deleted_count > 0
            {
                receipt.deleted_count
            } else {
                receipt.high_confidence_deleted_count
            };
            let skipped_low_confidence_count = if receipt.skipped_low_confidence_count == 0
                && evaluated_count >= high_confidence_deleted_count
            {
                evaluated_count.saturating_sub(high_confidence_deleted_count)
            } else {
                receipt.skipped_low_confidence_count
            };
            json!({
                "operation": method.method_name(),
                "mailbox": receipt.mailbox,
                "deleted_count": receipt.deleted_count,
                "evaluated_count": evaluated_count,
                "high_confidence_deleted_count": high_confidence_deleted_count,
                "skipped_low_confidence_count": skipped_low_confidence_count,
                "classification_policy": {
                    "mode": "high_confidence_spam_only",
                    "ontology_version": ontology_version,
                    "spam_confidence_threshold_bps": confidence_threshold_bps,
                },
                "executed_at_utc": iso_datetime_from_unix_ms(receipt.executed_at_ms),
                "citation": format!(
                    "imap://{}/cleanup/{}",
                    normalize_mailbox(&receipt.mailbox),
                    hex::encode(receipt.operation_id)
                ),
            })
            .to_string()
        }
        WalletMailToolMethod::Reply => {
            let receipt_key = mail_reply_receipt_storage_key(&receipt_operation_id);
            let receipt_bytes = state.get(&receipt_key).map_err(TransactionError::State)?.ok_or_else(|| {
                TransactionError::Invalid("wallet_network reply receipt missing after execution".to_string())
            })?;
            let receipt: MailReplyReceipt = codec::from_bytes_canonical(&receipt_bytes)?;
            json!({
                "operation": method.method_name(),
                "mailbox": receipt.mailbox,
                "to": receipt.to,
                "subject": receipt.subject,
                "sent_message_id": receipt.sent_message_id,
                "executed_at_utc": iso_datetime_from_unix_ms(receipt.executed_at_ms),
                "citation": format!(
                    "mailto:{}?subject={}",
                    receipt.to,
                    receipt.subject
                ),
            })
            .to_string()
        }
    };

    Ok(Some((true, Some(output), None)))
}

pub async fn handle_action_execution(
    service: &DesktopAgentService,
    tool: AgentTool,
    session_id: [u8; 32],
    step_index: u32,
    visual_phash: [u8; 32],
    rules: &crate::agentic::rules::ActionRules,
    agent_state: &AgentState,
    os_driver: &Arc<dyn OsDriver>,
    scoped_exception_hash: Option<[u8; 32]>,
    mut execution_state: Option<&mut dyn StateAccess>,
    execution_call_context: Option<ServiceCallContext<'_>>,
) -> Result<(bool, Option<String>, Option<String>), TransactionError> {
    let mut tool = tool;

    let mcp = service
        .mcp
        .clone()
        .unwrap_or_else(|| Arc::new(McpManager::new()));

    // [VERIFIED] This line ensures the registry propagates to execution
    let lens_registry_arc = service.lens_registry.clone();

    let mut foreground_window = os_driver.get_active_window_info().await.unwrap_or(None);
    let target_app_hint = agent_state.target.as_ref().and_then(|t| t.app_hint.clone());

    // Pre-policy normalization:
    // - Convert search-result browser navigation into governed `web__search` for WebResearch.
    // - Ensure `web__search` carries a computed SERP URL for deterministic policy hashing.
    normalize_web_research_tool_call(
        &mut tool,
        agent_state.resolved_intent.as_ref(),
        &agent_state.goal,
    );

    // `web__search` carries a computed SERP URL for deterministic
    // policy enforcement + hashing (the model should only provide the query).
    if let AgentTool::WebSearch { query, url, .. } = &mut tool {
        if url.as_ref().map(|u| u.trim().is_empty()).unwrap_or(true) {
            *url = Some(crate::agentic::web::build_default_search_url(query));
        }
    }

    // Stage D transform-first enforcement for egress-capable tools.
    pii::apply_pii_transform_first(service, rules, session_id, scoped_exception_hash, &mut tool)
        .await?;

    // 1. Serialization for Policy Check
    let tool_value =
        serde_json::to_value(&tool).map_err(|e| TransactionError::Serialization(e.to_string()))?;

    let args_value = if let Some(args) = tool_value.get("arguments") {
        args.clone()
    } else {
        json!({})
    };

    let request_params = serde_jcs::to_vec(&args_value)
        .map_err(|e| TransactionError::Serialization(e.to_string()))?;

    // 2. Compute Canonical Tool Bytes for Hash Stability
    let tool_jcs =
        serde_jcs::to_vec(&tool).map_err(|e| TransactionError::Serialization(e.to_string()))?;
    let tool_hash_bytes = ioi_crypto::algorithms::hash::sha256(&tool_jcs).unwrap();
    let mut tool_hash = [0u8; 32];
    tool_hash.copy_from_slice(tool_hash_bytes.as_ref());

    let mut target = tool.target();
    // `FrameType::Observation` inspection can invoke screenshot captioning; gate it via a
    // distinct policy target so default-safe rules can require explicit approval.
    if let AgentTool::MemoryInspect { frame_id } = &tool {
        if let Some(scs_mutex) = service.scs.as_ref() {
            if let Ok(store) = scs_mutex.lock() {
                if let Some(frame) = store.toc.frames.get(*frame_id as usize) {
                    if matches!(frame.frame_type, FrameType::Observation) {
                        target = ioi_types::app::ActionTarget::Custom(
                            "memory::inspect_observation".to_string(),
                        );
                    }
                }
            }
        }
    }

    let dummy_request = ioi_types::app::ActionRequest {
        target: target.clone(),
        params: request_params,
        context: ioi_types::app::ActionContext {
            agent_id: "desktop_agent".into(),
            session_id: Some(session_id),
            window_id: None,
        },
        nonce: step_index as u64,
    };

    let target_str = match &target {
        ioi_types::app::ActionTarget::Custom(s) => s.clone(),
        _ => serde_json::to_string(&target)
            .unwrap_or_else(|_| "unknown".to_string())
            .trim_matches('"')
            .to_string(),
    };

    // 3. Policy Check
    let skip_policy = matches!(tool, AgentTool::SystemFail { .. });

    if !skip_policy {
        let approved_by_token = agent_state
            .pending_approval
            .as_ref()
            .map(|token| token.request_hash == tool_hash)
            .unwrap_or(false);
        let approved_by_runtime_secret = approvals::is_runtime_secret_install_retry_approved(
            &tool,
            tool_hash,
            session_id,
            agent_state,
        );
        let is_approved = approved_by_token || approved_by_runtime_secret;

        if is_approved {
            if approved_by_token {
                log::info!(
                    "Policy Gate: Pre-approved via Token for hash {}",
                    hex::encode(tool_hash)
                );
            } else {
                log::info!(
                    "Policy Gate: Pre-approved via runtime secret retry for hash {}",
                    hex::encode(tool_hash)
                );
            }
        } else {
            // Import PolicyEngine from service level
            use crate::agentic::policy::PolicyEngine;
            use crate::agentic::rules::Verdict;

            let verdict = PolicyEngine::evaluate(
                rules,
                &dummy_request,
                &service.scrubber.model,
                os_driver,
                None,
            )
            .await;

            match verdict {
                Verdict::Allow => {}
                Verdict::Block => {
                    if let Some(tx) = &service.event_sender {
                        let _ = tx.send(ioi_types::app::KernelEvent::FirewallInterception {
                            verdict: "BLOCK".to_string(),
                            target: target_str,
                            request_hash: tool_hash,
                            session_id: Some(session_id),
                        });
                    }
                    return Err(TransactionError::Invalid("Blocked by Policy".into()));
                }
                Verdict::RequireApproval => {
                    log::info!(
                        "Policy Gate: RequireApproval for hash: {}",
                        hex::encode(tool_hash)
                    );

                    if let Some(tx) = &service.event_sender {
                        let _ = tx.send(ioi_types::app::KernelEvent::FirewallInterception {
                            verdict: "REQUIRE_APPROVAL".to_string(),
                            target: target_str,
                            request_hash: tool_hash,
                            session_id: Some(session_id),
                        });
                    }
                    return Err(TransactionError::PendingApproval(hex::encode(tool_hash)));
                }
            }
        }
    }

    // Pre-execution focus recovery for click-like tools.
    // This reduces FocusMismatch loops by verifying/repairing focus before click dispatch.
    if focus::is_focus_sensitive_tool(&tool) {
        if let Some(hint) = target_app_hint
            .as_deref()
            .map(str::trim)
            .filter(|h| !h.is_empty())
        {
            if !focus::window_matches_hint(foreground_window.as_ref(), hint) {
                match os_driver.focus_window(hint).await {
                    Ok(true) => {
                        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                        foreground_window =
                            os_driver.get_active_window_info().await.unwrap_or(None);
                        if !focus::window_matches_hint(foreground_window.as_ref(), hint) {
                            return Ok((
                                false,
                                None,
                                Some(format!(
                                    "ERROR_CLASS=FocusMismatch Focused window still does not match target '{}'.",
                                    hint
                                )),
                            ));
                        }
                    }
                    Ok(false) => {
                        return Ok((
                            false,
                            None,
                            Some(format!(
                                "ERROR_CLASS=FocusMismatch Unable to focus target window '{}'.",
                                hint
                            )),
                        ));
                    }
                    Err(e) => {
                        let err = e.to_string();
                        if focus::is_missing_focus_dependency_error(&err) {
                            return Ok((
                                false,
                                None,
                                Some(format!(
                                    "ERROR_CLASS=MissingDependency Focus dependency unavailable while focusing '{}': {}",
                                    hint, err
                                )),
                            ));
                        }
                        return Ok((
                            false,
                            None,
                            Some(format!(
                                "ERROR_CLASS=FocusMismatch Focus attempt failed for '{}': {}",
                                hint, err
                            )),
                        ));
                    }
                }
            }
        }
    }

    // Construct executor locally with all dependencies after focus recovery.
    let executor = ToolExecutor::new(
        service.gui.clone(),
        os_driver.clone(),
        service.terminal.clone(),
        service.browser.clone(),
        mcp,
        service.event_sender.clone(),
        Some(lens_registry_arc),
        service.reasoning_inference.clone(), // Pass reasoning engine for visual search
        Some(service.scrubber.clone()),
    )
    .with_window_context(
        foreground_window.clone(),
        target_app_hint.clone(),
        Some(agent_state.current_tier),
    )
    .with_expected_visual_hash(Some(visual_phash))
    .with_working_directory(Some(agent_state.working_directory.clone()));

    // Explicitly acquire lease for browser tools
    if matches!(
        tool,
        AgentTool::BrowserNavigate { .. }
            | AgentTool::BrowserSnapshot { .. }
            | AgentTool::BrowserClick { .. }
            | AgentTool::BrowserClickElement { .. }
            | AgentTool::BrowserSyntheticClick { .. }
            | AgentTool::BrowserScroll { .. }
            | AgentTool::BrowserType { .. }
            | AgentTool::BrowserKey { .. }
    ) {
        service.browser.set_lease(true);
    }

    // 5. Handle Meta-Tools and Execution
    match tool {
        AgentTool::SystemFail {
            reason,
            missing_capability,
        } => {
            log::warn!(
                "Agent explicit failure: {} (Missing: {:?})",
                reason,
                missing_capability
            );
            let error_msg = if let Some(cap) = missing_capability {
                let reason_lc = reason.to_lowercase();
                let is_true_capability_gap = reason_lc.contains("missing tool")
                    || reason_lc.contains("tool is missing")
                    || reason_lc.contains("not listed in your available tools")
                    || reason_lc.contains("capability missing")
                    || reason_lc.contains("tier restricted")
                    || reason_lc.contains("no typing-capable tool is available")
                    || reason_lc.contains("no clipboard-capable tool is available")
                    || reason_lc.contains("no click-capable tool is available")
                    || (reason_lc.contains("no ")
                        && reason_lc.contains("tool")
                        && reason_lc.contains("available"));

                if is_true_capability_gap {
                    format!(
                        "ESCALATE_REQUEST: Missing capability '{}'. Reason: {}",
                        cap, reason
                    )
                } else {
                    // Treat lookup/runtime failures as action failures, not tier/capability upgrades.
                    format!("Agent Failure: {} (claimed capability: '{}')", reason, cap)
                }
            } else {
                format!("Agent Failure: {}", reason)
            };
            if let Some(tx) = &service.event_sender {
                let _ = tx.send(ioi_types::app::KernelEvent::AgentActionResult {
                    session_id,
                    step_index,
                    tool_name: "system__fail".to_string(),
                    output: error_msg.clone(),
                    // [FIX] Authoritative Status
                    agent_status: "Failed".to_string(),
                });
            }
            Ok((false, None, Some(error_msg)))
        }
        AgentTool::MemorySearch { query } => {
            if service.scs.is_none() {
                return Ok((
                    false,
                    None,
                    Some(
                        "ERROR_CLASS=ToolUnavailable memory__search requires an SCS-backed memory store."
                            .to_string(),
                    ),
                ));
            }

            let trimmed = query.trim();
            if trimmed.is_empty() {
                return Ok((
                    false,
                    None,
                    Some(
                        "ERROR_CLASS=TargetNotFound memory__search requires a non-empty query."
                            .to_string(),
                    ),
                ));
            }

            let out = service.retrieve_context_hybrid(trimmed, None).await;
            let out = if out.trim().is_empty() {
                "No matching memories found.".to_string()
            } else {
                out
            };
            Ok((true, Some(out), None))
        }
        AgentTool::MemoryInspect { frame_id } => {
            let scs_mutex = match service.scs.as_ref() {
                Some(m) => m,
                None => {
                    return Ok((
                        false,
                        None,
                        Some(
                            "ERROR_CLASS=ToolUnavailable memory__inspect requires an SCS-backed memory store."
                                .to_string(),
                        ),
                    ))
                }
            };

            let frame_type = {
                let store = match scs_mutex.lock() {
                    Ok(store) => store,
                    Err(_) => {
                        return Ok((
                            false,
                            None,
                            Some("ERROR_CLASS=UnexpectedState SCS lock poisoned.".to_string()),
                        ))
                    }
                };

                match store.toc.frames.get(frame_id as usize) {
                    Some(frame) => frame.frame_type,
                    None => {
                        return Ok((
                            false,
                            None,
                            Some(format!(
                                "ERROR_CLASS=TargetNotFound Frame {} not found in memory store.",
                                frame_id
                            )),
                        ))
                    }
                }
            };

            match frame_type {
                FrameType::Observation => match service.inspect_frame(frame_id).await {
                    Ok(desc) => Ok((true, Some(desc), None)),
                    Err(e) => Ok((
                        false,
                        None,
                        Some(format!(
                            "ERROR_CLASS=UnexpectedState memory__inspect failed: {}",
                            e
                        )),
                    )),
                },
                FrameType::Thought | FrameType::Action => {
                    let payload = {
                        let store = match scs_mutex.lock() {
                            Ok(store) => store,
                            Err(_) => {
                                return Ok((
                                    false,
                                    None,
                                    Some("ERROR_CLASS=UnexpectedState SCS lock poisoned."
                                        .to_string()),
                                ))
                            }
                        };

                        match store.read_frame_payload(frame_id) {
                            Ok(payload) => payload,
                            Err(e) => {
                                return Ok((
                                    false,
                                    None,
                                    Some(format!(
                                        "ERROR_CLASS=UnexpectedState Failed to read frame payload: {}",
                                        e
                                    )),
                                ))
                            }
                        }
                    };

                    match codec::from_bytes_canonical::<RecordedMessage>(&payload) {
                        Ok(recorded) => {
                            let content = if recorded.scrubbed_for_model.is_empty() {
                                recorded.scrubbed_for_scs
                            } else {
                                recorded.scrubbed_for_model
                            };
                            let out = serde_json::json!({
                                "frame_id": frame_id,
                                "frame_type": format!("{:?}", frame_type),
                                "role": recorded.role,
                                "timestamp_ms": recorded.timestamp_ms,
                                "content": content,
                            })
                            .to_string();
                            Ok((true, Some(out), None))
                        }
                        Err(_) => Ok((
                            true,
                            Some(format!(
                                "{{\"frame_id\":{},\"frame_type\":\"{:?}\",\"content\":\"<Non-Recorded Payload>\"}}",
                                frame_id, frame_type
                            )),
                            None,
                        )),
                    }
                }
                _ => Ok((
                    true,
                    Some(format!(
                        "{{\"frame_id\":{},\"frame_type\":\"{:?}\",\"content\":\"<Unsupported Frame Type>\"}}",
                        frame_id, frame_type
                    )),
                    None,
                )),
            }
        }
        AgentTool::AgentDelegate { goal, budget } => {
            // Orchestration is stateful; spawning the child session is handled in the step layer
            // so receipts + session state mutations remain atomic and auditable.
            let _ = (goal, budget);
            Ok((true, None, None))
        }
        AgentTool::AgentAwait { .. } => Ok((true, None, None)),
        AgentTool::AgentPause { .. } => Ok((true, None, None)),
        AgentTool::AgentComplete { .. } => Ok((true, None, None)),
        AgentTool::CommerceCheckout { .. } => Ok((
            true,
            Some("System: Initiated UCP Checkout (Pending Guardian Approval)".to_string()),
            None,
        )),
        AgentTool::ChatReply { message } => Ok((true, Some(format!("Replied: {}", message)), None)),
        AgentTool::OsFocusWindow { title } => match os_driver.focus_window(&title).await {
            Ok(true) => {
                // Give the window manager a brief moment to apply focus.
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                let focused = os_driver.get_active_window_info().await.unwrap_or(None);
                let msg = if let Some(win) = focused {
                    format!("Focused '{}' ({})", win.title, win.app_name)
                } else {
                    format!("Focus requested for '{}'", title)
                };
                Ok((true, Some(msg), None))
            }
            Ok(false) => Ok((false, None, Some(format!("No window matched '{}'", title)))),
            Err(e) => {
                let err = e.to_string();
                if focus::is_missing_focus_dependency_error(&err) {
                    Ok((
                        false,
                        None,
                        Some(format!(
                            "ERROR_CLASS=MissingDependency Focus dependency unavailable for '{}': {}",
                            title, err
                        )),
                    ))
                } else {
                    Ok((
                        false,
                        None,
                        Some(format!("Window focus failed for '{}': {}", title, err)),
                    ))
                }
            }
        },
        AgentTool::OsCopy { content } => match os_driver.set_clipboard(&content).await {
            Ok(()) => Ok((true, Some("Copied to clipboard".to_string()), None)),
            Err(e) => Ok((false, None, Some(format!("Clipboard write failed: {}", e)))),
        },
        AgentTool::OsPaste {} => match os_driver.get_clipboard().await {
            Ok(content) => Ok((true, Some(content), None)),
            Err(e) => Ok((false, None, Some(format!("Clipboard read failed: {}", e)))),
        },
        AgentTool::Dynamic(value) => {
            if let (Some(state), Some(call_context)) =
                (execution_state.as_deref_mut(), execution_call_context)
            {
                if let Some(result) = try_execute_wallet_mail_dynamic_tool(
                    state,
                    call_context,
                    &value,
                    session_id,
                    step_index,
                )
                .await?
                {
                    return Ok(result);
                }
            }

            let result = executor
                .execute(
                    AgentTool::Dynamic(value),
                    session_id,
                    step_index,
                    visual_phash,
                    agent_state.visual_som_map.as_ref(),
                    agent_state.visual_semantic_map.as_ref(),
                    agent_state.active_lens.as_deref(),
                )
                .await;
            Ok((result.success, result.history_entry, result.error))
        }

        // Delegate Execution Tools
        _ => {
            let result = executor
                .execute(
                    tool,
                    session_id,
                    step_index,
                    visual_phash,
                    agent_state.visual_som_map.as_ref(),
                    agent_state.visual_semantic_map.as_ref(),
                    agent_state.active_lens.as_deref(),
                )
                .await;
            Ok((result.success, result.history_entry, result.error))
        }
    }
}

pub fn select_runtime(
    service: &DesktopAgentService,
    state: &crate::agentic::desktop::types::AgentState,
) -> std::sync::Arc<dyn ioi_api::vm::inference::InferenceRuntime> {
    if state.consecutive_failures > 0 {
        return service.reasoning_inference.clone();
    }
    if state.step_count == 0 {
        return service.reasoning_inference.clone();
    }
    match state.last_action_type.as_deref() {
        Some("gui__click") | Some("gui__type") => {
            // Prefer fast inference if available for simple UI follow-ups
            service.fast_inference.clone()
        }
        _ => service.reasoning_inference.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::approvals::is_runtime_secret_install_retry_approved;
    use super::focus::is_focus_sensitive_tool;
    use super::normalize_web_research_tool_call;
    use crate::agentic::desktop::runtime_secret;
    use crate::agentic::desktop::types::{AgentMode, AgentState, AgentStatus, ExecutionTier};
    use ioi_types::app::agentic::{
        AgentTool, ComputerAction, IntentConfidenceBand, IntentScopeProfile, ResolvedIntentState,
    };
    use std::collections::BTreeMap;

    fn test_agent_state() -> AgentState {
        AgentState {
            session_id: [0u8; 32],
            goal: "test".to_string(),
            transcript_root: [0u8; 32],
            status: AgentStatus::Running,
            step_count: 0,
            max_steps: 8,
            last_action_type: None,
            parent_session_id: None,
            child_session_ids: vec![],
            budget: 1,
            tokens_used: 0,
            consecutive_failures: 0,
            pending_approval: None,
            pending_tool_call: None,
            pending_tool_jcs: None,
            pending_tool_hash: None,
            pending_visual_hash: None,
            recent_actions: vec![],
            mode: AgentMode::Agent,
            current_tier: ExecutionTier::DomHeadless,
            last_screen_phash: None,
            execution_queue: vec![],
            active_skill_hash: None,
            tool_execution_log: BTreeMap::new(),
            visual_som_map: None,
            visual_semantic_map: None,
            swarm_context: None,
            target: None,
            resolved_intent: None,

            awaiting_intent_clarification: false,

            working_directory: ".".to_string(),
            active_lens: None,
            pending_search_completion: None,
            command_history: Default::default(),
        }
    }

    #[test]
    fn right_click_variants_require_focus_recovery() {
        assert!(is_focus_sensitive_tool(&AgentTool::Computer(
            ComputerAction::RightClick {
                coordinate: Some([10, 20]),
            },
        )));
        assert!(is_focus_sensitive_tool(&AgentTool::Computer(
            ComputerAction::RightClickId { id: 12 },
        )));
        assert!(is_focus_sensitive_tool(&AgentTool::Computer(
            ComputerAction::RightClickElement {
                id: "file_row".to_string(),
            },
        )));
    }

    #[test]
    fn browser_click_tools_do_not_require_native_focus_recovery() {
        assert!(!is_focus_sensitive_tool(&AgentTool::BrowserClick {
            selector: "#submit".to_string(),
        }));
        assert!(!is_focus_sensitive_tool(&AgentTool::BrowserClickElement {
            id: "btn_submit".to_string(),
        }));
        assert!(!is_focus_sensitive_tool(
            &AgentTool::BrowserSyntheticClick { x: 20, y: 30 }
        ));
    }

    #[test]
    fn runtime_secret_retry_is_approved_only_for_matching_pending_install() {
        let session_id = [9u8; 32];
        let session_hex = hex::encode(session_id);
        runtime_secret::set_secret(&session_hex, "sudo_password", "pw".to_string(), true, 60)
            .expect("set runtime sudo secret");

        let mut state = test_agent_state();
        let hash = [7u8; 32];
        state.pending_tool_hash = Some(hash);

        let install_tool = AgentTool::SysInstallPackage {
            package: "gnome-calculator".to_string(),
            manager: Some("apt-get".to_string()),
        };
        assert!(is_runtime_secret_install_retry_approved(
            &install_tool,
            hash,
            session_id,
            &state
        ));

        assert!(!is_runtime_secret_install_retry_approved(
            &install_tool,
            [8u8; 32],
            session_id,
            &state
        ));

        let non_install = AgentTool::SysExec {
            command: "echo".to_string(),
            args: vec!["ok".to_string()],
            stdin: None,
            detach: false,
        };
        assert!(!is_runtime_secret_install_retry_approved(
            &non_install,
            hash,
            session_id,
            &state
        ));
    }

    fn resolved(scope: IntentScopeProfile) -> ResolvedIntentState {
        ResolvedIntentState {
            intent_id: "test".to_string(),
            scope,
            band: IntentConfidenceBand::High,
            score: 0.95,
            top_k: vec![],
            preferred_tier: "tool_first".to_string(),
            matrix_version: "v1".to_string(),
            matrix_source_hash: [0u8; 32],
            receipt_hash: [0u8; 32],
            constrained: false,
        }
    }

    #[test]
    fn rewrites_search_navigation_to_web_search_for_web_research_scope() {
        let mut tool = AgentTool::BrowserNavigate {
            url: "https://duckduckgo.com/?q=latest+news".to_string(),
        };
        let intent = resolved(IntentScopeProfile::WebResearch);

        normalize_web_research_tool_call(&mut tool, Some(&intent), "fallback query");

        match tool {
            AgentTool::WebSearch { query, limit, url } => {
                assert_eq!(query, "latest news");
                assert_eq!(limit, Some(super::WEB_PIPELINE_SEARCH_LIMIT));
                let expected = crate::agentic::web::build_default_search_url("latest news");
                assert_eq!(url.as_deref(), Some(expected.as_str()));
            }
            other => panic!("expected WebSearch, got {:?}", other),
        }
    }

    #[test]
    fn does_not_rewrite_non_search_navigation_or_non_web_scope() {
        let mut tool = AgentTool::BrowserNavigate {
            url: "https://example.com/news".to_string(),
        };
        let intent = resolved(IntentScopeProfile::WebResearch);
        normalize_web_research_tool_call(&mut tool, Some(&intent), "fallback query");
        assert!(matches!(tool, AgentTool::BrowserNavigate { .. }));

        let mut scoped_tool = AgentTool::BrowserNavigate {
            url: "https://duckduckgo.com/?q=latest+news".to_string(),
        };
        let non_web_intent = resolved(IntentScopeProfile::Conversation);
        normalize_web_research_tool_call(&mut scoped_tool, Some(&non_web_intent), "fallback");
        assert!(matches!(scoped_tool, AgentTool::BrowserNavigate { .. }));
    }

    #[test]
    fn normalizes_direct_web_search_limit_for_web_research_scope() {
        let mut tool = AgentTool::WebSearch {
            query: "top US breaking news last 6 hours".to_string(),
            limit: Some(3),
            url: None,
        };
        let intent = resolved(IntentScopeProfile::WebResearch);
        normalize_web_research_tool_call(&mut tool, Some(&intent), "fallback");

        match tool {
            AgentTool::WebSearch { query, limit, url } => {
                assert_eq!(query, "top US breaking news last 6 hours");
                assert_eq!(limit, Some(super::WEB_PIPELINE_SEARCH_LIMIT));
                let expected = crate::agentic::web::build_default_search_url(
                    "top US breaking news last 6 hours",
                );
                assert_eq!(url.as_deref(), Some(expected.as_str()));
            }
            other => panic!("expected WebSearch, got {:?}", other),
        }
    }

    #[test]
    fn rewrites_memory_search_to_web_search_for_web_research_scope() {
        let mut tool = AgentTool::MemorySearch {
            query: "active cloud incidents us impact".to_string(),
        };
        let intent = resolved(IntentScopeProfile::WebResearch);
        normalize_web_research_tool_call(&mut tool, Some(&intent), "fallback");

        match tool {
            AgentTool::WebSearch { query, limit, url } => {
                assert_eq!(query, "active cloud incidents us impact");
                assert_eq!(limit, Some(super::WEB_PIPELINE_SEARCH_LIMIT));
                let expected = crate::agentic::web::build_default_search_url(
                    "active cloud incidents us impact",
                );
                assert_eq!(url.as_deref(), Some(expected.as_str()));
            }
            other => panic!("expected WebSearch, got {:?}", other),
        }
    }

    #[test]
    fn rewrites_empty_memory_search_with_fallback_for_web_research_scope() {
        let mut tool = AgentTool::MemorySearch {
            query: "   ".to_string(),
        };
        let intent = resolved(IntentScopeProfile::WebResearch);
        normalize_web_research_tool_call(
            &mut tool,
            Some(&intent),
            "as of now top active us cloud incidents",
        );

        match tool {
            AgentTool::WebSearch { query, limit, url } => {
                assert_eq!(query, "as of now top active us cloud incidents");
                assert_eq!(limit, Some(super::WEB_PIPELINE_SEARCH_LIMIT));
                let expected = crate::agentic::web::build_default_search_url(
                    "as of now top active us cloud incidents",
                );
                assert_eq!(url.as_deref(), Some(expected.as_str()));
            }
            other => panic!("expected WebSearch, got {:?}", other),
        }
    }

    #[test]
    fn rewrites_memory_search_when_live_external_research_goal_overrides_scope() {
        let mut tool = AgentTool::MemorySearch {
            query: "active cloud incidents us impact".to_string(),
        };
        let workspace_intent = resolved(IntentScopeProfile::WorkspaceOps);
        normalize_web_research_tool_call(
            &mut tool,
            Some(&workspace_intent),
            "As of now (UTC), top active cloud incidents with citations",
        );

        match tool {
            AgentTool::WebSearch { query, limit, url } => {
                assert_eq!(query, "active cloud incidents us impact");
                assert_eq!(limit, Some(super::WEB_PIPELINE_SEARCH_LIMIT));
                let expected = crate::agentic::web::build_default_search_url(
                    "active cloud incidents us impact",
                );
                assert_eq!(url.as_deref(), Some(expected.as_str()));
            }
            other => panic!("expected WebSearch, got {:?}", other),
        }
    }

    #[test]
    fn does_not_rewrite_memory_search_for_workspace_local_goal() {
        let mut tool = AgentTool::MemorySearch {
            query: "intent resolver".to_string(),
        };
        let workspace_intent = resolved(IntentScopeProfile::WorkspaceOps);
        normalize_web_research_tool_call(
            &mut tool,
            Some(&workspace_intent),
            "Search the repository for intent resolver code and patch tests",
        );

        assert!(matches!(tool, AgentTool::MemorySearch { .. }));
    }
}
