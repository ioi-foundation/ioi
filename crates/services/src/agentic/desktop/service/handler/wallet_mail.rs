use super::super::ServiceCallContext;
use crate::wallet_network::mail_ontology::{
    parse_confidence_band, parse_volume_band, spam_confidence_band, MAIL_ONTOLOGY_SIGNAL_VERSION,
    SPAM_HIGH_CONFIDENCE_THRESHOLD_BPS,
};
use crate::wallet_network::LeaseActionReplayWindowState;
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_types::app::wallet_network::{
    MailDeleteSpamParams, MailDeleteSpamReceipt, MailListRecentParams, MailListRecentReceipt,
    MailReadLatestParams, MailReadLatestReceipt, MailReplyParams, MailReplyReceipt,
    SessionChannelRecord, SessionChannelState, SessionLease,
};
use ioi_types::codec;
use ioi_types::error::TransactionError;
use serde_json::{json, Map as JsonMap, Value as JsonValue};
use std::collections::BTreeMap;

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

fn extract_dynamic_args_object(
    arguments: &JsonValue,
) -> Result<JsonMap<String, JsonValue>, TransactionError> {
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
    let decoded = hex::decode(trimmed)
        .map_err(|e| TransactionError::Invalid(format!("{} must be 32-byte hex: {}", label, e)))?;
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
        let Ok(channel) = codec::from_bytes_canonical::<SessionChannelRecord>(&channel_bytes)
        else {
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

pub(super) async fn try_execute_wallet_mail_dynamic_tool(
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
        .unwrap_or_else(|| "primary".to_string());

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
    let op_nonce = pick_hex_32(&args, &["op_nonce", "opNonce"])?
        .unwrap_or_else(|| op_nonce_from_operation(operation_id, step_index));
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
            let reply_to_message_id =
                pick_string(&args, &["reply_to_message_id", "replyToMessageId"])
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
        .handle_service_call(state, method.method_name(), &params_bytes, &mut wallet_ctx)
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
            let receipt_bytes = state
                .get(&receipt_key)
                .map_err(TransactionError::State)?
                .ok_or_else(|| {
                    TransactionError::Invalid(
                        "wallet_network read receipt missing after execution".to_string(),
                    )
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
            let receipt_bytes = state
                .get(&receipt_key)
                .map_err(TransactionError::State)?
                .ok_or_else(|| {
                    TransactionError::Invalid(
                        "wallet_network list receipt missing after execution".to_string(),
                    )
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
                    ((receipt.messages.len() as u32).saturating_mul(10_000)
                        / evaluated_count.max(1)) as u16
                }
            } else {
                receipt.parse_confidence_bps
            };
            let parse_volume_band_value = if receipt.parse_volume_band.trim().is_empty() {
                parse_volume_band(receipt.messages.len()).to_string()
            } else {
                receipt.parse_volume_band.clone()
            };
            let mailbox_total_count = if receipt.mailbox_total_count == 0 {
                evaluated_count.max(receipt.messages.len() as u32)
            } else {
                receipt.mailbox_total_count
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
                    "mailbox_total_count": mailbox_total_count,
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
            let receipt_bytes = state
                .get(&receipt_key)
                .map_err(TransactionError::State)?
                .ok_or_else(|| {
                    TransactionError::Invalid(
                        "wallet_network delete receipt missing after execution".to_string(),
                    )
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
            let high_confidence_deleted_count =
                if receipt.high_confidence_deleted_count == 0 && receipt.deleted_count > 0 {
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
            let mailbox_total_count_before = if receipt.mailbox_total_count_before == 0 {
                evaluated_count
            } else {
                receipt.mailbox_total_count_before
            };
            let mailbox_total_count_after = if receipt.mailbox_total_count_after == 0 {
                mailbox_total_count_before.saturating_sub(high_confidence_deleted_count)
            } else {
                receipt.mailbox_total_count_after
            };
            let mailbox_total_count_delta = if receipt.mailbox_total_count_delta == 0
                && mailbox_total_count_before >= mailbox_total_count_after
            {
                mailbox_total_count_before.saturating_sub(mailbox_total_count_after)
            } else {
                receipt.mailbox_total_count_delta
            };
            let cleanup_scope = if receipt.cleanup_scope.trim().is_empty() {
                if normalize_mailbox(&receipt.mailbox) == "primary"
                    || normalize_mailbox(&receipt.mailbox) == "inbox"
                {
                    "primary_inbox".to_string()
                } else {
                    "spam_mailbox".to_string()
                }
            } else {
                receipt.cleanup_scope.clone()
            };
            let preserved_transactional_or_personal_count =
                receipt.preserved_transactional_or_personal_count;
            let preserved_trusted_system_count = receipt.preserved_trusted_system_count;
            let preserved_low_confidence_other_count = receipt.preserved_low_confidence_other_count;
            let preserved_due_to_delete_cap_count = receipt.preserved_due_to_delete_cap_count;
            let preserved_reason_counts = if receipt.preserved_reason_counts.is_empty() {
                BTreeMap::from([
                    (
                        "transactional_or_personal".to_string(),
                        preserved_transactional_or_personal_count,
                    ),
                    (
                        "trusted_system_sender".to_string(),
                        preserved_trusted_system_count,
                    ),
                    (
                        "low_confidence_other".to_string(),
                        preserved_low_confidence_other_count,
                    ),
                    (
                        "delete_cap_guardrail".to_string(),
                        preserved_due_to_delete_cap_count,
                    ),
                ])
            } else {
                receipt.preserved_reason_counts.clone()
            };
            let total_preserved_count = preserved_transactional_or_personal_count
                .saturating_add(preserved_trusted_system_count)
                .saturating_add(preserved_low_confidence_other_count)
                .saturating_add(preserved_due_to_delete_cap_count);
            let classification_mode = if cleanup_scope.eq_ignore_ascii_case("primary_inbox") {
                "high_confidence_unwanted_preserve_transactional_personal"
            } else {
                "high_confidence_spam_only"
            };
            json!({
                "operation": method.method_name(),
                "mailbox": receipt.mailbox,
                "cleanup_scope": cleanup_scope,
                "deleted_count": receipt.deleted_count,
                "evaluated_count": evaluated_count,
                "high_confidence_deleted_count": high_confidence_deleted_count,
                "skipped_low_confidence_count": skipped_low_confidence_count,
                "mailbox_total_count_before": mailbox_total_count_before,
                "mailbox_total_count_after": mailbox_total_count_after,
                "mailbox_total_count_delta": mailbox_total_count_delta,
                "preserved_transactional_or_personal_count": preserved_transactional_or_personal_count,
                "preserved_trusted_system_count": preserved_trusted_system_count,
                "preserved_low_confidence_other_count": preserved_low_confidence_other_count,
                "preserved_due_to_delete_cap_count": preserved_due_to_delete_cap_count,
                "preserved_reason_counts": preserved_reason_counts,
                "total_preserved_count": total_preserved_count,
                "preservation_evidence": {
                    "transactional_or_personal_count": preserved_transactional_or_personal_count,
                    "trusted_system_sender_count": preserved_trusted_system_count,
                    "low_confidence_other_count": preserved_low_confidence_other_count,
                    "due_to_delete_cap_count": preserved_due_to_delete_cap_count,
                    "reason_counts": preserved_reason_counts,
                    "total_preserved_count": total_preserved_count,
                    "preserve_modes": [
                        "transactional_or_personal",
                        "trusted_system_sender",
                        "low_confidence_other",
                        "delete_cap_guardrail"
                    ]
                },
                "classification_policy": {
                    "mode": classification_mode,
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
            let receipt_bytes = state
                .get(&receipt_key)
                .map_err(TransactionError::State)?
                .ok_or_else(|| {
                    TransactionError::Invalid(
                        "wallet_network reply receipt missing after execution".to_string(),
                    )
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
