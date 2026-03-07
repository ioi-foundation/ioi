use super::super::{DesktopAgentService, ServiceCallContext};
use crate::agentic::pii_substrate;
use crate::wallet_network::mail_ontology::{
    parse_confidence_band, parse_volume_band, spam_confidence_band, MAIL_ONTOLOGY_SIGNAL_VERSION,
    SPAM_HIGH_CONFIDENCE_THRESHOLD_BPS,
};
use crate::wallet_network::LeaseActionReplayWindowState;
use ioi_api::state::{service_namespace_prefix, NamespacedStateAccess, StateAccess};
use ioi_api::transaction::context::TxContext;
use ioi_api::vm::inference::InferenceRuntime;
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::agentic::{InferenceOptions, PiiClass};
use ioi_types::app::wallet_network::{
    MailConnectorEnsureBindingParams, MailConnectorRecord, MailDeleteSpamParams,
    MailDeleteSpamReceipt, MailListRecentParams, MailListRecentReceipt, MailReadLatestParams,
    MailReadLatestReceipt, MailReplyParams, MailReplyReceipt, SessionChannelRecord,
    SessionChannelState, SessionLease,
};
use ioi_types::app::{ExecutionContractReceiptEvent, KernelEvent};
use ioi_types::codec;
use ioi_types::error::{TransactionError, VmError};
use ioi_types::keys::active_service_key;
use ioi_types::service_configs::ActiveServiceMeta;
use lettre::message::Mailbox;
use serde::Deserialize;
use serde_json::{json, Map as JsonMap, Value as JsonValue};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

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
const MAIL_CONNECTOR_PREFIX: &[u8] = b"mail_connector::";
const MAIL_READ_RECEIPT_PREFIX: &[u8] = b"mail_read_receipt::";
const MAIL_LIST_RECEIPT_PREFIX: &[u8] = b"mail_list_receipt::";
const MAIL_DELETE_RECEIPT_PREFIX: &[u8] = b"mail_delete_receipt::";
const MAIL_REPLY_RECEIPT_PREFIX: &[u8] = b"mail_reply_receipt::";
const WALLET_SERVICE_ID: &str = "wallet_network";
const MAIL_CONNECTOR_ENSURE_BINDING_METHOD: &str = "mail_connector_ensure_binding@v1";
const CEC_CONTRACT_VERSION: &str = "cec.v0.4";
const MAIL_REPLY_SYNTHESIS_MAX_ATTEMPTS: usize = 3;

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
const MAIL_REPLY_SYNTHESIS_MODEL_ID: &str = "mail_reply_synthesis.v1";

#[derive(Clone, Debug, PartialEq, Eq)]
struct MailDraftToken {
    id: String,
    placeholder: String,
    raw_value: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct MailReplyDraft {
    to: String,
    subject: String,
    body: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct MailReplyDraftCandidate {
    to: Option<String>,
    subject: Option<String>,
    body: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct MailReplySynthesisContext {
    sanitized_request: String,
    email_tokens: Vec<MailDraftToken>,
    replacement_tokens: Vec<MailDraftToken>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum MailReplySignatureMode {
    #[default]
    Omit,
    SenderName,
}

#[derive(Debug, Deserialize)]
struct MailReplySynthesisOutput {
    to_token: String,
    subject: String,
    body: String,
    #[serde(default)]
    signoff: Option<String>,
    #[serde(default)]
    signature_mode: MailReplySignatureMode,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ExplicitMailReplyDraftResolution {
    Absent,
    Accepted(MailReplyDraft),
    NeedsSynthesis {
        candidate: MailReplyDraftCandidate,
        lint_error: String,
    },
}

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

fn is_wallet_mail_namespace_tool_name(name: &str) -> bool {
    let normalized = name.trim().to_ascii_lowercase();
    normalized.starts_with("wallet_network__mail_")
        || normalized.starts_with("wallet_mail_")
        || normalized.starts_with("mail__")
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

fn mail_connector_storage_key(mailbox: &str) -> Vec<u8> {
    [MAIL_CONNECTOR_PREFIX, normalize_mailbox(mailbox).as_bytes()].concat()
}

fn load_active_service_meta(
    state: &dyn StateAccess,
    service_id: &str,
) -> Result<ActiveServiceMeta, TransactionError> {
    let key = active_service_key(service_id);
    let bytes = state
        .get(&key)
        .map_err(TransactionError::State)?
        .ok_or_else(|| {
            TransactionError::Invalid(format!(
                "active service metadata is missing for '{}'",
                service_id
            ))
        })?;
    codec::from_bytes_canonical(&bytes).map_err(Into::into)
}

fn mailbox_connector_configured(
    state: &dyn StateAccess,
    mailbox_hint: &str,
) -> Result<bool, TransactionError> {
    state
        .get(&mail_connector_storage_key(mailbox_hint))
        .map(|value| value.is_some())
        .map_err(TransactionError::State)
}

fn inference_vm_error_to_tx(err: VmError) -> TransactionError {
    TransactionError::Invalid(err.to_string())
}

fn is_missing_mail_binding_error(error: &TransactionError) -> bool {
    let text = error.to_string().to_ascii_lowercase();
    text.contains("no wallet mail lease binding available")
        || text.contains("unable to resolve wallet mail channel_id")
        || text.contains("unable to resolve wallet mail lease_id")
}

async fn ensure_wallet_mail_binding(
    state: &mut dyn StateAccess,
    wallet_service: &std::sync::Arc<dyn ioi_api::services::BlockchainService>,
    call_context: ServiceCallContext<'_>,
    mailbox: &str,
    session_id: [u8; 32],
    step_index: u32,
    now_ms: u64,
) -> Result<(), TransactionError> {
    let request_id = compute_sha256_id(&format!(
        "wallet-mail-binding:{}:{}:{}:{}",
        hex::encode(session_id),
        step_index,
        normalize_mailbox(mailbox),
        now_ms
    ));
    let params = MailConnectorEnsureBindingParams {
        request_id,
        mailbox: normalize_mailbox(mailbox),
        audience: Some(call_context.signer_account_id.0),
        lease_ttl_ms: None,
    };
    let payload = codec::to_bytes_canonical(&params)?;
    let mut wallet_ctx = TxContext {
        block_height: call_context.block_height,
        block_timestamp: call_context.block_timestamp,
        chain_id: call_context.chain_id,
        signer_account_id: call_context.signer_account_id,
        services: call_context.services,
        simulation: call_context.simulation,
        is_internal: call_context.is_internal,
    };
    wallet_service
        .handle_service_call(
            state,
            MAIL_CONNECTOR_ENSURE_BINDING_METHOD,
            &payload,
            &mut wallet_ctx,
        )
        .await
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

fn pick_nonempty_string(args: &JsonMap<String, JsonValue>, keys: &[&str]) -> Option<String> {
    pick_string(args, keys)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn is_redacted_email_placeholder(value: &str) -> bool {
    let normalized = value.trim().to_ascii_lowercase();
    normalized.contains("<redacted:email>")
        || normalized == "redacted:email"
        || normalized == "redacted_email"
}

fn canonicalize_mail_recipient(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || is_redacted_email_placeholder(trimmed) {
        return None;
    }

    let mailto_stripped =
        if trimmed.len() >= "mailto:".len() && trimmed[..7].eq_ignore_ascii_case("mailto:") {
            trimmed[7..]
                .split(['?', '#'])
                .next()
                .map(str::trim)
                .unwrap_or("")
        } else {
            trimmed
        };
    if !mailto_stripped.is_empty() && mailto_stripped.parse::<Mailbox>().is_ok() {
        return Some(mailto_stripped.to_string());
    }
    trimmed
        .parse::<Mailbox>()
        .ok()
        .map(|mailbox| mailbox.to_string())
}

fn load_mailbox_sender_display_name(
    state: &dyn StateAccess,
    mailbox: &str,
) -> Result<Option<String>, TransactionError> {
    let Some(bytes) = state
        .get(&mail_connector_storage_key(mailbox))
        .map_err(TransactionError::State)?
    else {
        return Ok(None);
    };
    let connector: MailConnectorRecord = codec::from_bytes_canonical(&bytes)?;
    Ok(connector
        .config
        .sender_display_name
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty()))
}

fn mail_token_placeholder(token_id: &str) -> String {
    format!("{{{{{}}}}}", token_id)
}

fn emit_execution_contract_receipt_event(
    service: &DesktopAgentService,
    session_id: [u8; 32],
    step_index: u32,
    intent_id: &str,
    stage: &str,
    key: &str,
    satisfied: bool,
    evidence_material: &str,
) {
    let Some(tx) = service.event_sender.as_ref() else {
        return;
    };
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let evidence_payload = format!(
        "intent_id={};stage={};key={};satisfied={};evidence={}",
        intent_id, stage, key, satisfied, evidence_material
    );
    let evidence_commit_hash = sha256(evidence_payload.as_bytes())
        .map(|digest| format!("sha256:{}", hex::encode(digest.as_ref())))
        .unwrap_or_else(|_| "sha256:unavailable".to_string());
    let _ = tx.send(KernelEvent::ExecutionContractReceipt(
        ExecutionContractReceiptEvent {
            contract_version: CEC_CONTRACT_VERSION.to_string(),
            session_id,
            step_index,
            intent_id: intent_id.to_string(),
            stage: stage.to_string(),
            key: key.to_string(),
            satisfied,
            timestamp_ms,
            evidence_commit_hash,
            verifier_command_commit_hash: None,
            probe_source: None,
            observed_value: None,
            evidence_type: None,
            provider_id: None,
            synthesized_payload_hash: None,
        },
    ));
}

fn unresolved_mail_draft_placeholder_present(value: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    lowered.contains("<redacted:")
        || lowered.contains("[your name]")
        || lowered.contains("[your-name]")
        || lowered.contains("[your_name]")
        || lowered.contains("{{")
        || lowered.contains("}}")
}

fn validate_mail_draft_text(label: &str, value: String) -> Result<String, TransactionError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(TransactionError::Invalid(format!(
            "ERROR_CLASS=SynthesisFailed wallet_network__mail_reply produced empty {}",
            label
        )));
    }
    if unresolved_mail_draft_placeholder_present(trimmed) {
        return Err(TransactionError::Invalid(format!(
            "ERROR_CLASS=SynthesisFailed wallet_network__mail_reply produced unresolved placeholders in {}",
            label
        )));
    }
    Ok(trimmed.to_string())
}

fn rehydrate_mail_draft_text(
    value: &str,
    replacement_tokens: &[MailDraftToken],
) -> Result<String, TransactionError> {
    let mut out = value.to_string();
    for token in replacement_tokens {
        out = out.replace(&token.placeholder, &token.raw_value);
    }
    validate_mail_draft_text("text", out)
}

fn assemble_mail_reply_body(
    body: String,
    signoff: Option<String>,
    signature_mode: MailReplySignatureMode,
    sender_display_name: Option<&str>,
) -> Result<String, TransactionError> {
    let mut out = validate_mail_draft_text("body", body)?;
    let signoff = match signoff {
        Some(value) if !value.trim().is_empty() => {
            Some(validate_mail_draft_text("signoff", value)?)
        }
        _ => None,
    };
    let sender_display_name = sender_display_name
        .map(str::trim)
        .filter(|value| !value.is_empty());

    match (signoff, signature_mode) {
        (Some(signoff), MailReplySignatureMode::Omit) => {
            out.push_str("\n\n");
            out.push_str(&signoff);
        }
        (Some(signoff), MailReplySignatureMode::SenderName) => {
            let sender_display_name = sender_display_name.ok_or_else(|| {
                TransactionError::Invalid(
                    "ERROR_CLASS=SynthesisFailed wallet_network__mail_reply requested sender-name signature without a configured mailbox sender display name".to_string(),
                )
            })?;
            out.push_str("\n\n");
            out.push_str(&signoff);
            out.push('\n');
            out.push_str(sender_display_name);
        }
        (None, MailReplySignatureMode::SenderName) => {
            let sender_display_name = sender_display_name.ok_or_else(|| {
                TransactionError::Invalid(
                    "ERROR_CLASS=SynthesisFailed wallet_network__mail_reply requested sender-name signature without a configured mailbox sender display name".to_string(),
                )
            })?;
            out.push_str("\n\n");
            out.push_str(sender_display_name);
        }
        (None, MailReplySignatureMode::Omit) => {}
    }

    Ok(out)
}

fn resolve_explicit_mail_reply_draft(
    args: &JsonMap<String, JsonValue>,
) -> Result<ExplicitMailReplyDraftResolution, TransactionError> {
    let to = pick_nonempty_string(args, &["to"]);
    let subject = pick_nonempty_string(args, &["subject"]);
    let body = pick_nonempty_string(args, &["body"]);
    if to.is_none() && subject.is_none() && body.is_none() {
        return Ok(ExplicitMailReplyDraftResolution::Absent);
    }

    let candidate = MailReplyDraftCandidate {
        to: to.clone(),
        subject: subject.clone(),
        body: body.clone(),
    };
    let Some(raw_to) = to else {
        return Ok(ExplicitMailReplyDraftResolution::NeedsSynthesis {
            candidate,
            lint_error: "ERROR_CLASS=SynthesisFailed wallet_network__mail_reply requires canonical 'to', 'subject', and 'body' when explicit draft fields are provided".to_string(),
        });
    };
    let Some(to) = canonicalize_mail_recipient(&raw_to) else {
        let lint_error = if is_redacted_email_placeholder(&raw_to) {
            "ERROR_CLASS=SynthesisFailed wallet_network__mail_reply explicit recipient was redacted and requires pre-execution draft synthesis from the user request".to_string()
        } else {
            "ERROR_CLASS=SynthesisFailed wallet_network__mail_reply requires a valid canonical recipient email address".to_string()
        };
        return Ok(ExplicitMailReplyDraftResolution::NeedsSynthesis {
            candidate,
            lint_error,
        });
    };
    let Some(subject) = subject else {
        return Ok(ExplicitMailReplyDraftResolution::NeedsSynthesis {
            candidate,
            lint_error: "ERROR_CLASS=SynthesisFailed wallet_network__mail_reply requires canonical 'to', 'subject', and 'body' when explicit draft fields are provided".to_string(),
        });
    };
    let subject = validate_mail_draft_text("subject", subject);
    let subject = match subject {
        Ok(value) => value,
        Err(error) => {
            return Ok(ExplicitMailReplyDraftResolution::NeedsSynthesis {
                candidate,
                lint_error: error.to_string(),
            })
        }
    };
    let Some(body) = body else {
        return Ok(ExplicitMailReplyDraftResolution::NeedsSynthesis {
            candidate,
            lint_error: "ERROR_CLASS=SynthesisFailed wallet_network__mail_reply requires canonical 'to', 'subject', and 'body' when explicit draft fields are provided".to_string(),
        });
    };
    let body = validate_mail_draft_text("body", body);
    let body = match body {
        Ok(value) => value,
        Err(error) => {
            return Ok(ExplicitMailReplyDraftResolution::NeedsSynthesis {
                candidate,
                lint_error: error.to_string(),
            })
        }
    };

    Ok(ExplicitMailReplyDraftResolution::Accepted(MailReplyDraft {
        to,
        subject,
        body,
    }))
}

fn build_mail_reply_synthesis_context(
    latest_user_message: &str,
    candidate_recipient: Option<&str>,
) -> Result<MailReplySynthesisContext, TransactionError> {
    let evidence = pii_substrate::build_evidence_graph(latest_user_message).map_err(|e| {
        TransactionError::Invalid(format!(
            "ERROR_CLASS=SynthesisFailed failed to inspect mail request PII substrate: {}",
            e
        ))
    })?;
    let mut email_spans = evidence
        .spans
        .iter()
        .filter(|span| span.pii_class == PiiClass::Email)
        .collect::<Vec<_>>();
    email_spans.sort_by_key(|span| (span.start_index, span.end_index));

    let mut sanitized_request = String::with_capacity(latest_user_message.len());
    let mut last_index = 0usize;
    let mut email_tokens = Vec::<MailDraftToken>::new();
    let mut replacement_tokens = Vec::<MailDraftToken>::new();

    for span in email_spans {
        let start = span.start_index as usize;
        let end = span.end_index as usize;
        if start >= end
            || end > latest_user_message.len()
            || !latest_user_message.is_char_boundary(start)
            || !latest_user_message.is_char_boundary(end)
            || start < last_index
        {
            continue;
        }
        let raw_email = latest_user_message[start..end].trim();
        if raw_email.is_empty() || raw_email.parse::<Mailbox>().is_err() {
            continue;
        }
        sanitized_request.push_str(&latest_user_message[last_index..start]);
        let token = if let Some(existing) = email_tokens
            .iter()
            .find(|candidate| candidate.raw_value.eq_ignore_ascii_case(raw_email))
            .cloned()
        {
            existing
        } else {
            let token_id = format!("EMAIL_{}", email_tokens.len() + 1);
            let token = MailDraftToken {
                placeholder: mail_token_placeholder(&token_id),
                id: token_id,
                raw_value: raw_email.to_string(),
            };
            email_tokens.push(token.clone());
            replacement_tokens.push(token.clone());
            token
        };
        sanitized_request.push_str(&token.placeholder);
        last_index = end;
    }
    sanitized_request.push_str(&latest_user_message[last_index..]);

    if let Some(raw_email) = candidate_recipient
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .and_then(canonicalize_mail_recipient)
    {
        let already_present = email_tokens
            .iter()
            .any(|candidate| candidate.raw_value.eq_ignore_ascii_case(&raw_email));
        if !already_present {
            let token_id = format!("EMAIL_{}", email_tokens.len() + 1);
            let token = MailDraftToken {
                placeholder: mail_token_placeholder(&token_id),
                id: token_id,
                raw_value: raw_email,
            };
            email_tokens.push(token.clone());
            replacement_tokens.push(token);
        }
    }

    if email_tokens.is_empty() {
        return Err(TransactionError::Invalid(
            "ERROR_CLASS=SynthesisFailed wallet_network__mail_reply could not derive any recipient email token from the latest user request".to_string(),
        ));
    }

    Ok(MailReplySynthesisContext {
        sanitized_request,
        email_tokens,
        replacement_tokens,
    })
}

fn build_mail_reply_synthesis_prompt(
    context: &MailReplySynthesisContext,
    sender_name_available: bool,
    reply_to_message_id: Option<&str>,
    candidate_payload_json: Option<&str>,
    validation_error: Option<&str>,
    previous_output_json: Option<&str>,
) -> Result<Vec<u8>, TransactionError> {
    let email_token_lines = context
        .email_tokens
        .iter()
        .map(|token| format!("- {}", token.id))
        .collect::<Vec<_>>();
    let payload = json!([
        {
            "role": "system",
            "content": "You synthesize a final outbound email draft for the mail.reply intent. Return exactly one JSON object with this schema: {\"to_token\":\"EMAIL_1\",\"subject\":\"...\",\"body\":\"...\",\"signoff\":null,\"signature_mode\":\"omit\"}. Rules: 1) to_token must equal one listed email token exactly. 2) subject must be final send-ready plain text. 3) body must contain only the actual message content; never include sender names or unresolved placeholders in body. 4) signoff must be null or a plain closing phrase like \"Best regards,\" and must not include a sender name. 5) signature_mode must be exactly \"sender_name\" only when sender_name_available=true and you want the local runtime to append the configured mailbox sender display name after signoff; otherwise use \"omit\". 6) Do not invent recipients, dates, or facts not present in the request. 7) You may mention listed email token placeholders in subject/body only when the user explicitly wants those values present. 8) Never output placeholders like [Your Name], [your-name], <REDACTED:email>, <REDACTED:name>, {{SENDER_NAME}}, or any other unresolved placeholder."
        },
        {
            "role": "user",
            "content": format!(
                "Request:\\n{}\\n\\nAvailable email tokens:\\n{}\\n\\nSender name available:\\n{}\\n\\nReply-to message id:\\n{}\\n\\nUpstream candidate draft:\\n{}\\n\\nCurrent draft lint issue:\\n{}\\n\\nPrevious invalid synthesis output:\\n{}",
                context.sanitized_request,
                email_token_lines.join("\n"),
                if sender_name_available { "true" } else { "false" },
                reply_to_message_id.unwrap_or("none"),
                candidate_payload_json.unwrap_or("none"),
                validation_error.unwrap_or("none"),
                previous_output_json.unwrap_or("none")
            )
        }
    ]);
    serde_json::to_vec(&payload).map_err(|e| {
        TransactionError::Serialization(format!(
            "mail reply synthesis prompt encoding failed: {}",
            e
        ))
    })
}

async fn synthesize_mail_reply_draft(
    service: &DesktopAgentService,
    latest_user_message: &str,
    sender_display_name: Option<&str>,
    reply_to_message_id: Option<&str>,
    session_id: [u8; 32],
    candidate: Option<&MailReplyDraftCandidate>,
    validation_error: Option<&str>,
) -> Result<MailReplyDraft, TransactionError> {
    let runtime: &dyn InferenceRuntime = service.reasoning_inference.as_ref();
    let sender_display_name = sender_display_name
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let candidate_recipient = candidate
        .and_then(|candidate| candidate.to.as_deref())
        .and_then(canonicalize_mail_recipient);
    let context =
        build_mail_reply_synthesis_context(latest_user_message, candidate_recipient.as_deref())?;
    let candidate_payload_json = candidate.map(|candidate| {
        serde_json::to_string(&json!({
            "to": candidate.to,
            "subject": candidate.subject,
            "body": candidate.body,
        }))
        .unwrap_or_else(|_| "null".to_string())
    });
    let mut current_validation_error = validation_error.map(ToString::to_string);
    let mut previous_output_json = None::<String>;

    for attempt_idx in 0..MAIL_REPLY_SYNTHESIS_MAX_ATTEMPTS {
        let prompt = build_mail_reply_synthesis_prompt(
            &context,
            sender_display_name.is_some(),
            reply_to_message_id,
            candidate_payload_json.as_deref(),
            current_validation_error.as_deref(),
            previous_output_json.as_deref(),
        )?;
        let inference_input = service
            .prepare_cloud_inference_input(
                Some(session_id),
                "mail_reply_synthesis",
                MAIL_REPLY_SYNTHESIS_MODEL_ID,
                &prompt,
            )
            .await?;
        let output = runtime
            .execute_inference(
                [0u8; 32],
                &inference_input,
                InferenceOptions {
                    temperature: 0.0,
                    json_mode: true,
                    max_tokens: 512,
                    ..Default::default()
                },
            )
            .await
            .map_err(inference_vm_error_to_tx)?;
        let raw_output = String::from_utf8(output).map_err(|e| {
            TransactionError::Invalid(format!(
                "ERROR_CLASS=SynthesisFailed mail reply synthesis produced non-UTF8 output: {}",
                e
            ))
        })?;
        let parsed: Result<MailReplySynthesisOutput, TransactionError> =
            serde_json::from_str(raw_output.trim()).map_err(|e| {
                TransactionError::Invalid(format!(
                    "ERROR_CLASS=SynthesisFailed mail reply synthesis returned invalid JSON: {}",
                    e
                ))
            });
        let draft = parsed.and_then(|parsed| {
            let to = context
                .email_tokens
                .iter()
                .find(|token| token.id == parsed.to_token.trim())
                .map(|token| token.raw_value.clone())
                .ok_or_else(|| {
                    TransactionError::Invalid(format!(
                        "ERROR_CLASS=SynthesisFailed mail reply synthesis selected unknown recipient token '{}'",
                        parsed.to_token.trim()
                    ))
                })?;
            let subject =
                rehydrate_mail_draft_text(&parsed.subject, &context.replacement_tokens)?;
            let body = assemble_mail_reply_body(
                rehydrate_mail_draft_text(&parsed.body, &context.replacement_tokens)?,
                parsed.signoff,
                parsed.signature_mode,
                sender_display_name,
            )?;
            Ok(MailReplyDraft { to, subject, body })
        });
        match draft {
            Ok(draft) => return Ok(draft),
            Err(error) if attempt_idx + 1 < MAIL_REPLY_SYNTHESIS_MAX_ATTEMPTS => {
                current_validation_error = Some(error.to_string());
                previous_output_json = Some(raw_output.trim().to_string());
            }
            Err(error) => return Err(error),
        }
    }

    Err(TransactionError::Invalid(
        "ERROR_CLASS=SynthesisFailed mail reply synthesis exhausted all correction attempts"
            .to_string(),
    ))
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

async fn execute_wallet_mail_dynamic_tool_on_state(
    service: &DesktopAgentService,
    state: &mut dyn StateAccess,
    wallet_service: &std::sync::Arc<dyn ioi_api::services::BlockchainService>,
    call_context: ServiceCallContext<'_>,
    method: WalletMailToolMethod,
    args: &JsonMap<String, JsonValue>,
    mailbox_hint: &str,
    latest_user_message: Option<&str>,
    session_id: [u8; 32],
    step_index: u32,
    now_ms: u64,
) -> Result<(bool, Option<String>, Option<String>), TransactionError> {
    let channel_id = pick_hex_32(args, &["channel_id", "channelId"])?;
    let lease_id = pick_hex_32(args, &["lease_id", "leaseId"])?;
    let inferred = if channel_id.is_none() || lease_id.is_none() {
        match infer_mail_binding(
            state,
            method,
            call_context.signer_account_id.0,
            mailbox_hint,
            now_ms,
        ) {
            Ok(binding) => Some(binding),
            Err(error) if is_missing_mail_binding_error(&error) => {
                ensure_wallet_mail_binding(
                    state,
                    wallet_service,
                    call_context,
                    mailbox_hint,
                    session_id,
                    step_index,
                    now_ms,
                )
                .await?;
                Some(infer_mail_binding(
                    state,
                    method,
                    call_context.signer_account_id.0,
                    mailbox_hint,
                    now_ms,
                )?)
            }
            Err(error) => return Err(error),
        }
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

    let op_seq = pick_u64(args, &["op_seq", "opSeq"])
        .filter(|value| *value >= 1)
        .unwrap_or_else(|| infer_next_op_seq(state, channel_id, lease_id));
    let operation_id = pick_hex_32(args, &["operation_id", "operationId"])?.unwrap_or_else(|| {
        compute_sha256_id(&format!(
            "{}:{}:{}:{}:{}",
            hex::encode(session_id),
            step_index,
            method.method_name(),
            op_seq,
            now_ms
        ))
    });
    let op_nonce = pick_hex_32(args, &["op_nonce", "opNonce"])?
        .unwrap_or_else(|| op_nonce_from_operation(operation_id, step_index));
    let requested_at_ms = pick_u64(args, &["requested_at_ms", "requestedAtMs"]).unwrap_or(now_ms);

    let mut reply_output_draft = None::<MailReplyDraft>;
    let (params_bytes, receipt_operation_id) = match method {
        WalletMailToolMethod::ReadLatest => {
            let params = MailReadLatestParams {
                operation_id,
                channel_id,
                lease_id,
                op_seq,
                op_nonce: Some(op_nonce),
                mailbox: mailbox_hint.to_string(),
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
                mailbox: mailbox_hint.to_string(),
                limit: pick_u32(args, &["limit"]).unwrap_or(25).clamp(1, 200),
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
                mailbox: mailbox_hint.to_string(),
                max_delete: pick_u32(args, &["max_delete", "maxDelete"]).unwrap_or(25),
                requested_at_ms,
            };
            (codec::to_bytes_canonical(&params)?, params.operation_id)
        }
        WalletMailToolMethod::Reply => {
            let sender_display_name = load_mailbox_sender_display_name(state, mailbox_hint)?;
            let reply_to_message_id =
                pick_string(args, &["reply_to_message_id", "replyToMessageId"])
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(ToString::to_string);
            let draft = match resolve_explicit_mail_reply_draft(args)? {
                ExplicitMailReplyDraftResolution::Accepted(explicit_draft) => explicit_draft,
                ExplicitMailReplyDraftResolution::Absent => {
                    let latest_user_message = latest_user_message.ok_or_else(|| {
                        TransactionError::Invalid(
                            "ERROR_CLASS=SynthesisFailed wallet_network__mail_reply requires the latest user request to synthesize a draft when explicit canonical fields are absent"
                                .to_string(),
                        )
                    })?;
                    synthesize_mail_reply_draft(
                        service,
                        latest_user_message,
                        sender_display_name.as_deref(),
                        reply_to_message_id.as_deref(),
                        session_id,
                        None,
                        None,
                    )
                    .await?
                }
                ExplicitMailReplyDraftResolution::NeedsSynthesis {
                    candidate,
                    lint_error,
                } => {
                    let latest_user_message = latest_user_message.ok_or_else(|| {
                        TransactionError::Invalid(format!(
                            "{}; latest user request is required for pre-execution draft synthesis",
                            lint_error
                        ))
                    })?;
                    synthesize_mail_reply_draft(
                        service,
                        latest_user_message,
                        sender_display_name.as_deref(),
                        reply_to_message_id.as_deref(),
                        session_id,
                        Some(&candidate),
                        Some(&lint_error),
                    )
                    .await?
                }
            };
            emit_execution_contract_receipt_event(
                service,
                session_id,
                step_index,
                "mail.reply",
                "provider_selection",
                "payload_synthesis",
                true,
                &format!(
                    "mailbox={};recipient={};subject={}",
                    mailbox_hint, draft.to, draft.subject
                ),
            );
            reply_output_draft = Some(draft.clone());

            let params = MailReplyParams {
                operation_id,
                channel_id,
                lease_id,
                op_seq,
                op_nonce: Some(op_nonce),
                mailbox: mailbox_hint.to_string(),
                to: draft.to,
                subject: draft.subject,
                body: draft.body,
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
        return Ok((
            false,
            None,
            Some(format!(
                "ERROR_CLASS=UnexpectedState wallet_network dynamic call '{}' failed: {}",
                method.method_name(),
                error
            )),
        ));
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
                "body": reply_output_draft
                    .as_ref()
                    .map(|draft| draft.body.clone())
                    .unwrap_or_default(),
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

    Ok((true, Some(output), None))
}

pub(super) async fn try_execute_wallet_mail_dynamic_tool(
    service: &DesktopAgentService,
    state: &mut dyn StateAccess,
    call_context: ServiceCallContext<'_>,
    dynamic_tool: &JsonValue,
    latest_user_message: Option<&str>,
    session_id: [u8; 32],
    step_index: u32,
) -> Result<Option<(bool, Option<String>, Option<String>)>, TransactionError> {
    let Some(tool_name) = dynamic_tool.get("name").and_then(|value| value.as_str()) else {
        return Ok(None);
    };
    let Some(method) = wallet_mail_method_from_tool_name(tool_name) else {
        if is_wallet_mail_namespace_tool_name(tool_name) {
            return Ok(Some((
                false,
                None,
                Some(format!(
                    "ERROR_CLASS=UnsupportedTool unsupported wallet mail tool '{}'",
                    tool_name.trim()
                )),
            )));
        }
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
    if mailbox_connector_configured(state, &mailbox_hint)? {
        let result = execute_wallet_mail_dynamic_tool_on_state(
            service,
            state,
            &wallet_service,
            call_context,
            method,
            &args,
            &mailbox_hint,
            latest_user_message,
            session_id,
            step_index,
            now_ms,
        )
        .await?;
        return Ok(Some(result));
    }

    let wallet_meta = load_active_service_meta(state, WALLET_SERVICE_ID)?;
    {
        let wallet_prefix = service_namespace_prefix(WALLET_SERVICE_ID);
        let mut wallet_state = NamespacedStateAccess::new(state, wallet_prefix, &wallet_meta);
        if mailbox_connector_configured(&wallet_state, &mailbox_hint)? {
            let result = execute_wallet_mail_dynamic_tool_on_state(
                service,
                &mut wallet_state,
                &wallet_service,
                call_context,
                method,
                &args,
                &mailbox_hint,
                latest_user_message,
                session_id,
                step_index,
                now_ms,
            )
            .await?;
            return Ok(Some(result));
        }
    }

    let result = execute_wallet_mail_dynamic_tool_on_state(
        service,
        state,
        &wallet_service,
        call_context,
        method,
        &args,
        &mailbox_hint,
        latest_user_message,
        session_id,
        step_index,
        now_ms,
    )
    .await?;
    Ok(Some(result))
}

#[cfg(test)]
mod tests {
    use super::{
        assemble_mail_reply_body, build_mail_reply_synthesis_context, canonicalize_mail_recipient,
        is_wallet_mail_namespace_tool_name, mail_token_placeholder, rehydrate_mail_draft_text,
        resolve_explicit_mail_reply_draft, validate_mail_draft_text,
        wallet_mail_method_from_tool_name, ExplicitMailReplyDraftResolution, MailDraftToken,
        MailReplySignatureMode,
    };
    use serde_json::{json, Map as JsonMap, Value as JsonValue};

    #[test]
    fn wallet_mail_namespace_detection_includes_connector_tools() {
        assert!(is_wallet_mail_namespace_tool_name(
            "wallet_network__mail_connector_upsert"
        ));
        assert!(is_wallet_mail_namespace_tool_name("mail__read_latest"));
        assert!(!is_wallet_mail_namespace_tool_name("web__search"));
    }

    #[test]
    fn wallet_mail_method_mapping_excludes_connector_setup_tools() {
        assert!(wallet_mail_method_from_tool_name("wallet_network__mail_read_latest").is_some());
        assert!(
            wallet_mail_method_from_tool_name("wallet_network__mail_connector_upsert").is_none()
        );
    }

    #[test]
    fn explicit_mail_reply_draft_requires_canonical_to_subject_and_body() {
        let value = json!({
            "to": "team@ioi.network",
            "body": "Tomorrow's standup is moved to 2 PM."
        });
        let args: JsonMap<String, JsonValue> =
            value.as_object().expect("test args must be object").clone();

        let resolution = resolve_explicit_mail_reply_draft(&args)
            .expect("partial explicit draft should become synthesis candidate");
        assert!(matches!(
            resolution,
            ExplicitMailReplyDraftResolution::NeedsSynthesis { .. }
        ));
    }

    #[test]
    fn explicit_mail_reply_draft_accepts_canonical_fields() {
        let value = json!({
            "to": "team@ioi.network",
            "subject": "Standup moved",
            "body": "Tomorrow's standup is moved to 2 PM."
        });
        let args: JsonMap<String, JsonValue> =
            value.as_object().expect("test args must be object").clone();

        let resolution =
            resolve_explicit_mail_reply_draft(&args).expect("explicit fields should resolve");
        match resolution {
            ExplicitMailReplyDraftResolution::Accepted(draft) => {
                assert_eq!(draft.to, "team@ioi.network");
                assert_eq!(draft.subject, "Standup moved");
                assert_eq!(draft.body, "Tomorrow's standup is moved to 2 PM.");
            }
            other => panic!("expected accepted explicit draft, got {:?}", other),
        }
    }

    #[test]
    fn explicit_mail_reply_draft_accepts_mailto_recipient() {
        let value = json!({
            "to": "mailto:team@ioi.network?subject=Ignored",
            "subject": "Standup moved",
            "body": "Tomorrow's standup is moved to 2 PM."
        });
        let args: JsonMap<String, JsonValue> =
            value.as_object().expect("test args must be object").clone();

        let resolution =
            resolve_explicit_mail_reply_draft(&args).expect("mailto recipient should parse");
        match resolution {
            ExplicitMailReplyDraftResolution::Accepted(draft) => {
                assert_eq!(draft.to, "team@ioi.network");
            }
            other => panic!("expected accepted explicit draft, got {:?}", other),
        }
    }

    #[test]
    fn explicit_mail_reply_draft_ignores_redacted_recipient_and_defers_to_synthesis() {
        let value = json!({
            "to": "<REDACTED:email>",
            "subject": "Standup moved",
            "body": "Tomorrow's standup is moved to 2 PM."
        });
        let args: JsonMap<String, JsonValue> =
            value.as_object().expect("test args must be object").clone();

        let resolution =
            resolve_explicit_mail_reply_draft(&args).expect("redacted explicit draft should defer");
        assert!(matches!(
            resolution,
            ExplicitMailReplyDraftResolution::NeedsSynthesis { .. }
        ));
    }

    #[test]
    fn explicit_mail_reply_draft_defers_placeholder_body_to_synthesis() {
        let value = json!({
            "to": "team@ioi.network",
            "subject": "Standup moved",
            "body": "Hello,\n\nBest regards,\n[Your Name]"
        });
        let args: JsonMap<String, JsonValue> =
            value.as_object().expect("test args must be object").clone();

        let resolution = resolve_explicit_mail_reply_draft(&args)
            .expect("placeholder body should defer to synthesis");
        assert!(matches!(
            resolution,
            ExplicitMailReplyDraftResolution::NeedsSynthesis { .. }
        ));
    }

    #[test]
    fn assemble_mail_reply_body_appends_mailbox_sender_name_when_requested() {
        let body = assemble_mail_reply_body(
            "Tomorrow's standup is moved to 2 PM.".to_string(),
            Some("Best regards,".to_string()),
            MailReplySignatureMode::SenderName,
            Some("Levi Josman"),
        )
        .expect("sender-name signature should assemble");
        assert_eq!(
            body,
            "Tomorrow's standup is moved to 2 PM.\n\nBest regards,\nLevi Josman"
        );
    }

    #[test]
    fn assemble_mail_reply_body_rejects_sender_name_signature_when_unconfigured() {
        let error = assemble_mail_reply_body(
            "Tomorrow's standup is moved to 2 PM.".to_string(),
            Some("Best regards,".to_string()),
            MailReplySignatureMode::SenderName,
            None,
        )
        .expect_err("unconfigured sender-name signature must fail");
        assert!(error
            .to_string()
            .contains("requested sender-name signature"));
    }

    #[test]
    fn synthesis_context_tokenizes_email_entities_and_candidate_recipient() {
        let context = build_mail_reply_synthesis_context(
            "Draft an email to team@ioi.network saying tomorrow's standup is moved to 2 PM and cc team@ioi.network again.",
            Some("ops@ioi.network"),
        )
        .expect("context should build");

        assert_eq!(
            context.sanitized_request,
            "Draft an email to {{EMAIL_1}} saying tomorrow's standup is moved to 2 PM and cc {{EMAIL_1}} again."
        );
        assert_eq!(context.email_tokens.len(), 2);
        assert_eq!(context.email_tokens[0].id, "EMAIL_1");
        assert_eq!(context.email_tokens[0].raw_value, "team@ioi.network");
        assert_eq!(context.email_tokens[1].id, "EMAIL_2");
        assert_eq!(context.email_tokens[1].raw_value, "ops@ioi.network");
    }

    #[test]
    fn synthesis_context_requires_at_least_one_email_entity() {
        let error =
            build_mail_reply_synthesis_context("Send an email about tomorrow's standup.", None)
                .expect_err("context must require email token");
        assert!(error
            .to_string()
            .contains("could not derive any recipient email token"));
    }

    #[test]
    fn rehydrate_mail_draft_text_replaces_tokens_and_validates_result() {
        let value = rehydrate_mail_draft_text(
            "Hello {{EMAIL_1}}",
            &[MailDraftToken {
                id: "EMAIL_1".to_string(),
                placeholder: mail_token_placeholder("EMAIL_1"),
                raw_value: "team@ioi.network".to_string(),
            }],
        )
        .expect("email token should resolve");
        assert_eq!(value, "Hello team@ioi.network");
    }

    #[test]
    fn validate_mail_draft_text_rejects_legacy_placeholders() {
        let error = validate_mail_draft_text("body", "Best regards,\n[Your Name]".to_string())
            .expect_err("legacy placeholders must fail");
        assert!(error.to_string().contains("unresolved placeholders"));
    }

    #[test]
    fn canonicalize_mail_recipient_accepts_direct_mailbox_and_mailto() {
        assert_eq!(
            canonicalize_mail_recipient("team@ioi.network").as_deref(),
            Some("team@ioi.network")
        );
        assert_eq!(
            canonicalize_mail_recipient("mailto:team@ioi.network?subject=ignored").as_deref(),
            Some("team@ioi.network")
        );
    }
}
