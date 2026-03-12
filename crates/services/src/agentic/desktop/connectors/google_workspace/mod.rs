mod configure;
mod shield;
mod types;

use super::{
    google_api, google_auth, ConnectorPostconditionEvidence, ConnectorPostconditionProof,
    ConnectorPostconditionVerifierBinding, ConnectorProtectedSlotBinding,
    ConnectorProviderProbeBinding, ConnectorSymbolicReferenceBinding,
    ConnectorSymbolicReferenceInferenceBinding, ConnectorToolRouteBinding,
    PostconditionVerificationFuture, ProviderCandidateDiscoveryFuture, ResolvedSymbolicReference,
    SymbolicReferenceInferenceFuture, SymbolicReferenceResolutionFuture,
};
use crate::agentic::desktop::service::DesktopAgentService;
use crate::agentic::desktop::types::AgentState;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ioi_types::app::agentic::{
    ArgumentOrigin, CapabilityId, LlmToolDefinition, ProtectedSlotKind, ToolCapabilityBinding,
};
use ioi_types::app::ActionTarget;
use ioi_types::error::TransactionError;
use lettre::message::Mailbox;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use time::format_description::well_known::Rfc3339;
use time::{Duration as TimeDuration, OffsetDateTime};

pub use configure::connector_configure;
pub use shield::matches_google_connector_id;
use shield::{enforce_google_tool_shield_policy, runtime_resume_already_authorizes_google_tool};
pub use types::{
    ConnectorActionDefinition, ConnectorActionResult, ConnectorConfigureResult,
    ConnectorFieldDefinition, ConnectorFieldOption, GOOGLE_CONNECTOR_ID, GOOGLE_CONNECTOR_PROVIDER,
};
use types::{
    GoogleConnectorActionSpec, GwsCommandOutput, BIGQUERY_READ_TARGET, BIGQUERY_TOOL_NAME,
    BIGQUERY_WRITE_TARGET, GWS_DEFAULT_TIMEOUT_SECS,
};

pub fn google_connector_actions() -> Vec<ConnectorActionDefinition> {
    google_connector_action_specs()
        .into_iter()
        .map(|spec| ConnectorActionDefinition {
            id: spec.id.to_string(),
            service: spec.service.to_string(),
            service_label: spec.service_label.to_string(),
            tool_name: spec.tool_name.to_string(),
            label: spec.label.to_string(),
            description: spec.description.to_string(),
            kind: spec.kind.to_string(),
            confirm_before_run: spec.confirm_before_run,
            fields: spec.fields,
            required_scopes: spec
                .required_scopes
                .iter()
                .map(|scope| (*scope).to_string())
                .collect(),
        })
        .collect()
}

pub fn google_connector_tool_definitions() -> Vec<LlmToolDefinition> {
    google_connector_action_specs()
        .into_iter()
        .map(|spec| LlmToolDefinition {
            name: spec.tool_name.to_string(),
            description: spec.description.to_string(),
            parameters: connector_fields_to_schema(&spec.fields).to_string(),
        })
        .collect()
}

pub fn google_connector_tool_bindings() -> Vec<ToolCapabilityBinding> {
    google_connector_action_specs()
        .into_iter()
        .map(|spec| ToolCapabilityBinding {
            tool_name: spec.tool_name.to_string(),
            action_target: ActionTarget::Custom(spec.tool_name.to_string()),
            capabilities: spec
                .capabilities
                .iter()
                .map(|capability| CapabilityId::from(*capability))
                .collect(),
        })
        .collect()
}

fn google_service_route_binding(service: &str) -> Option<(&'static str, &'static str)> {
    match service {
        "gmail" => Some(("mail.google.gmail", "google_gmail")),
        "calendar" => Some(("calendar.google.workspace", "google_calendar")),
        "docs" => Some(("docs.google.workspace", "google_docs")),
        "sheets" => Some(("sheets.google.workspace", "google_sheets")),
        "drive" => Some(("drive.google.workspace", "google_drive")),
        "tasks" => Some(("tasks.google.workspace", "google_tasks")),
        "chat" => Some(("chat.google.workspace", "google_chat")),
        "bigquery" => Some(("bigquery.google.workspace", "google_bigquery")),
        "events" => Some(("events.google.workspace", "google_events")),
        "workflow" => Some(("workflow.google.workspace", "google_workflow")),
        "expert" => Some(("expert.google.workspace", "google_expert")),
        _ => None,
    }
}

pub fn google_connector_tool_route_bindings() -> Vec<ConnectorToolRouteBinding> {
    google_connector_action_specs()
        .into_iter()
        .filter_map(|spec| {
            let (provider_family, route_label) = google_service_route_binding(spec.service)?;
            Some(ConnectorToolRouteBinding {
                tool_name: spec.tool_name,
                provider_family,
                route_label,
            })
        })
        .collect()
}

pub fn is_google_connector_tool_name(name: &str) -> bool {
    let normalized = name.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return false;
    }
    google_connector_action_specs()
        .iter()
        .any(|spec| spec.tool_name == normalized)
}

pub fn is_google_mail_tool_name(name: &str) -> bool {
    name.trim()
        .to_ascii_lowercase()
        .starts_with("connector__google__gmail_")
}

pub fn google_tool_provider_family(name: &str) -> Option<&'static str> {
    let normalized = name.trim().to_ascii_lowercase();
    google_connector_tool_route_bindings()
        .into_iter()
        .find(|binding| binding.tool_name == normalized)
        .map(|binding| binding.provider_family)
}

pub fn google_tool_route_label(name: &str) -> Option<&'static str> {
    let normalized = name.trim().to_ascii_lowercase();
    google_connector_tool_route_bindings()
        .into_iter()
        .find(|binding| binding.tool_name == normalized)
        .map(|binding| binding.route_label)
}

fn capability_vec(sorted_caps: &BTreeSet<CapabilityId>) -> Vec<CapabilityId> {
    sorted_caps.iter().cloned().collect()
}

fn google_family_summary(provider_family: &str, account: Option<&str>) -> String {
    let surface = match provider_family {
        "mail.google.gmail" => "Connected Gmail route",
        "calendar.google.workspace" => "Connected Google Calendar route",
        "docs.google.workspace" => "Connected Google Docs route",
        "sheets.google.workspace" => "Connected Google Sheets route",
        "drive.google.workspace" => "Connected Google Drive route",
        "tasks.google.workspace" => "Connected Google Tasks route",
        "chat.google.workspace" => "Connected Google Chat route",
        "bigquery.google.workspace" => "Connected Google BigQuery route",
        "events.google.workspace" => "Connected Google Events route",
        "workflow.google.workspace" => "Connected Google workflow route",
        "expert.google.workspace" => "Connected expert Google route",
        _ => "Connected Google provider route",
    };
    match account.filter(|value| !value.trim().is_empty()) {
        Some(account) => format!("{} for account {}.", surface, account.trim()),
        None => format!("{}.", surface),
    }
}

async fn discover_google_provider_candidates(
    provider_family: &str,
    route_label: &str,
    capabilities: &BTreeSet<CapabilityId>,
) -> Vec<ioi_types::app::agentic::ProviderRouteCandidate> {
    let Ok(status) = google_auth::status().await else {
        return Vec::new();
    };
    if status.status != "connected" {
        return Vec::new();
    }
    let account = status
        .data
        .get("account")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let provider_id = format!(
        "google://{}/{}",
        account.unwrap_or("connected-account"),
        provider_family
    );
    vec![ioi_types::app::agentic::ProviderRouteCandidate {
        provider_family: provider_family.to_string(),
        route_label: route_label.to_string(),
        connector_id: GOOGLE_CONNECTOR_ID.to_string(),
        provider_id: Some(provider_id),
        account_label: account.map(str::to_string),
        capabilities: capability_vec(capabilities),
        summary: google_family_summary(provider_family, account),
    }]
}

fn discover_google_provider_candidates_boxed<'a>(
    _state: Option<&'a dyn ioi_api::state::StateAccess>,
    provider_family: &'a str,
    route_label: &'a str,
    capabilities: &'a BTreeSet<CapabilityId>,
) -> ProviderCandidateDiscoveryFuture<'a> {
    Box::pin(async move {
        discover_google_provider_candidates(provider_family, route_label, capabilities).await
    })
}

pub fn google_connector_provider_probe_bindings() -> Vec<ConnectorProviderProbeBinding> {
    let mut seen = BTreeSet::new();
    google_connector_tool_route_bindings()
        .into_iter()
        .filter(|binding| seen.insert(binding.provider_family))
        .map(|binding| ConnectorProviderProbeBinding {
            provider_family: binding.provider_family,
            discover: discover_google_provider_candidates_boxed,
        })
        .collect()
}

fn google_selected_provider_id(agent_state: &AgentState) -> Option<String> {
    agent_state
        .resolved_intent
        .as_ref()
        .and_then(|resolved| resolved.provider_selection.as_ref())
        .and_then(|selection| selection.selected_provider_id.clone())
}

fn resolve_google_symbolic_reference_boxed<'a>(
    agent_state: &'a AgentState,
    reference: &'a str,
) -> SymbolicReferenceResolutionFuture<'a> {
    Box::pin(async move {
        match reference.trim() {
            "connected_account.email" => {
                let auth = google_auth::access_context(&[]).await?;
                let Some(email) = auth
                    .account_email
                    .as_deref()
                    .and_then(canonicalize_email_recipient)
                else {
                    return Ok(None);
                };
                Ok(Some(ResolvedSymbolicReference {
                    value: Value::String(email.clone()),
                    origin: ArgumentOrigin::StateRef,
                    evidence: format!("symbolic_ref=connected_account.email;resolved={}", email),
                    provider_id: google_selected_provider_id(agent_state),
                }))
            }
            _ => Ok(None),
        }
    })
}

pub fn google_connector_symbolic_reference_bindings() -> Vec<ConnectorSymbolicReferenceBinding> {
    vec![ConnectorSymbolicReferenceBinding {
        connector_id: GOOGLE_CONNECTOR_ID,
        resolve: resolve_google_symbolic_reference_boxed,
    }]
}

fn query_mentions_connected_account_alias(query: &str, provider_terms: &[&str]) -> bool {
    let normalized_query = format!(" {} ", normalize_alias_phrase(query));
    if normalized_query.trim().is_empty() {
        return false;
    }

    let generic_aliases = [
        "connected address",
        "my connected address",
        "your connected address",
        "connected email",
        "my connected email",
        "your connected email",
        "connected email address",
        "my connected email address",
        "your connected email address",
        "connected account",
        "my connected account",
        "your connected account",
        "connected account email",
        "my connected account email",
        "your connected account email",
    ];
    if generic_aliases.iter().any(|candidate| {
        normalized_query.contains(&format!(" {} ", normalize_alias_phrase(candidate)))
    }) {
        return true;
    }

    provider_terms.iter().any(|provider| {
        let provider = normalize_alias_phrase(provider);
        [
            format!("connected {} address", provider),
            format!("my connected {} address", provider),
            format!("your connected {} address", provider),
            format!("connected {} email", provider),
            format!("my connected {} email", provider),
            format!("your connected {} email", provider),
            format!("connected {} email address", provider),
            format!("my connected {} email address", provider),
            format!("your connected {} email address", provider),
            format!("connected {} account", provider),
            format!("my connected {} account", provider),
            format!("your connected {} account", provider),
            format!("connected {} account email", provider),
            format!("my connected {} account email", provider),
            format!("your connected {} account email", provider),
        ]
        .iter()
        .any(|candidate| normalized_query.contains(&format!(" {} ", candidate)))
    })
}

fn infer_google_symbolic_reference_from_query_boxed<'a>(
    _agent_state: &'a AgentState,
    _slot: &'a str,
    query: &'a str,
    protected_slot_kind: ProtectedSlotKind,
) -> SymbolicReferenceInferenceFuture<'a> {
    Box::pin(async move {
        if !matches!(
            protected_slot_kind,
            ProtectedSlotKind::EmailAddress | ProtectedSlotKind::AccountEmail
        ) {
            return Ok(None);
        }
        if query_mentions_connected_account_alias(query, &["google", "gmail", "google workspace"]) {
            return Ok(Some("connected_account.email".to_string()));
        }
        Ok(None)
    })
}

pub fn google_connector_symbolic_reference_inference_bindings(
) -> Vec<ConnectorSymbolicReferenceInferenceBinding> {
    vec![ConnectorSymbolicReferenceInferenceBinding {
        connector_id: GOOGLE_CONNECTOR_ID,
        infer: infer_google_symbolic_reference_from_query_boxed,
    }]
}

fn protected_slot_kind_for_google_field(
    field: &ConnectorFieldDefinition,
) -> Option<ProtectedSlotKind> {
    match field.field_type.as_str() {
        "email" => Some(ProtectedSlotKind::EmailAddress),
        _ => None,
    }
}

pub fn google_connector_protected_slot_bindings() -> Vec<ConnectorProtectedSlotBinding> {
    let mut bindings = Vec::new();
    for spec in google_connector_action_specs() {
        for field in spec.fields {
            let Some(protected_slot_kind) = protected_slot_kind_for_google_field(&field) else {
                continue;
            };
            bindings.push(ConnectorProtectedSlotBinding {
                tool_name: spec.tool_name.to_string(),
                slot: field.id,
                protected_slot_kind,
            });
        }
    }
    bindings
}

fn extract_first_json_object(raw: &str) -> Option<String> {
    let start = raw.find('{')?;
    let mut brace_depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (idx, ch) in raw[start..].char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == '"' {
            in_string = !in_string;
            continue;
        }
        if in_string {
            continue;
        }
        if ch == '{' {
            brace_depth = brace_depth.saturating_add(1);
            continue;
        }
        if ch == '}' {
            brace_depth = brace_depth.saturating_sub(1);
            if brace_depth == 0 {
                let end = start + idx + 1;
                return Some(raw[start..end].to_string());
            }
        }
    }
    None
}

fn parse_json_payload_from_history(history_entry: &str) -> Option<Value> {
    extract_first_json_object(history_entry)
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
}

fn expected_mailbox_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .filter_map(canonicalize_email_recipient)
        .collect::<Vec<_>>()
}

fn gmail_to_header_matches(actual_to: Option<&str>, expected_to: &str) -> bool {
    let Some(actual_to) = actual_to else {
        return false;
    };
    let expected = canonicalize_email_recipient(expected_to)
        .unwrap_or_else(|| expected_to.trim().to_ascii_lowercase());
    expected_mailbox_list(actual_to)
        .into_iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(&expected))
}

fn gmail_body_matches(actual_body: Option<&str>, expected_body: &str) -> bool {
    actual_body
        .map(|body| body.trim() == expected_body.trim())
        .unwrap_or(false)
}

fn verify_google_postconditions_boxed<'a>(
    agent_state: &'a AgentState,
    tool_name: &'a str,
    tool_args: &'a Value,
    history_entry: &'a str,
) -> PostconditionVerificationFuture<'a> {
    Box::pin(async move {
        let normalized = tool_name.trim().to_ascii_lowercase();
        let (message_id, required_label) = match normalized.as_str() {
            "connector__google__gmail_draft_email" => {
                let payload = parse_json_payload_from_history(history_entry).ok_or_else(|| {
                    "Google draft verification could not parse structured action output."
                        .to_string()
                })?;
                (
                    payload
                        .get("message")
                        .and_then(|message| message.get("id"))
                        .and_then(Value::as_str)
                        .map(str::to_string)
                        .ok_or_else(|| {
                            "Google draft verification payload was missing message.id.".to_string()
                        })?,
                    "DRAFT",
                )
            }
            "connector__google__gmail_send_email" => {
                let payload = parse_json_payload_from_history(history_entry).ok_or_else(|| {
                    "Google send verification could not parse structured action output.".to_string()
                })?;
                (
                    payload
                        .get("id")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                        .ok_or_else(|| {
                            "Google send verification payload was missing message id.".to_string()
                        })?,
                    "SENT",
                )
            }
            _ => return Ok(None),
        };

        let expected_to = tool_args.get("to").and_then(Value::as_str).ok_or_else(|| {
            "Google mail verification requires a grounded `to` argument.".to_string()
        })?;
        let expected_subject = tool_args
            .get("subject")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                "Google mail verification requires a grounded `subject` argument.".to_string()
            })?;
        let expected_body = tool_args
            .get("body")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                "Google mail verification requires a grounded `body` argument.".to_string()
            })?;
        let readback = google_api::gmail_readback_message(&message_id).await?;
        let to_match = gmail_to_header_matches(readback.to.as_deref(), expected_to);
        let subject_match = readback
            .subject
            .as_deref()
            .map(|actual| actual.trim() == expected_subject.trim())
            .unwrap_or(false);
        let body_match = gmail_body_matches(readback.body_text.as_deref(), expected_body);
        let label_match = readback
            .label_ids
            .iter()
            .any(|label| label.eq_ignore_ascii_case(required_label));
        if !(to_match && subject_match && body_match && label_match) {
            return Err(format!(
                "ERROR_CLASS=PostconditionFailed Google mail verification failed. message_id={} to_match={} subject_match={} body_match={} label_match={}",
                readback.message_id, to_match, subject_match, body_match, label_match
            ));
        }

        Ok(Some(ConnectorPostconditionProof {
            evidence: vec![ConnectorPostconditionEvidence {
                key: "mail.reply.completed".to_string(),
                evidence: format!(
                    "message_id={};thread_id={};label={};to={};subject={}",
                    readback.message_id,
                    readback.thread_id.unwrap_or_default(),
                    required_label,
                    expected_to,
                    expected_subject
                ),
                observed_value: Some(readback.message_id),
                evidence_type: Some("gmail_readback".to_string()),
                provider_id: google_selected_provider_id(agent_state),
            }],
        }))
    })
}

pub fn google_connector_postcondition_verifier_bindings(
) -> Vec<ConnectorPostconditionVerifierBinding> {
    vec![ConnectorPostconditionVerifierBinding {
        connector_id: GOOGLE_CONNECTOR_ID,
        verify: verify_google_postconditions_boxed,
    }]
}

pub fn is_google_duplicate_safe_tool_name(name: &str) -> bool {
    matches!(
        name.trim().to_ascii_lowercase().as_str(),
        "connector__google__gmail_read_emails"
            | "connector__google__gmail_get_thread"
            | "connector__google__gmail_list_labels"
            | "connector__google__calendar_get_event"
            | "connector__google__calendar_list_events_for_date"
            | "connector__google__docs_read_document"
            | "connector__google__sheets_read_range"
            | "connector__google__sheets_get_spreadsheet"
            | "connector__google__tasks_list_tasks"
            | "connector__google__workflow_standup_report"
            | "connector__google__workflow_meeting_prep"
            | "connector__google__workflow_weekly_digest"
    )
}

pub fn google_read_policy_targets() -> Vec<String> {
    let mut targets = google_connector_action_specs()
        .into_iter()
        .filter(|spec| {
            spec.kind == "read"
                || matches!(
                    spec.tool_name,
                    "connector__google__workflow_standup_report"
                        | "connector__google__workflow_meeting_prep"
                        | "connector__google__workflow_weekly_digest"
                )
        })
        .map(|spec| spec.tool_name.to_string())
        .collect::<Vec<_>>();
    targets.push(BIGQUERY_READ_TARGET.to_string());
    targets
}

pub fn google_dynamic_tool_target(raw_json: &Value) -> Option<ActionTarget> {
    let name = raw_json.get("name").and_then(Value::as_str)?;
    let normalized = name.trim().to_ascii_lowercase();
    if normalized.is_empty() || !is_google_connector_tool_name(&normalized) {
        return None;
    }

    if normalized == BIGQUERY_TOOL_NAME {
        let arguments = parse_dynamic_arguments(raw_json);
        let query = arguments
            .get("query")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let label = if is_bigquery_read_query(query) {
            BIGQUERY_READ_TARGET
        } else {
            BIGQUERY_WRITE_TARGET
        };
        return Some(ActionTarget::Custom(label.to_string()));
    }

    Some(ActionTarget::Custom(normalized))
}

pub async fn connector_run_action(
    connector_id: &str,
    action_id: &str,
    input: Value,
) -> Result<ConnectorActionResult, String> {
    if !matches_google_connector_id(connector_id) {
        return Err(format!("Unsupported connector '{}'", connector_id));
    }

    let spec = find_action_by_id(action_id)
        .ok_or_else(|| format!("Unsupported Google connector action '{}'", action_id))?;
    let normalized_input = normalize_google_action_input(&spec, &input).await?;
    let args = build_google_workspace_args(&spec, &normalized_input)?;
    let output = run_gws_command(
        &args,
        command_timeout_secs_for_action(spec.id),
        spec.required_scopes,
    )
    .await?;
    let data = parse_jsonish_output(&output.stdout);
    let summary = summarize_action(&spec, &data, &normalized_input);

    Ok(ConnectorActionResult {
        connector_id: GOOGLE_CONNECTOR_ID.to_string(),
        action_id: spec.id.to_string(),
        tool_name: spec.tool_name.to_string(),
        provider: GOOGLE_CONNECTOR_PROVIDER.to_string(),
        summary,
        data,
        raw_output: Some(output.stdout),
        executed_at_utc: now_rfc3339(),
    })
}

pub async fn try_execute_dynamic_tool(
    service: &DesktopAgentService,
    agent_state: &AgentState,
    session_id: [u8; 32],
    raw_json: &Value,
) -> Result<Option<(bool, Option<String>, Option<String>)>, TransactionError> {
    let Some(tool_name) = raw_json.get("name").and_then(Value::as_str) else {
        return Ok(None);
    };
    let normalized = tool_name.trim().to_ascii_lowercase();
    let Some(spec) = find_action_by_tool_name(&normalized) else {
        return Ok(None);
    };

    let arguments = parse_dynamic_arguments(raw_json);
    let runtime_resume_approval =
        runtime_resume_already_authorizes_google_tool(agent_state, raw_json);
    enforce_google_tool_shield_policy(
        service,
        agent_state,
        session_id,
        &spec,
        &arguments,
        runtime_resume_approval,
    )?;

    match connector_run_action(GOOGLE_CONNECTOR_ID, spec.id, arguments).await {
        Ok(result) => {
            let payload = serde_json::to_string_pretty(&result.data).unwrap_or_default();
            let history = if payload.is_empty() || payload == "null" {
                result.summary
            } else {
                format!("{}\n\n{}", result.summary, payload)
            };
            Ok(Some((true, Some(history), None)))
        }
        Err(error) => Ok(Some((
            false,
            None,
            Some(format!("Google connector action failed: {}", error)),
        ))),
    }
}

fn google_connector_action_specs() -> Vec<GoogleConnectorActionSpec> {
    vec![
        GoogleConnectorActionSpec {
            id: "gmail.read_emails",
            service: "gmail",
            service_label: "Gmail",
            tool_name: "connector__google__gmail_read_emails",
            label: "Gmail Read Emails",
            description: "Read Gmail messages by query with sender, subject, preview, and labels.",
            kind: "read",
            confirm_before_run: false,
            required_scopes: &["gmail.readonly", "gmail.modify"],
            capabilities: &[
                "mail.read.latest",
                "mail.list.recent",
                "filesystem.read",
                "gmail.read",
            ],
            fields: vec![
                number_field(
                    "max",
                    "Max messages",
                    20,
                    false,
                    Some("Maximum number of messages to return."),
                ),
                text_field(
                    "query",
                    "Search query",
                    Some("is:unread"),
                    false,
                    Some("Gmail search query such as `label:inbox newer_than:7d`."),
                ),
                select_field(
                    "includeLabels",
                    "Include labels",
                    "false",
                    vec![("No", "false"), ("Yes", "true")],
                    Some("Include label names in the output."),
                ),
            ],
        },
        GoogleConnectorActionSpec {
            id: "gmail.send_email",
            service: "gmail",
            service_label: "Gmail",
            tool_name: "connector__google__gmail_send_email",
            label: "Gmail Send Email",
            description: "Send an email through Gmail using the connected Google account.",
            kind: "write",
            confirm_before_run: true,
            required_scopes: &["gmail.modify"],
            capabilities: &[
                "mail.reply",
                "mail.send",
                "filesystem.read",
                "filesystem.write",
                "gmail.write",
            ],
            fields: vec![
                email_field("to", "Recipient", true, Some("alice@example.com")),
                text_field("subject", "Subject", None, true, None),
                textarea_field("body", "Body", None, true, Some("Plain text message body.")),
                text_field(
                    "threadId",
                    "Thread ID",
                    None,
                    false,
                    Some("Optional Gmail thread to keep the send bound to an existing conversation."),
                ),
                text_field(
                    "inReplyTo",
                    "In-Reply-To",
                    None,
                    false,
                    Some("Optional RFC Message-ID header for explicit reply threading."),
                ),
                text_field(
                    "references",
                    "References",
                    None,
                    false,
                    Some("Optional References header for explicit reply threading."),
                ),
            ],
        },
        GoogleConnectorActionSpec {
            id: "gmail.draft_email",
            service: "gmail",
            service_label: "Gmail",
            tool_name: "connector__google__gmail_draft_email",
            label: "Gmail Draft Email",
            description: "Create a Gmail draft without sending it.",
            kind: "write",
            confirm_before_run: true,
            required_scopes: &["gmail.modify"],
            capabilities: &[
                "mail.reply",
                "mail.send",
                "filesystem.read",
                "filesystem.write",
                "gmail.write",
            ],
            fields: vec![
                email_field("to", "Recipient", true, Some("alice@example.com")),
                text_field("subject", "Subject", None, true, None),
                textarea_field("body", "Body", None, true, Some("Plain text draft body.")),
                text_field(
                    "threadId",
                    "Thread ID",
                    None,
                    false,
                    Some("Optional Gmail thread to keep the draft bound to an existing conversation."),
                ),
                text_field(
                    "inReplyTo",
                    "In-Reply-To",
                    None,
                    false,
                    Some("Optional RFC Message-ID header for explicit reply threading."),
                ),
                text_field(
                    "references",
                    "References",
                    None,
                    false,
                    Some("Optional References header for explicit reply threading."),
                ),
            ],
        },
        GoogleConnectorActionSpec {
            id: "gmail.mark_as_read",
            service: "gmail",
            service_label: "Gmail",
            tool_name: "connector__google__gmail_mark_as_read",
            label: "Gmail Mark As Read",
            description: "Remove the `UNREAD` label from a Gmail message.",
            kind: "write",
            confirm_before_run: true,
            required_scopes: &["gmail.modify"],
            capabilities: &[
                "mail.read.latest",
                "filesystem.read",
                "filesystem.write",
                "gmail.write",
            ],
            fields: vec![text_field("messageId", "Message ID", None, true, None)],
        },
        GoogleConnectorActionSpec {
            id: "gmail.archive_email",
            service: "gmail",
            service_label: "Gmail",
            tool_name: "connector__google__gmail_archive_email",
            label: "Gmail Archive Email",
            description: "Archive a Gmail message by removing the `INBOX` label.",
            kind: "write",
            confirm_before_run: true,
            required_scopes: &["gmail.modify"],
            capabilities: &[
                "mail.read.latest",
                "filesystem.read",
                "filesystem.write",
                "gmail.write",
            ],
            fields: vec![text_field("messageId", "Message ID", None, true, None)],
        },
        GoogleConnectorActionSpec {
            id: "gmail.apply_label",
            service: "gmail",
            service_label: "Gmail",
            tool_name: "connector__google__gmail_apply_label",
            label: "Gmail Apply Label",
            description: "Apply one or more Gmail labels to a message.",
            kind: "write",
            confirm_before_run: true,
            required_scopes: &["gmail.modify"],
            capabilities: &[
                "filesystem.read",
                "filesystem.write",
                "gmail.write",
            ],
            fields: vec![
                text_field("messageId", "Message ID", None, true, None),
                textarea_field(
                    "labelIds",
                    "Label IDs",
                    None,
                    true,
                    Some("Comma or newline separated label IDs."),
                ),
            ],
        },
        GoogleConnectorActionSpec {
            id: "gmail.create_label",
            service: "gmail",
            service_label: "Gmail",
            tool_name: "connector__google__gmail_create_label",
            label: "Gmail Create Label",
            description: "Create a new Gmail label.",
            kind: "write",
            confirm_before_run: true,
            required_scopes: &["gmail.modify"],
            capabilities: &[
                "filesystem.read",
                "filesystem.write",
                "gmail.write",
            ],
            fields: vec![
                text_field("name", "Label name", None, true, None),
                select_field(
                    "messageListVisibility",
                    "Message list visibility",
                    "show",
                    vec![("Show", "show"), ("Hide", "hide")],
                    None,
                ),
                select_field(
                    "labelListVisibility",
                    "Label list visibility",
                    "labelShow",
                    vec![
                        ("Show", "labelShow"),
                        ("Show if unread", "labelShowIfUnread"),
                        ("Hide", "labelHide"),
                    ],
                    None,
                ),
            ],
        },
        GoogleConnectorActionSpec {
            id: "gmail.get_thread",
            service: "gmail",
            service_label: "Gmail",
            tool_name: "connector__google__gmail_get_thread",
            label: "Gmail Get Thread",
            description: "Fetch a Gmail thread with its messages and metadata.",
            kind: "read",
            confirm_before_run: false,
            required_scopes: &["gmail.readonly", "gmail.modify"],
            capabilities: &[
                "mail.read.latest",
                "mail.list.recent",
                "filesystem.read",
                "gmail.read",
            ],
            fields: vec![
                text_field("threadId", "Thread ID", None, true, None),
                select_field(
                    "format",
                    "Format",
                    "full",
                    vec![
                        ("Full", "full"),
                        ("Metadata", "metadata"),
                        ("Minimal", "minimal"),
                    ],
                    None,
                ),
            ],
        },
        GoogleConnectorActionSpec {
            id: "gmail.list_labels",
            service: "gmail",
            service_label: "Gmail",
            tool_name: "connector__google__gmail_list_labels",
            label: "Gmail List Labels",
            description: "List Gmail labels for the connected account.",
            kind: "read",
            confirm_before_run: false,
            required_scopes: &["gmail.readonly", "gmail.modify"],
            capabilities: &[
                "mail.read.latest",
                "mail.list.recent",
                "filesystem.read",
                "gmail.read",
            ],
            fields: vec![],
        },
        GoogleConnectorActionSpec {
            id: "gmail.watch_emails",
            service: "gmail",
            service_label: "Gmail",
            tool_name: "connector__google__gmail_watch_emails",
            label: "Gmail Watch Emails",
            description: "Start or reconnect a durable Gmail watch backed by Pub/Sub and the Autopilot runtime.",
            kind: "admin",
            confirm_before_run: true,
            required_scopes: &["gmail.modify", "pubsub", "cloud-platform"],
            capabilities: &[
                "filesystem.read",
                "filesystem.write",
                "gmail.events",
                "events.manage",
            ],
            fields: vec![
                text_field(
                    "project",
                    "Project ID",
                    None,
                    false,
                    Some("Required when creating Pub/Sub resources."),
                ),
                text_field(
                    "subscription",
                    "Existing subscription",
                    None,
                    false,
                    Some("Reconnect to an existing Pub/Sub subscription."),
                ),
                text_field(
                    "topic",
                    "Existing topic",
                    None,
                    false,
                    Some("Use an existing Pub/Sub topic that already grants Gmail publish access."),
                ),
                text_field(
                    "labelIds",
                    "Label IDs",
                    Some("INBOX"),
                    false,
                    Some("Comma separated Gmail label IDs."),
                ),
                number_field("maxMessages", "Max messages", 10, false, None),
                number_field("pollInterval", "Poll interval seconds", 5, false, None),
                select_field(
                    "msgFormat",
                    "Message format",
                    "full",
                    vec![
                        ("Full", "full"),
                        ("Metadata", "metadata"),
                        ("Minimal", "minimal"),
                        ("Raw", "raw"),
                    ],
                    None,
                ),
                select_field(
                    "once",
                    "Pull once",
                    "false",
                    vec![("Yes", "true"), ("No", "false")],
                    Some("Default is `false` so the background runtime keeps consuming deliveries."),
                ),
                select_field(
                    "cleanup",
                    "Cleanup",
                    "false",
                    vec![("No", "false"), ("Yes", "true")],
                    Some("Delete created Pub/Sub resources when the watch exits."),
                ),
                text_field(
                    "outputDir",
                    "Output directory",
                    None,
                    false,
                    Some("Optional directory to write message JSON files."),
                ),
                text_field(
                    "automationActionId",
                    "Automation action ID",
                    None,
                    false,
                    Some("Optional connector action to run for each normalized Gmail delivery."),
                ),
                textarea_field(
                    "automationInputTemplate",
                    "Automation input template",
                    Some("{\"messageId\":\"{{message.messageId}}\",\"tasklist\":\"@default\"}"),
                    false,
                    Some("Optional JSON template rendered against the Gmail delivery context."),
                ),
            ],
        },
        GoogleConnectorActionSpec {
            id: "bigquery.execute_query",
            service: "bigquery",
            service_label: "Google BigQuery",
            tool_name: BIGQUERY_TOOL_NAME,
            label: "BigQuery Execute Query",
            description: "Execute a BigQuery SQL statement using the connected Google account.",
            kind: "read",
            confirm_before_run: false,
            required_scopes: &["cloud-platform"],
            capabilities: &[
                "filesystem.read",
                "bigquery.query",
            ],
            fields: vec![
                text_field(
                    "projectId",
                    "Project ID",
                    None,
                    false,
                    Some("Defaults to GOOGLE_CLOUD_PROJECT or GOOGLE_WORKSPACE_PROJECT_ID when set."),
                ),
                text_field("location", "Location", None, false, Some("Optional BigQuery location.")),
                textarea_field("query", "SQL query", None, true, None),
                number_field("maxResults", "Max results", 100, false, None),
                select_field(
                    "useLegacySql",
                    "Use legacy SQL",
                    "false",
                    vec![("No", "false"), ("Yes", "true")],
                    None,
                ),
            ],
        },
        GoogleConnectorActionSpec {
            id: "calendar.get_event",
            service: "calendar",
            service_label: "Google Calendar",
            tool_name: "connector__google__calendar_get_event",
            label: "Google Calendar Get Event",
            description: "Fetch a single Google Calendar event by ID.",
            kind: "read",
            confirm_before_run: false,
            required_scopes: &["calendar.readonly", "calendar"],
            capabilities: &[
                "filesystem.read",
                "calendar.read",
            ],
            fields: vec![
                text_field("calendarId", "Calendar ID", Some("primary"), false, None),
                text_field("eventId", "Event ID", None, true, None),
            ],
        },
        GoogleConnectorActionSpec {
            id: "calendar.list_events_for_date",
            service: "calendar",
            service_label: "Google Calendar",
            tool_name: "connector__google__calendar_list_events_for_date",
            label: "Google Calendar List Events For Date",
            description: "List calendar events for a specific calendar day.",
            kind: "read",
            confirm_before_run: false,
            required_scopes: &["calendar.readonly", "calendar"],
            capabilities: &[
                "filesystem.read",
                "calendar.read",
            ],
            fields: vec![
                text_field("calendarId", "Calendar ID", Some("primary"), false, None),
                text_field(
                    "date",
                    "Date",
                    Some("2026-03-07"),
                    true,
                    Some("Date in YYYY-MM-DD format."),
                ),
                number_field("maxResults", "Max results", 25, false, None),
            ],
        },
        GoogleConnectorActionSpec {
            id: "calendar.create_event",
            service: "calendar",
            service_label: "Google Calendar",
            tool_name: "connector__google__calendar_create_event",
            label: "Google Calendar Create Event",
            description: "Create a new Google Calendar event.",
            kind: "write",
            confirm_before_run: true,
            required_scopes: &["calendar"],
            capabilities: &[
                "filesystem.read",
                "filesystem.write",
                "calendar.write",
            ],
            fields: vec![
                text_field("calendarId", "Calendar ID", Some("primary"), false, None),
                text_field("summary", "Summary", None, true, None),
                text_field(
                    "start",
                    "Start",
                    Some("2026-03-07T15:00:00-05:00"),
                    true,
                    Some("RFC3339 timestamp."),
                ),
                text_field(
                    "end",
                    "End",
                    Some("2026-03-07T15:30:00-05:00"),
                    true,
                    Some("RFC3339 timestamp."),
                ),
                text_field("location", "Location", None, false, None),
                textarea_field("description", "Description", None, false, None),
                textarea_field(
                    "attendees",
                    "Attendees",
                    None,
                    false,
                    Some("Comma or newline separated attendee emails."),
                ),
            ],
        },
        GoogleConnectorActionSpec {
            id: "calendar.update_event",
            service: "calendar",
            service_label: "Google Calendar",
            tool_name: "connector__google__calendar_update_event",
            label: "Google Calendar Update Event",
            description: "Patch an existing Google Calendar event.",
            kind: "write",
            confirm_before_run: true,
            required_scopes: &["calendar"],
            capabilities: &[
                "filesystem.read",
                "filesystem.write",
                "calendar.write",
            ],
            fields: vec![
                text_field("calendarId", "Calendar ID", Some("primary"), false, None),
                text_field("eventId", "Event ID", None, true, None),
                text_field("summary", "Summary", None, false, None),
                text_field(
                    "start",
                    "Start",
                    Some("2026-03-07T15:00:00-05:00"),
                    false,
                    Some("Optional RFC3339 timestamp."),
                ),
                text_field(
                    "end",
                    "End",
                    Some("2026-03-07T15:30:00-05:00"),
                    false,
                    Some("Optional RFC3339 timestamp."),
                ),
                text_field("location", "Location", None, false, None),
                textarea_field("description", "Description", None, false, None),
                textarea_field(
                    "attendees",
                    "Attendees",
                    None,
                    false,
                    Some("Replaces the attendee list when provided."),
                ),
            ],
        },
        GoogleConnectorActionSpec {
            id: "calendar.delete_event",
            service: "calendar",
            service_label: "Google Calendar",
            tool_name: "connector__google__calendar_delete_event",
            label: "Google Calendar Delete Event",
            description: "Delete a Google Calendar event.",
            kind: "write",
            confirm_before_run: true,
            required_scopes: &["calendar"],
            capabilities: &[
                "filesystem.read",
                "filesystem.write",
                "calendar.write",
            ],
            fields: vec![
                text_field("calendarId", "Calendar ID", Some("primary"), false, None),
                text_field("eventId", "Event ID", None, true, None),
            ],
        },
        GoogleConnectorActionSpec {
            id: "docs.create_document",
            service: "docs",
            service_label: "Google Docs",
            tool_name: "connector__google__docs_create_document",
            label: "Google Docs Create Document",
            description: "Create a new Google Doc.",
            kind: "write",
            confirm_before_run: true,
            required_scopes: &["documents"],
            capabilities: &[
                "filesystem.read",
                "filesystem.write",
                "docs.write",
            ],
            fields: vec![text_field("title", "Title", None, true, None)],
        },
        GoogleConnectorActionSpec {
            id: "docs.read_document",
            service: "docs",
            service_label: "Google Docs",
            tool_name: "connector__google__docs_read_document",
            label: "Google Docs Read Document",
            description: "Read a Google Doc.",
            kind: "read",
            confirm_before_run: false,
            required_scopes: &["documents.readonly", "documents"],
            capabilities: &[
                "filesystem.read",
                "docs.read",
            ],
            fields: vec![text_field("documentId", "Document ID", None, true, None)],
        },
        GoogleConnectorActionSpec {
            id: "docs.append_text",
            service: "docs",
            service_label: "Google Docs",
            tool_name: "connector__google__docs_append_text",
            label: "Google Docs Append Text",
            description: "Append text to the end of a Google Doc body.",
            kind: "write",
            confirm_before_run: true,
            required_scopes: &["documents"],
            capabilities: &[
                "filesystem.read",
                "filesystem.write",
                "docs.write",
            ],
            fields: vec![
                text_field("documentId", "Document ID", None, true, None),
                textarea_field("text", "Text", None, true, None),
            ],
        },
        GoogleConnectorActionSpec {
            id: "docs.replace_text",
            service: "docs",
            service_label: "Google Docs",
            tool_name: "connector__google__docs_replace_text",
            label: "Google Docs Replace Text",
            description: "Replace matching text in a Google Doc using `replaceAllText`.",
            kind: "write",
            confirm_before_run: true,
            required_scopes: &["documents"],
            capabilities: &[
                "filesystem.read",
                "filesystem.write",
                "docs.write",
            ],
            fields: vec![
                text_field("documentId", "Document ID", None, true, None),
                text_field("searchText", "Search text", None, true, None),
                text_field("replaceText", "Replace with", None, true, None),
                select_field(
                    "matchCase",
                    "Match case",
                    "false",
                    vec![("No", "false"), ("Yes", "true")],
                    None,
                ),
            ],
        },
        GoogleConnectorActionSpec {
            id: "sheets.read_range",
            service: "sheets",
            service_label: "Google Sheets",
            tool_name: "connector__google__sheets_read_range",
            label: "Google Sheets Read Range",
            description: "Read values from a Google Sheet range.",
            kind: "read",
            confirm_before_run: false,
            required_scopes: &["spreadsheets.readonly", "spreadsheets"],
            capabilities: &[
                "filesystem.read",
                "sheets.read",
            ],
            fields: vec![
                text_field("spreadsheetId", "Spreadsheet ID", None, true, None),
                text_field("range", "Range", Some("Sheet1!A1:D10"), true, None),
            ],
        },
        GoogleConnectorActionSpec {
            id: "sheets.create_spreadsheet",
            service: "sheets",
            service_label: "Google Sheets",
            tool_name: "connector__google__sheets_create_spreadsheet",
            label: "Google Sheets Create Spreadsheet",
            description: "Create a new Google Spreadsheet.",
            kind: "write",
            confirm_before_run: true,
            required_scopes: &["spreadsheets"],
            capabilities: &[
                "filesystem.read",
                "filesystem.write",
                "sheets.write",
            ],
            fields: vec![text_field("title", "Title", None, true, None)],
        },
        GoogleConnectorActionSpec {
            id: "sheets.write_range",
            service: "sheets",
            service_label: "Google Sheets",
            tool_name: "connector__google__sheets_write_range",
            label: "Google Sheets Write Range",
            description: "Overwrite a Google Sheet range with JSON row data.",
            kind: "write",
            confirm_before_run: true,
            required_scopes: &["spreadsheets"],
            capabilities: &[
                "filesystem.read",
                "filesystem.write",
                "sheets.write",
            ],
            fields: vec![
                text_field("spreadsheetId", "Spreadsheet ID", None, true, None),
                text_field("range", "Range", Some("Sheet1!A1"), true, None),
                textarea_field(
                    "valuesJson",
                    "Values JSON",
                    Some("[[\"Deploy\",\"v1.0\"]]"),
                    true,
                    Some("JSON array of rows."),
                ),
                select_field(
                    "valueInputOption",
                    "Value input option",
                    "USER_ENTERED",
                    vec![
                        ("User entered", "USER_ENTERED"),
                        ("Raw", "RAW"),
                    ],
                    None,
                ),
            ],
        },
        GoogleConnectorActionSpec {
            id: "sheets.append_rows",
            service: "sheets",
            service_label: "Google Sheets",
            tool_name: "connector__google__sheets_append_rows",
            label: "Google Sheets Append Rows",
            description: "Append JSON row data to a Google Sheet.",
            kind: "write",
            confirm_before_run: true,
            required_scopes: &["spreadsheets"],
            capabilities: &[
                "filesystem.read",
                "filesystem.write",
                "sheets.write",
            ],
            fields: vec![
                text_field("spreadsheetId", "Spreadsheet ID", None, true, None),
                textarea_field(
                    "valuesJson",
                    "Values JSON",
                    Some("[[\"Alice\",100,true]]"),
                    true,
                    Some("JSON array of rows."),
                ),
            ],
        },
        GoogleConnectorActionSpec {
            id: "sheets.clear_range",
            service: "sheets",
            service_label: "Google Sheets",
            tool_name: "connector__google__sheets_clear_range",
            label: "Google Sheets Clear Range",
            description: "Clear values from a Google Sheet range.",
            kind: "write",
            confirm_before_run: true,
            required_scopes: &["spreadsheets"],
            capabilities: &[
                "filesystem.read",
                "filesystem.write",
                "sheets.write",
            ],
            fields: vec![
                text_field("spreadsheetId", "Spreadsheet ID", None, true, None),
                text_field("range", "Range", Some("Sheet1!A1:D10"), true, None),
            ],
        },
        GoogleConnectorActionSpec {
            id: "sheets.get_spreadsheet",
            service: "sheets",
            service_label: "Google Sheets",
            tool_name: "connector__google__sheets_get_spreadsheet",
            label: "Google Sheets Get Spreadsheet",
            description: "Fetch spreadsheet metadata and optional ranges.",
            kind: "read",
            confirm_before_run: false,
            required_scopes: &["spreadsheets.readonly", "spreadsheets"],
            capabilities: &[
                "filesystem.read",
                "sheets.read",
            ],
            fields: vec![
                text_field("spreadsheetId", "Spreadsheet ID", None, true, None),
                textarea_field(
                    "ranges",
                    "Ranges",
                    None,
                    false,
                    Some("Optional comma or newline separated ranges."),
                ),
                select_field(
                    "includeGridData",
                    "Include grid data",
                    "false",
                    vec![("No", "false"), ("Yes", "true")],
                    None,
                ),
            ],
        },
        GoogleConnectorActionSpec {
            id: "drive.upload_file",
            service: "drive",
            service_label: "Google Drive",
            tool_name: "connector__google__drive_upload_file",
            label: "Drive Upload File",
            description: "Upload a local file to Google Drive.",
            kind: "write",
            confirm_before_run: true,
            required_scopes: &["drive"],
            capabilities: &[
                "filesystem.read",
                "filesystem.write",
                "drive.write",
            ],
            fields: vec![
                text_field(
                    "filePath",
                    "Local file path",
                    None,
                    true,
                    Some("/absolute/path/to/file.pdf"),
                ),
                text_field("parentId", "Parent folder ID", None, false, None),
                text_field("name", "Target name", None, false, None),
            ],
        },
        GoogleConnectorActionSpec {
            id: "drive.share_file",
            service: "drive",
            service_label: "Google Drive",
            tool_name: "connector__google__drive_share_file",
            label: "Drive Share File",
            description: "Share a Google Drive file with a specific user and role.",
            kind: "write",
            confirm_before_run: true,
            required_scopes: &["drive"],
            capabilities: &[
                "filesystem.read",
                "filesystem.write",
                "drive.write",
            ],
            fields: vec![
                text_field("fileId", "File ID", None, true, None),
                email_field("email", "Share with", true, Some("alice@example.com")),
                select_field(
                    "role",
                    "Role",
                    "reader",
                    vec![
                        ("Viewer", "reader"),
                        ("Commenter", "commenter"),
                        ("Editor", "writer"),
                    ],
                    None,
                ),
            ],
        },
        GoogleConnectorActionSpec {
            id: "tasks.list_tasks",
            service: "tasks",
            service_label: "Google Tasks",
            tool_name: "connector__google__tasks_list_tasks",
            label: "Google Tasks List Tasks",
            description: "List tasks from a Google Tasks list.",
            kind: "read",
            confirm_before_run: false,
            required_scopes: &["tasks.readonly", "tasks"],
            capabilities: &[
                "filesystem.read",
                "tasks.read",
            ],
            fields: vec![
                text_field("tasklist", "Task list", Some("@default"), false, None),
                select_field(
                    "showCompleted",
                    "Show completed",
                    "false",
                    vec![("No", "false"), ("Yes", "true")],
                    None,
                ),
                number_field("maxResults", "Max results", 20, false, None),
            ],
        },
        GoogleConnectorActionSpec {
            id: "tasks.create_task",
            service: "tasks",
            service_label: "Google Tasks",
            tool_name: "connector__google__tasks_create_task",
            label: "Google Tasks Create Task",
            description: "Create a task in Google Tasks.",
            kind: "write",
            confirm_before_run: true,
            required_scopes: &["tasks"],
            capabilities: &[
                "filesystem.read",
                "filesystem.write",
                "tasks.write",
            ],
            fields: vec![
                text_field("tasklist", "Task list", Some("@default"), false, None),
                text_field("title", "Title", None, true, None),
                textarea_field("notes", "Notes", None, false, None),
                text_field(
                    "due",
                    "Due",
                    Some("2026-03-07T17:00:00Z"),
                    false,
                    Some("Optional RFC3339 due timestamp."),
                ),
            ],
        },
        GoogleConnectorActionSpec {
            id: "chat.send_message",
            service: "chat",
            service_label: "Google Chat",
            tool_name: "connector__google__chat_send_message",
            label: "Google Chat Send Message",
            description: "Send a text message to a Google Chat space.",
            kind: "write",
            confirm_before_run: true,
            required_scopes: &["chat.messages.create"],
            capabilities: &[
                "filesystem.read",
                "filesystem.write",
                "chat.write",
            ],
            fields: vec![
                text_field("space", "Space", Some("spaces/AAAA..."), true, None),
                textarea_field("text", "Text", None, true, None),
            ],
        },
        GoogleConnectorActionSpec {
            id: "workflow.standup_report",
            service: "workflow",
            service_label: "Workflow",
            tool_name: "connector__google__workflow_standup_report",
            label: "Standup Report",
            description: "Summarize today's meetings and open tasks as a standup report.",
            kind: "workflow",
            confirm_before_run: false,
            required_scopes: &["calendar.readonly", "tasks.readonly"],
            capabilities: &[
                "filesystem.read",
                "workflow.execute",
            ],
            fields: vec![],
        },
        GoogleConnectorActionSpec {
            id: "workflow.meeting_prep",
            service: "workflow",
            service_label: "Workflow",
            tool_name: "connector__google__workflow_meeting_prep",
            label: "Meeting Prep",
            description: "Prepare for the next meeting with attendees, links, and context.",
            kind: "workflow",
            confirm_before_run: false,
            required_scopes: &["calendar.readonly"],
            capabilities: &[
                "filesystem.read",
                "workflow.execute",
            ],
            fields: vec![text_field("calendar", "Calendar", Some("primary"), false, None)],
        },
        GoogleConnectorActionSpec {
            id: "workflow.email_to_task",
            service: "workflow",
            service_label: "Workflow",
            tool_name: "connector__google__workflow_email_to_task",
            label: "Email To Task",
            description: "Create a task from a Gmail message subject and snippet.",
            kind: "workflow",
            confirm_before_run: true,
            required_scopes: &["gmail.readonly", "tasks"],
            capabilities: &[
                "filesystem.read",
                "filesystem.write",
                "workflow.execute",
            ],
            fields: vec![
                text_field("messageId", "Gmail message ID", None, true, None),
                text_field("tasklist", "Task list", Some("@default"), false, None),
            ],
        },
        GoogleConnectorActionSpec {
            id: "workflow.weekly_digest",
            service: "workflow",
            service_label: "Workflow",
            tool_name: "connector__google__workflow_weekly_digest",
            label: "Weekly Digest",
            description: "Combine this week's meetings and unread email count.",
            kind: "workflow",
            confirm_before_run: false,
            required_scopes: &["calendar.readonly", "gmail.readonly"],
            capabilities: &[
                "filesystem.read",
                "workflow.execute",
            ],
            fields: vec![],
        },
        GoogleConnectorActionSpec {
            id: "workflow.file_announce",
            service: "workflow",
            service_label: "Workflow",
            tool_name: "connector__google__workflow_file_announce",
            label: "File Announce",
            description: "Announce a Drive file in a Google Chat space.",
            kind: "workflow",
            confirm_before_run: true,
            required_scopes: &["drive.readonly", "chat.messages.create"],
            capabilities: &[
                "filesystem.read",
                "filesystem.write",
                "workflow.execute",
            ],
            fields: vec![
                text_field("fileId", "File ID", None, true, None),
                text_field("space", "Space", Some("spaces/AAAA..."), true, None),
                textarea_field("message", "Message", None, false, None),
            ],
        },
        GoogleConnectorActionSpec {
            id: "events.subscribe",
            service: "events",
            service_label: "Workspace Events",
            tool_name: "connector__google__events_subscribe",
            label: "Workspace Events Subscribe",
            description: "Start or reconnect durable Google Workspace event ingestion backed by Pub/Sub and the Autopilot runtime.",
            kind: "admin",
            confirm_before_run: true,
            required_scopes: &["pubsub", "cloud-platform", "chat.messages.readonly"],
            capabilities: &[
                "filesystem.read",
                "filesystem.write",
                "events.manage",
            ],
            fields: vec![
                text_field(
                    "target",
                    "Target resource",
                    Some("//chat.googleapis.com/spaces/SPACE_ID"),
                    false,
                    Some("Required when creating a new Workspace Events subscription."),
                ),
                text_field(
                    "eventTypes",
                    "Event types",
                    Some("google.workspace.chat.message.v1.created"),
                    false,
                    Some("Comma separated CloudEvents types."),
                ),
                text_field(
                    "project",
                    "Project ID",
                    None,
                    false,
                    Some("Required when creating new Pub/Sub resources."),
                ),
                text_field(
                    "subscription",
                    "Existing subscription",
                    None,
                    false,
                    Some("Reconnect to an existing Pub/Sub subscription."),
                ),
                number_field("maxMessages", "Max messages", 10, false, None),
                number_field("pollInterval", "Poll interval seconds", 5, false, None),
                select_field(
                    "once",
                    "Pull once",
                    "false",
                    vec![("Yes", "true"), ("No", "false")],
                    Some("Default is `false` so the background runtime keeps consuming deliveries."),
                ),
                select_field(
                    "cleanup",
                    "Cleanup",
                    "false",
                    vec![("No", "false"), ("Yes", "true")],
                    None,
                ),
                select_field(
                    "noAck",
                    "No ack",
                    "false",
                    vec![("No", "false"), ("Yes", "true")],
                    Some("Leave pulled messages unacknowledged."),
                ),
                text_field("outputDir", "Output directory", None, false, None),
                text_field(
                    "automationActionId",
                    "Automation action ID",
                    None,
                    false,
                    Some("Optional connector action to run for each normalized Workspace event."),
                ),
                textarea_field(
                    "automationInputTemplate",
                    "Automation input template",
                    Some("{\"text\":\"Workspace event {{event.eventType}} on {{event.subject}}\"}"),
                    false,
                    Some("Optional JSON template rendered against the Workspace event context."),
                ),
            ],
        },
        GoogleConnectorActionSpec {
            id: "events.renew",
            service: "events",
            service_label: "Workspace Events",
            tool_name: "connector__google__events_renew",
            label: "Workspace Events Renew",
            description: "Reactivate one or more Workspace Events subscriptions.",
            kind: "admin",
            confirm_before_run: true,
            required_scopes: &["pubsub", "cloud-platform", "chat.messages.readonly"],
            capabilities: &[
                "filesystem.read",
                "filesystem.write",
                "events.manage",
            ],
            fields: vec![
                text_field(
                    "name",
                    "Subscription name",
                    Some("subscriptions/SUB_ID"),
                    false,
                    Some("Use for a single subscription."),
                ),
                select_field(
                    "all",
                    "Renew all",
                    "false",
                    vec![("No", "false"), ("Yes", "true")],
                    Some("Renew all subscriptions expiring within the provided window."),
                ),
                text_field("within", "Within", Some("1h"), false, Some("Window for `--all`.")),
            ],
        },
        GoogleConnectorActionSpec {
            id: "expert.raw_request",
            service: "expert",
            service_label: "Expert Mode",
            tool_name: "connector__google__expert_raw_request",
            label: "Google Expert Raw Request",
            description: "Invoke an arbitrary Google API method through the Google connector.",
            kind: "expert",
            confirm_before_run: true,
            required_scopes: &["cloud-platform", "drive", "gmail.modify", "calendar", "documents", "spreadsheets"],
            capabilities: &[
                "filesystem.read",
                "filesystem.write",
                "google.expert",
            ],
            fields: vec![
                text_field(
                    "service",
                    "Service",
                    Some("drive"),
                    true,
                    Some("Known alias like `drive` or explicit `<api>:<version>` such as `bigquery:v2`."),
                ),
                text_field(
                    "resourcePath",
                    "Resource path",
                    Some("files"),
                    false,
                    Some("Space, slash, or dot separated resource path."),
                ),
                text_field("method", "Method", Some("list"), true, None),
                textarea_field(
                    "paramsJson",
                    "Params JSON",
                    Some("{\"pageSize\":10}"),
                    false,
                    Some("JSON object for request path and query parameters."),
                ),
                textarea_field(
                    "bodyJson",
                    "Body JSON",
                    Some("{\"name\":\"example\"}"),
                    false,
                    Some("JSON request body."),
                ),
                text_field("uploadPath", "Upload path", None, false, None),
                select_field(
                    "pageAll",
                    "Page all",
                    "false",
                    vec![("No", "false"), ("Yes", "true")],
                    None,
                ),
                number_field("pageLimit", "Page limit", 25, false, None),
                number_field("pageDelayMs", "Page delay ms", 100, false, None),
            ],
        },
    ]
}

fn find_action_by_id(action_id: &str) -> Option<GoogleConnectorActionSpec> {
    let normalized = action_id.trim().to_ascii_lowercase();
    google_connector_action_specs()
        .into_iter()
        .find(|spec| spec.id == normalized)
}

fn find_action_by_tool_name(tool_name: &str) -> Option<GoogleConnectorActionSpec> {
    let normalized = tool_name.trim().to_ascii_lowercase();
    google_connector_action_specs()
        .into_iter()
        .find(|spec| spec.tool_name == normalized)
}

fn connector_fields_to_schema(fields: &[ConnectorFieldDefinition]) -> Value {
    let mut properties = serde_json::Map::new();
    let mut required = Vec::new();

    for field in fields {
        let mut schema = serde_json::Map::new();
        match field.field_type.as_str() {
            "number" => {
                schema.insert("type".to_string(), json!("number"));
            }
            "select" => {
                schema.insert("type".to_string(), json!("string"));
                if let Some(options) = field.options.as_ref() {
                    schema.insert(
                        "enum".to_string(),
                        Value::Array(
                            options
                                .iter()
                                .map(|option| Value::String(option.value.clone()))
                                .collect(),
                        ),
                    );
                }
            }
            _ => {
                schema.insert("type".to_string(), json!("string"));
                if field.field_type == "email" {
                    schema.insert("format".to_string(), json!("email"));
                }
            }
        }

        schema.insert("title".to_string(), Value::String(field.label.clone()));
        if let Some(description) = field.description.as_ref() {
            schema.insert(
                "description".to_string(),
                Value::String(description.clone()),
            );
        }
        if let Some(default_value) = field.default_value.as_ref() {
            schema.insert("default".to_string(), default_value.clone());
        }
        properties.insert(field.id.clone(), Value::Object(schema));
        if field.required {
            required.push(Value::String(field.id.clone()));
        }
    }

    json!({
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": false
    })
}

fn build_google_workspace_args(
    spec: &GoogleConnectorActionSpec,
    input: &Value,
) -> Result<Vec<String>, String> {
    match spec.id {
        "gmail.read_emails" => {
            let mut args = vec![
                "gmail".into(),
                "+triage".into(),
                "--max".into(),
                optional_u64(input, "max").unwrap_or(20).to_string(),
                "--format".into(),
                "json".into(),
            ];
            if let Some(query) = optional_string(input, "query") {
                args.push("--query".into());
                args.push(query);
            }
            if optional_bool(input, "includeLabels").unwrap_or(false) {
                args.push("--labels".into());
            }
            Ok(args)
        }
        "gmail.send_email" => {
            let mut args = vec![
                "gmail".into(),
                "+send".into(),
                "--to".into(),
                required_string(input, "to")?,
                "--subject".into(),
                required_string(input, "subject")?,
                "--body".into(),
                required_string(input, "body")?,
                "--format".into(),
                "json".into(),
            ];
            if let Some(thread_id) = optional_string(input, "threadId") {
                args.push("--thread-id".into());
                args.push(thread_id);
            }
            if let Some(in_reply_to) = optional_string(input, "inReplyTo") {
                args.push("--in-reply-to".into());
                args.push(in_reply_to);
            }
            if let Some(references) = optional_string(input, "references") {
                args.push("--references".into());
                args.push(references);
            }
            Ok(args)
        }
        "gmail.draft_email" => {
            let raw = build_gmail_raw_message(
                &required_string(input, "to")?,
                &required_string(input, "subject")?,
                &required_string(input, "body")?,
                optional_string(input, "inReplyTo").as_deref(),
                optional_string(input, "references").as_deref(),
            );
            let mut message = json!({ "raw": raw });
            if let Some(thread_id) = optional_string(input, "threadId") {
                message["threadId"] = Value::String(thread_id);
            }
            Ok(vec![
                "gmail".into(),
                "drafts".into(),
                "create".into(),
                "--params".into(),
                json!({ "userId": "me" }).to_string(),
                "--json".into(),
                json!({ "message": message }).to_string(),
                "--format".into(),
                "json".into(),
            ])
        }
        "gmail.mark_as_read" => build_gmail_modify_args(
            required_string(input, "messageId")?,
            json!({ "removeLabelIds": ["UNREAD"] }),
        ),
        "gmail.archive_email" => build_gmail_modify_args(
            required_string(input, "messageId")?,
            json!({ "removeLabelIds": ["INBOX"] }),
        ),
        "gmail.apply_label" => {
            let labels = split_multivalue(&required_string(input, "labelIds")?);
            if labels.is_empty() {
                return Err("At least one Gmail label ID is required.".to_string());
            }
            build_gmail_modify_args(
                required_string(input, "messageId")?,
                json!({ "addLabelIds": labels }),
            )
        }
        "gmail.create_label" => Ok(vec![
            "gmail".into(),
            "users".into(),
            "labels".into(),
            "create".into(),
            "--params".into(),
            json!({ "userId": "me" }).to_string(),
            "--json".into(),
            json!({
                "name": required_string(input, "name")?,
                "messageListVisibility": optional_string(input, "messageListVisibility").unwrap_or_else(|| "show".to_string()),
                "labelListVisibility": optional_string(input, "labelListVisibility").unwrap_or_else(|| "labelShow".to_string())
            })
            .to_string(),
            "--format".into(),
            "json".into(),
        ]),
        "gmail.get_thread" => Ok(vec![
            "gmail".into(),
            "users".into(),
            "threads".into(),
            "get".into(),
            "--params".into(),
            json!({
                "userId": "me",
                "id": required_string(input, "threadId")?,
                "format": optional_string(input, "format").unwrap_or_else(|| "full".to_string())
            })
            .to_string(),
            "--format".into(),
            "json".into(),
        ]),
        "gmail.list_labels" => Ok(vec![
            "gmail".into(),
            "users".into(),
            "labels".into(),
            "list".into(),
            "--params".into(),
            json!({ "userId": "me" }).to_string(),
            "--format".into(),
            "json".into(),
        ]),
        "gmail.watch_emails" => {
            let mut args = vec![
                "gmail".into(),
                "+watch".into(),
                "--max-messages".into(),
                optional_u64(input, "maxMessages").unwrap_or(10).to_string(),
                "--poll-interval".into(),
                optional_u64(input, "pollInterval").unwrap_or(5).to_string(),
                "--msg-format".into(),
                optional_string(input, "msgFormat").unwrap_or_else(|| "full".to_string()),
                "--format".into(),
                "json".into(),
            ];
            if let Some(project) = optional_string(input, "project") {
                args.push("--project".into());
                args.push(project);
            }
            if let Some(subscription) = optional_string(input, "subscription") {
                args.push("--subscription".into());
                args.push(subscription);
            }
            if let Some(topic) = optional_string(input, "topic") {
                args.push("--topic".into());
                args.push(topic);
            }
            if let Some(label_ids) = optional_string(input, "labelIds") {
                args.push("--label-ids".into());
                args.push(label_ids);
            }
            if optional_bool(input, "once").unwrap_or(true) {
                args.push("--once".into());
            }
            if optional_bool(input, "cleanup").unwrap_or(false) {
                args.push("--cleanup".into());
            }
            if let Some(output_dir) = optional_string(input, "outputDir") {
                args.push("--output-dir".into());
                args.push(output_dir);
            }
            Ok(args)
        }
        "bigquery.execute_query" => {
            let project_id = optional_string(input, "projectId")
                .or_else(default_google_project_id)
                .ok_or_else(|| {
                    "BigQuery projectId is required. Set `projectId`, `GOOGLE_CLOUD_PROJECT`, or `GOOGLE_WORKSPACE_PROJECT_ID`.".to_string()
                })?;
            let mut body = json!({
                "query": required_string(input, "query")?,
                "useLegacySql": optional_bool(input, "useLegacySql").unwrap_or(false),
                "maxResults": optional_u64(input, "maxResults").unwrap_or(100),
            });
            if let Some(location) = optional_string(input, "location") {
                body["location"] = Value::String(location);
            }
            Ok(vec![
                "bigquery:v2".into(),
                "jobs".into(),
                "query".into(),
                "--params".into(),
                json!({ "projectId": project_id }).to_string(),
                "--json".into(),
                body.to_string(),
                "--format".into(),
                "json".into(),
            ])
        }
        "calendar.get_event" => Ok(vec![
            "calendar".into(),
            "events".into(),
            "get".into(),
            "--params".into(),
            json!({
                "calendarId": optional_string(input, "calendarId").unwrap_or_else(|| "primary".to_string()),
                "eventId": required_string(input, "eventId")?
            })
            .to_string(),
            "--format".into(),
            "json".into(),
        ]),
        "calendar.list_events_for_date" => {
            let date = required_string(input, "date")?;
            let (time_min, time_max) = date_to_day_bounds(&date)?;
            Ok(vec![
                "calendar".into(),
                "events".into(),
                "list".into(),
                "--params".into(),
                json!({
                    "calendarId": optional_string(input, "calendarId").unwrap_or_else(|| "primary".to_string()),
                    "timeMin": time_min,
                    "timeMax": time_max,
                    "singleEvents": true,
                    "orderBy": "startTime",
                    "maxResults": optional_u64(input, "maxResults").unwrap_or(25)
                })
                .to_string(),
                "--format".into(),
                "json".into(),
            ])
        }
        "calendar.create_event" => {
            let mut args = vec![
                "calendar".into(),
                "+insert".into(),
                "--calendar".into(),
                optional_string(input, "calendarId").unwrap_or_else(|| "primary".to_string()),
                "--summary".into(),
                required_string(input, "summary")?,
                "--start".into(),
                required_string(input, "start")?,
                "--end".into(),
                required_string(input, "end")?,
                "--format".into(),
                "json".into(),
            ];
            if let Some(location) = optional_string(input, "location") {
                args.push("--location".into());
                args.push(location);
            }
            if let Some(description) = optional_string(input, "description") {
                args.push("--description".into());
                args.push(description);
            }
            if let Some(attendees) = optional_string(input, "attendees") {
                for attendee in split_multivalue(&attendees) {
                    args.push("--attendee".into());
                    args.push(attendee);
                }
            }
            Ok(args)
        }
        "calendar.update_event" => {
            let calendar_id =
                optional_string(input, "calendarId").unwrap_or_else(|| "primary".to_string());
            let event_id = required_string(input, "eventId")?;
            let mut body = json!({});
            let mut changed = false;

            if let Some(summary) = optional_string(input, "summary") {
                body["summary"] = Value::String(summary);
                changed = true;
            }
            if let Some(start) = optional_string(input, "start") {
                body["start"] = json!({ "dateTime": start });
                changed = true;
            }
            if let Some(end) = optional_string(input, "end") {
                body["end"] = json!({ "dateTime": end });
                changed = true;
            }
            if let Some(location) = optional_string(input, "location") {
                body["location"] = Value::String(location);
                changed = true;
            }
            if let Some(description) = optional_string(input, "description") {
                body["description"] = Value::String(description);
                changed = true;
            }
            if let Some(attendees) = optional_string(input, "attendees") {
                body["attendees"] = Value::Array(
                    split_multivalue(&attendees)
                        .into_iter()
                        .map(|email| json!({ "email": email }))
                        .collect(),
                );
                changed = true;
            }

            if !changed {
                return Err("Provide at least one field to update.".to_string());
            }

            Ok(vec![
                "calendar".into(),
                "events".into(),
                "patch".into(),
                "--params".into(),
                json!({
                    "calendarId": calendar_id,
                    "eventId": event_id
                })
                .to_string(),
                "--json".into(),
                body.to_string(),
                "--format".into(),
                "json".into(),
            ])
        }
        "calendar.delete_event" => Ok(vec![
            "calendar".into(),
            "events".into(),
            "delete".into(),
            "--params".into(),
            json!({
                "calendarId": optional_string(input, "calendarId").unwrap_or_else(|| "primary".to_string()),
                "eventId": required_string(input, "eventId")?
            })
            .to_string(),
            "--format".into(),
            "json".into(),
        ]),
        "docs.create_document" => Ok(vec![
            "docs".into(),
            "documents".into(),
            "create".into(),
            "--json".into(),
            json!({ "title": required_string(input, "title")? }).to_string(),
            "--format".into(),
            "json".into(),
        ]),
        "docs.read_document" => Ok(vec![
            "docs".into(),
            "documents".into(),
            "get".into(),
            "--params".into(),
            json!({ "documentId": required_string(input, "documentId")? }).to_string(),
            "--format".into(),
            "json".into(),
        ]),
        "docs.append_text" => Ok(vec![
            "docs".into(),
            "+write".into(),
            "--document".into(),
            required_string(input, "documentId")?,
            "--text".into(),
            required_string(input, "text")?,
            "--format".into(),
            "json".into(),
        ]),
        "docs.replace_text" => Ok(vec![
            "docs".into(),
            "documents".into(),
            "batchUpdate".into(),
            "--params".into(),
            json!({ "documentId": required_string(input, "documentId")? }).to_string(),
            "--json".into(),
            json!({
                "requests": [{
                    "replaceAllText": {
                        "containsText": {
                            "text": required_string(input, "searchText")?,
                            "matchCase": optional_bool(input, "matchCase").unwrap_or(false)
                        },
                        "replaceText": required_string(input, "replaceText")?
                    }
                }]
            })
            .to_string(),
            "--format".into(),
            "json".into(),
        ]),
        "sheets.read_range" => Ok(vec![
            "sheets".into(),
            "+read".into(),
            "--spreadsheet".into(),
            required_string(input, "spreadsheetId")?,
            "--range".into(),
            required_string(input, "range")?,
            "--format".into(),
            "json".into(),
        ]),
        "sheets.create_spreadsheet" => Ok(vec![
            "sheets".into(),
            "spreadsheets".into(),
            "create".into(),
            "--json".into(),
            json!({ "properties": { "title": required_string(input, "title")? } }).to_string(),
            "--format".into(),
            "json".into(),
        ]),
        "sheets.write_range" => {
            let values = normalize_sheet_values(required_json_value(input, "valuesJson")?)?;
            Ok(vec![
                "sheets".into(),
                "spreadsheets".into(),
                "values".into(),
                "update".into(),
                "--params".into(),
                json!({
                    "spreadsheetId": required_string(input, "spreadsheetId")?,
                    "range": required_string(input, "range")?,
                    "valueInputOption": optional_string(input, "valueInputOption").unwrap_or_else(|| "USER_ENTERED".to_string())
                })
                .to_string(),
                "--json".into(),
                json!({ "values": values }).to_string(),
                "--format".into(),
                "json".into(),
            ])
        }
        "sheets.append_rows" => Ok(vec![
            "sheets".into(),
            "+append".into(),
            "--spreadsheet".into(),
            required_string(input, "spreadsheetId")?,
            "--json-values".into(),
            normalize_sheet_values(required_json_value(input, "valuesJson")?)?.to_string(),
            "--format".into(),
            "json".into(),
        ]),
        "sheets.clear_range" => Ok(vec![
            "sheets".into(),
            "spreadsheets".into(),
            "values".into(),
            "clear".into(),
            "--params".into(),
            json!({
                "spreadsheetId": required_string(input, "spreadsheetId")?,
                "range": required_string(input, "range")?
            })
            .to_string(),
            "--json".into(),
            "{}".into(),
            "--format".into(),
            "json".into(),
        ]),
        "sheets.get_spreadsheet" => {
            let mut params = json!({
                "spreadsheetId": required_string(input, "spreadsheetId")?,
                "includeGridData": optional_bool(input, "includeGridData").unwrap_or(false)
            });
            if let Some(ranges) = optional_string(input, "ranges") {
                params["ranges"] = Value::Array(
                    split_multivalue(&ranges)
                        .into_iter()
                        .map(Value::String)
                        .collect(),
                );
            }
            Ok(vec![
                "sheets".into(),
                "spreadsheets".into(),
                "get".into(),
                "--params".into(),
                params.to_string(),
                "--format".into(),
                "json".into(),
            ])
        }
        "drive.upload_file" => {
            let mut args = vec![
                "drive".into(),
                "+upload".into(),
                required_string(input, "filePath")?,
                "--format".into(),
                "json".into(),
            ];
            if let Some(parent_id) = optional_string(input, "parentId") {
                args.push("--parent".into());
                args.push(parent_id);
            }
            if let Some(name) = optional_string(input, "name") {
                args.push("--name".into());
                args.push(name);
            }
            Ok(args)
        }
        "drive.share_file" => Ok(vec![
            "drive".into(),
            "permissions".into(),
            "create".into(),
            "--params".into(),
            json!({
                "fileId": required_string(input, "fileId")?,
                "sendNotificationEmail": false
            })
            .to_string(),
            "--json".into(),
            json!({
                "role": optional_string(input, "role").unwrap_or_else(|| "reader".to_string()),
                "type": "user",
                "emailAddress": required_string(input, "email")?
            })
            .to_string(),
            "--format".into(),
            "json".into(),
        ]),
        "tasks.list_tasks" => Ok(vec![
            "tasks".into(),
            "tasks".into(),
            "list".into(),
            "--params".into(),
            json!({
                "tasklist": optional_string(input, "tasklist").unwrap_or_else(|| "@default".to_string()),
                "showCompleted": optional_bool(input, "showCompleted").unwrap_or(false),
                "maxResults": optional_u64(input, "maxResults").unwrap_or(20)
            })
            .to_string(),
            "--format".into(),
            "json".into(),
        ]),
        "tasks.create_task" => {
            let mut body = json!({ "title": required_string(input, "title")? });
            if let Some(notes) = optional_string(input, "notes") {
                body["notes"] = Value::String(notes);
            }
            if let Some(due) = optional_string(input, "due") {
                body["due"] = Value::String(due);
            }
            Ok(vec![
                "tasks".into(),
                "tasks".into(),
                "insert".into(),
                "--params".into(),
                json!({ "tasklist": optional_string(input, "tasklist").unwrap_or_else(|| "@default".to_string()) }).to_string(),
                "--json".into(),
                body.to_string(),
                "--format".into(),
                "json".into(),
            ])
        }
        "chat.send_message" => Ok(vec![
            "chat".into(),
            "+send".into(),
            "--space".into(),
            required_string(input, "space")?,
            "--text".into(),
            required_string(input, "text")?,
            "--format".into(),
            "json".into(),
        ]),
        "workflow.standup_report" => Ok(vec![
            "workflow".into(),
            "+standup-report".into(),
            "--format".into(),
            "json".into(),
        ]),
        "workflow.meeting_prep" => {
            let mut args = vec![
                "workflow".into(),
                "+meeting-prep".into(),
                "--format".into(),
                "json".into(),
            ];
            if let Some(calendar) = optional_string(input, "calendar") {
                args.push("--calendar".into());
                args.push(calendar);
            }
            Ok(args)
        }
        "workflow.email_to_task" => {
            let mut args = vec![
                "workflow".into(),
                "+email-to-task".into(),
                "--message-id".into(),
                required_string(input, "messageId")?,
                "--format".into(),
                "json".into(),
            ];
            if let Some(tasklist) = optional_string(input, "tasklist") {
                args.push("--tasklist".into());
                args.push(tasklist);
            }
            Ok(args)
        }
        "workflow.weekly_digest" => Ok(vec![
            "workflow".into(),
            "+weekly-digest".into(),
            "--format".into(),
            "json".into(),
        ]),
        "workflow.file_announce" => {
            let mut args = vec![
                "workflow".into(),
                "+file-announce".into(),
                "--file-id".into(),
                required_string(input, "fileId")?,
                "--space".into(),
                required_string(input, "space")?,
                "--format".into(),
                "json".into(),
            ];
            if let Some(message) = optional_string(input, "message") {
                args.push("--message".into());
                args.push(message);
            }
            Ok(args)
        }
        "events.subscribe" => {
            let mut args = vec![
                "events".into(),
                "+subscribe".into(),
                "--max-messages".into(),
                optional_u64(input, "maxMessages").unwrap_or(10).to_string(),
                "--poll-interval".into(),
                optional_u64(input, "pollInterval").unwrap_or(5).to_string(),
                "--format".into(),
                "json".into(),
            ];
            if let Some(target) = optional_string(input, "target") {
                args.push("--target".into());
                args.push(target);
            }
            if let Some(event_types) = optional_string(input, "eventTypes") {
                args.push("--event-types".into());
                args.push(event_types);
            }
            if let Some(project) = optional_string(input, "project") {
                args.push("--project".into());
                args.push(project);
            }
            if let Some(subscription) = optional_string(input, "subscription") {
                args.push("--subscription".into());
                args.push(subscription);
            }
            if optional_bool(input, "once").unwrap_or(true) {
                args.push("--once".into());
            }
            if optional_bool(input, "cleanup").unwrap_or(false) {
                args.push("--cleanup".into());
            }
            if optional_bool(input, "noAck").unwrap_or(false) {
                args.push("--no-ack".into());
            }
            if let Some(output_dir) = optional_string(input, "outputDir") {
                args.push("--output-dir".into());
                args.push(output_dir);
            }
            Ok(args)
        }
        "events.renew" => {
            let mut args = vec![
                "events".into(),
                "+renew".into(),
                "--within".into(),
                optional_string(input, "within").unwrap_or_else(|| "1h".to_string()),
                "--format".into(),
                "json".into(),
            ];
            if optional_bool(input, "all").unwrap_or(false) {
                args.push("--all".into());
            } else {
                args.push("--name".into());
                args.push(required_string(input, "name")?);
            }
            Ok(args)
        }
        "expert.raw_request" => build_google_raw_request_args(input),
        other => Err(format!("Unsupported Google connector action '{}'", other)),
    }
}

fn build_google_raw_request_args(input: &Value) -> Result<Vec<String>, String> {
    let service = required_string(input, "service")?;
    let method = required_string(input, "method")?;
    let mut args = vec![service];

    if let Some(resource_path) = optional_string(input, "resourcePath") {
        for segment in split_resource_path(&resource_path) {
            args.push(segment);
        }
    }
    args.push(method);

    if let Some(params_json) = optional_json_string(input, "paramsJson")? {
        args.push("--params".into());
        args.push(params_json);
    }
    if let Some(body_json) = optional_json_string(input, "bodyJson")? {
        args.push("--json".into());
        args.push(body_json);
    }
    if let Some(upload_path) = optional_string(input, "uploadPath") {
        args.push("--upload".into());
        args.push(upload_path);
    }
    if optional_bool(input, "pageAll").unwrap_or(false) {
        args.push("--page-all".into());
        args.push("--page-limit".into());
        args.push(optional_u64(input, "pageLimit").unwrap_or(25).to_string());
        args.push("--page-delay-ms".into());
        args.push(
            optional_u64(input, "pageDelayMs")
                .unwrap_or(100)
                .to_string(),
        );
    }
    args.push("--format".into());
    args.push("json".into());
    Ok(args)
}

fn build_gmail_modify_args(message_id: String, body: Value) -> Result<Vec<String>, String> {
    Ok(vec![
        "gmail".into(),
        "users".into(),
        "messages".into(),
        "modify".into(),
        "--params".into(),
        json!({ "userId": "me", "id": message_id }).to_string(),
        "--json".into(),
        body.to_string(),
        "--format".into(),
        "json".into(),
    ])
}

async fn normalize_google_action_input(
    spec: &GoogleConnectorActionSpec,
    input: &Value,
) -> Result<Value, String> {
    let mut normalized = input.clone();
    match spec.id {
        "gmail.send_email" | "gmail.draft_email" => {
            let Some(raw_to) = input.get("to").and_then(Value::as_str) else {
                return Ok(normalized);
            };
            let resolved_to = resolve_google_mail_recipient(raw_to).await?;
            if let Some(object) = normalized.as_object_mut() {
                object.insert("to".to_string(), Value::String(resolved_to));
            }
        }
        _ => {}
    }
    Ok(normalized)
}

async fn resolve_google_mail_recipient(raw: &str) -> Result<String, String> {
    if let Some(canonical) = canonicalize_email_recipient(raw) {
        return Ok(canonical);
    }

    if !looks_like_connected_account_alias(raw, &["google", "gmail", "google workspace"]) {
        return Ok(raw.trim().to_string());
    }

    let auth = google_auth::access_context(&[]).await?;
    resolve_connected_account_alias(
        raw,
        auth.account_email.as_deref(),
        &["google", "gmail", "google workspace"],
    )
    .ok_or_else(|| {
            "Autopilot could not determine the connected Google account email. Use an explicit recipient address or reconnect the Google connector.".to_string()
        })
}

fn resolve_connected_account_alias(
    raw: &str,
    connected_account_email: Option<&str>,
    provider_terms: &[&str],
) -> Option<String> {
    if !looks_like_connected_account_alias(raw, provider_terms) {
        return None;
    }
    connected_account_email.and_then(canonicalize_email_recipient)
}

fn canonicalize_email_recipient(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    let candidate =
        if trimmed.len() >= "mailto:".len() && trimmed[..7].eq_ignore_ascii_case("mailto:") {
            trimmed[7..]
                .split(['?', '#'])
                .next()
                .map(str::trim)
                .unwrap_or("")
        } else {
            trimmed
        };

    if candidate.is_empty() {
        return None;
    }

    candidate
        .parse::<Mailbox>()
        .ok()
        .map(|mailbox| mailbox.to_string())
}

fn normalize_alias_phrase(raw: &str) -> String {
    raw.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                ' '
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn looks_like_connected_account_alias(raw: &str, provider_terms: &[&str]) -> bool {
    let normalized = normalize_alias_phrase(raw);
    if normalized.is_empty() {
        return false;
    }

    let generic_aliases = [
        "connected address",
        "my connected address",
        "your connected address",
        "connected email",
        "my connected email",
        "your connected email",
        "connected email address",
        "my connected email address",
        "your connected email address",
        "connected account",
        "my connected account",
        "your connected account",
        "connected account email",
        "my connected account email",
        "your connected account email",
    ];
    if generic_aliases.contains(&normalized.as_str()) {
        return true;
    }

    provider_terms.iter().any(|provider| {
        let provider = normalize_alias_phrase(provider);
        [
            format!("connected {} address", provider),
            format!("my connected {} address", provider),
            format!("your connected {} address", provider),
            format!("connected {} email", provider),
            format!("my connected {} email", provider),
            format!("your connected {} email", provider),
            format!("connected {} email address", provider),
            format!("my connected {} email address", provider),
            format!("your connected {} email address", provider),
            format!("connected {} account", provider),
            format!("my connected {} account", provider),
            format!("your connected {} account", provider),
            format!("connected {} account email", provider),
            format!("my connected {} account email", provider),
            format!("your connected {} account email", provider),
        ]
        .iter()
        .any(|candidate| candidate == &normalized)
    })
}

fn summarize_action(spec: &GoogleConnectorActionSpec, data: &Value, input: &Value) -> String {
    match spec.id {
        "gmail.read_emails" => {
            let count = data
                .as_array()
                .map(|items| items.len())
                .or_else(|| {
                    data.get("messages")
                        .and_then(Value::as_array)
                        .map(|items| items.len())
                })
                .unwrap_or(0);
            format!("Loaded {} Gmail messages.", count)
        }
        "gmail.send_email" => format!(
            "Sent Gmail message to {}.",
            input
                .get("to")
                .and_then(Value::as_str)
                .unwrap_or("recipient")
        ),
        "gmail.draft_email" => format!(
            "Created Gmail draft for {}.",
            input
                .get("to")
                .and_then(Value::as_str)
                .unwrap_or("recipient")
        ),
        "gmail.mark_as_read" => "Marked Gmail message as read.".to_string(),
        "gmail.archive_email" => "Archived Gmail message.".to_string(),
        "gmail.apply_label" => "Applied Gmail labels.".to_string(),
        "gmail.create_label" => format!(
            "Created Gmail label '{}'.",
            data.get("name")
                .and_then(Value::as_str)
                .or_else(|| input.get("name").and_then(Value::as_str))
                .unwrap_or("label")
        ),
        "gmail.get_thread" => {
            let count = data
                .get("messages")
                .and_then(Value::as_array)
                .map(|messages| messages.len())
                .unwrap_or(0);
            format!("Loaded Gmail thread with {} messages.", count)
        }
        "gmail.list_labels" => {
            let count = data
                .get("labels")
                .and_then(Value::as_array)
                .map(|labels| labels.len())
                .unwrap_or(0);
            format!("Loaded {} Gmail labels.", count)
        }
        "gmail.watch_emails" => "Initialized Gmail watch flow.".to_string(),
        "bigquery.execute_query" => {
            if is_bigquery_read_query(
                input
                    .get("query")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
            ) {
                let rows = data
                    .get("rows")
                    .and_then(Value::as_array)
                    .map(|items| items.len())
                    .unwrap_or(0);
                format!("Executed BigQuery read query and returned {} rows.", rows)
            } else {
                "Executed BigQuery mutation query.".to_string()
            }
        }
        "calendar.get_event" => {
            let summary = data
                .get("summary")
                .and_then(Value::as_str)
                .unwrap_or("event");
            format!("Loaded calendar event '{}'.", summary)
        }
        "calendar.list_events_for_date" => {
            let count = data
                .get("items")
                .and_then(Value::as_array)
                .map(|items| items.len())
                .unwrap_or(0);
            format!("Loaded {} calendar events for the selected date.", count)
        }
        "calendar.create_event" => format!(
            "Created calendar event '{}'.",
            data.get("summary")
                .and_then(Value::as_str)
                .or_else(|| input.get("summary").and_then(Value::as_str))
                .unwrap_or("event")
        ),
        "calendar.update_event" => "Updated calendar event.".to_string(),
        "calendar.delete_event" => "Deleted calendar event.".to_string(),
        "docs.create_document" => format!(
            "Created Google Doc '{}'.",
            data.get("title")
                .and_then(Value::as_str)
                .or_else(|| input.get("title").and_then(Value::as_str))
                .unwrap_or("document")
        ),
        "docs.read_document" => "Loaded Google Doc.".to_string(),
        "docs.append_text" => "Appended text to Google Doc.".to_string(),
        "docs.replace_text" => "Replaced text in Google Doc.".to_string(),
        "sheets.read_range" => "Loaded Google Sheets range.".to_string(),
        "sheets.create_spreadsheet" => format!(
            "Created Google Sheet '{}'.",
            data.get("properties")
                .and_then(|properties| properties.get("title"))
                .and_then(Value::as_str)
                .or_else(|| input.get("title").and_then(Value::as_str))
                .unwrap_or("spreadsheet")
        ),
        "sheets.write_range" => "Wrote values to Google Sheet.".to_string(),
        "sheets.append_rows" => "Appended rows to Google Sheet.".to_string(),
        "sheets.clear_range" => "Cleared Google Sheet range.".to_string(),
        "sheets.get_spreadsheet" => "Loaded Google Spreadsheet metadata.".to_string(),
        "drive.upload_file" => format!(
            "Uploaded Drive file '{}'.",
            data.get("name")
                .and_then(Value::as_str)
                .or_else(|| input.get("name").and_then(Value::as_str))
                .unwrap_or("file")
        ),
        "drive.share_file" => format!(
            "Shared Drive file with {}.",
            input
                .get("email")
                .and_then(Value::as_str)
                .unwrap_or("recipient")
        ),
        "tasks.list_tasks" => {
            let count = data
                .get("items")
                .and_then(Value::as_array)
                .map(|items| items.len())
                .unwrap_or(0);
            format!("Loaded {} Google Tasks.", count)
        }
        "tasks.create_task" => format!(
            "Created Google Task '{}'.",
            data.get("title")
                .and_then(Value::as_str)
                .or_else(|| input.get("title").and_then(Value::as_str))
                .unwrap_or("task")
        ),
        "chat.send_message" => "Sent Google Chat message.".to_string(),
        "workflow.standup_report" => "Generated standup report.".to_string(),
        "workflow.meeting_prep" => "Prepared meeting context.".to_string(),
        "workflow.email_to_task" => "Created task from email.".to_string(),
        "workflow.weekly_digest" => "Generated weekly digest.".to_string(),
        "workflow.file_announce" => "Announced file in Google Chat.".to_string(),
        "events.subscribe" => "Initialized Workspace Events subscription flow.".to_string(),
        "events.renew" => "Renewed Workspace Events subscription.".to_string(),
        "expert.raw_request" => "Executed Google expert raw request.".to_string(),
        _ => "Google connector action completed.".to_string(),
    }
}

async fn run_gws_command(
    args: &[String],
    timeout_secs: u64,
    required_scopes: &[&str],
) -> Result<GwsCommandOutput, String> {
    let stdout = google_api::run_google_command(args, timeout_secs, required_scopes).await?;
    Ok(GwsCommandOutput { stdout })
}

fn parse_jsonish_output(stdout: &str) -> Value {
    serde_json::from_str(stdout).unwrap_or_else(|_| {
        let parsed_lines = stdout
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(serde_json::from_str::<Value>)
            .collect::<Result<Vec<_>, _>>();

        match parsed_lines {
            Ok(lines) if !lines.is_empty() => Value::Array(lines),
            _ => json!({ "stdout": stdout }),
        }
    })
}

fn parse_dynamic_arguments(raw_json: &Value) -> Value {
    match raw_json.get("arguments") {
        Some(Value::String(encoded)) => serde_json::from_str(encoded).unwrap_or_else(|_| json!({})),
        Some(value) => value.clone(),
        None => json!({}),
    }
}

fn build_gmail_raw_message(
    to: &str,
    subject: &str,
    body: &str,
    in_reply_to: Option<&str>,
    references: Option<&str>,
) -> String {
    let mut headers = vec![
        format!("To: {}", to.trim()),
        format!("Subject: {}", subject.trim()),
    ];
    if let Some(value) = in_reply_to.map(str::trim).filter(|value| !value.is_empty()) {
        headers.push(format!("In-Reply-To: {}", value));
    }
    if let Some(value) = references.map(str::trim).filter(|value| !value.is_empty()) {
        headers.push(format!("References: {}", value));
    }
    headers.push("Content-Type: text/plain; charset=UTF-8".to_string());
    let mime = format!("{}\r\n\r\n{}", headers.join("\r\n"), body);
    URL_SAFE_NO_PAD.encode(mime.as_bytes())
}

fn default_google_project_id() -> Option<String> {
    std::env::var("GOOGLE_CLOUD_PROJECT")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            std::env::var("GOOGLE_WORKSPACE_PROJECT_ID")
                .ok()
                .filter(|value| !value.trim().is_empty())
        })
}

fn required_string(input: &Value, key: &str) -> Result<String, String> {
    optional_string(input, key)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("'{}' is required.", key))
}

fn optional_string(input: &Value, key: &str) -> Option<String> {
    input
        .get(key)
        .and_then(Value::as_str)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn optional_bool(input: &Value, key: &str) -> Option<bool> {
    input.get(key).and_then(|value| match value {
        Value::Bool(value) => Some(*value),
        Value::String(text) => match text.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" => Some(true),
            "false" | "0" | "no" => Some(false),
            _ => None,
        },
        _ => None,
    })
}

fn optional_u64(input: &Value, key: &str) -> Option<u64> {
    input.get(key).and_then(|value| match value {
        Value::Number(number) => number.as_u64(),
        Value::String(text) => text.trim().parse::<u64>().ok(),
        _ => None,
    })
}

fn required_json_value(input: &Value, key: &str) -> Result<Value, String> {
    let raw = required_string(input, key)?;
    serde_json::from_str::<Value>(&raw)
        .map_err(|error| format!("'{}' must be valid JSON: {}", key, error))
}

fn optional_json_string(input: &Value, key: &str) -> Result<Option<String>, String> {
    let Some(raw) = optional_string(input, key) else {
        return Ok(None);
    };
    let value = serde_json::from_str::<Value>(&raw)
        .map_err(|error| format!("'{}' must be valid JSON: {}", key, error))?;
    Ok(Some(value.to_string()))
}

fn split_multivalue(raw: &str) -> Vec<String> {
    raw.split(|ch| ch == ',' || ch == '\n')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn split_resource_path(raw: &str) -> Vec<String> {
    raw.split(|ch: char| ch.is_whitespace() || ch == '.' || ch == '/')
        .map(str::trim)
        .filter(|segment| !segment.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn normalize_sheet_values(values: Value) -> Result<Value, String> {
    match values {
        Value::Array(rows) => {
            if rows.is_empty() {
                Ok(Value::Array(Vec::new()))
            } else if rows.iter().all(Value::is_array) {
                Ok(Value::Array(rows))
            } else {
                Ok(Value::Array(vec![Value::Array(rows)]))
            }
        }
        other => Err(format!(
            "Sheet values must be a JSON array or array of arrays, received {}.",
            other
        )),
    }
}

fn is_bigquery_read_query(query: &str) -> bool {
    let normalized = query
        .trim_start()
        .trim_start_matches(|ch: char| ch == '(')
        .trim_start()
        .to_ascii_lowercase();
    normalized.starts_with("select")
        || normalized.starts_with("with")
        || normalized.starts_with("show")
        || normalized.starts_with("describe")
        || normalized.starts_with("explain")
}

fn date_to_day_bounds(date: &str) -> Result<(String, String), String> {
    let format = time::format_description::parse("[year]-[month]-[day]")
        .map_err(|error| format!("Failed to build date parser: {}", error))?;
    let parsed = time::Date::parse(date, &format)
        .map_err(|error| format!("Invalid date '{}': {}", date, error))?;
    let start = parsed
        .with_hms(0, 0, 0)
        .map_err(|error| error.to_string())?;
    let end = start + TimeDuration::days(1);
    let start_rfc3339 = start
        .assume_utc()
        .format(&Rfc3339)
        .map_err(|error| error.to_string())?;
    let end_rfc3339 = end
        .assume_utc()
        .format(&Rfc3339)
        .map_err(|error| error.to_string())?;
    Ok((start_rfc3339, end_rfc3339))
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

fn command_timeout_secs_for_action(action_id: &str) -> u64 {
    match action_id {
        "gmail.watch_emails" | "events.subscribe" | "events.renew" => 300,
        _ => GWS_DEFAULT_TIMEOUT_SECS,
    }
}

fn text_field(
    id: &str,
    label: &str,
    default_value: Option<&str>,
    required: bool,
    description: Option<&str>,
) -> ConnectorFieldDefinition {
    ConnectorFieldDefinition {
        id: id.to_string(),
        label: label.to_string(),
        field_type: "text".to_string(),
        required,
        placeholder: default_value.map(ToString::to_string),
        description: description.map(ToString::to_string),
        default_value: default_value.map(|value| Value::String(value.to_string())),
        options: None,
    }
}

fn textarea_field(
    id: &str,
    label: &str,
    default_value: Option<&str>,
    required: bool,
    description: Option<&str>,
) -> ConnectorFieldDefinition {
    ConnectorFieldDefinition {
        id: id.to_string(),
        label: label.to_string(),
        field_type: "textarea".to_string(),
        required,
        placeholder: default_value.map(ToString::to_string),
        description: description.map(ToString::to_string),
        default_value: default_value.map(|value| Value::String(value.to_string())),
        options: None,
    }
}

fn email_field(
    id: &str,
    label: &str,
    required: bool,
    placeholder: Option<&str>,
) -> ConnectorFieldDefinition {
    ConnectorFieldDefinition {
        id: id.to_string(),
        label: label.to_string(),
        field_type: "email".to_string(),
        required,
        placeholder: placeholder.map(ToString::to_string),
        description: None,
        default_value: None,
        options: None,
    }
}

fn number_field(
    id: &str,
    label: &str,
    default_value: u64,
    required: bool,
    description: Option<&str>,
) -> ConnectorFieldDefinition {
    ConnectorFieldDefinition {
        id: id.to_string(),
        label: label.to_string(),
        field_type: "number".to_string(),
        required,
        placeholder: Some(default_value.to_string()),
        description: description.map(ToString::to_string),
        default_value: Some(Value::Number(default_value.into())),
        options: None,
    }
}

fn select_field(
    id: &str,
    label: &str,
    default_value: &str,
    options: Vec<(&str, &str)>,
    description: Option<&str>,
) -> ConnectorFieldDefinition {
    ConnectorFieldDefinition {
        id: id.to_string(),
        label: label.to_string(),
        field_type: "select".to_string(),
        required: false,
        placeholder: None,
        description: description.map(ToString::to_string),
        default_value: Some(Value::String(default_value.to_string())),
        options: Some(
            options
                .into_iter()
                .map(|(label, value)| ConnectorFieldOption {
                    label: label.to_string(),
                    value: value.to_string(),
                })
                .collect(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::shield::compute_google_shield_request_hash;
    use super::{
        connector_fields_to_schema, enforce_google_tool_shield_policy, find_action_by_id,
        google_connector_actions, google_connector_protected_slot_bindings,
        google_connector_tool_bindings, google_connector_tool_definitions,
        google_dynamic_tool_target, infer_google_symbolic_reference_from_query_boxed,
        is_bigquery_read_query, looks_like_connected_account_alias, normalize_sheet_values,
        parse_jsonish_output, query_mentions_connected_account_alias,
        resolve_connected_account_alias, BIGQUERY_READ_TARGET, BIGQUERY_WRITE_TARGET,
        GOOGLE_CONNECTOR_ID,
    };
    use crate::agentic::desktop::service::DesktopAgentService;
    use crate::agentic::desktop::types::{AgentMode, AgentState, AgentStatus, ExecutionTier};
    use async_trait::async_trait;
    use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
    use ioi_api::vm::inference::{mock::MockInferenceRuntime, InferenceRuntime};
    use ioi_drivers::browser::BrowserDriver;
    use ioi_drivers::terminal::TerminalDriver;
    use ioi_types::app::action::{ApprovalScope, ApprovalToken};
    use ioi_types::app::agentic::ProtectedSlotKind;
    use ioi_types::app::{ActionTarget, KernelEvent, SignatureSuite};
    use ioi_types::error::{TransactionError, VmError};
    use serde::{Deserialize, Serialize};
    use serde_json::json;
    use std::collections::{BTreeMap, VecDeque};
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[derive(Default)]
    struct NoopGuiDriver;

    #[async_trait]
    impl GuiDriver for NoopGuiDriver {
        async fn capture_screen(
            &self,
            _crop_rect: Option<(i32, i32, u32, u32)>,
        ) -> Result<Vec<u8>, VmError> {
            Err(VmError::HostError("noop gui".into()))
        }

        async fn capture_raw_screen(&self) -> Result<Vec<u8>, VmError> {
            Err(VmError::HostError("noop gui".into()))
        }

        async fn capture_tree(&self) -> Result<String, VmError> {
            Err(VmError::HostError("noop gui".into()))
        }

        async fn capture_context(
            &self,
            _intent: &ioi_types::app::ActionRequest,
        ) -> Result<ioi_types::app::ContextSlice, VmError> {
            Err(VmError::HostError("noop gui".into()))
        }

        async fn inject_input(&self, _event: InputEvent) -> Result<(), VmError> {
            Err(VmError::HostError("noop gui".into()))
        }

        async fn get_element_center(&self, _id: u32) -> Result<Option<(u32, u32)>, VmError> {
            Ok(None)
        }

        async fn register_som_overlay(
            &self,
            _map: std::collections::HashMap<u32, (i32, i32, i32, i32)>,
        ) -> Result<(), VmError> {
            Ok(())
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum TestDecisionMode {
        Auto,
        Confirm,
        Block,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum TestAutomationMode {
        ConfirmOnCreate,
        ConfirmOnRun,
        ManualOnly,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum TestDataHandlingMode {
        LocalOnly,
        LocalRedacted,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct TestGlobalPolicyDefaults {
        reads: TestDecisionMode,
        writes: TestDecisionMode,
        admin: TestDecisionMode,
        expert: TestDecisionMode,
        automations: TestAutomationMode,
        data_handling: TestDataHandlingMode,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct TestConnectorPolicyOverride {
        inherit_global: bool,
        reads: TestDecisionMode,
        writes: TestDecisionMode,
        admin: TestDecisionMode,
        expert: TestDecisionMode,
        automations: TestAutomationMode,
        data_handling: TestDataHandlingMode,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct TestShieldPolicyState {
        version: u8,
        global: TestGlobalPolicyDefaults,
        overrides: BTreeMap<String, TestConnectorPolicyOverride>,
    }

    fn temp_policy_path() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("ioi_google_shield_policy_{nanos}.json"))
    }

    fn write_policy_file(path: &PathBuf, override_state: TestConnectorPolicyOverride) {
        let state = TestShieldPolicyState {
            version: 1,
            global: TestGlobalPolicyDefaults {
                reads: TestDecisionMode::Auto,
                writes: TestDecisionMode::Confirm,
                admin: TestDecisionMode::Confirm,
                expert: TestDecisionMode::Block,
                automations: TestAutomationMode::ConfirmOnCreate,
                data_handling: TestDataHandlingMode::LocalOnly,
            },
            overrides: BTreeMap::from([(GOOGLE_CONNECTOR_ID.to_string(), override_state)]),
        };

        std::fs::write(
            path,
            serde_json::to_vec(&state).expect("policy should serialize"),
        )
        .expect("policy should write");
    }

    fn build_test_service(policy_path: PathBuf) -> DesktopAgentService {
        let inference: Arc<dyn InferenceRuntime> = Arc::new(MockInferenceRuntime);
        let (tx, _rx) = tokio::sync::broadcast::channel(8);
        DesktopAgentService::new(
            Arc::new(NoopGuiDriver),
            Arc::new(TerminalDriver::new()),
            Arc::new(BrowserDriver::new()),
            inference,
        )
        .with_shield_policy_path(policy_path)
        .with_event_sender(tx)
    }

    fn base_agent_state() -> AgentState {
        AgentState {
            session_id: [7u8; 32],
            goal: "test google connector policy".to_string(),
            transcript_root: [0u8; 32],
            status: AgentStatus::Running,
            step_count: 0,
            max_steps: 4,
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
            pending_request_nonce: None,
            pending_visual_hash: None,
            recent_actions: vec![],
            mode: AgentMode::Agent,
            current_tier: ExecutionTier::DomHeadless,
            last_screen_phash: None,
            execution_queue: vec![],
            pending_search_completion: None,
            planner_state: None,
            active_skill_hash: None,
            tool_execution_log: BTreeMap::new(),
            visual_som_map: None,
            visual_semantic_map: None,
            swarm_context: None,
            target: None,
            resolved_intent: None,
            awaiting_intent_clarification: false,
            working_directory: ".".to_string(),
            command_history: VecDeque::new(),
            active_lens: None,
        }
    }

    #[test]
    fn connector_catalog_contains_langchain_surface() {
        let actions = google_connector_actions();
        assert!(actions
            .iter()
            .any(|action| action.id == "gmail.read_emails"));
        assert!(actions
            .iter()
            .any(|action| action.id == "bigquery.execute_query"));
        assert!(actions
            .iter()
            .any(|action| action.id == "docs.replace_text"));
        assert!(actions
            .iter()
            .any(|action| action.id == "sheets.get_spreadsheet"));
    }

    #[test]
    fn connector_tool_definitions_are_generated() {
        let tools = google_connector_tool_definitions();
        assert!(tools
            .iter()
            .any(|tool| tool.name == "connector__google__gmail_send_email"));
        assert!(tools
            .iter()
            .any(|tool| tool.name == "connector__google__workflow_file_announce"));
    }

    #[test]
    fn connector_tool_bindings_include_workspace_caps() {
        let bindings = google_connector_tool_bindings();
        assert!(bindings.iter().any(|binding| {
            binding.tool_name == "connector__google__calendar_create_event"
                && binding
                    .capabilities
                    .iter()
                    .any(|capability| capability.as_str() == "filesystem.write")
        }));
    }

    #[test]
    fn bigquery_read_detection_handles_common_select_forms() {
        assert!(is_bigquery_read_query("SELECT * FROM table"));
        assert!(is_bigquery_read_query(
            "with sample as (select 1) select * from sample"
        ));
        assert!(!is_bigquery_read_query("INSERT INTO table values (1)"));
        assert!(!is_bigquery_read_query("CREATE TABLE x AS SELECT 1"));
    }

    #[test]
    fn google_dynamic_target_classifies_bigquery_queries() {
        let read = json!({
            "name": "connector__google__bigquery_execute_query",
            "arguments": { "query": "select * from dataset.table" }
        });
        assert_eq!(
            google_dynamic_tool_target(&read),
            Some(ActionTarget::Custom(BIGQUERY_READ_TARGET.to_string()))
        );

        let write = json!({
            "name": "connector__google__bigquery_execute_query",
            "arguments": { "query": "delete from dataset.table where id = 1" }
        });
        assert_eq!(
            google_dynamic_tool_target(&write),
            Some(ActionTarget::Custom(BIGQUERY_WRITE_TARGET.to_string()))
        );
    }

    #[test]
    fn parse_jsonish_output_supports_ndjson() {
        let parsed = parse_jsonish_output("{\"ok\":true}\n{\"ok\":false}");
        assert!(parsed.as_array().is_some());
    }

    #[test]
    fn sheet_values_are_normalized_to_rows() {
        let normalized = normalize_sheet_values(json!(["A", "B"])).expect("row should normalize");
        assert_eq!(normalized, json!([["A", "B"]]));
    }

    #[test]
    fn connector_schema_marks_required_fields() {
        let actions = google_connector_actions();
        let action = actions
            .iter()
            .find(|action| action.id == "gmail.send_email")
            .expect("gmail send action present");
        let schema = connector_fields_to_schema(&action.fields);
        let required = schema
            .get("required")
            .and_then(|value| value.as_array())
            .expect("required array present");
        assert!(required.iter().any(|value| value.as_str() == Some("to")));
        assert!(required
            .iter()
            .any(|value| value.as_str() == Some("subject")));
    }

    #[test]
    fn gmail_send_action_exposes_optional_threading_fields() {
        let action = find_action_by_id("gmail.send_email").expect("gmail send action present");
        let field_ids = action
            .fields
            .iter()
            .map(|field| field.id.as_str())
            .collect::<Vec<_>>();
        assert!(field_ids.contains(&"threadId"));
        assert!(field_ids.contains(&"inReplyTo"));
        assert!(field_ids.contains(&"references"));
    }

    #[test]
    fn gmail_raw_message_includes_reply_headers_when_provided() {
        use base64::Engine as _;

        let raw = super::build_gmail_raw_message(
            "user@example.com",
            "Subject",
            "Body",
            Some("<message-1@example.com>"),
            Some("<message-0@example.com> <message-1@example.com>"),
        );
        let decoded = String::from_utf8(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(raw.as_bytes())
                .expect("raw message should decode"),
        )
        .expect("decoded raw message should be utf-8");

        assert!(decoded.contains("In-Reply-To: <message-1@example.com>\r\n"));
        assert!(decoded.contains("References: <message-0@example.com> <message-1@example.com>\r\n"));
    }

    #[test]
    fn protected_slot_bindings_cover_google_email_destinations() {
        let bindings = google_connector_protected_slot_bindings();
        assert!(bindings.iter().any(|binding| {
            binding.tool_name == "connector__google__gmail_draft_email"
                && binding.slot == "to"
                && binding.protected_slot_kind == ProtectedSlotKind::EmailAddress
        }));
        assert!(bindings.iter().any(|binding| {
            binding.tool_name == "connector__google__gmail_send_email"
                && binding.slot == "to"
                && binding.protected_slot_kind == ProtectedSlotKind::EmailAddress
        }));
    }

    #[test]
    fn connected_account_alias_detection_covers_google_phrases() {
        assert!(looks_like_connected_account_alias(
            "my connected Google address",
            &["google", "gmail", "google workspace"]
        ));
        assert!(looks_like_connected_account_alias(
            "your connected Gmail account email",
            &["google", "gmail", "google workspace"]
        ));
        assert!(!looks_like_connected_account_alias(
            "alice@example.com",
            &["google", "gmail", "google workspace"]
        ));
    }

    #[test]
    fn connected_account_alias_resolves_to_known_google_account_email() {
        let resolved = resolve_connected_account_alias(
            "your connected Google address",
            Some("ioifoundationhl@gmail.com"),
            &["google", "gmail", "google workspace"],
        );
        assert_eq!(resolved.as_deref(), Some("ioifoundationhl@gmail.com"));
    }

    #[test]
    fn query_level_connected_account_alias_detection_covers_full_requests() {
        assert!(query_mentions_connected_account_alias(
            "Draft an email to my connected Google address with subject hello and do not send it.",
            &["google", "gmail", "google workspace"]
        ));
        assert!(query_mentions_connected_account_alias(
            "Send a message to your connected Gmail account email confirming the deploy.",
            &["google", "gmail", "google workspace"]
        ));
        assert!(!query_mentions_connected_account_alias(
            "Send a message to alice@example.com confirming the deploy.",
            &["google", "gmail", "google workspace"]
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn query_level_symbolic_reference_inference_returns_connected_account_email() {
        let state = base_agent_state();
        let inferred = infer_google_symbolic_reference_from_query_boxed(
            &state,
            "to",
            "Draft an email to my connected Google address with subject hello.",
            ProtectedSlotKind::EmailAddress,
        )
        .await
        .expect("inference should succeed");
        assert_eq!(inferred.as_deref(), Some("connected_account.email"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn write_actions_emit_pending_approval_when_policy_requires_confirm() {
        let policy_path = temp_policy_path();
        write_policy_file(
            &policy_path,
            TestConnectorPolicyOverride {
                inherit_global: false,
                reads: TestDecisionMode::Auto,
                writes: TestDecisionMode::Confirm,
                admin: TestDecisionMode::Confirm,
                expert: TestDecisionMode::Block,
                automations: TestAutomationMode::ConfirmOnCreate,
                data_handling: TestDataHandlingMode::LocalOnly,
            },
        );

        let inference: Arc<dyn InferenceRuntime> = Arc::new(MockInferenceRuntime);
        let (tx, mut rx) = tokio::sync::broadcast::channel(8);
        let service = DesktopAgentService::new(
            Arc::new(NoopGuiDriver),
            Arc::new(TerminalDriver::new()),
            Arc::new(BrowserDriver::new()),
            inference,
        )
        .with_shield_policy_path(policy_path.clone())
        .with_event_sender(tx);
        let agent_state = base_agent_state();
        let spec = find_action_by_id("gmail.send_email").expect("gmail send spec present");
        let input = json!({
            "to": "user@example.com",
            "subject": "Approval test",
            "body": "Pending approval expected"
        });

        let result = enforce_google_tool_shield_policy(
            &service,
            &agent_state,
            [9u8; 32],
            &spec,
            &input,
            false,
        );

        match result {
            Err(TransactionError::PendingApproval(_)) => {}
            other => panic!("expected pending approval, got {:?}", other),
        }

        let event = rx
            .recv()
            .await
            .expect("interception event should be emitted");
        match event {
            KernelEvent::FirewallInterception {
                verdict, target, ..
            } => {
                assert_eq!(verdict, "REQUIRE_APPROVAL");
                assert_eq!(target, spec.tool_name);
            }
            other => panic!("expected firewall interception event, got {:?}", other),
        }

        let _ = std::fs::remove_file(policy_path);
    }

    #[test]
    fn matching_pending_approval_allows_google_write_action() {
        let policy_path = temp_policy_path();
        write_policy_file(
            &policy_path,
            TestConnectorPolicyOverride {
                inherit_global: false,
                reads: TestDecisionMode::Auto,
                writes: TestDecisionMode::Confirm,
                admin: TestDecisionMode::Confirm,
                expert: TestDecisionMode::Block,
                automations: TestAutomationMode::ConfirmOnCreate,
                data_handling: TestDataHandlingMode::LocalOnly,
            },
        );

        let service = build_test_service(policy_path.clone());
        let spec = find_action_by_id("gmail.send_email").expect("gmail send spec present");
        let input = json!({
            "to": "user@example.com",
            "subject": "Approved send",
            "body": "This should pass policy enforcement"
        });
        let request_hash =
            compute_google_shield_request_hash(&spec, &input).expect("request hash should compute");

        let mut agent_state = base_agent_state();
        agent_state.pending_approval = Some(ApprovalToken {
            schema_version: 2,
            request_hash,
            audience: [0u8; 32],
            revocation_epoch: 0,
            nonce: [0u8; 32],
            counter: 0,
            scope: ApprovalScope::default(),
            visual_hash: None,
            pii_action: None,
            scoped_exception: None,
            approver_sig: vec![],
            approver_suite: SignatureSuite::ED25519,
        });

        let result = enforce_google_tool_shield_policy(
            &service,
            &agent_state,
            [9u8; 32],
            &spec,
            &input,
            false,
        );
        assert!(
            result.is_ok(),
            "matching approval token should allow execution"
        );

        let _ = std::fs::remove_file(policy_path);
    }

    #[test]
    fn canonical_resume_approval_allows_google_write_action_without_connector_hash_match() {
        let policy_path = temp_policy_path();
        write_policy_file(
            &policy_path,
            TestConnectorPolicyOverride {
                inherit_global: false,
                reads: TestDecisionMode::Auto,
                writes: TestDecisionMode::Confirm,
                admin: TestDecisionMode::Confirm,
                expert: TestDecisionMode::Block,
                automations: TestAutomationMode::ConfirmOnCreate,
                data_handling: TestDataHandlingMode::LocalOnly,
            },
        );

        let service = build_test_service(policy_path.clone());
        let spec = find_action_by_id("gmail.draft_email").expect("gmail draft spec present");
        let input = json!({
            "to": "user@example.com",
            "subject": "Approved draft",
            "body": "This should pass during canonical resume"
        });

        let mut agent_state = base_agent_state();
        agent_state.pending_approval = Some(ApprovalToken {
            schema_version: 2,
            request_hash: [7u8; 32],
            audience: [0u8; 32],
            revocation_epoch: 0,
            nonce: [0u8; 32],
            counter: 0,
            scope: ApprovalScope::default(),
            visual_hash: None,
            pii_action: None,
            scoped_exception: None,
            approver_sig: vec![],
            approver_suite: SignatureSuite::ED25519,
        });
        agent_state.pending_tool_jcs = Some(
            serde_jcs::to_vec(&json!({
                "name": spec.tool_name,
                "arguments": input,
            }))
            .expect("canonical pending tool"),
        );

        let result = enforce_google_tool_shield_policy(
            &service,
            &agent_state,
            [9u8; 32],
            &spec,
            &json!({
                "to": "user@example.com",
                "subject": "Approved draft",
                "body": "This should pass during canonical resume"
            }),
            true,
        );
        assert!(
            result.is_ok(),
            "canonical resume approval should allow execution without a second connector gate"
        );

        let _ = std::fs::remove_file(policy_path);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn expert_actions_emit_block_when_policy_blocks_expert_mode() {
        let policy_path = temp_policy_path();
        write_policy_file(
            &policy_path,
            TestConnectorPolicyOverride {
                inherit_global: false,
                reads: TestDecisionMode::Auto,
                writes: TestDecisionMode::Auto,
                admin: TestDecisionMode::Auto,
                expert: TestDecisionMode::Block,
                automations: TestAutomationMode::ManualOnly,
                data_handling: TestDataHandlingMode::LocalOnly,
            },
        );

        let inference: Arc<dyn InferenceRuntime> = Arc::new(MockInferenceRuntime);
        let (tx, mut rx) = tokio::sync::broadcast::channel(8);
        let service = DesktopAgentService::new(
            Arc::new(NoopGuiDriver),
            Arc::new(TerminalDriver::new()),
            Arc::new(BrowserDriver::new()),
            inference,
        )
        .with_shield_policy_path(policy_path.clone())
        .with_event_sender(tx);
        let agent_state = base_agent_state();
        let spec = find_action_by_id("expert.raw_request").expect("expert raw spec present");
        let input = json!({
            "service": "gmail",
            "method": "users.messages.list"
        });

        let result = enforce_google_tool_shield_policy(
            &service,
            &agent_state,
            [9u8; 32],
            &spec,
            &input,
            false,
        );

        match result {
            Err(TransactionError::Invalid(message)) => {
                assert!(message.contains("expert Google actions are disabled"));
            }
            other => panic!("expected blocked expert action, got {:?}", other),
        }

        let event = rx.recv().await.expect("block event should be emitted");
        match event {
            KernelEvent::FirewallInterception {
                verdict, target, ..
            } => {
                assert_eq!(verdict, "BLOCK");
                assert_eq!(target, spec.tool_name);
            }
            other => panic!("expected firewall interception event, got {:?}", other),
        }

        let _ = std::fs::remove_file(policy_path);
    }
}
