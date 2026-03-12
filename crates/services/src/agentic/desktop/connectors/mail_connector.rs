use super::{
    ConnectorPostconditionEvidence, ConnectorPostconditionProof,
    ConnectorPostconditionVerifierBinding, ConnectorProtectedSlotBinding,
    ConnectorProviderProbeBinding, ConnectorSymbolicReferenceBinding,
    ConnectorSymbolicReferenceInferenceBinding, ConnectorToolRouteBinding,
    PostconditionVerificationFuture, ProviderCandidateDiscoveryFuture, ResolvedSymbolicReference,
    SymbolicReferenceInferenceFuture, SymbolicReferenceResolutionFuture,
};
use crate::agentic::desktop::types::AgentState;
use ioi_api::state::StateAccess;
use ioi_types::app::agentic::{CapabilityId, ProtectedSlotKind, ProviderRouteCandidate};
use ioi_types::app::wallet_network::MailConnectorRecord;
use ioi_types::codec;
use serde_json::Value;
use std::collections::BTreeSet;

const MAIL_CONNECTOR_PREFIX: &[u8] = b"mail_connector::";
pub const MAIL_CONNECTOR_ID: &str = "wallet_network.mail";
const MAIL_PROVIDER_FAMILY: &str = "mail.wallet_network";
const MAIL_ROUTE_LABEL: &str = "mail_connector";

const MAIL_TOOL_ROUTE_BINDINGS: &[ConnectorToolRouteBinding] = &[
    ConnectorToolRouteBinding {
        tool_name: "wallet_network__mail_read_latest",
        provider_family: MAIL_PROVIDER_FAMILY,
        route_label: MAIL_ROUTE_LABEL,
    },
    ConnectorToolRouteBinding {
        tool_name: "wallet_mail_read_latest",
        provider_family: MAIL_PROVIDER_FAMILY,
        route_label: MAIL_ROUTE_LABEL,
    },
    ConnectorToolRouteBinding {
        tool_name: "mail__read_latest",
        provider_family: MAIL_PROVIDER_FAMILY,
        route_label: MAIL_ROUTE_LABEL,
    },
    ConnectorToolRouteBinding {
        tool_name: "wallet_network__mail_list_recent",
        provider_family: MAIL_PROVIDER_FAMILY,
        route_label: MAIL_ROUTE_LABEL,
    },
    ConnectorToolRouteBinding {
        tool_name: "wallet_mail_list_recent",
        provider_family: MAIL_PROVIDER_FAMILY,
        route_label: MAIL_ROUTE_LABEL,
    },
    ConnectorToolRouteBinding {
        tool_name: "mail__list_recent",
        provider_family: MAIL_PROVIDER_FAMILY,
        route_label: MAIL_ROUTE_LABEL,
    },
    ConnectorToolRouteBinding {
        tool_name: "wallet_network__mail_delete_spam",
        provider_family: MAIL_PROVIDER_FAMILY,
        route_label: MAIL_ROUTE_LABEL,
    },
    ConnectorToolRouteBinding {
        tool_name: "wallet_mail_delete_spam",
        provider_family: MAIL_PROVIDER_FAMILY,
        route_label: MAIL_ROUTE_LABEL,
    },
    ConnectorToolRouteBinding {
        tool_name: "mail__delete_spam",
        provider_family: MAIL_PROVIDER_FAMILY,
        route_label: MAIL_ROUTE_LABEL,
    },
    ConnectorToolRouteBinding {
        tool_name: "wallet_network__mail_reply",
        provider_family: MAIL_PROVIDER_FAMILY,
        route_label: MAIL_ROUTE_LABEL,
    },
    ConnectorToolRouteBinding {
        tool_name: "wallet_mail_reply",
        provider_family: MAIL_PROVIDER_FAMILY,
        route_label: MAIL_ROUTE_LABEL,
    },
    ConnectorToolRouteBinding {
        tool_name: "mail__reply",
        provider_family: MAIL_PROVIDER_FAMILY,
        route_label: MAIL_ROUTE_LABEL,
    },
];

pub fn mail_connector_tool_route_bindings() -> Vec<ConnectorToolRouteBinding> {
    MAIL_TOOL_ROUTE_BINDINGS.to_vec()
}

fn capability_vec(sorted_caps: &BTreeSet<CapabilityId>) -> Vec<CapabilityId> {
    sorted_caps.iter().cloned().collect()
}

fn discover_mail_provider_candidates(
    state: Option<&dyn StateAccess>,
    provider_family: &str,
    route_label: &str,
    capabilities: &BTreeSet<CapabilityId>,
) -> Vec<ProviderRouteCandidate> {
    let Some(state) = state else {
        return Vec::new();
    };
    let Ok(scan) = state.prefix_scan(MAIL_CONNECTOR_PREFIX) else {
        return Vec::new();
    };

    let mut candidates = Vec::<ProviderRouteCandidate>::new();
    for item in scan {
        let Ok((_, bytes)) = item else {
            continue;
        };
        let Ok(record) = codec::from_bytes_canonical::<MailConnectorRecord>(&bytes) else {
            continue;
        };
        let mailbox = record.mailbox.trim().to_string();
        let account = record.config.account_email.trim().to_string();
        let provider_id = format!(
            "mail://{}#{}",
            if account.is_empty() {
                "unlabeled-account"
            } else {
                account.as_str()
            },
            if mailbox.is_empty() {
                "primary"
            } else {
                mailbox.as_str()
            }
        );
        let summary = if account.is_empty() {
            format!(
                "Connected generic mail route for mailbox '{}'.",
                if mailbox.is_empty() {
                    "primary"
                } else {
                    mailbox.as_str()
                }
            )
        } else {
            format!(
                "Connected generic mail route for mailbox '{}' on account {}.",
                if mailbox.is_empty() {
                    "primary"
                } else {
                    mailbox.as_str()
                },
                account
            )
        };
        candidates.push(ProviderRouteCandidate {
            provider_family: provider_family.to_string(),
            route_label: route_label.to_string(),
            connector_id: MAIL_CONNECTOR_ID.to_string(),
            provider_id: Some(provider_id),
            account_label: if account.is_empty() {
                None
            } else {
                Some(account)
            },
            capabilities: capability_vec(capabilities),
            summary,
        });
    }
    candidates
}

fn discover_mail_provider_candidates_boxed<'a>(
    state: Option<&'a dyn StateAccess>,
    provider_family: &'a str,
    route_label: &'a str,
    capabilities: &'a BTreeSet<CapabilityId>,
) -> ProviderCandidateDiscoveryFuture<'a> {
    Box::pin(async move {
        discover_mail_provider_candidates(state, provider_family, route_label, capabilities)
    })
}

pub fn mail_connector_provider_probe_bindings() -> Vec<ConnectorProviderProbeBinding> {
    vec![ConnectorProviderProbeBinding {
        provider_family: MAIL_PROVIDER_FAMILY,
        discover: discover_mail_provider_candidates_boxed,
    }]
}

fn resolve_mail_symbolic_reference_boxed<'a>(
    _agent_state: &'a AgentState,
    _reference: &'a str,
) -> SymbolicReferenceResolutionFuture<'a> {
    Box::pin(async { Ok(None::<ResolvedSymbolicReference>) })
}

pub fn mail_connector_symbolic_reference_bindings() -> Vec<ConnectorSymbolicReferenceBinding> {
    vec![ConnectorSymbolicReferenceBinding {
        connector_id: MAIL_CONNECTOR_ID,
        resolve: resolve_mail_symbolic_reference_boxed,
    }]
}

fn infer_mail_symbolic_reference_boxed<'a>(
    _agent_state: &'a AgentState,
    _slot: &'a str,
    _query: &'a str,
    _protected_slot_kind: ProtectedSlotKind,
) -> SymbolicReferenceInferenceFuture<'a> {
    Box::pin(async { Ok(None::<String>) })
}

pub fn mail_connector_symbolic_reference_inference_bindings(
) -> Vec<ConnectorSymbolicReferenceInferenceBinding> {
    vec![ConnectorSymbolicReferenceInferenceBinding {
        connector_id: MAIL_CONNECTOR_ID,
        infer: infer_mail_symbolic_reference_boxed,
    }]
}

pub fn mail_connector_protected_slot_bindings() -> Vec<ConnectorProtectedSlotBinding> {
    Vec::new()
}

fn mail_selected_provider_id(agent_state: &AgentState) -> Option<String> {
    agent_state
        .resolved_intent
        .as_ref()
        .and_then(|resolved| resolved.provider_selection.as_ref())
        .and_then(|selection| selection.selected_provider_id.clone())
}

fn extract_first_json_object(raw: &str) -> Option<String> {
    let start = raw.find('{')?;
    let mut brace_depth = 0usize;
    let mut in_string = false;
    let mut escape = false;
    for (idx, ch) in raw[start..].char_indices() {
        if in_string {
            if escape {
                escape = false;
                continue;
            }
            if ch == '\\' {
                escape = true;
                continue;
            }
            if ch == '"' {
                in_string = false;
            }
            continue;
        }
        if ch == '"' {
            in_string = true;
            continue;
        }
        if ch == '{' {
            brace_depth += 1;
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

fn mailto_citation_matches(citation: &str, expected_to: &str, expected_subject: &str) -> bool {
    let Some(rest) = citation.trim().strip_prefix("mailto:") else {
        return false;
    };
    let Some((recipient, subject_query)) = rest.split_once("?subject=") else {
        return false;
    };
    recipient.trim().eq_ignore_ascii_case(expected_to.trim())
        && subject_query.trim() == expected_subject.trim()
}

fn verify_mail_postconditions_boxed<'a>(
    agent_state: &'a AgentState,
    tool_name: &'a str,
    tool_args: &'a Value,
    history_entry: &'a str,
) -> PostconditionVerificationFuture<'a> {
    Box::pin(async move {
        let normalized = tool_name.trim().to_ascii_lowercase();
        if !matches!(
            normalized.as_str(),
            "wallet_network__mail_reply" | "wallet_mail_reply" | "mail__reply"
        ) {
            return Ok(None);
        }

        let payload = parse_json_payload_from_history(history_entry).ok_or_else(|| {
            "Mail reply verification could not parse structured action output.".to_string()
        })?;
        let mailbox = payload
            .get("mailbox")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| "Mail reply verification payload was missing mailbox.".to_string())?;
        let to = payload
            .get("to")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| "Mail reply verification payload was missing recipient.".to_string())?;
        let subject = payload
            .get("subject")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| "Mail reply verification payload was missing subject.".to_string())?;
        let body = payload
            .get("body")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| "Mail reply verification payload was missing body.".to_string())?;
        let sent_message_id = payload
            .get("sent_message_id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                "Mail reply verification payload was missing sent_message_id.".to_string()
            })?;
        let citation = payload
            .get("citation")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| "Mail reply verification payload was missing citation.".to_string())?;

        let mailbox_matches = tool_args
            .get("mailbox")
            .and_then(Value::as_str)
            .map(|expected| expected.trim().eq_ignore_ascii_case(mailbox))
            .unwrap_or(true);
        let to_matches = tool_args
            .get("to")
            .and_then(Value::as_str)
            .map(|expected| expected.trim().eq_ignore_ascii_case(to))
            .unwrap_or(true);
        let subject_matches = tool_args
            .get("subject")
            .and_then(Value::as_str)
            .map(|expected| expected.trim() == subject)
            .unwrap_or(true);
        let body_matches = tool_args
            .get("body")
            .and_then(Value::as_str)
            .map(|expected| expected.trim() == body)
            .unwrap_or(true);
        let citation_matches = mailto_citation_matches(citation, to, subject);

        if !(mailbox_matches && to_matches && subject_matches && body_matches && citation_matches) {
            return Err(format!(
                "ERROR_CLASS=PostconditionFailed Mail reply verification failed. mailbox_matches={} to_matches={} subject_matches={} body_matches={} citation_matches={}",
                mailbox_matches, to_matches, subject_matches, body_matches, citation_matches
            ));
        }

        Ok(Some(ConnectorPostconditionProof {
            evidence: vec![ConnectorPostconditionEvidence {
                key: "mail.reply.completed".to_string(),
                evidence: format!(
                    "mailbox={};to={};subject={};sent_message_id={}",
                    mailbox, to, subject, sent_message_id
                ),
                observed_value: Some(sent_message_id.to_string()),
                evidence_type: Some("mail_connector_receipt".to_string()),
                provider_id: mail_selected_provider_id(agent_state),
            }],
        }))
    })
}

pub fn mail_connector_postcondition_verifier_bindings() -> Vec<ConnectorPostconditionVerifierBinding>
{
    vec![ConnectorPostconditionVerifierBinding {
        connector_id: MAIL_CONNECTOR_ID,
        verify: verify_mail_postconditions_boxed,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use ioi_state::primitives::hash::HashCommitmentScheme;
    use ioi_state::tree::iavl::IAVLTree;
    use ioi_types::app::wallet_network::{
        MailConnectorAuthMode, MailConnectorConfig, MailConnectorEndpoint, MailConnectorProvider,
        MailConnectorRecord, MailConnectorSecretAliases, MailConnectorTlsMode,
    };
    use std::collections::BTreeMap;

    #[test]
    fn discovers_mail_provider_candidates_from_connector_state() {
        let mut state = IAVLTree::new(HashCommitmentScheme::new());
        let record = MailConnectorRecord {
            mailbox: "primary".to_string(),
            config: MailConnectorConfig {
                provider: MailConnectorProvider::ImapSmtp,
                auth_mode: MailConnectorAuthMode::Password,
                account_email: "local-mail@example.com".to_string(),
                sender_display_name: Some("Local Mail".to_string()),
                imap: MailConnectorEndpoint {
                    host: "imap.example.com".to_string(),
                    port: 993,
                    tls_mode: MailConnectorTlsMode::Tls,
                },
                smtp: MailConnectorEndpoint {
                    host: "smtp.example.com".to_string(),
                    port: 465,
                    tls_mode: MailConnectorTlsMode::Tls,
                },
                secret_aliases: MailConnectorSecretAliases {
                    imap_username_alias: "imap_username".to_string(),
                    imap_password_alias: "imap_password".to_string(),
                    smtp_username_alias: "smtp_username".to_string(),
                    smtp_password_alias: "smtp_password".to_string(),
                },
                metadata: BTreeMap::new(),
            },
            created_at_ms: 0,
            updated_at_ms: 0,
        };
        state
            .insert(
                b"mail_connector::primary",
                &codec::to_bytes_canonical(&record).expect("encode mail connector"),
            )
            .expect("insert mail connector");

        let capabilities = BTreeSet::from([CapabilityId::from("mail.reply")]);
        let candidates = discover_mail_provider_candidates(
            Some(&state),
            MAIL_PROVIDER_FAMILY,
            MAIL_ROUTE_LABEL,
            &capabilities,
        );

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].provider_family, MAIL_PROVIDER_FAMILY);
        assert_eq!(candidates[0].route_label, MAIL_ROUTE_LABEL);
        assert_eq!(
            candidates[0].provider_id.as_deref(),
            Some("mail://local-mail@example.com#primary")
        );
    }
}
