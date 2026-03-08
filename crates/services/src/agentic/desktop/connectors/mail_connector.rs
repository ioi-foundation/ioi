use super::{
    ConnectorPostconditionProof, ConnectorPostconditionVerifierBinding,
    ConnectorProtectedSlotBinding,
    ConnectorProviderProbeBinding, ConnectorSymbolicReferenceBinding,
    ConnectorSymbolicReferenceInferenceBinding, ConnectorToolRouteBinding,
    PostconditionVerificationFuture, ProviderCandidateDiscoveryFuture,
    ResolvedSymbolicReference, SymbolicReferenceInferenceFuture,
    SymbolicReferenceResolutionFuture,
};
use crate::agentic::desktop::types::AgentState;
use ioi_api::state::StateAccess;
use ioi_types::app::agentic::{CapabilityId, ProtectedSlotKind, ProviderRouteCandidate};
use ioi_types::app::wallet_network::MailConnectorRecord;
use ioi_types::codec;
use std::collections::BTreeSet;

const MAIL_CONNECTOR_PREFIX: &[u8] = b"mail_connector::";
const MAIL_CONNECTOR_ID: &str = "wallet_network.mail";
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

fn verify_mail_postconditions_boxed<'a>(
    _agent_state: &'a AgentState,
    _tool_name: &'a str,
    _tool_args: &'a serde_json::Value,
    _history_entry: &'a str,
) -> PostconditionVerificationFuture<'a> {
    Box::pin(async { Ok(None::<ConnectorPostconditionProof>) })
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
