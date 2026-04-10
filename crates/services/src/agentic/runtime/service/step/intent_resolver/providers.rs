use super::*;
use crate::agentic::runtime::connectors::connector_provider_probe_bindings;
use ioi_api::state::StateAccess;
use ioi_types::app::agentic::ProviderSelectionMode;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct ProviderSelectionPayload {
    #[serde(default)]
    selected_provider_family: Option<String>,
    #[serde(default)]
    selected_provider_id: Option<String>,
    #[serde(default)]
    selection_basis: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}

fn binding_matches_required_capabilities(
    binding: &ToolCapabilityBinding,
    required_capabilities: &[CapabilityId],
) -> bool {
    !required_capabilities.is_empty()
        && binding.capabilities.iter().any(|capability| {
            required_capabilities
                .iter()
                .any(|required| required == capability)
        })
}

fn provider_family_catalog(
    bindings: &[ToolCapabilityBinding],
    required_capabilities: &[CapabilityId],
) -> BTreeMap<String, (String, BTreeSet<CapabilityId>)> {
    let mut families = BTreeMap::<String, (String, BTreeSet<CapabilityId>)>::new();
    for binding in bindings {
        if !binding_matches_required_capabilities(binding, required_capabilities) {
            continue;
        }
        let Some(provider_family) = tool_provider_family(&binding.tool_name) else {
            continue;
        };
        let route_label = tool_provider_route_label(&binding.tool_name)
            .unwrap_or(provider_family)
            .to_string();
        let entry = families
            .entry(provider_family.to_string())
            .or_insert_with(|| (route_label, BTreeSet::new()));
        for capability in &binding.capabilities {
            if required_capabilities
                .iter()
                .any(|required| required == capability)
            {
                entry.1.insert(capability.clone());
            }
        }
    }
    families
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

fn parse_provider_selection_payload(
    raw: &str,
) -> Result<ProviderSelectionPayload, TransactionError> {
    serde_json::from_str::<ProviderSelectionPayload>(raw).or_else(|_| {
        let extracted = extract_first_json_object(raw).ok_or_else(|| {
            TransactionError::Invalid(
                "ERROR_CLASS=ResolverContractViolation provider selection output missing JSON"
                    .to_string(),
            )
        })?;
        serde_json::from_str::<ProviderSelectionPayload>(&extracted).map_err(|error| {
            TransactionError::Invalid(format!(
                "ERROR_CLASS=ResolverContractViolation provider selection output parse failed: {}",
                error
            ))
        })
    })
}

async fn synthesize_provider_selection(
    service: &RuntimeAgentService,
    runtime: &Arc<dyn InferenceRuntime>,
    session_id: [u8; 32],
    query: &str,
    intent_id: &str,
    required_capabilities: &[CapabilityId],
    candidates: &[ProviderRouteCandidate],
) -> ProviderSelectionPayload {
    let candidates_json = candidates
        .iter()
        .map(|candidate| {
            json!({
                "providerFamily": candidate.provider_family,
                "routeLabel": candidate.route_label,
                "connectorId": candidate.connector_id,
                "providerId": candidate.provider_id,
                "accountLabel": candidate.account_label,
                "capabilities": candidate.capabilities,
                "summary": candidate.summary,
            })
        })
        .collect::<Vec<_>>();
    let payload = json!([
        {
            "role": "system",
            "content": "Select the best provider route for a resolved intent. Output JSON only."
        },
        {
            "role": "user",
            "content": format!(
                "Query:\n{}\n\nResolved intent:\n{}\n\nRequired capabilities:\n{}\n\nAvailable provider routes:\n{}\n\nReturn exactly one JSON object with this schema:\n{{\"selectedProviderFamily\":<string|null>,\"selectedProviderId\":<string|null>,\"selectionBasis\":<string>,\"reason\":<string>}}\nRules:\n1) Choose one route only when the query semantically distinguishes a provider/account/service among the listed routes.\n2) Prefer explicit user references to a provider, connector, account, mailbox, or service surface.\n3) If multiple routes can satisfy the request and the query does not distinguish them, return null for both selected fields and set selectionBasis to \"unresolved\".\n4) Never invent provider families or provider ids.\n5) Keep routing generic; do not rely on brittle keyword matching.",
                query,
                intent_id,
                serde_json::to_string(required_capabilities).unwrap_or_default(),
                serde_json::to_string(&candidates_json).unwrap_or_default()
            )
        }
    ]);
    let input_bytes = match serde_json::to_vec(&payload) {
        Ok(encoded) => encoded,
        Err(error) => {
            log::warn!(
                "IntentResolver provider selection payload encode failed error={}",
                error
            );
            return ProviderSelectionPayload {
                selection_basis: Some("unresolved".to_string()),
                reason: Some("payload_encode_failed".to_string()),
                ..Default::default()
            };
        }
    };
    let airlocked_input = match service
        .prepare_cloud_inference_input(
            Some(session_id),
            "intent_resolver",
            INTENT_PROVIDER_SELECTION_MODEL_ID,
            &input_bytes,
        )
        .await
    {
        Ok(encoded) => encoded,
        Err(error) => {
            log::warn!(
                "IntentResolver provider selection airlock failed session={} error={}",
                hex::encode(&session_id[..4]),
                error
            );
            return ProviderSelectionPayload {
                selection_basis: Some("unresolved".to_string()),
                reason: Some("airlock_failed".to_string()),
                ..Default::default()
            };
        }
    };
    let output = match runtime
        .execute_inference(
            [0u8; 32],
            &airlocked_input,
            ioi_types::app::agentic::InferenceOptions {
                temperature: 0.0,
                json_mode: true,
                max_tokens: 256,
                ..Default::default()
            },
        )
        .await
    {
        Ok(bytes) => bytes,
        Err(error) => {
            log::warn!(
                "IntentResolver provider selection inference failed error={}",
                vm_error_to_tx(error)
            );
            return ProviderSelectionPayload {
                selection_basis: Some("unresolved".to_string()),
                reason: Some("inference_failed".to_string()),
                ..Default::default()
            };
        }
    };
    let raw = String::from_utf8_lossy(&output).to_string();
    match parse_provider_selection_payload(&raw) {
        Ok(parsed) => parsed,
        Err(error) => {
            log::warn!(
                "IntentResolver provider selection parse failed error={}",
                error
            );
            ProviderSelectionPayload {
                selection_basis: Some("unresolved".to_string()),
                reason: Some("parse_failed".to_string()),
                ..Default::default()
            }
        }
    }
}

pub(super) async fn resolve_provider_selection_state(
    service: &RuntimeAgentService,
    state: Option<&dyn StateAccess>,
    runtime: &Arc<dyn InferenceRuntime>,
    session_id: [u8; 32],
    query: &str,
    entry: &IntentMatrixEntry,
    required_capabilities: &[CapabilityId],
    bindings: &[ToolCapabilityBinding],
) -> Option<ProviderSelectionState> {
    if !matches!(
        entry.effective_provider_selection_mode(),
        ProviderSelectionMode::DynamicSynthesis
    ) {
        return None;
    }

    let family_catalog = provider_family_catalog(bindings, required_capabilities);
    if family_catalog.is_empty() {
        return None;
    }

    let mut candidates = Vec::<ProviderRouteCandidate>::new();
    let probe_bindings = connector_provider_probe_bindings();
    for (provider_family, (route_label, capabilities)) in &family_catalog {
        let Some(probe) = probe_bindings
            .iter()
            .find(|binding| binding.provider_family == provider_family.as_str())
        else {
            continue;
        };
        candidates
            .extend((probe.discover)(state, provider_family, route_label, capabilities).await);
    }

    candidates.sort_by(|left, right| {
        left.provider_family
            .cmp(&right.provider_family)
            .then_with(|| left.connector_id.cmp(&right.connector_id))
            .then_with(|| left.provider_id.cmp(&right.provider_id))
            .then_with(|| left.account_label.cmp(&right.account_label))
    });

    if candidates.is_empty() {
        return Some(ProviderSelectionState {
            mode: entry.effective_provider_selection_mode(),
            selection_basis: Some("unresolved".to_string()),
            candidates,
            ..Default::default()
        });
    }

    if candidates.len() == 1 {
        let candidate = candidates.first().cloned().unwrap_or_default();
        return Some(ProviderSelectionState {
            mode: entry.effective_provider_selection_mode(),
            selected_provider_family: Some(candidate.provider_family.clone()),
            selected_route_label: Some(candidate.route_label.clone()),
            selected_provider_id: candidate.provider_id.clone(),
            selected_connector_id: Some(candidate.connector_id.clone()),
            selection_basis: Some("single_available".to_string()),
            candidates,
        });
    }

    let payload = synthesize_provider_selection(
        service,
        runtime,
        session_id,
        query,
        &entry.intent_id,
        required_capabilities,
        &candidates,
    )
    .await;

    let selected_candidate = payload
        .selected_provider_family
        .as_deref()
        .and_then(|family| {
            payload
                .selected_provider_id
                .as_deref()
                .and_then(|provider_id| {
                    candidates.iter().find(|candidate| {
                        candidate.provider_family == family
                            && candidate.provider_id.as_deref() == Some(provider_id)
                    })
                })
                .or_else(|| {
                    candidates
                        .iter()
                        .find(|candidate| candidate.provider_family == family)
                })
        })
        .cloned();

    Some(ProviderSelectionState {
        mode: entry.effective_provider_selection_mode(),
        selected_provider_family: selected_candidate
            .as_ref()
            .map(|candidate| candidate.provider_family.clone()),
        selected_route_label: selected_candidate
            .as_ref()
            .map(|candidate| candidate.route_label.clone()),
        selected_provider_id: selected_candidate
            .as_ref()
            .and_then(|candidate| candidate.provider_id.clone()),
        selected_connector_id: selected_candidate
            .as_ref()
            .map(|candidate| candidate.connector_id.clone()),
        selection_basis: payload
            .selection_basis
            .or_else(|| payload.reason)
            .or_else(|| Some("unresolved".to_string())),
        candidates,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agentic::runtime::service::RuntimeAgentService;
    use async_trait::async_trait;
    use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
    use ioi_api::vm::inference::{mock::MockInferenceRuntime, InferenceRuntime};
    use ioi_drivers::browser::BrowserDriver;
    use ioi_drivers::terminal::TerminalDriver;
    use ioi_state::primitives::hash::HashCommitmentScheme;
    use ioi_state::tree::iavl::IAVLTree;
    use ioi_types::app::agentic::CapabilityId;
    use ioi_types::app::agentic::{
        ExecutionApplicabilityClass, IntentMatrixEntry, IntentQueryBindingClass,
        IntentScopeProfile, ProviderSelectionMode, VerificationMode,
    };
    use ioi_types::app::wallet_network::{
        MailConnectorAuthMode, MailConnectorConfig, MailConnectorEndpoint, MailConnectorProvider,
        MailConnectorRecord, MailConnectorSecretAliases, MailConnectorTlsMode,
    };
    use ioi_types::app::{ActionRequest, ContextSlice};
    use ioi_types::codec;
    use ioi_types::error::VmError;
    use std::collections::BTreeMap;
    use std::collections::HashMap;
    use std::sync::Arc;

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

        async fn capture_context(&self, _intent: &ActionRequest) -> Result<ContextSlice, VmError> {
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
            _map: HashMap<u32, (i32, i32, i32, i32)>,
        ) -> Result<(), VmError> {
            Ok(())
        }
    }

    fn binding(tool_name: &str, capabilities: &[&str]) -> ToolCapabilityBinding {
        ToolCapabilityBinding {
            tool_name: tool_name.to_string(),
            action_target: ActionTarget::Custom(tool_name.to_string()),
            capabilities: capabilities
                .iter()
                .map(|capability| CapabilityId::from(*capability))
                .collect(),
        }
    }

    #[test]
    fn provider_family_catalog_groups_bindings_by_provider_family() {
        let bindings = vec![
            binding("wallet_network__mail_reply", &["mail.reply", "mail.send"]),
            binding(
                "connector__google__gmail_draft_email",
                &["mail.reply", "mail.send", "gmail.write"],
            ),
        ];

        let catalog = provider_family_catalog(&bindings, &[CapabilityId::from("mail.reply")]);

        assert!(catalog.contains_key("mail.wallet_network"));
        assert!(catalog.contains_key("mail.google.gmail"));
        assert_eq!(
            catalog.get("mail.wallet_network").expect("mail family").0,
            "mail_connector"
        );
        assert_eq!(
            catalog.get("mail.google.gmail").expect("google family").0,
            "google_gmail"
        );
    }

    #[test]
    fn provider_probe_registry_covers_all_registered_provider_families() {
        let registered = super::tool_capability_bindings()
            .into_iter()
            .filter_map(|binding| tool_provider_family(&binding.tool_name))
            .collect::<BTreeSet<_>>();
        let covered = connector_provider_probe_bindings()
            .into_iter()
            .map(|binding| binding.provider_family)
            .collect::<BTreeSet<_>>();

        for provider_family in registered {
            assert!(
                covered.contains(provider_family),
                "missing provider probe binding for family {}",
                provider_family
            );
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn dynamic_provider_selection_auto_selects_single_discovered_connector_route() {
        let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
        let terminal = Arc::new(TerminalDriver::new());
        let browser = Arc::new(BrowserDriver::new());
        let inference: Arc<dyn InferenceRuntime> = Arc::new(MockInferenceRuntime);
        let service = RuntimeAgentService::new(gui, terminal, browser, inference.clone());

        let entry = IntentMatrixEntry {
            intent_id: "mail.reply".to_string(),
            semantic_descriptor: "compose outbound email".to_string(),
            query_binding: IntentQueryBindingClass::None,
            required_capabilities: vec![CapabilityId::from("mail.reply")],
            risk_class: "high".to_string(),
            scope: IntentScopeProfile::Conversation,
            preferred_tier: "tool_first".to_string(),
            applicability_class: ExecutionApplicabilityClass::Mixed,
            requires_host_discovery: Some(false),
            provider_selection_mode: Some(ProviderSelectionMode::DynamicSynthesis),
            required_receipts: vec![
                "provider_selection".to_string(),
                "provider_selection_commit".to_string(),
                "execution".to_string(),
                "verification".to_string(),
            ],
            required_postconditions: vec![],
            verification_mode: Some(VerificationMode::DeterministicCheck),
            aliases: vec![],
            exemplars: vec![],
        };

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

        let selection = resolve_provider_selection_state(
            &service,
            Some(&state),
            &inference,
            [0u8; 32],
            "draft an email to team@example.com",
            &entry,
            &[CapabilityId::from("mail.reply")],
            &[binding("wallet_network__mail_reply", &["mail.reply"])],
        )
        .await
        .expect("provider selection should be synthesized");

        assert_eq!(
            selection.selected_provider_family.as_deref(),
            Some("mail.wallet_network")
        );
        assert_eq!(
            selection.selected_route_label.as_deref(),
            Some("mail_connector")
        );
        assert_eq!(
            selection.selection_basis.as_deref(),
            Some("single_available")
        );
    }
}
