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
    ExecutionApplicabilityClass, IntentCatalogEntry, IntentQueryBindingClass, IntentScopeProfile,
    ProviderSelectionMode, VerificationMode,
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

    let entry = IntentCatalogEntry {
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
        required_evidence: vec![
            "provider_selection".to_string(),
            "provider_selection_commit".to_string(),
            "execution".to_string(),
            "verification".to_string(),
        ],
        success_conditions: vec![],
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
