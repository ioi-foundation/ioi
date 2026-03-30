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
