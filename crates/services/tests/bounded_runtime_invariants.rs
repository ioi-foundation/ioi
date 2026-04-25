use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ioi_api::vm::drivers::os::{OsDriver, WindowInfo};
use ioi_api::vm::inference::{LocalSafetyModel, PiiInspection, PiiRiskSurface, SafetyVerdict};
use ioi_services::agentic::policy::PolicyEngine;
use ioi_services::agentic::rules::{ActionRules, DefaultPolicy, Rule, RuleConditions, Verdict};
use ioi_services::agentic::runtime::kernel::approval::{
    ApprovalScopeContext, AuthorityScopeMatcher,
};
use ioi_services::agentic::runtime::kernel::deadline::{with_deadline, ExecutionDeadline};
use ioi_services::agentic::runtime::kernel::evidence::{
    BrowserReceiptManifest, FilesystemReceiptManifest, ReceiptManifestKind,
};
use ioi_services::agentic::runtime::kernel::inference::{
    ModelInvocationReceipt, ModelRuntimeErrorClass,
};
use ioi_services::agentic::runtime::kernel::intervention::{
    EvidenceTier, OperatorIntervention, OperatorInterventionStatus, OperatorInterventionType,
};
use ioi_services::agentic::runtime::kernel::marketplace::{
    MarketplaceAdmissionError, MarketplaceSchemaVersion, MarketplaceServiceContract,
    MarketplaceServiceKind, REQUIRED_SCHEMA_NAMES,
};
use ioi_services::agentic::runtime::kernel::plan::{
    validate_plan, ExecutablePlan, ExecutableStep, ExecutableStepKind, PlanValidationError,
    PlanValidationStatus, RunBudget,
};
use ioi_services::agentic::runtime::kernel::profile::{
    RuntimeProfile, RuntimeProfileConfig, RuntimeProfileValidator,
};
use ioi_services::agentic::runtime::kernel::scope::{
    RuntimeScope, RuntimeScopeKind, ScopeLeaseRegistry,
};
use ioi_services::agentic::runtime::kernel::settlement::{
    ArtifactPromotionReceipt, PromotionValidationError, SettlementReceiptBundleV2,
    SettlementReceiptBundleV2Input,
};
use ioi_services::agentic::runtime::kernel::trace::SettlementTraceBundle;
use ioi_types::app::agentic::EvidenceGraph;
use ioi_types::app::{
    ActionContext, ActionRequest, ActionTarget, ApprovalAuthority, SignatureSuite,
};
use ioi_types::error::VmError;

struct NoopSafety;

#[async_trait]
impl LocalSafetyModel for NoopSafety {
    async fn classify_intent(&self, _input: &str) -> anyhow::Result<SafetyVerdict> {
        Ok(SafetyVerdict::Safe)
    }

    async fn detect_pii(&self, _input: &str) -> anyhow::Result<Vec<(usize, usize, String)>> {
        Ok(Vec::new())
    }

    async fn inspect_pii(
        &self,
        _input: &str,
        _risk_surface: PiiRiskSurface,
    ) -> anyhow::Result<PiiInspection> {
        Ok(PiiInspection {
            evidence: EvidenceGraph::default(),
            ambiguous: false,
            stage2_status: None,
        })
    }
}

struct NoopOs;

#[async_trait]
impl OsDriver for NoopOs {
    async fn get_active_window_title(&self) -> Result<Option<String>, VmError> {
        Ok(None)
    }

    async fn get_active_window_info(&self) -> Result<Option<WindowInfo>, VmError> {
        Ok(None)
    }

    async fn focus_window(&self, _title_query: &str) -> Result<bool, VmError> {
        Ok(false)
    }

    async fn set_clipboard(&self, _content: &str) -> Result<(), VmError> {
        Ok(())
    }

    async fn get_clipboard(&self) -> Result<String, VmError> {
        Ok(String::new())
    }
}

fn request(target: ActionTarget, params: serde_json::Value) -> ActionRequest {
    ActionRequest {
        target,
        params: serde_json::to_vec(&params).expect("params serialize"),
        context: ActionContext {
            agent_id: "test-agent".to_string(),
            session_id: Some([4u8; 32]),
            window_id: Some(9),
        },
        nonce: 1,
    }
}

fn authority(scopes: Vec<&str>) -> ApprovalAuthority {
    ApprovalAuthority {
        schema_version: 1,
        authority_id: [1u8; 32],
        public_key: vec![1, 2, 3],
        signature_suite: SignatureSuite::ED25519,
        expires_at: 1_000,
        revoked: false,
        scope_allowlist: scopes.into_iter().map(str::to_string).collect(),
    }
}

fn h(byte: u8) -> [u8; 32] {
    [byte; 32]
}

#[test]
fn approval_scope_rejects_out_of_scope_authority() {
    let action = request(
        ActionTarget::BrowserInteract,
        serde_json::json!({"url": "https://example.com"}),
    );
    let context = ApprovalScopeContext::from_action_request(&action)
        .with_operation_label("desktop_agent.resume");

    let decision =
        AuthorityScopeMatcher::evaluate(&authority(vec!["wallet_network.approval"]), &context);

    assert!(!decision.allowed);
    assert_eq!(
        decision.reason.as_deref(),
        Some("approval_grant_out_of_scope:target=browser::interact")
    );
}

#[test]
fn approval_scope_accepts_registered_operation_label() {
    let action = request(
        ActionTarget::BrowserInteract,
        serde_json::json!({"url": "https://example.com"}),
    );
    let context = ApprovalScopeContext::from_action_request(&action)
        .with_operation_label("desktop_agent.resume");

    let decision =
        AuthorityScopeMatcher::evaluate(&authority(vec!["desktop_agent.resume"]), &context);

    assert!(decision.allowed);
}

#[tokio::test]
async fn policy_evaluation_record_preserves_matched_rule_provenance() {
    let rules = ActionRules {
        policy_id: "test-policy".to_string(),
        defaults: DefaultPolicy::DenyAll,
        rules: vec![Rule {
            rule_id: Some("allow-web-retrieve".to_string()),
            target: "web::retrieve".to_string(),
            conditions: RuleConditions::default(),
            action: Verdict::Allow,
        }],
        ontology_policy: Default::default(),
        pii_controls: Default::default(),
    };
    let action = request(
        ActionTarget::WebRetrieve,
        serde_json::json!({"url": "https://example.com"}),
    );
    let safety: Arc<dyn LocalSafetyModel> = Arc::new(NoopSafety);
    let os: Arc<dyn OsDriver> = Arc::new(NoopOs);

    let record =
        PolicyEngine::evaluate_record_with_working_directory(&rules, &action, None, &safety, &os)
            .await;

    assert_eq!(record.verdict, Verdict::Allow);
    assert_eq!(record.matched_rule_ids, vec!["allow-web-retrieve"]);
    assert_eq!(record.default_policy_used, None);
    assert!(record.policy_hash.is_some());
}

#[tokio::test]
async fn policy_evaluation_record_marks_default_policy_when_no_rule_matches() {
    let rules = ActionRules {
        policy_id: "test-policy".to_string(),
        defaults: DefaultPolicy::RequireApproval,
        rules: Vec::new(),
        ontology_policy: Default::default(),
        pii_controls: Default::default(),
    };
    let action = request(
        ActionTarget::FsWrite,
        serde_json::json!({"path": "/tmp/out"}),
    );
    let safety: Arc<dyn LocalSafetyModel> = Arc::new(NoopSafety);
    let os: Arc<dyn OsDriver> = Arc::new(NoopOs);

    let record =
        PolicyEngine::evaluate_record_with_working_directory(&rules, &action, None, &safety, &os)
            .await;

    assert_eq!(record.verdict, Verdict::RequireApproval);
    assert_eq!(
        record.default_policy_used.as_deref(),
        Some("require_approval")
    );
    let matched = record.matched_rules_for_decision();
    assert!(matched
        .iter()
        .any(|entry| entry == "default:require_approval"));
    assert!(matched.iter().any(|entry| entry.starts_with("pii:")));
}

#[test]
fn projection_trace_receipts_are_not_settlement_receipts() {
    let bundle = SettlementTraceBundle {
        session_id: "session".to_string(),
        root_trace_id: "trace".to_string(),
        spans: Vec::new(),
        settlement_receipt_refs: Vec::new(),
        projection_event_refs: vec!["event:receipt:1".to_string()],
        missing_settlement_refs: vec!["settlement_trace_loader_not_configured".to_string()],
        artifact_refs: Vec::new(),
        approval_refs: Vec::new(),
        evidence_tiers: vec![EvidenceTier::Projection, EvidenceTier::MissingSettlement],
    };

    assert!(!bundle.is_settlement_backed());
    assert!(bundle.settlement_receipt_refs.is_empty());
    assert!(!bundle.projection_event_refs.is_empty());
    assert!(!bundle.missing_settlement_refs.is_empty());
}

#[tokio::test]
async fn execution_deadline_returns_bounded_timeout_failure() {
    let deadline = ExecutionDeadline::from_timeout_ms(1, "invariant-test");
    let result = with_deadline(&deadline, async {
        tokio::time::sleep(Duration::from_millis(20)).await;
        "completed"
    })
    .await;

    assert!(result.is_err());
    assert_eq!(
        result.err().map(|error| error.timeout_policy),
        Some("timeout_ms=1".to_string())
    );
}

#[test]
fn receipt_manifest_requires_target_specific_evidence_and_hashes_stably() {
    let missing = ReceiptManifestKind::Filesystem(FilesystemReceiptManifest {
        path: "/workspace/out.txt".to_string(),
        operation: "write".to_string(),
        before_hash: None,
        after_hash: None,
        diff_hash: None,
        workspace_scope: "/workspace".to_string(),
        postcondition: "file exists".to_string(),
    });
    assert_eq!(
        missing.missing_required_evidence(),
        vec!["before_hash_or_after_hash_or_diff_hash"]
    );

    let complete = ReceiptManifestKind::Browser(BrowserReceiptManifest {
        before_dom_hash: h(1),
        before_screenshot_hash: h(2),
        origin: "https://example.com".to_string(),
        url: "https://example.com/form".to_string(),
        selected_element_ref: "button[name=submit]".to_string(),
        action: "click".to_string(),
        after_dom_hash: h(3),
        after_screenshot_hash: h(4),
        postcondition: "confirmation visible".to_string(),
    });

    assert!(complete.is_complete());
    assert_eq!(
        complete.canonical_hash().expect("hash"),
        complete.canonical_hash().expect("hash")
    );
}

#[test]
fn settlement_bundle_v2_hash_is_verifier_stable() {
    let bundle = SettlementReceiptBundleV2::build(SettlementReceiptBundleV2Input {
        request_hash: h(1),
        committed_action_ref: h(2),
        policy_decision_ref: h(3),
        capability_lease_ref: h(4),
        approval_grant_ref: Some(h(5)),
        invocation_envelope_ref: h(6),
        observation_refs: vec![h(7)],
        postcondition_refs: vec![h(8)],
        artifact_refs: vec![h(9)],
        trace_refs: vec![h(10)],
        replay_manifest_ref: Some(h(11)),
    })
    .expect("bundle");

    assert!(bundle.verify().is_ok());
    assert_eq!(
        bundle.settlement_hash,
        bundle.compute_settlement_hash().expect("hash")
    );
}

#[test]
fn artifact_promotion_requires_validation_and_settlement_provenance() {
    let missing = ArtifactPromotionReceipt {
        artifact_id: "artifact-1".to_string(),
        artifact_hashes: vec![h(1)],
        generation_strategy: "chat_artifact".to_string(),
        candidate_refs: vec![h(2)],
        winning_candidate_ref: Some(h(2)),
        merge_receipt_refs: Vec::new(),
        validation_hash: h(3),
        render_eval_hash: Some(h(4)),
        execution_envelope_hash: h(5),
        settlement_refs: Vec::new(),
        promotion_decision: "promote".to_string(),
        promotion_reason: "validated".to_string(),
    };

    assert_eq!(
        missing.validate(),
        Err(PromotionValidationError::MissingSettlementRefs)
    );

    let mut complete = missing;
    complete.settlement_refs.push(h(6));
    assert!(complete.validate().is_ok());
    assert_eq!(
        complete.canonical_hash().expect("hash"),
        complete.canonical_hash().expect("hash")
    );
}

#[test]
fn executable_plan_rejects_invalid_dependencies_and_parallel_write_conflicts() {
    let scope = RuntimeScope::new(RuntimeScopeKind::FilesystemPath, "/workspace/src");
    let plan = ExecutablePlan {
        plan_id: "plan-1".to_string(),
        session_id: h(9),
        intent_hash: h(8),
        steps: vec![
            ExecutableStep {
                step_id: "edit-a".to_string(),
                kind: ExecutableStepKind::Tool,
                tool_or_model_ref: Some("filesystem.write".to_string()),
                typed_args: serde_json::json!({}),
                dependencies: Vec::new(),
                read_scopes: Vec::new(),
                write_scopes: vec![scope.clone()],
                required_capabilities: vec!["cap:fs:write".to_string()],
                timeout_policy: Some("timeout_ms=1000".to_string()),
                approval_requirement: None,
                expected_postconditions: vec!["diff applies".to_string()],
            },
            ExecutableStep {
                step_id: "edit-b".to_string(),
                kind: ExecutableStepKind::Tool,
                tool_or_model_ref: Some("filesystem.write".to_string()),
                typed_args: serde_json::json!({}),
                dependencies: vec!["missing-step".to_string()],
                read_scopes: Vec::new(),
                write_scopes: vec![RuntimeScope::new(
                    RuntimeScopeKind::FilesystemPath,
                    "/workspace/src/lib.rs",
                )],
                required_capabilities: vec!["cap:fs:write".to_string()],
                timeout_policy: Some("timeout_ms=1000".to_string()),
                approval_requirement: None,
                expected_postconditions: vec!["diff applies".to_string()],
            },
        ],
        dependency_graph: Vec::new(),
        scope_requirements: vec![scope],
        budget: RunBudget {
            max_steps: 2,
            max_runtime_ms: 10_000,
            max_model_tokens: 0,
        },
        policy_summary: "bounded".to_string(),
        validation_status: PlanValidationStatus::Pending,
        receipt_manifest: vec![ReceiptManifestKind::Filesystem(FilesystemReceiptManifest {
            path: "/workspace/src/lib.rs".to_string(),
            operation: "write".to_string(),
            before_hash: Some(h(1)),
            after_hash: Some(h(2)),
            diff_hash: Some(h(3)),
            workspace_scope: "/workspace".to_string(),
            postcondition: "diff applies".to_string(),
        })],
    };

    let errors = validate_plan(&plan).expect_err("plan should be invalid");
    assert!(errors.iter().any(|error| matches!(
        error,
        PlanValidationError::MissingDependency { missing_dependency, .. }
            if missing_dependency == "missing-step"
    )));
    assert!(errors.iter().any(|error| matches!(
        error,
        PlanValidationError::OverlappingIndependentWriteScope { .. }
    )));
}

#[test]
fn scope_lease_registry_rejects_overlapping_write_scopes() {
    let mut registry = ScopeLeaseRegistry::new();
    let read = registry
        .acquire_read(
            RuntimeScope::new(RuntimeScopeKind::FilesystemPath, "/workspace/src"),
            "reader",
        )
        .expect("read lease");
    let second_read = registry
        .acquire_read(
            RuntimeScope::new(RuntimeScopeKind::FilesystemPath, "/workspace/src/lib.rs"),
            "reader-2",
        )
        .expect("second read lease");

    assert_ne!(read.lease_id, second_read.lease_id);
    let conflict = registry
        .acquire_write(
            RuntimeScope::new(RuntimeScopeKind::FilesystemPath, "/workspace/src/lib.rs"),
            "writer",
        )
        .expect_err("write should conflict with active reads");

    assert_eq!(conflict.receipt.reason, "overlapping_write_scope");
}

#[test]
fn production_profile_rejects_dev_and_unconfined_capabilities() {
    let mut config = RuntimeProfileConfig::strict(RuntimeProfile::Production);
    config.browser_no_sandbox_enabled = true;
    config.dev_filesystem_mcp_enabled = true;
    config.unverified_mcp_allowed = true;
    config.unconfined_plugin_allowed = true;
    config.receipt_strictness_enabled = false;
    config.external_approval_enforced = false;

    let violations = RuntimeProfileValidator::validate(&config).expect_err("violations");
    let keys: Vec<&str> = violations.iter().map(|violation| violation.key).collect();
    assert!(keys.contains(&"browser_no_sandbox_enabled"));
    assert!(keys.contains(&"dev_filesystem_mcp_enabled"));
    assert!(keys.contains(&"unverified_mcp_allowed"));
    assert!(keys.contains(&"unconfined_plugin_allowed"));
    assert!(keys.contains(&"receipt_strictness_enabled"));
    assert!(keys.contains(&"external_approval_enforced"));
}

#[test]
fn model_runtime_error_taxonomy_uses_stable_machine_labels() {
    assert_eq!(
        ModelRuntimeErrorClass::MalformedStructuredOutput.as_str(),
        "MalformedStructuredOutput"
    );
    let receipt =
        ModelInvocationReceipt::from_output("gpt-test", "local", 42, false, br#"{"answer":true}"#)
            .expect("receipt");

    assert_eq!(receipt.model_id, "gpt-test");
    assert_eq!(receipt.provider, "local");
    assert!(receipt.error_class.is_none());
}

#[test]
fn operator_intervention_does_not_imply_authority_from_projection_state() {
    let intervention = OperatorIntervention {
        intervention_id: "int-1".to_string(),
        session_id: "session-1".to_string(),
        intervention_type: OperatorInterventionType::ApprovalRequired,
        authority_required: "external_grant".to_string(),
        request_hash: Some(h(1)),
        policy_hash: Some(h(2)),
        status: OperatorInterventionStatus::Resolved,
        deadline_at_ms: 10_000,
        resolution_options: vec!["import_grant".to_string()],
        evidence_tier: EvidenceTier::Projection,
    };

    assert_eq!(intervention.evidence_tier.label(), "Projection");
    assert!(!intervention.implies_authority());
}

#[test]
fn marketplace_contract_requires_versioned_authority_and_evidence_schemas() {
    let incomplete = MarketplaceServiceContract {
        service_id: "connector.example".to_string(),
        kind: MarketplaceServiceKind::Connector,
        schema_versions: Vec::new(),
        declared_capabilities: vec!["cap:connector:read".to_string()],
        declared_scopes: vec!["connector:example".to_string()],
        deadline_policies: vec!["timeout_ms=1000".to_string()],
        evidence_manifests: vec!["connector".to_string()],
        admission_profile: "marketplace".to_string(),
    };
    assert_eq!(
        incomplete.validate(),
        Err(MarketplaceAdmissionError::MissingSchemaVersion("tool"))
    );

    let complete = MarketplaceServiceContract {
        schema_versions: REQUIRED_SCHEMA_NAMES
            .iter()
            .map(|name| MarketplaceSchemaVersion {
                schema_name: (*name).to_string(),
                version: 1,
            })
            .collect(),
        ..incomplete
    };

    assert!(complete.validate().is_ok());
}
