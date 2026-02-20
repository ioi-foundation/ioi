// Unit tests (moved out of lib.rs)

use super::{
    apply_transform, build_assist_receipt, check_exception_usage_increment_ok,
    decode_exception_usage_state, expected_assist_identity, graph_hash,
    mint_default_scoped_exception, route_pii_decision_for_target,
    route_pii_decision_with_assist_for_target, scrub_text, validate_resume_review_contract,
    validate_review_request_compat, verify_scoped_exception_for_decision, CimAssistContext,
    CimAssistProvider, CimAssistReceipt, CimAssistResult, CimAssistV0Provider,
    NoopCimAssistProvider, PiiReviewContractError, PiiRoutingOutcome, ResumeReviewMode,
    RiskSurface, ScopedExceptionVerifyError, REVIEW_REQUEST_VERSION,
};
use ioi_types::app::action::{ApprovalScope, ApprovalToken, PiiApprovalAction};
use ioi_types::app::agentic::{
    EvidenceGraph, EvidenceSpan, FirewallDecision, PiiClass, PiiConfidenceBucket, PiiControls,
    PiiDecisionMaterial, PiiReviewRequest, PiiReviewSummary, PiiSeverity, PiiTarget,
    RawOverrideMode,
};
use ioi_types::app::ActionTarget;

#[derive(Debug, Clone, Copy)]
struct IdentityProvider {
    kind: &'static str,
    version: &'static str,
    config_hash: [u8; 32],
    module_hash: [u8; 32],
}

impl CimAssistProvider for IdentityProvider {
    fn assist_kind(&self) -> &str {
        self.kind
    }

    fn assist_version(&self) -> &str {
        self.version
    }

    fn assist_config_hash(&self) -> [u8; 32] {
        self.config_hash
    }

    fn assist_module_hash(&self) -> [u8; 32] {
        self.module_hash
    }

    fn assist(
        &self,
        graph: &EvidenceGraph,
        _ctx: &CimAssistContext<'_>,
    ) -> anyhow::Result<CimAssistResult> {
        Ok(CimAssistResult {
            output_graph: graph.clone(),
            assist_applied: false,
        })
    }
}

#[test]
fn noop_assist_provider_is_invoked_not_applied_and_hashes_are_deterministic() {
    let graph = EvidenceGraph::default();
    let policy = PiiControls::default();
    let provider = NoopCimAssistProvider;
    let target = PiiTarget::Action(ActionTarget::ClipboardWrite);
    let ctx = CimAssistContext {
        target: &target,
        risk_surface: RiskSurface::Egress,
        policy: &policy,
        supports_transform: true,
    };

    let result = provider.assist(&graph, &ctx).expect("assist");
    assert_eq!(result.output_graph, graph);
    assert!(!result.assist_applied);

    let receipt = build_assist_receipt(
        &provider,
        &graph,
        &result.output_graph,
        result.assist_applied,
    );
    assert!(receipt.assist_invoked);
    assert!(!receipt.assist_applied);
    assert_eq!(receipt.assist_kind, "noop");
    assert_eq!(receipt.assist_version, "noop-v1");
    assert_eq!(receipt.assist_input_graph_hash, graph_hash(&graph));
    assert_eq!(receipt.assist_output_graph_hash, graph_hash(&graph));

    let mut changed_graph = graph.clone();
    changed_graph.source_hash = [1u8; 32];
    assert_ne!(graph_hash(&graph), graph_hash(&changed_graph));
}

#[test]
fn decision_hash_is_deterministic_for_same_material() {
    let graph = EvidenceGraph::default();
    let target = PiiTarget::Action(ActionTarget::ClipboardWrite);
    let a = route_pii_decision_for_target(
        &graph,
        &PiiControls::default(),
        RiskSurface::Egress,
        &target,
        true,
    );
    let b = route_pii_decision_for_target(
        &graph,
        &PiiControls::default(),
        RiskSurface::Egress,
        &target,
        true,
    );
    assert_eq!(a.decision_hash, b.decision_hash);
}

#[test]
fn decision_hash_changes_when_assist_identity_changes() {
    let graph = EvidenceGraph::default();
    let policy = PiiControls::default();
    let target = PiiTarget::Action(ActionTarget::ClipboardWrite);
    let ctx = CimAssistContext {
        target: &target,
        risk_surface: RiskSurface::Egress,
        policy: &policy,
        supports_transform: true,
    };

    let provider_a = IdentityProvider {
        kind: "noop",
        version: "noop-v1",
        config_hash: [0u8; 32],
        module_hash: [0u8; 32],
    };
    let provider_b = IdentityProvider {
        kind: "cim_wasm",
        version: "cim-wasm-v0.1",
        config_hash: [0u8; 32],
        module_hash: [0u8; 32],
    };

    let result_a = provider_a.assist(&graph, &ctx).expect("assist a");
    let assist_a = build_assist_receipt(
        &provider_a,
        &graph,
        &result_a.output_graph,
        result_a.assist_applied,
    );
    let routed_a = route_pii_decision_with_assist_for_target(
        &graph,
        &policy,
        RiskSurface::Egress,
        &target,
        true,
        &assist_a,
    );

    let result_b = provider_b.assist(&graph, &ctx).expect("assist b");
    let assist_b = build_assist_receipt(
        &provider_b,
        &graph,
        &result_b.output_graph,
        result_b.assist_applied,
    );
    let routed_b = route_pii_decision_with_assist_for_target(
        &graph,
        &policy,
        RiskSurface::Egress,
        &target,
        true,
        &assist_b,
    );

    assert_eq!(routed_a.decision, routed_b.decision);
    assert_ne!(routed_a.decision_hash, routed_b.decision_hash);
}

#[test]
fn decision_hash_changes_when_supports_transform_toggles() {
    let graph = EvidenceGraph::default();
    let policy = PiiControls::default();
    let target = PiiTarget::Action(ActionTarget::ClipboardWrite);
    let with_transform =
        route_pii_decision_for_target(&graph, &policy, RiskSurface::Egress, &target, true);
    let without_transform =
        route_pii_decision_for_target(&graph, &policy, RiskSurface::Egress, &target, false);

    assert_eq!(with_transform.decision, without_transform.decision);
    assert_ne!(
        with_transform.decision_hash,
        without_transform.decision_hash
    );
}

#[test]
fn assist_identity_hash_changes_with_config_or_module_hash() {
    let graph = EvidenceGraph::default();
    let base = IdentityProvider {
        kind: "cim_wasm",
        version: "cim-wasm-v0.2",
        config_hash: [1u8; 32],
        module_hash: [2u8; 32],
    };
    let config_changed = IdentityProvider {
        config_hash: [3u8; 32],
        ..base
    };
    let module_changed = IdentityProvider {
        module_hash: [4u8; 32],
        ..base
    };

    let a = build_assist_receipt(&base, &graph, &graph, false);
    let b = build_assist_receipt(&config_changed, &graph, &graph, false);
    let c = build_assist_receipt(&module_changed, &graph, &graph, false);

    assert_ne!(a.assist_identity_hash, b.assist_identity_hash);
    assert_ne!(a.assist_identity_hash, c.assist_identity_hash);
}

#[test]
fn secret_egress_never_returns_allow() {
    let graph = EvidenceGraph {
        version: 1,
        source_hash: [1u8; 32],
        ambiguous: false,
        spans: vec![EvidenceSpan {
            start_index: 0,
            end_index: 10,
            pii_class: PiiClass::ApiKey,
            severity: PiiSeverity::High,
            confidence_bucket: PiiConfidenceBucket::High,
            pattern_id: "test/api_key".to_string(),
            validator_passed: true,
            context_keywords: vec![],
            evidence_source: "test".to_string(),
        }],
    };
    let policy = PiiControls::default();
    let target = PiiTarget::Action(ActionTarget::ClipboardWrite);

    let with_transform =
        route_pii_decision_for_target(&graph, &policy, RiskSurface::Egress, &target, true);
    let without_transform =
        route_pii_decision_for_target(&graph, &policy, RiskSurface::Egress, &target, false);

    assert!(!matches!(with_transform.decision, FirewallDecision::Allow));
    assert!(!matches!(
        without_transform.decision,
        FirewallDecision::Allow
    ));
}

#[test]
fn canonical_placeholder_labels_are_used() {
    let input = "send sk_live_abcd1234abcd1234 to john@example.com";
    let detections = vec![
        (5usize, 28usize, "API_KEY".to_string()),
        (32usize, 48usize, "EMAIL".to_string()),
    ];
    let (scrubbed, _) = scrub_text(input, &detections).expect("scrub");
    assert!(scrubbed.contains("<REDACTED:api_key>"));
    assert!(scrubbed.contains("<REDACTED:email>"));
}

#[test]
fn invalid_span_boundaries_do_not_panic_and_fail_leak_check() {
    let graph = EvidenceGraph {
        version: 1,
        source_hash: [0u8; 32],
        ambiguous: false,
        spans: vec![EvidenceSpan {
            start_index: 1,
            end_index: 2,
            pii_class: PiiClass::ApiKey,
            severity: PiiSeverity::High,
            confidence_bucket: PiiConfidenceBucket::High,
            pattern_id: "test".to_string(),
            validator_passed: true,
            context_keywords: vec![],
            evidence_source: "test".to_string(),
        }],
    };

    let outcome = PiiRoutingOutcome {
        decision: FirewallDecision::RedactThenAllow,
        transform_plan: None,
        stage2_decision: None,
        assist: CimAssistReceipt {
            assist_invoked: false,
            assist_applied: false,
            assist_kind: "test".to_string(),
            assist_version: "test-v1".to_string(),
            assist_identity_hash: [0u8; 32],
            assist_config_hash: [0u8; 32],
            assist_module_hash: [0u8; 32],
            assist_input_graph_hash: [0u8; 32],
            assist_output_graph_hash: [0u8; 32],
        },
        decision_hash: [0u8; 32],
    };

    let (_scrubbed, _map, report) = apply_transform("🔥secret", &graph, &outcome).expect("apply");
    assert!(!report.no_raw_substring_leak);
    assert_eq!(report.unresolved_spans, 1);
}

#[test]
fn overlapping_spans_redact_without_false_unresolved_failures() {
    let input = "token: sk_live_abcd1234abcd1234";
    let secret_start = input.find("sk_live_").expect("secret start");
    let secret_end = secret_start + "sk_live_abcd1234abcd1234".len();
    let token_start = input.find("token:").expect("token start");

    let graph = EvidenceGraph {
        version: 1,
        source_hash: [0u8; 32],
        ambiguous: false,
        spans: vec![
            EvidenceSpan {
                start_index: token_start as u32,
                end_index: secret_end as u32,
                pii_class: PiiClass::SecretToken,
                severity: PiiSeverity::High,
                confidence_bucket: PiiConfidenceBucket::High,
                pattern_id: "test/secret_token".to_string(),
                validator_passed: true,
                context_keywords: vec![],
                evidence_source: "test".to_string(),
            },
            EvidenceSpan {
                start_index: secret_start as u32,
                end_index: secret_end as u32,
                pii_class: PiiClass::ApiKey,
                severity: PiiSeverity::High,
                confidence_bucket: PiiConfidenceBucket::High,
                pattern_id: "test/api_key".to_string(),
                validator_passed: true,
                context_keywords: vec![],
                evidence_source: "test".to_string(),
            },
        ],
    };

    let outcome = PiiRoutingOutcome {
        decision: FirewallDecision::RedactThenAllow,
        transform_plan: None,
        stage2_decision: None,
        assist: CimAssistReceipt {
            assist_invoked: false,
            assist_applied: false,
            assist_kind: "test".to_string(),
            assist_version: "test-v1".to_string(),
            assist_identity_hash: [0u8; 32],
            assist_config_hash: [0u8; 32],
            assist_module_hash: [0u8; 32],
            assist_input_graph_hash: [0u8; 32],
            assist_output_graph_hash: [0u8; 32],
        },
        decision_hash: [0u8; 32],
    };

    let (scrubbed, _map, report) = apply_transform(input, &graph, &outcome).expect("apply");
    assert!(!scrubbed.contains("sk_live_abcd1234abcd1234"));
    assert!(!scrubbed.contains("token: sk_live_abcd1234abcd1234"));
    assert!(report.no_raw_substring_leak);
    assert_eq!(report.unresolved_spans, 0);
    assert_eq!(report.remaining_span_count, 0);
}

fn low_severity_email_graph() -> EvidenceGraph {
    EvidenceGraph {
        version: 1,
        source_hash: [7u8; 32],
        ambiguous: false,
        spans: vec![EvidenceSpan {
            start_index: 0,
            end_index: 16,
            pii_class: PiiClass::Email,
            severity: PiiSeverity::Low,
            confidence_bucket: PiiConfidenceBucket::High,
            pattern_id: "email/test".to_string(),
            validator_passed: true,
            context_keywords: vec![],
            evidence_source: "test".to_string(),
        }],
    }
}

#[test]
fn scoped_exception_verifier_rejects_class_mismatch() {
    let graph = low_severity_email_graph();
    let target = PiiTarget::Action(ActionTarget::ClipboardWrite);
    let decision_hash = [9u8; 32];
    let mut policy = PiiControls::default();
    policy.raw_override_mode = RawOverrideMode::ScopedLowSeverityOnly;
    let mut exception = mint_default_scoped_exception(
        &graph,
        &target,
        RiskSurface::Egress,
        decision_hash,
        1_000,
        "test",
    )
    .expect("mint");
    exception.allowed_classes = vec![PiiClass::Phone];

    let result = verify_scoped_exception_for_decision(
        &exception,
        &graph,
        &target,
        RiskSurface::Egress,
        decision_hash,
        &policy,
        1_001,
        0,
    );
    assert_eq!(result, Err(ScopedExceptionVerifyError::ClassMismatch));
}

#[test]
fn scoped_exception_verifier_rejects_expired_and_overused_and_binding_mismatch() {
    let graph = low_severity_email_graph();
    let target = PiiTarget::Action(ActionTarget::ClipboardWrite);
    let decision_hash = [11u8; 32];
    let mut policy = PiiControls::default();
    policy.raw_override_mode = RawOverrideMode::ScopedLowSeverityOnly;
    let exception = mint_default_scoped_exception(
        &graph,
        &target,
        RiskSurface::Egress,
        decision_hash,
        2_000,
        "test",
    )
    .expect("mint");

    let expired = verify_scoped_exception_for_decision(
        &exception,
        &graph,
        &target,
        RiskSurface::Egress,
        decision_hash,
        &policy,
        exception.expires_at,
        0,
    );
    assert_eq!(expired, Err(ScopedExceptionVerifyError::Expired));

    let overused = verify_scoped_exception_for_decision(
        &exception,
        &graph,
        &target,
        RiskSurface::Egress,
        decision_hash,
        &policy,
        2_100,
        1,
    );
    assert_eq!(overused, Err(ScopedExceptionVerifyError::Overused));

    let wrong_target = PiiTarget::Action(ActionTarget::NetFetch);
    let binding_mismatch = verify_scoped_exception_for_decision(
        &exception,
        &graph,
        &wrong_target,
        RiskSurface::Egress,
        decision_hash,
        &policy,
        2_100,
        0,
    );
    assert_eq!(
        binding_mismatch,
        Err(ScopedExceptionVerifyError::DestinationMismatch)
    );
}

fn sample_approval_token(
    request_hash: [u8; 32],
    pii_action: Option<PiiApprovalAction>,
) -> ApprovalToken {
    ApprovalToken {
        schema_version: 2,
        request_hash,
        audience: [1u8; 32],
        revocation_epoch: 0,
        nonce: [2u8; 32],
        counter: 1,
        scope: ApprovalScope {
            expires_at: 9_999,
            max_usages: Some(1),
        },
        visual_hash: None,
        pii_action,
        scoped_exception: None,
        approver_sig: vec![],
        approver_suite: ioi_types::app::SignatureSuite::ED25519,
    }
}

fn sample_review_request(hash: [u8; 32], deadline_ms: u64) -> PiiReviewRequest {
    let (assist_kind, assist_version, assist_identity_hash) = expected_assist_identity();
    PiiReviewRequest {
        request_version: REVIEW_REQUEST_VERSION,
        decision_hash: hash,
        material: PiiDecisionMaterial {
            version: 3,
            target: PiiTarget::Action(ActionTarget::ClipboardWrite),
            risk_surface: "egress".to_string(),
            supports_transform: true,
            source_hash: [1u8; 32],
            span_count: 1,
            ambiguous: false,
            decision: FirewallDecision::RequireUserReview,
            transform_plan_id: None,
            stage2_kind: Some("request_more_info".to_string()),
            assist_invoked: true,
            assist_applied: false,
            assist_kind,
            assist_version,
            assist_identity_hash,
            assist_input_graph_hash: [0u8; 32],
            assist_output_graph_hash: [0u8; 32],
        },
        summary: PiiReviewSummary {
            target_label: "clipboard::write".to_string(),
            span_summary: "spans=1".to_string(),
            class_counts: std::collections::BTreeMap::new(),
            severity_counts: std::collections::BTreeMap::new(),
            stage2_prompt: "Review".to_string(),
        },
        session_id: Some([2u8; 32]),
        created_at_ms: 100,
        deadline_ms,
    }
}

#[test]
fn resume_contract_rejects_hash_mismatch() {
    let expected_hash = [7u8; 32];
    let token = sample_approval_token([8u8; 32], Some(PiiApprovalAction::Deny));
    let request = sample_review_request(expected_hash, 10_000);

    let result = validate_resume_review_contract(expected_hash, &token, Some(&request), 9_000);
    assert_eq!(
        result,
        Err(PiiReviewContractError::ApprovalTokenHashMismatch)
    );
}

#[test]
fn resume_contract_rejects_missing_request_when_pii_action_present() {
    let expected_hash = [9u8; 32];
    let token = sample_approval_token(expected_hash, Some(PiiApprovalAction::ApproveTransform));
    let result = validate_resume_review_contract(expected_hash, &token, None, 500);
    assert_eq!(
        result,
        Err(PiiReviewContractError::PiiActionWithoutReviewRequest)
    );
}

#[test]
fn resume_contract_accepts_deny_without_review_request() {
    let expected_hash = [9u8; 32];
    let token = sample_approval_token(expected_hash, Some(PiiApprovalAction::Deny));
    let result = validate_resume_review_contract(expected_hash, &token, None, 500)
        .expect("deny should be allowed without a review request");
    assert_eq!(result, ResumeReviewMode::LegacyApproval);
}

#[test]
fn resume_contract_rejects_missing_pii_action_for_review_request() {
    let expected_hash = [10u8; 32];
    let token = sample_approval_token(expected_hash, None);
    let request = sample_review_request(expected_hash, 10_000);

    let result = validate_resume_review_contract(expected_hash, &token, Some(&request), 9_000);
    assert_eq!(
        result,
        Err(PiiReviewContractError::MissingPiiActionForReview)
    );
}

#[test]
fn resume_contract_rejects_expired_deadline() {
    let expected_hash = [11u8; 32];
    let token = sample_approval_token(expected_hash, Some(PiiApprovalAction::Deny));
    let request = sample_review_request(expected_hash, 1_000);

    let result = validate_resume_review_contract(expected_hash, &token, Some(&request), 1_001);
    assert_eq!(
        result,
        Err(PiiReviewContractError::ReviewApprovalDeadlineExceeded)
    );
}

#[test]
fn resume_contract_accepts_review_bound_token_at_deadline_boundary() {
    let expected_hash = [12u8; 32];
    let token = sample_approval_token(expected_hash, Some(PiiApprovalAction::Deny));
    let request = sample_review_request(expected_hash, 1_000);

    let result = validate_resume_review_contract(expected_hash, &token, Some(&request), 1_000)
        .expect("boundary deadline should be valid");
    assert_eq!(result, ResumeReviewMode::ReviewBound);
}

#[test]
fn review_request_compat_rejects_v2() {
    let mut request = sample_review_request([13u8; 32], 5_000);
    request.request_version = 2;
    let result = validate_review_request_compat(&request);
    assert_eq!(
        result,
        Err(PiiReviewContractError::UnsupportedReviewRequestVersion {
            found: 2,
            expected: REVIEW_REQUEST_VERSION,
        })
    );
}

#[test]
fn review_request_compat_rejects_wrong_assist_identity() {
    let mut request = sample_review_request([14u8; 32], 5_000);
    request.material.assist_identity_hash = [0xAB; 32];
    let result = validate_review_request_compat(&request);
    assert!(matches!(
        result,
        Err(PiiReviewContractError::AssistIdentityHashMismatch { .. })
    ));
}

#[test]
fn review_request_compat_accepts_expected_cim_identity() {
    let request = sample_review_request([15u8; 32], 5_000);
    validate_review_request_compat(&request).expect("expected v3+cim request to be valid");
}
fn cim_severity_rank(severity: PiiSeverity) -> u8 {
    match severity {
        PiiSeverity::Low => 0,
        PiiSeverity::Medium => 1,
        PiiSeverity::High => 2,
        PiiSeverity::Critical => 3,
    }
}
fn cim_confidence_rank(confidence: PiiConfidenceBucket) -> u8 {
    match confidence {
        PiiConfidenceBucket::Low => 0,
        PiiConfidenceBucket::Medium => 1,
        PiiConfidenceBucket::High => 2,
    }
}
fn cim_sample_ambiguous_graph() -> EvidenceGraph {
    EvidenceGraph {
        version: 1,
        source_hash: [0xA5; 32],
        ambiguous: true,
        spans: vec![
            EvidenceSpan {
                start_index: 0,
                end_index: 16,
                pii_class: PiiClass::CardPan,
                severity: PiiSeverity::High,
                confidence_bucket: PiiConfidenceBucket::Medium,
                pattern_id: "card_pan/heuristic".to_string(),
                validator_passed: false,
                context_keywords: vec!["tracking".to_string(), "invoice".to_string()],
                evidence_source: "regex".to_string(),
            },
            EvidenceSpan {
                start_index: 20,
                end_index: 32,
                pii_class: PiiClass::Phone,
                severity: PiiSeverity::Low,
                confidence_bucket: PiiConfidenceBucket::Medium,
                pattern_id: "phone/heuristic".to_string(),
                validator_passed: false,
                context_keywords: vec!["order id".to_string()],
                evidence_source: "regex".to_string(),
            },
            EvidenceSpan {
                start_index: 36,
                end_index: 48,
                pii_class: PiiClass::Custom("order_code".to_string()),
                severity: PiiSeverity::Medium,
                confidence_bucket: PiiConfidenceBucket::Low,
                pattern_id: "custom/ambiguous".to_string(),
                validator_passed: false,
                context_keywords: vec!["tracking".to_string()],
                evidence_source: "heuristic".to_string(),
            },
        ],
    }
}
#[test]
fn cim_v0_is_deterministic_and_decision_hash_stable() {
    let graph = cim_sample_ambiguous_graph();
    let policy = PiiControls::default();
    let target = PiiTarget::Action(ActionTarget::ClipboardWrite);
    let provider = CimAssistV0Provider::default();
    let ctx = CimAssistContext {
        target: &target,
        risk_surface: RiskSurface::Egress,
        policy: &policy,
        supports_transform: true,
    };

    let run_a = provider.assist(&graph, &ctx).expect("assist a");
    let run_b = provider.assist(&graph, &ctx).expect("assist b");
    assert_eq!(run_a.output_graph, run_b.output_graph);
    assert_eq!(run_a.assist_applied, run_b.assist_applied);

    let assist_a =
        build_assist_receipt(&provider, &graph, &run_a.output_graph, run_a.assist_applied);
    let assist_b =
        build_assist_receipt(&provider, &graph, &run_b.output_graph, run_b.assist_applied);
    let routed_a = route_pii_decision_with_assist_for_target(
        &run_a.output_graph,
        &policy,
        RiskSurface::Egress,
        &target,
        true,
        &assist_a,
    );
    let routed_b = route_pii_decision_with_assist_for_target(
        &run_b.output_graph,
        &policy,
        RiskSurface::Egress,
        &target,
        true,
        &assist_b,
    );
    assert_eq!(routed_a.decision_hash, routed_b.decision_hash);
}
#[test]
fn cim_v0_preserves_source_and_never_escalates_spans() {
    let graph = cim_sample_ambiguous_graph();
    let policy = PiiControls::default();
    let target = PiiTarget::Action(ActionTarget::ClipboardWrite);
    let provider = CimAssistV0Provider::default();
    let ctx = CimAssistContext {
        target: &target,
        risk_surface: RiskSurface::Egress,
        policy: &policy,
        supports_transform: true,
    };

    let refined = provider.assist(&graph, &ctx).expect("assist");
    assert_eq!(refined.output_graph.source_hash, graph.source_hash);
    assert!(refined.output_graph.spans.len() <= graph.spans.len());

    for out_span in &refined.output_graph.spans {
        let matching_input = graph
            .spans
            .iter()
            .find(|input| {
                input.start_index == out_span.start_index
                    && input.end_index == out_span.end_index
                    && input.pii_class == out_span.pii_class
                    && input.severity == out_span.severity
                    && input.pattern_id == out_span.pattern_id
                    && input.evidence_source == out_span.evidence_source
            })
            .expect("output span must map to an input span");
        assert!(
            cim_confidence_rank(out_span.confidence_bucket)
                <= cim_confidence_rank(matching_input.confidence_bucket),
            "provider must not increase confidence"
        );
        assert!(
            cim_severity_rank(out_span.severity) <= cim_severity_rank(matching_input.severity),
            "provider must not increase severity"
        );
    }
}
#[test]
fn cim_v0_resolves_ambiguous_card_phone_and_custom_cases() {
    let graph = cim_sample_ambiguous_graph();
    let policy = PiiControls::default();
    let target = PiiTarget::Action(ActionTarget::ClipboardWrite);
    let provider = CimAssistV0Provider::default();
    let ctx = CimAssistContext {
        target: &target,
        risk_surface: RiskSurface::Egress,
        policy: &policy,
        supports_transform: true,
    };

    let refined = provider.assist(&graph, &ctx).expect("assist");
    assert!(refined.assist_applied);
    assert!(!refined.output_graph.ambiguous);
    assert!(
        refined.output_graph.spans.is_empty(),
        "v0 ambiguity samples should be dropped deterministically"
    );
}
#[test]
fn cim_v0_identity_changes_decision_hash_vs_noop() {
    let graph = cim_sample_ambiguous_graph();
    let policy = PiiControls::default();
    let target = PiiTarget::Action(ActionTarget::ClipboardWrite);

    let noop = NoopCimAssistProvider;
    let noop_result = noop
        .assist(
            &graph,
            &CimAssistContext {
                target: &target,
                risk_surface: RiskSurface::Egress,
                policy: &policy,
                supports_transform: true,
            },
        )
        .expect("noop assist");
    let noop_receipt = build_assist_receipt(
        &noop,
        &graph,
        &noop_result.output_graph,
        noop_result.assist_applied,
    );
    let noop_routed = route_pii_decision_with_assist_for_target(
        &noop_result.output_graph,
        &policy,
        RiskSurface::Egress,
        &target,
        true,
        &noop_receipt,
    );

    let cim = CimAssistV0Provider::default();
    let cim_result = cim
        .assist(
            &graph,
            &CimAssistContext {
                target: &target,
                risk_surface: RiskSurface::Egress,
                policy: &policy,
                supports_transform: true,
            },
        )
        .expect("cim assist");
    let cim_receipt = build_assist_receipt(
        &cim,
        &graph,
        &cim_result.output_graph,
        cim_result.assist_applied,
    );
    let cim_routed = route_pii_decision_with_assist_for_target(
        &cim_result.output_graph,
        &policy,
        RiskSurface::Egress,
        &target,
        true,
        &cim_receipt,
    );

    assert_ne!(noop_routed.decision_hash, cim_routed.decision_hash);
}

#[test]
fn usage_counter_decode_and_increment_fail_closed() {
    let invalid = decode_exception_usage_state(Some(&[0xFF, 0x00]));
    assert_eq!(
        invalid,
        Err(PiiReviewContractError::InvalidExceptionUsageState)
    );

    let overflow = check_exception_usage_increment_ok(u32::MAX);
    assert_eq!(
        overflow,
        Err(PiiReviewContractError::ExceptionUsageOverflow)
    );
}
