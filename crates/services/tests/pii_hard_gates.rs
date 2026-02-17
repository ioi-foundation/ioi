// Path: crates/services/tests/pii_hard_gates.rs

use anyhow::Result;
use async_trait::async_trait;
use ioi_api::state::service_namespace_prefix;
use ioi_api::vm::drivers::os::{OsDriver, WindowInfo};
use ioi_api::vm::inference::{
    InferenceRuntime, LocalSafetyModel, PiiInspection, PiiRiskSurface, SafetyVerdict,
};
use ioi_pii::{
    apply_transform, build_decision_material, build_review_summary, mint_default_scoped_exception,
    route_pii_decision_for_target, verify_scoped_exception_for_decision, CimAssistReceipt,
    PiiRoutingOutcome, RiskSurface, ScopedExceptionVerifyError, REVIEW_REQUEST_VERSION,
};
use ioi_services::agentic::desktop::cloud_airlock::execute_cloud_inference;
use ioi_services::agentic::desktop::keys::pii::review::request as review_request_key;
use ioi_services::agentic::pii_scrubber::PiiScrubber;
use ioi_services::agentic::policy::PolicyEngine;
use ioi_services::agentic::rules::{ActionRules, DefaultPolicy, Verdict};
use ioi_types::app::agentic::{
    EvidenceGraph, EvidenceSpan, FirewallDecision, InferenceOptions, PiiClass, PiiConfidenceBucket,
    PiiControls, PiiReviewRequest, PiiSeverity, PiiTarget, RawOverrideMode,
};
use ioi_types::app::{ActionContext, ActionRequest, ActionTarget};
use ioi_types::codec;
use ioi_types::error::VmError;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;

struct DummyOs;

#[async_trait]
impl OsDriver for DummyOs {
    async fn get_active_window_title(&self) -> Result<Option<String>, VmError> {
        Ok(Some("Test Window".to_string()))
    }

    async fn get_active_window_info(&self) -> Result<Option<WindowInfo>, VmError> {
        Ok(Some(WindowInfo {
            title: "Test Window".to_string(),
            x: 0,
            y: 0,
            width: 800,
            height: 600,
            app_name: "test".to_string(),
        }))
    }

    async fn focus_window(&self, _title_query: &str) -> Result<bool, VmError> {
        Ok(true)
    }

    async fn set_clipboard(&self, _content: &str) -> Result<(), VmError> {
        Ok(())
    }

    async fn get_clipboard(&self) -> Result<String, VmError> {
        Ok(String::new())
    }
}

struct DummySafety;

#[async_trait]
impl LocalSafetyModel for DummySafety {
    async fn classify_intent(&self, _input: &str) -> anyhow::Result<SafetyVerdict> {
        Ok(SafetyVerdict::Safe)
    }

    async fn detect_pii(&self, _input: &str) -> anyhow::Result<Vec<(usize, usize, String)>> {
        Ok(vec![])
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

struct SubstrateSafety;

#[async_trait]
impl LocalSafetyModel for SubstrateSafety {
    async fn classify_intent(&self, _input: &str) -> anyhow::Result<SafetyVerdict> {
        Ok(SafetyVerdict::Safe)
    }

    async fn detect_pii(&self, input: &str) -> anyhow::Result<Vec<(usize, usize, String)>> {
        let graph = ioi_services::agentic::pii_substrate::build_evidence_graph(input)?;
        Ok(ioi_services::agentic::pii_substrate::to_legacy_detections(
            &graph,
        ))
    }

    async fn inspect_pii(
        &self,
        input: &str,
        _risk_surface: PiiRiskSurface,
    ) -> anyhow::Result<PiiInspection> {
        let graph = ioi_services::agentic::pii_substrate::build_evidence_graph(input)?;
        Ok(PiiInspection {
            ambiguous: graph.ambiguous,
            evidence: graph,
            stage2_status: None,
        })
    }
}

#[derive(Default)]
struct RecordingRuntime {
    last_input: Arc<Mutex<Vec<u8>>>,
}

#[async_trait]
impl InferenceRuntime for RecordingRuntime {
    async fn execute_inference(
        &self,
        _: [u8; 32],
        input: &[u8],
        _: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        if let Ok(mut guard) = self.last_input.lock() {
            *guard = input.to_vec();
        }
        Ok(br#"{"ok":true}"#.to_vec())
    }

    async fn load_model(&self, _: [u8; 32], _: &Path) -> Result<(), VmError> {
        Ok(())
    }

    async fn unload_model(&self, _: [u8; 32]) -> Result<(), VmError> {
        Ok(())
    }
}

fn sample_high_graph() -> EvidenceGraph {
    EvidenceGraph {
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
            context_keywords: vec!["api key".to_string()],
            evidence_source: "test".to_string(),
        }],
    }
}

fn sample_low_email_graph(input: &str) -> EvidenceGraph {
    let email_start = input.find("john@example.com").expect("email start") as u32;
    let email_end = email_start + "john@example.com".len() as u32;

    EvidenceGraph {
        version: 1,
        source_hash: [3u8; 32],
        ambiguous: false,
        spans: vec![EvidenceSpan {
            start_index: email_start,
            end_index: email_end,
            pii_class: PiiClass::Email,
            severity: PiiSeverity::Low,
            confidence_bucket: PiiConfidenceBucket::High,
            pattern_id: "test/email".to_string(),
            validator_passed: true,
            context_keywords: vec!["email".to_string()],
            evidence_source: "test".to_string(),
        }],
    }
}

#[test]
fn hard_gate_high_severity_raw_egress_denied_and_hash_deterministic() {
    let graph = sample_high_graph();
    let policy = PiiControls::default();
    let target = PiiTarget::Action(ActionTarget::NetFetch);

    let a = ioi_pii::route_pii_decision_for_target(
        &graph,
        &policy,
        RiskSurface::Egress,
        &target,
        false,
    );
    let b = ioi_pii::route_pii_decision_for_target(
        &graph,
        &policy,
        RiskSurface::Egress,
        &target,
        false,
    );

    assert!(matches!(a.decision, FirewallDecision::Deny));
    assert_eq!(a.decision_hash, b.decision_hash);
    assert_ne!(a.decision_hash, [0u8; 32]);
    assert!(a.assist.assist_invoked);
    assert!(!a.assist.assist_applied);
    assert_eq!(a.assist.assist_kind, "cim_v0");
    assert_eq!(a.assist.assist_version, "cim-v0.1");
    assert_ne!(a.assist.assist_identity_hash, [0u8; 32]);
}

#[test]
fn hard_gate_secret_egress_never_allows_raw_payload() {
    let graph = sample_high_graph();
    let policy = PiiControls::default();
    let target = PiiTarget::Action(ActionTarget::ClipboardWrite);

    let with_transform =
        ioi_pii::route_pii_decision_for_target(&graph, &policy, RiskSurface::Egress, &target, true);
    let without_transform = ioi_pii::route_pii_decision_for_target(
        &graph,
        &policy,
        RiskSurface::Egress,
        &target,
        false,
    );

    assert!(!matches!(with_transform.decision, FirewallDecision::Allow));
    assert!(!matches!(
        without_transform.decision,
        FirewallDecision::Allow
    ));
}

#[test]
fn hard_gate_transform_has_no_raw_leak_report() {
    let input = "copy sk_live_abcd1234abcd1234 and john@example.com";
    let key_start = input.find("sk_live_").expect("key start") as u32;
    let key_end = key_start + "sk_live_abcd1234abcd1234".len() as u32;
    let email_start = input.find("john@example.com").expect("email start") as u32;
    let email_end = email_start + "john@example.com".len() as u32;

    let evidence = EvidenceGraph {
        version: 1,
        source_hash: [2u8; 32],
        ambiguous: false,
        spans: vec![
            EvidenceSpan {
                start_index: key_start,
                end_index: key_end,
                pii_class: PiiClass::ApiKey,
                severity: PiiSeverity::High,
                confidence_bucket: PiiConfidenceBucket::High,
                pattern_id: "test/api_key".to_string(),
                validator_passed: true,
                context_keywords: vec![],
                evidence_source: "test".to_string(),
            },
            EvidenceSpan {
                start_index: email_start,
                end_index: email_end,
                pii_class: PiiClass::Email,
                severity: PiiSeverity::Low,
                confidence_bucket: PiiConfidenceBucket::High,
                pattern_id: "test/email".to_string(),
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
        decision_hash: [9u8; 32],
    };

    let (scrubbed, _map, report) = apply_transform(input, &evidence, &outcome).expect("transform");

    assert!(!scrubbed.contains("sk_live_abcd1234abcd1234"));
    assert!(!scrubbed.contains("john@example.com"));
    assert!(report.no_raw_substring_leak);
    assert_eq!(report.remaining_span_count, 0);
}

#[test]
fn hard_gate_policy_blocks_high_risk_non_utf8_payload() {
    let rules = ActionRules {
        policy_id: "test-policy".to_string(),
        defaults: DefaultPolicy::AllowAll,
        ontology_policy: Default::default(),
        pii_controls: PiiControls::default(),
        rules: vec![],
    };

    let request = ActionRequest {
        target: ActionTarget::ClipboardWrite,
        params: vec![0xff, 0xfe, 0xfd],
        context: ActionContext {
            agent_id: "agent-test".to_string(),
            session_id: None,
            window_id: None,
        },
        nonce: 1,
    };

    let os = Arc::new(DummyOs) as Arc<dyn OsDriver>;
    let safety = Arc::new(DummySafety) as Arc<dyn LocalSafetyModel>;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let verdict = rt.block_on(PolicyEngine::evaluate(&rules, &request, &safety, &os, None));
    assert!(matches!(verdict, Verdict::Block));
}

#[test]
fn review_request_persisted_and_retrievable_by_decision_hash() {
    let input = "send to john@example.com";
    let graph = sample_low_email_graph(input);
    let target = PiiTarget::Action(ActionTarget::NetFetch);
    let mut policy = PiiControls::default();
    policy.safe_transform_enabled = false;

    let routed = route_pii_decision_for_target(&graph, &policy, RiskSurface::Egress, &target, true);
    assert!(matches!(routed.decision, FirewallDecision::Quarantine));

    let material = build_decision_material(
        &graph,
        &routed.decision,
        routed.transform_plan.as_ref(),
        routed.stage2_decision.as_ref(),
        RiskSurface::Egress,
        &target,
        true,
        &routed.assist,
    );
    let summary = build_review_summary(&graph, &target, routed.stage2_decision.as_ref());
    let request = PiiReviewRequest {
        request_version: REVIEW_REQUEST_VERSION,
        decision_hash: routed.decision_hash,
        material,
        summary,
        session_id: Some([0x11; 32]),
        created_at_ms: 1_000,
        deadline_ms: 3_000,
    };

    let local_key = review_request_key(&routed.decision_hash);
    let full_key = [
        service_namespace_prefix("desktop_agent").as_slice(),
        local_key.as_slice(),
    ]
    .concat();
    let mut state: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
    state.insert(
        full_key.clone(),
        codec::to_bytes_canonical(&request).expect("encode request"),
    );

    let raw = state.get(&full_key).expect("stored request bytes");
    let decoded: PiiReviewRequest =
        codec::from_bytes_canonical(raw).expect("decode review request");
    assert_eq!(decoded.decision_hash, routed.decision_hash);
    assert_eq!(decoded.summary.target_label, target.canonical_label());
}

#[test]
fn quarantine_then_approve_transform_paths_to_deterministic_scrubbed_pass() {
    let input = "forward john@example.com to remote sink";
    let graph = sample_low_email_graph(input);
    let target = PiiTarget::Action(ActionTarget::NetFetch);

    let mut denied_policy = PiiControls::default();
    denied_policy.safe_transform_enabled = false;
    let quarantined =
        route_pii_decision_for_target(&graph, &denied_policy, RiskSurface::Egress, &target, true);
    assert!(matches!(quarantined.decision, FirewallDecision::Quarantine));

    let mut approved_policy = denied_policy.clone();
    approved_policy.safe_transform_enabled = true;
    let transformed =
        route_pii_decision_for_target(&graph, &approved_policy, RiskSurface::Egress, &target, true);
    assert!(matches!(
        transformed.decision,
        FirewallDecision::RedactThenAllow | FirewallDecision::TokenizeThenAllow
    ));

    let (scrubbed, _map, report) = apply_transform(input, &graph, &transformed).expect("transform");
    assert!(!scrubbed.contains("john@example.com"));
    assert!(report.no_raw_substring_leak);
}

#[test]
fn low_severity_scoped_exception_grant_passes_once_then_fails_second_use() {
    let input = "send john@example.com to external destination";
    let graph = sample_low_email_graph(input);
    let target = PiiTarget::Action(ActionTarget::NetFetch);

    let policy = PiiControls {
        raw_override_mode: RawOverrideMode::ScopedLowSeverityOnly,
        raw_override_default_enabled: true,
        ..PiiControls::default()
    };

    let routed = route_pii_decision_for_target(&graph, &policy, RiskSurface::Egress, &target, true);
    assert!(matches!(
        routed.decision,
        FirewallDecision::RequireUserReview
    ));

    let exception = mint_default_scoped_exception(
        &graph,
        &target,
        RiskSurface::Egress,
        routed.decision_hash,
        1_000,
        "test grant",
    )
    .expect("mint scoped exception");

    let first = verify_scoped_exception_for_decision(
        &exception,
        &graph,
        &target,
        RiskSurface::Egress,
        routed.decision_hash,
        &policy,
        1_100,
        0,
    );
    assert!(first.is_ok());

    let second = verify_scoped_exception_for_decision(
        &exception,
        &graph,
        &target,
        RiskSurface::Egress,
        routed.decision_hash,
        &policy,
        1_200,
        1,
    );
    assert!(matches!(second, Err(ScopedExceptionVerifyError::Overused)));
}

#[test]
fn expired_scoped_exception_fails_closed() {
    let input = "send john@example.com to external destination";
    let graph = sample_low_email_graph(input);
    let target = PiiTarget::Action(ActionTarget::NetFetch);

    let policy = PiiControls {
        raw_override_mode: RawOverrideMode::ScopedLowSeverityOnly,
        raw_override_default_enabled: true,
        ..PiiControls::default()
    };

    let routed = route_pii_decision_for_target(&graph, &policy, RiskSurface::Egress, &target, true);
    let exception = mint_default_scoped_exception(
        &graph,
        &target,
        RiskSurface::Egress,
        routed.decision_hash,
        1_000,
        "test grant",
    )
    .expect("mint scoped exception");

    let expired = verify_scoped_exception_for_decision(
        &exception,
        &graph,
        &target,
        RiskSurface::Egress,
        routed.decision_hash,
        &policy,
        exception.expires_at,
        0,
    );
    assert!(matches!(expired, Err(ScopedExceptionVerifyError::Expired)));
}

#[tokio::test(flavor = "current_thread")]
async fn hard_gate_cloud_airlock_redacts_secret_before_runtime_bytes() {
    let runtime = Arc::new(RecordingRuntime::default());
    let scrubber = PiiScrubber::new(Arc::new(SubstrateSafety));
    let prompt = b"Plan this step using key sk_live_abcd1234abcd1234 and john@example.com";

    let _ = execute_cloud_inference(
        &(runtime.clone() as Arc<dyn InferenceRuntime>),
        &scrubber,
        None,
        None,
        "desktop_agent",
        "model_hash:0000000000000000000000000000000000000000000000000000000000000000",
        [0u8; 32],
        prompt,
        InferenceOptions::default(),
    )
    .await
    .expect("airlocked cloud inference");

    let captured = runtime.last_input.lock().expect("capture lock").clone();
    let captured_str = String::from_utf8(captured).expect("utf8 captured payload");
    assert!(!captured_str.contains("sk_live_abcd1234abcd1234"));
    assert!(!captured_str.contains("john@example.com"));
    assert!(captured_str.contains("<REDACTED:api_key>"));
    assert!(captured_str.contains("<REDACTED:email>"));
}

#[test]
fn hard_gate_desktop_cloud_inference_callsites_use_airlock_path() {
    let desktop_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("agentic")
        .join("desktop");
    let mut violations = Vec::new();

    for entry in walkdir::WalkDir::new(&desktop_root)
        .into_iter()
        .filter_map(Result::ok)
    {
        if !entry.file_type().is_file() {
            continue;
        }
        if entry.path().extension().and_then(|ext| ext.to_str()) != Some("rs") {
            continue;
        }

        let content = fs::read_to_string(entry.path()).expect("read desktop source file");
        if !content.contains("execute_inference(") {
            continue;
        }

        let rel = entry
            .path()
            .strip_prefix(Path::new(env!("CARGO_MANIFEST_DIR")))
            .unwrap_or(entry.path());
        let rel_str = rel.to_string_lossy();

        if rel_str.ends_with("desktop/cloud_airlock.rs") {
            continue;
        }

        let uses_airlock = content.contains("prepare_cloud_inference_input(")
            || content.contains("execute_cloud_inference(");
        if !uses_airlock {
            violations.push(rel_str.to_string());
        }
    }

    assert!(
        violations.is_empty(),
        "Desktop cloud inference callsites bypass airlock path: {:?}",
        violations
    );
}
