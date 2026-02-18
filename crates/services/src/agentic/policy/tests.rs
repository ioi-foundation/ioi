use super::filesystem::{required_filesystem_path_keys, validate_allow_paths_condition};
use super::targets::policy_target_aliases;
use super::PolicyEngine;

use crate::agentic::rules::{ActionRules, DefaultPolicy, Rule, RuleConditions, Verdict};
use anyhow::Result;
use async_trait::async_trait;
use ioi_api::vm::drivers::os::{OsDriver, WindowInfo};
use ioi_api::vm::inference::{LocalSafetyModel, PiiInspection, PiiRiskSurface, SafetyVerdict};
use ioi_pii::{compute_decision_hash, route_pii_decision_for_target, RiskSurface};
use ioi_types::app::agentic::{
    EvidenceGraph, EvidenceSpan, PiiClass, PiiConfidenceBucket, PiiControls, PiiSeverity, PiiTarget,
};
use ioi_types::app::{ActionContext, ActionRequest, ActionTarget};
use ioi_types::error::VmError;
use std::sync::Arc;

struct DummySafety {
    graph: EvidenceGraph,
}

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
            evidence: self.graph.clone(),
            ambiguous: self.graph.ambiguous,
            stage2_status: None,
        })
    }
}

struct DummyOs;

#[async_trait]
impl OsDriver for DummyOs {
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

#[test]
fn custom_copy_target_keeps_exact_name_and_fs_write_alias() {
    let aliases = policy_target_aliases(&ActionTarget::Custom("filesystem__copy_path".into()));
    assert_eq!(aliases[0], "filesystem__copy_path");
    assert!(aliases.iter().any(|alias| alias == "fs::write"));
}

#[test]
fn browser_click_element_target_keeps_compatibility_aliases() {
    let aliases = policy_target_aliases(&ActionTarget::Custom("browser::click_element".into()));
    assert_eq!(aliases[0], "browser::click_element");
    assert!(aliases.iter().any(|alias| alias == "browser::click"));
    assert!(aliases
        .iter()
        .any(|alias| alias == "browser__click_element"));
}

#[test]
fn copy_and_move_require_source_and_destination_paths() {
    let keys =
        required_filesystem_path_keys(&ActionTarget::Custom("filesystem__move_path".to_string()))
            .expect("move path should require deterministic path keys");
    assert_eq!(keys, ["source_path", "destination_path"]);
}

#[test]
fn allow_paths_blocks_copy_when_destination_outside_allowed_roots() {
    let allowed = vec!["/workspace".to_string()];
    let params = serde_json::json!({
        "source_path": "/workspace/src.txt",
        "destination_path": "/tmp/out.txt"
    });
    let params = serde_json::to_vec(&params).expect("params should serialize");

    let allowed_by_policy = validate_allow_paths_condition(
        &allowed,
        &ActionTarget::Custom("filesystem__copy_path".into()),
        &params,
    );
    assert!(!allowed_by_policy);
}

#[test]
fn allow_paths_accepts_copy_when_all_paths_are_within_allowed_roots() {
    let allowed = vec!["/workspace".to_string()];
    let params = serde_json::json!({
        "source_path": "/workspace/src.txt",
        "destination_path": "/workspace/out/dst.txt"
    });
    let params = serde_json::to_vec(&params).expect("params should serialize");

    let allowed_by_policy = validate_allow_paths_condition(
        &allowed,
        &ActionTarget::Custom("filesystem__copy_path".into()),
        &params,
    );
    assert!(allowed_by_policy);
}

#[test]
fn allow_paths_blocks_prefix_collision_path() {
    let allowed = vec!["/workspace".to_string()];
    let params = serde_json::json!({
        "path": "/workspace2/private.txt"
    });
    let params = serde_json::to_vec(&params).expect("params should serialize");

    let allowed_by_policy =
        validate_allow_paths_condition(&allowed, &ActionTarget::FsRead, &params);
    assert!(!allowed_by_policy);
}

#[test]
fn allow_paths_blocks_parent_traversal_segments() {
    let allowed = vec!["/workspace".to_string()];
    let params = serde_json::json!({
        "path": "/workspace/../../etc/passwd"
    });
    let params = serde_json::to_vec(&params).expect("params should serialize");

    let allowed_by_policy =
        validate_allow_paths_condition(&allowed, &ActionTarget::FsRead, &params);
    assert!(!allowed_by_policy);
}

#[test]
fn allow_paths_accepts_normalized_path_within_allowed_root() {
    let allowed = vec!["/workspace".to_string()];
    let params = serde_json::json!({
        "path": "/workspace/subdir/../notes.txt"
    });
    let params = serde_json::to_vec(&params).expect("params should serialize");

    let allowed_by_policy =
        validate_allow_paths_condition(&allowed, &ActionTarget::FsRead, &params);
    assert!(allowed_by_policy);
}

#[test]
fn allow_domains_allows_exact_and_subdomain_hosts() {
    let graph = EvidenceGraph {
        version: 1,
        source_hash: [0u8; 32],
        ambiguous: false,
        spans: vec![],
    };

    let rules = ActionRules {
        policy_id: "policy".to_string(),
        defaults: DefaultPolicy::DenyAll,
        ontology_policy: Default::default(),
        pii_controls: PiiControls::default(),
        rules: vec![Rule {
            rule_id: Some("allow-example".to_string()),
            target: "net::fetch".to_string(),
            conditions: RuleConditions {
                allow_domains: Some(vec!["example.com".to_string()]),
                ..Default::default()
            },
            action: Verdict::Allow,
        }],
    };

    let safety = Arc::new(DummySafety { graph }) as Arc<dyn LocalSafetyModel>;
    let os = Arc::new(DummyOs) as Arc<dyn OsDriver>;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");

    for url in ["https://example.com/a", "https://www.example.com/b", "example.com/c"] {
        let params = serde_json::json!({ "url": url });
        let params = serde_json::to_vec(&params).expect("params should serialize");

        let request = ActionRequest {
            target: ActionTarget::NetFetch,
            params,
            context: ActionContext {
                agent_id: "agent".to_string(),
                session_id: None,
                window_id: None,
            },
            nonce: 1,
        };

        let verdict = rt.block_on(PolicyEngine::evaluate(&rules, &request, &safety, &os, None));
        assert_eq!(verdict, Verdict::Allow, "url should be allowed: {}", url);
    }
}

#[test]
fn allow_domains_blocks_substring_bypass_host() {
    let graph = EvidenceGraph {
        version: 1,
        source_hash: [0u8; 32],
        ambiguous: false,
        spans: vec![],
    };

    let rules = ActionRules {
        policy_id: "policy".to_string(),
        defaults: DefaultPolicy::DenyAll,
        ontology_policy: Default::default(),
        pii_controls: PiiControls::default(),
        rules: vec![Rule {
            rule_id: Some("allow-example".to_string()),
            target: "net::fetch".to_string(),
            conditions: RuleConditions {
                allow_domains: Some(vec!["example.com".to_string()]),
                ..Default::default()
            },
            action: Verdict::Allow,
        }],
    };

    let safety = Arc::new(DummySafety { graph }) as Arc<dyn LocalSafetyModel>;
    let os = Arc::new(DummyOs) as Arc<dyn OsDriver>;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");

    let params = serde_json::json!({ "url": "https://example.com.evil.com/" });
    let params = serde_json::to_vec(&params).expect("params should serialize");
    let request = ActionRequest {
        target: ActionTarget::NetFetch,
        params,
        context: ActionContext {
            agent_id: "agent".to_string(),
            session_id: None,
            window_id: None,
        },
        nonce: 1,
    };

    let verdict = rt.block_on(PolicyEngine::evaluate(&rules, &request, &safety, &os, None));
    assert_eq!(verdict, Verdict::Block);
}

#[test]
fn pii_overlay_material_hash_matches_direct_router_hash() {
    let graph = EvidenceGraph {
        version: 1,
        source_hash: [7u8; 32],
        ambiguous: false,
        spans: vec![EvidenceSpan {
            start_index: 5,
            end_index: 27,
            pii_class: PiiClass::ApiKey,
            severity: PiiSeverity::High,
            confidence_bucket: PiiConfidenceBucket::High,
            pattern_id: "test/api_key".to_string(),
            validator_passed: true,
            context_keywords: vec!["api key".to_string()],
            evidence_source: "test".to_string(),
        }],
    };
    let rules = ActionRules {
        policy_id: "policy".to_string(),
        defaults: DefaultPolicy::AllowAll,
        ontology_policy: Default::default(),
        pii_controls: PiiControls::default(),
        rules: vec![],
    };
    let request = ActionRequest {
        target: ActionTarget::ClipboardWrite,
        params: b"copy sk_live_abcd1234abcd1234".to_vec(),
        context: ActionContext {
            agent_id: "agent".to_string(),
            session_id: None,
            window_id: None,
        },
        nonce: 1,
    };

    let safety = Arc::new(DummySafety {
        graph: graph.clone(),
    }) as Arc<dyn LocalSafetyModel>;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");

    let (_verdict, material_opt) = rt
        .block_on(PolicyEngine::evaluate_pii_overlay_details(
            &rules, &request, &safety,
        ))
        .expect("pii overlay details");
    let material = material_opt.expect("expected material from successful route");
    let overlay_hash = compute_decision_hash(&material);

    let direct = route_pii_decision_for_target(
        &graph,
        &rules.pii_controls,
        RiskSurface::Egress,
        &PiiTarget::Action(ActionTarget::ClipboardWrite),
        false,
    );
    assert_eq!(overlay_hash, direct.decision_hash);
}
