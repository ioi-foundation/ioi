use super::filesystem::{
    augment_workspace_filesystem_policy, required_filesystem_path_keys,
    validate_allow_paths_condition,
};
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
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

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

struct CountingSafety {
    inspections: Arc<AtomicUsize>,
}

#[async_trait]
impl LocalSafetyModel for CountingSafety {
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
        self.inspections.fetch_add(1, Ordering::SeqCst);
        Ok(PiiInspection {
            evidence: EvidenceGraph {
                version: 1,
                source_hash: [0u8; 32],
                ambiguous: false,
                spans: vec![],
            },
            ambiguous: false,
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
    let aliases = policy_target_aliases(&ActionTarget::Custom("file__copy".into()));
    assert_eq!(aliases[0], "file__copy");
    assert!(aliases.iter().any(|alias| alias == "fs::write"));
}

#[test]
fn model_registry_target_keeps_exact_name_and_model_control_alias() {
    let aliases = policy_target_aliases(&ActionTarget::Custom("model_registry__load".into()));
    assert_eq!(aliases[0], "model_registry__load");
    assert!(aliases.iter().any(|alias| alias == "model::control"));
}

#[test]
fn software_install_execute_target_keeps_canonical_alias() {
    let aliases = policy_target_aliases(&ActionTarget::SoftwareInstallExecute);
    assert_eq!(aliases[0], "software::install_execute");
    assert!(aliases
        .iter()
        .any(|alias| alias == "software::install_execute"));
}

#[test]
fn copy_and_move_require_source_and_destination_paths() {
    let keys = required_filesystem_path_keys(&ActionTarget::Custom("file__move".to_string()))
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
        &ActionTarget::Custom("file__copy".into()),
        &params,
        None,
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
        &ActionTarget::Custom("file__copy".into()),
        &params,
        None,
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
        validate_allow_paths_condition(&allowed, &ActionTarget::FsRead, &params, None);
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
        validate_allow_paths_condition(&allowed, &ActionTarget::FsRead, &params, None);
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
        validate_allow_paths_condition(&allowed, &ActionTarget::FsRead, &params, None);
    assert!(allowed_by_policy);
}

#[test]
fn allow_paths_accepts_relative_request_against_working_directory() {
    let allowed = vec!["/workspace/repo".to_string()];
    let params = serde_json::json!({
        "path": "./src/main.rs"
    });
    let params = serde_json::to_vec(&params).expect("params should serialize");

    let allowed_by_policy = validate_allow_paths_condition(
        &allowed,
        &ActionTarget::FsRead,
        &params,
        Some("/workspace/repo"),
    );
    assert!(allowed_by_policy);
}

#[test]
fn allow_paths_blocks_relative_escape_against_working_directory() {
    let allowed = vec!["/workspace/repo".to_string()];
    let params = serde_json::json!({
        "path": "../secrets.txt"
    });
    let params = serde_json::to_vec(&params).expect("params should serialize");

    let allowed_by_policy = validate_allow_paths_condition(
        &allowed,
        &ActionTarget::FsRead,
        &params,
        Some("/workspace/repo"),
    );
    assert!(!allowed_by_policy);
}

#[test]
fn workspace_filesystem_policy_adds_repo_scoped_read_and_write_rules() {
    let rules = ActionRules {
        policy_id: "policy".to_string(),
        defaults: DefaultPolicy::RequireApproval,
        ontology_policy: Default::default(),
        pii_controls: PiiControls::default(),
        rules: vec![],
    };

    let effective = augment_workspace_filesystem_policy(&rules, Some("/workspace/repo"));

    let read_rule = effective
        .rules
        .iter()
        .find(|rule| rule.rule_id.as_deref() == Some("allow-workspace-fs-read"))
        .expect("workspace read rule should be present");
    assert_eq!(read_rule.target, "fs::read");
    assert_eq!(
        read_rule.conditions.allow_paths.as_ref(),
        Some(&vec!["/workspace/repo".to_string()])
    );

    let write_rule = effective
        .rules
        .iter()
        .find(|rule| rule.rule_id.as_deref() == Some("allow-workspace-fs-write"))
        .expect("workspace write rule should be present");
    assert_eq!(write_rule.target, "fs::write");
    assert_eq!(
        write_rule.conditions.allow_paths.as_ref(),
        Some(&vec!["/workspace/repo".to_string()])
    );
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

    for url in [
        "https://example.com/a",
        "https://www.example.com/b",
        "example.com/c",
    ] {
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

        let verdict = rt.block_on(PolicyEngine::evaluate(&rules, &request, &safety, &os));
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

    let verdict = rt.block_on(PolicyEngine::evaluate(&rules, &request, &safety, &os));
    assert_eq!(verdict, Verdict::Block);
}

#[test]
fn install_policy_accepts_resolver_backed_appimage_manager() {
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
            rule_id: Some("require-install-approval".to_string()),
            target: "software::install_execute".to_string(),
            conditions: RuleConditions::default(),
            action: Verdict::RequireApproval,
        }],
    };

    let safety = Arc::new(DummySafety { graph }) as Arc<dyn LocalSafetyModel>;
    let os = Arc::new(DummyOs) as Arc<dyn OsDriver>;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");

    let params = serde_json::json!({
        "plan_ref": "software-install-plan:v1:eyJ2ZXJzaW9uIjoxLCJyZXF1ZXN0Ijp7InRhcmdldF90ZXh0IjoiTE0gU3R1ZGlvIn19"
    });
    let params = serde_json::to_vec(&params).expect("params should serialize");
    let request = ActionRequest {
        target: ActionTarget::SoftwareInstallExecute,
        params,
        context: ActionContext {
            agent_id: "agent".to_string(),
            session_id: None,
            window_id: None,
        },
        nonce: 1,
    };

    let verdict = rt.block_on(PolicyEngine::evaluate(&rules, &request, &safety, &os));
    assert_eq!(verdict, Verdict::RequireApproval);
}

#[test]
fn install_policy_accepts_resolver_request_for_approval() {
    let graph = EvidenceGraph {
        version: 1,
        source_hash: [0u8; 32],
        ambiguous: false,
        spans: vec![],
    };

    let rules = ActionRules {
        policy_id: "policy".to_string(),
        defaults: DefaultPolicy::AllowAll,
        ontology_policy: Default::default(),
        pii_controls: PiiControls::default(),
        rules: vec![Rule {
            rule_id: Some("require-install-approval".to_string()),
            target: "software::install_resolve".to_string(),
            conditions: RuleConditions::default(),
            action: Verdict::RequireApproval,
        }],
    };

    let safety = Arc::new(DummySafety { graph }) as Arc<dyn LocalSafetyModel>;
    let os = Arc::new(DummyOs) as Arc<dyn OsDriver>;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");

    let params = serde_json::json!({
        "request": {
            "target_text": "LM Studio",
            "manager_preference": "appimage"
        }
    });
    let params = serde_json::to_vec(&params).expect("params should serialize");
    let request = ActionRequest {
        target: ActionTarget::SoftwareInstallResolve,
        params,
        context: ActionContext {
            agent_id: "agent".to_string(),
            session_id: None,
            window_id: None,
        },
        nonce: 1,
    };

    let verdict = rt.block_on(PolicyEngine::evaluate(&rules, &request, &safety, &os));
    assert_eq!(verdict, Verdict::RequireApproval);
}

#[test]
fn install_policy_accepts_auto_resolver_target_text_for_approval() {
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
            rule_id: Some("require-install-approval".to_string()),
            target: "software::install_resolve".to_string(),
            conditions: RuleConditions::default(),
            action: Verdict::RequireApproval,
        }],
    };

    let safety = Arc::new(DummySafety { graph }) as Arc<dyn LocalSafetyModel>;
    let os = Arc::new(DummyOs) as Arc<dyn OsDriver>;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");

    let params = serde_json::json!({
        "request": {
            "target_text": "lm studio",
            "manager_preference": "auto"
        }
    });
    let params = serde_json::to_vec(&params).expect("params should serialize");
    let request = ActionRequest {
        target: ActionTarget::SoftwareInstallResolve,
        params,
        context: ActionContext {
            agent_id: "agent".to_string(),
            session_id: None,
            window_id: None,
        },
        nonce: 1,
    };

    let verdict = rt.block_on(PolicyEngine::evaluate(&rules, &request, &safety, &os));
    assert_eq!(verdict, Verdict::RequireApproval);
}

#[test]
fn install_policy_blocks_unknown_manager_token() {
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
            rule_id: Some("require-install-approval".to_string()),
            target: "software::install_resolve".to_string(),
            conditions: RuleConditions::default(),
            action: Verdict::RequireApproval,
        }],
    };

    let safety = Arc::new(DummySafety { graph }) as Arc<dyn LocalSafetyModel>;
    let os = Arc::new(DummyOs) as Arc<dyn OsDriver>;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");

    let params = serde_json::json!({
        "request": {
            "target_text": "LM Studio",
            "manager_preference": "definitely-not-a-manager"
        }
    });
    let params = serde_json::to_vec(&params).expect("params should serialize");
    let request = ActionRequest {
        target: ActionTarget::SoftwareInstallResolve,
        params,
        context: ActionContext {
            agent_id: "agent".to_string(),
            session_id: None,
            window_id: None,
        },
        nonce: 1,
    };

    let verdict = rt.block_on(PolicyEngine::evaluate(&rules, &request, &safety, &os));
    assert_eq!(verdict, Verdict::Block);
}

#[test]
fn policy_record_without_pii_overlay_does_not_inspect_control_payload() {
    let rules = ActionRules {
        policy_id: "policy".to_string(),
        defaults: DefaultPolicy::RequireApproval,
        ontology_policy: Default::default(),
        pii_controls: PiiControls::default(),
        rules: vec![],
    };
    let inspections = Arc::new(AtomicUsize::new(0));
    let safety = Arc::new(CountingSafety {
        inspections: Arc::clone(&inspections),
    }) as Arc<dyn LocalSafetyModel>;
    let os = Arc::new(DummyOs) as Arc<dyn OsDriver>;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");

    let request = ActionRequest {
        target: ActionTarget::Custom("resume@v1".to_string()),
        params: serde_json::to_vec(&serde_json::json!({
            "__ioi_policy_non_json_params": {
                "method": "resume@v1",
                "encoding": "hex",
                "value": "009f92d3010203"
            }
        }))
        .expect("policy params should serialize"),
        context: ActionContext {
            agent_id: "agent".to_string(),
            session_id: None,
            window_id: None,
        },
        nonce: 1,
    };

    let record = rt.block_on(PolicyEngine::evaluate_record_without_pii_overlay(
        &rules, &request, None, &safety, &os,
    ));

    assert_eq!(record.verdict, Verdict::RequireApproval);
    assert_eq!(record.pii_decision_hash, None);
    assert_eq!(inspections.load(Ordering::SeqCst), 0);
}

#[test]
fn evaluate_with_working_directory_allows_relative_repo_read() {
    let graph = EvidenceGraph {
        version: 1,
        source_hash: [0u8; 32],
        ambiguous: false,
        spans: vec![],
    };

    let rules = ActionRules {
        policy_id: "policy".to_string(),
        defaults: DefaultPolicy::RequireApproval,
        ontology_policy: Default::default(),
        pii_controls: PiiControls::default(),
        rules: vec![Rule {
            rule_id: Some("allow-repo-read".to_string()),
            target: "fs::read".to_string(),
            conditions: RuleConditions {
                allow_paths: Some(vec!["/workspace/repo".to_string()]),
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

    let params = serde_json::json!({ "path": "./src/main.rs" });
    let params = serde_json::to_vec(&params).expect("params should serialize");
    let request = ActionRequest {
        target: ActionTarget::FsRead,
        params,
        context: ActionContext {
            agent_id: "agent".to_string(),
            session_id: None,
            window_id: None,
        },
        nonce: 1,
    };

    let verdict = rt.block_on(PolicyEngine::evaluate_with_working_directory(
        &rules,
        &request,
        Some("/workspace/repo"),
        &safety,
        &os,
    ));
    assert_eq!(verdict, Verdict::Allow);
}

#[test]
fn sys_exec_allow_commands_allows_rg_with_pipe_arg() -> Result<()> {
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
            rule_id: Some("allow-rg".to_string()),
            target: "sys::exec".to_string(),
            conditions: RuleConditions {
                allow_commands: Some(vec!["rg".to_string()]),
                ..Default::default()
            },
            action: Verdict::Allow,
        }],
    };

    let safety = Arc::new(DummySafety { graph }) as Arc<dyn LocalSafetyModel>;
    let os = Arc::new(DummyOs) as Arc<dyn OsDriver>;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    let params = serde_json::json!({
        "command": "rg",
        "args": ["foo|bar", "README.md"]
    });
    let params = serde_json::to_vec(&params)?;
    let request = ActionRequest {
        target: ActionTarget::SysExec,
        params,
        context: ActionContext {
            agent_id: "agent".to_string(),
            session_id: None,
            window_id: None,
        },
        nonce: 1,
    };

    let verdict = rt.block_on(PolicyEngine::evaluate(&rules, &request, &safety, &os));
    assert_eq!(verdict, Verdict::Allow);
    Ok(())
}

#[test]
fn sys_exec_allowlist_ignores_missing_command_field() -> Result<()> {
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
            rule_id: Some("allow-sys-noncommand".to_string()),
            target: "sys::exec".to_string(),
            conditions: RuleConditions {
                allow_commands: Some(vec!["rg".to_string()]),
                ..Default::default()
            },
            action: Verdict::Allow,
        }],
    };

    let safety = Arc::new(DummySafety { graph }) as Arc<dyn LocalSafetyModel>;
    let os = Arc::new(DummyOs) as Arc<dyn OsDriver>;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    // Simulates a sys::exec-targeted tool whose params do not include `command`
    // (for example: shell__cd).
    let params = serde_json::json!({ "path": "/tmp" });
    let params = serde_json::to_vec(&params)?;
    let request = ActionRequest {
        target: ActionTarget::SysExec,
        params,
        context: ActionContext {
            agent_id: "agent".to_string(),
            session_id: None,
            window_id: None,
        },
        nonce: 1,
    };

    let verdict = rt.block_on(PolicyEngine::evaluate(&rules, &request, &safety, &os));
    assert_eq!(verdict, Verdict::Allow);
    Ok(())
}

#[test]
fn sys_exec_allow_commands_cannot_enable_shell_binaries() -> Result<()> {
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
            rule_id: Some("allow-bash".to_string()),
            target: "sys::exec".to_string(),
            conditions: RuleConditions {
                allow_commands: Some(vec!["bash".to_string(), "/bin/sh".to_string()]),
                ..Default::default()
            },
            action: Verdict::Allow,
        }],
    };

    let safety = Arc::new(DummySafety { graph }) as Arc<dyn LocalSafetyModel>;
    let os = Arc::new(DummyOs) as Arc<dyn OsDriver>;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    let params = serde_json::json!({
        "command": "/bin/bash",
        "args": ["-lc", "echo ok | cat"]
    });
    let params = serde_json::to_vec(&params)?;
    let request = ActionRequest {
        target: ActionTarget::SysExec,
        params,
        context: ActionContext {
            agent_id: "agent".to_string(),
            session_id: None,
            window_id: None,
        },
        nonce: 1,
    };

    let verdict = rt.block_on(PolicyEngine::evaluate(&rules, &request, &safety, &os));
    assert_eq!(verdict, Verdict::Block);
    Ok(())
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
