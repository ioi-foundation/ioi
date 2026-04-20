use super::{
    enforce_wallet_mail_connector_policy, mail_scope_identity, PolicyDecisionMode,
    ShieldPolicyManager,
};
use crate::kernel::connectors::policy::parse_approval_error;
use crate::kernel::connectors::{
    GlobalPolicyDefaults, ShieldPolicyState, ShieldRememberApprovalInput,
};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

fn temp_policy_path(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    path.push(format!(
        "ioi-wallet-mail-policy-{name}-{}-{nonce}.json",
        std::process::id()
    ));
    path
}

fn cleanup_policy_artifacts(path: &Path) {
    let _ = fs::remove_file(path);
    let approval_memory = path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("shield_policy_memory.json");
    let _ = fs::remove_file(approval_memory);
}

#[test]
fn wallet_mail_reads_support_remembered_approval_reuse() {
    let path = temp_policy_path("remembered-mail-read");
    cleanup_policy_artifacts(&path);

    let manager = ShieldPolicyManager::new(path.clone());
    manager
        .replace_state(ShieldPolicyState {
            version: 1,
            global: GlobalPolicyDefaults {
                reads: PolicyDecisionMode::Confirm,
                ..Default::default()
            },
            overrides: HashMap::new(),
        })
        .expect("policy state should update");

    let (scope_key, scope_label) =
        mail_scope_identity("mail.read_latest", "Read latest mail", "primary");
    let blocked = enforce_wallet_mail_connector_policy(
        &manager,
        "mail.read_latest",
        "Read latest mail",
        "reads",
        &scope_key,
        &scope_label,
        false,
    )
    .expect_err("mail read should gate before approval");
    assert!(
        parse_approval_error(&blocked).is_some(),
        "expected shield approval marker"
    );

    manager
        .remember_approval(ShieldRememberApprovalInput {
            connector_id: super::super::MAIL_CONNECTOR_ID.to_string(),
            action_id: "mail.read_latest".to_string(),
            action_label: "Read latest mail".to_string(),
            policy_family: "reads".to_string(),
            scope_key: Some(scope_key.clone()),
            scope_label: Some(scope_label.clone()),
            source_label: Some("Mail connector panel".to_string()),
            scope_mode: None,
            expires_at_ms: None,
        })
        .expect("remember approval should succeed");

    enforce_wallet_mail_connector_policy(
        &manager,
        "mail.read_latest",
        "Read latest mail",
        "reads",
        &scope_key,
        &scope_label,
        false,
    )
    .expect("remembered mail read approval should auto-match");

    let snapshot = manager.approval_snapshot();
    assert!(
        snapshot.recent_receipts.iter().any(|receipt| {
            receipt.connector_id == super::super::MAIL_CONNECTOR_ID
                && receipt.action_id == "mail.read_latest"
                && receipt.status == "matched"
        }),
        "expected matched receipt for remembered mail read approval"
    );

    cleanup_policy_artifacts(&path);
}
