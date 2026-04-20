use super::*;

fn temp_policy_path(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    path.push(format!(
        "ioi-shield-policy-{name}-{}-{nonce}.json",
        std::process::id()
    ));
    path
}

fn cleanup_policy_artifacts(path: &Path) {
    let _ = fs::remove_file(path);
    let _ = fs::remove_file(approval_memory_path_for(path));
}

#[test]
fn remembered_approval_matches_and_records_hook_receipts() {
    let path = temp_policy_path("remembered-approval");
    cleanup_policy_artifacts(&path);

    let manager = ShieldPolicyManager::new(path.clone());
    let remembered = manager
        .remember_approval(ShieldRememberApprovalInput {
            connector_id: "google_workspace".to_string(),
            action_id: "gmail.send_email".to_string(),
            action_label: "Send Gmail reply".to_string(),
            policy_family: "writes".to_string(),
            scope_key: Some("connector:google_workspace:action:gmail.send_email".to_string()),
            scope_label: Some("Google Workspace · Gmail send".to_string()),
            source_label: Some("Connector panel".to_string()),
            scope_mode: None,
            expires_at_ms: None,
        })
        .expect("remember approval should succeed");

    assert_eq!(remembered.active_decision_count, 1);
    assert_eq!(remembered.decisions[0].match_count, 0);
    assert!(manager.match_remembered_approval(
        "google_workspace",
        "gmail.send_email",
        "writes",
        Some("connector:google_workspace:action:gmail.send_email"),
        "Send Gmail reply",
    ));

    let after_match = manager.approval_snapshot();
    assert_eq!(after_match.active_decision_count, 1);
    assert_eq!(after_match.decisions[0].match_count, 1);
    assert!(
        after_match
            .recent_receipts
            .iter()
            .any(|receipt| receipt.hook_kind == "pre_run_approval_hook"
                && receipt.status == "matched"),
        "expected remembered approval match receipt"
    );

    cleanup_policy_artifacts(&path);
}

#[test]
fn remembered_approval_can_broaden_scope_and_expire() {
    let path = temp_policy_path("approval-scope-and-expiry");
    cleanup_policy_artifacts(&path);

    let manager = ShieldPolicyManager::new(path.clone());
    let remembered = manager
        .remember_approval(ShieldRememberApprovalInput {
            connector_id: "google_workspace".to_string(),
            action_id: "gmail.send_email".to_string(),
            action_label: "Send Gmail reply".to_string(),
            policy_family: "writes".to_string(),
            scope_key: Some("connector:google_workspace:action:gmail.send_email".to_string()),
            scope_label: Some("Google Workspace · Gmail send".to_string()),
            source_label: Some("Connector panel".to_string()),
            scope_mode: None,
            expires_at_ms: None,
        })
        .expect("remember approval should succeed");

    let decision_id = remembered.decisions[0].decision_id.clone();
    let broadened = manager
        .set_approval_scope_mode(ShieldRememberedApprovalScopeUpdateInput {
            decision_id: decision_id.clone(),
            scope_mode: ShieldApprovalScopeMode::ConnectorPolicyFamily,
        })
        .expect("broadened scope should persist");

    assert_eq!(
        broadened.decisions[0].scope_mode,
        ShieldApprovalScopeMode::ConnectorPolicyFamily
    );
    assert_eq!(
        broadened.decisions[0].scope_key,
        "connector:google_workspace:policy_family:writes"
    );
    assert!(manager.match_remembered_approval(
        "google_workspace",
        "calendar.create_event",
        "writes",
        Some("connector:google_workspace:action:calendar.create_event"),
        "Create Calendar event",
    ));

    let expired = manager
        .set_approval_expiry(ShieldRememberedApprovalExpiryUpdateInput {
            decision_id: decision_id.clone(),
            expires_at_ms: Some(1),
        })
        .expect("expiry update should succeed");
    assert_eq!(expired.active_decision_count, 0);
    assert!(
        expired
            .recent_receipts
            .iter()
            .any(|receipt| receipt.status == "expired"
                && receipt.decision_id.as_deref() == Some(decision_id.as_str())),
        "expected expiry receipt"
    );
    assert!(!manager.match_remembered_approval(
        "google_workspace",
        "gmail.send_email",
        "writes",
        Some("connector:google_workspace:action:gmail.send_email"),
        "Send Gmail reply",
    ));

    cleanup_policy_artifacts(&path);
}

#[test]
fn remembered_approval_scope_mismatch_records_receipt() {
    let path = temp_policy_path("approval-scope-mismatch");
    cleanup_policy_artifacts(&path);

    let manager = ShieldPolicyManager::new(path.clone());
    manager
        .remember_approval(ShieldRememberApprovalInput {
            connector_id: "google_workspace".to_string(),
            action_id: "gmail.send_email".to_string(),
            action_label: "Send Gmail reply".to_string(),
            policy_family: "writes".to_string(),
            scope_key: Some("connector:google_workspace:action:gmail.send_email".to_string()),
            scope_label: Some("Google Workspace · Gmail send".to_string()),
            source_label: Some("Connector panel".to_string()),
            scope_mode: None,
            expires_at_ms: None,
        })
        .expect("remember approval should succeed");

    assert!(!manager.match_remembered_approval(
        "google_workspace",
        "calendar.create_event",
        "writes",
        Some("connector:google_workspace:action:calendar.create_event"),
        "Create Calendar event",
    ));

    let snapshot = manager.approval_snapshot();
    assert!(
        snapshot.recent_receipts.iter().any(|receipt| {
            receipt.hook_kind == "pre_run_approval_hook"
                && receipt.status == "scope_mismatch"
                && receipt.connector_id == "google_workspace"
                && receipt.action_id == "calendar.create_event"
        }),
        "expected scope mismatch receipt"
    );

    cleanup_policy_artifacts(&path);
}

#[test]
fn forgetting_approval_and_blocker_escalation_update_memory_snapshot() {
    let path = temp_policy_path("approval-forget");
    cleanup_policy_artifacts(&path);

    let manager = ShieldPolicyManager::new(path.clone());
    let remembered = manager
        .remember_approval(ShieldRememberApprovalInput {
            connector_id: "google_workspace".to_string(),
            action_id: "calendar.create_event".to_string(),
            action_label: "Create Calendar event".to_string(),
            policy_family: "writes".to_string(),
            scope_key: Some("connector:google_workspace:action:calendar.create_event".to_string()),
            scope_label: Some("Google Workspace · Calendar write".to_string()),
            source_label: Some("Assistant workbench".to_string()),
            scope_mode: None,
            expires_at_ms: None,
        })
        .expect("remember approval should succeed");

    let decision_id = remembered.decisions[0].decision_id.clone();
    let forgotten = manager
        .forget_approval(&decision_id)
        .expect("forget approval should succeed");
    assert_eq!(forgotten.active_decision_count, 0);
    assert!(
        forgotten
            .recent_receipts
            .iter()
            .any(|receipt| receipt.status == "revoked"
                && receipt.decision_id.as_deref() == Some(decision_id.as_str())),
        "expected revoked receipt for forgotten approval"
    );

    manager.record_blocker_escalation(
        "google_workspace",
        "calendar.create_event",
        "Create Calendar event",
        "writes",
        Some("connector:google_workspace:action:calendar.create_event"),
    );
    let after_blocker = manager.approval_snapshot();
    assert!(
        after_blocker
            .recent_receipts
            .iter()
            .any(|receipt| receipt.hook_kind == "blocker_escalation_hook"
                && receipt.status == "requested"),
        "expected blocker escalation hook receipt"
    );

    cleanup_policy_artifacts(&path);
}
