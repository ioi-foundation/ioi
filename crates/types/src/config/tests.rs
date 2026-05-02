use super::default_service_policies;
use crate::service_configs::MethodPermission;

#[test]
fn wallet_network_policy_exposes_policy_rule_upsert() {
    let policies = default_service_policies();
    let wallet = policies
        .get("wallet_network")
        .expect("wallet_network service policy should exist");

    assert!(
        wallet.methods.contains_key("upsert_policy_rule@v1"),
        "wallet_network ActiveServiceMeta must advertise upsert_policy_rule@v1",
    );
    assert_eq!(
        wallet.methods.get("register_approval_authority@v1"),
        Some(&MethodPermission::User),
        "wallet_network ActiveServiceMeta must advertise approval authority registration",
    );
    assert_eq!(
        wallet.methods.get("revoke_approval_authority@v1"),
        Some(&MethodPermission::User),
        "wallet_network ActiveServiceMeta must advertise approval authority revocation",
    );
}

#[test]
fn leakage_controller_policy_exposes_registration_and_internal_debit() {
    let policies = default_service_policies();
    let leakage = policies
        .get("leakage_controller")
        .expect("leakage_controller service policy should exist");

    assert_eq!(
        leakage.methods.get("register_policy@v1"),
        Some(&MethodPermission::User),
        "leakage_controller must allow user policy registration",
    );
    assert_eq!(
        leakage.methods.get("check_and_debit@v1"),
        Some(&MethodPermission::Internal),
        "leakage_controller must keep debit enforcement internal",
    );
    assert!(
        leakage
            .allowed_system_prefixes
            .iter()
            .any(|prefix| prefix == "leakage::"),
        "leakage_controller must retain access to its private state prefix",
    );
}

#[test]
fn desktop_agent_policy_exposes_gate_control_methods() {
    let policies = default_service_policies();
    let desktop_agent = policies
        .get("desktop_agent")
        .expect("desktop_agent service policy should exist");

    for method in [
        "deny@v1",
        "register_approval_authority@v1",
        "revoke_approval_authority@v1",
    ] {
        assert_eq!(
            desktop_agent.methods.get(method),
            Some(&MethodPermission::User),
            "desktop_agent ActiveServiceMeta must advertise {method}",
        );
    }
}
