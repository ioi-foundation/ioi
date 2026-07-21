use super::{
    default_service_policies, CommitmentSchemeType, ConsensusType, InferenceConfig, McpMode,
    StateTreeType, VmFuelCosts, WorkloadConfig, ZkConfig, WALLET_EFFECT_V2_CONFIG_MIGRATION_CODE,
};
use crate::service_configs::MethodPermission;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

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
    for method in [
        "issue_principal_authority_binding@v1",
        "revoke_principal_authority_binding@v1",
        "resolve_principal_authority@v1",
        "lookup_principal_authority_binding@v1",
        "consume_approval_grant@v1",
        "consume_approval_grant_for_effect@v1",
        "consume_approval_grant_for_effect@v2",
    ] {
        assert_eq!(
            wallet.methods.get(method),
            Some(&MethodPermission::User),
            "wallet_network ActiveServiceMeta must advertise {method}",
        );
    }
}

#[test]
fn stale_generated_wallet_method_map_requires_typed_config_migration_with_existing_state() {
    let fixture_dir = std::env::temp_dir().join(format!(
        "ioi-wallet-config-upgrade-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    std::fs::create_dir_all(&fixture_dir).expect("create upgrade fixture");
    let state_path = fixture_dir.join("existing-workload-state.json");
    let state_sentinel = br#"{"legacy_wallet_state":"must-not-mutate"}"#;
    std::fs::write(&state_path, state_sentinel).expect("write old state fixture");

    let mut service_policies = default_service_policies();
    service_policies
        .get_mut("wallet_network")
        .expect("wallet policy")
        .methods
        .remove("consume_approval_grant_for_effect@v2");
    let legacy_toml = toml::to_string(&WorkloadConfig {
        runtimes: vec!["WASM".to_string()],
        state_tree: StateTreeType::IAVL,
        commitment_scheme: CommitmentSchemeType::Hash,
        consensus_type: ConsensusType::Aft,
        genesis_file: "genesis.json".to_string(),
        state_file: state_path.to_string_lossy().into_owned(),
        srs_file_path: None,
        fuel_costs: VmFuelCosts::default(),
        initial_services: Vec::new(),
        service_policies,
        min_finality_depth: 1_000,
        keep_recent_heights: 100_000,
        epoch_size: 50_000,
        gc_interval_secs: 3_600,
        zk_config: ZkConfig::default(),
        inference: InferenceConfig::default(),
        fast_inference: None,
        reasoning_inference: None,
        connectors: HashMap::new(),
        mcp_servers: HashMap::new(),
        mcp_mode: McpMode::Disabled,
    })
    .expect("serialize old generated workload config");
    let parsed: WorkloadConfig =
        toml::from_str(&legacy_toml).expect("old config remains structurally readable");

    let error = parsed
        .validate()
        .expect_err("stale explicit method map must fail before old state is opened");
    assert!(
        error.starts_with(WALLET_EFFECT_V2_CONFIG_MIGRATION_CODE),
        "startup refusal must expose the stable migration code: {error}"
    );
    assert_eq!(
        std::fs::read(&state_path).expect("read old state after refusal"),
        state_sentinel,
        "required config migration must fail before existing state is mutated"
    );

    for (v1_permission, v2_permission) in [
        (MethodPermission::User, MethodPermission::Internal),
        (MethodPermission::Internal, MethodPermission::User),
    ] {
        let mut mismatched = parsed.clone();
        let methods = &mut mismatched
            .service_policies
            .get_mut("wallet_network")
            .expect("wallet policy")
            .methods;
        methods.insert(
            "consume_approval_grant_for_effect@v1".to_string(),
            v1_permission,
        );
        methods.insert(
            "consume_approval_grant_for_effect@v2".to_string(),
            v2_permission,
        );
        let error = mismatched
            .validate()
            .expect_err("mismatched v1/v2 permissions must fail before startup");
        assert!(
            error.starts_with(WALLET_EFFECT_V2_CONFIG_MIGRATION_CODE),
            "permission mismatch must expose the stable migration code: {error}"
        );
        assert_eq!(
            std::fs::read(&state_path).expect("read old state after mismatch refusal"),
            state_sentinel,
            "permission mismatch must fail before existing state is mutated"
        );
    }
    std::fs::remove_dir_all(fixture_dir).expect("remove upgrade fixture");
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
