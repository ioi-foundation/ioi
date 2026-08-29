use super::{
    default_service_policies, AftSafetyMode, CommitmentSchemeType, ConsensusType, InferenceConfig,
    McpMode, OrchestrationConfig, RuntimeFinalityProfile, StateTreeType, VmFuelCosts,
    WorkloadConfig, ZkConfig, WALLET_EFFECT_V2_CONFIG_MIGRATION_CODE,
    WALLET_STANDING_AUTHORITY_CONFIG_MIGRATION_CODE,
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
        "record_standing_approval_grant@v1",
        "consume_standing_approval_grant_for_effect@v1",
        "settle_standing_approval_grant_consumption@v1",
        "revoke_standing_approval_grant@v1",
    ] {
        assert_eq!(
            wallet.methods.get(method),
            Some(&MethodPermission::User),
            "wallet_network ActiveServiceMeta must advertise {method}",
        );
    }
}

#[test]
fn guardian_registry_policy_exposes_canonical_order_artifact_publication() {
    let policies = default_service_policies();
    let guardian_registry = policies
        .get("guardian_registry")
        .expect("guardian_registry service policy should exist");

    for method in [
        "publish_aft_canonical_order_artifact_bundle@v1",
        "publish_aft_canonical_collapse_object@v1",
    ] {
        assert_eq!(
            guardian_registry.methods.get(method),
            Some(&MethodPermission::User),
            "validator-signed canonical-order publication {method} must be admitted by the active service ABI",
        );
    }
}

#[test]
fn stale_wallet_method_map_requires_standing_authority_migration() {
    for standing_method in [
        "record_standing_approval_grant@v1",
        "consume_standing_approval_grant_for_effect@v1",
        "settle_standing_approval_grant_consumption@v1",
        "revoke_standing_approval_grant@v1",
    ] {
        let mut config = WorkloadConfig {
            runtimes: vec!["WASM".to_string()],
            state_tree: StateTreeType::IAVL,
            commitment_scheme: CommitmentSchemeType::Hash,
            consensus_type: ConsensusType::Aft,
            genesis_file: "genesis.json".to_string(),
            state_file: "state.json".to_string(),
            srs_file_path: None,
            fuel_costs: VmFuelCosts::default(),
            initial_services: Vec::new(),
            service_policies: default_service_policies(),
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
        };
        config
            .service_policies
            .get_mut("wallet_network")
            .expect("wallet policy")
            .methods
            .remove(standing_method);
        let error = config
            .validate()
            .expect_err("missing standing-authority method must fail before startup");
        assert!(
            error.starts_with(WALLET_STANDING_AUTHORITY_CONFIG_MIGRATION_CODE),
            "standing authority migration must expose its stable code: {error}"
        );
    }

    let mut config = WorkloadConfig {
        runtimes: vec!["WASM".to_string()],
        state_tree: StateTreeType::IAVL,
        commitment_scheme: CommitmentSchemeType::Hash,
        consensus_type: ConsensusType::Aft,
        genesis_file: "genesis.json".to_string(),
        state_file: "state.json".to_string(),
        srs_file_path: None,
        fuel_costs: VmFuelCosts::default(),
        initial_services: Vec::new(),
        service_policies: default_service_policies(),
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
    };
    config
        .service_policies
        .get_mut("wallet_network")
        .expect("wallet policy")
        .methods
        .insert(
            "consume_standing_approval_grant_for_effect@v1".to_string(),
            MethodPermission::Internal,
        );
    let error = config
        .validate()
        .expect_err("standing-authority permission mismatch must fail before startup");
    assert!(error.starts_with(WALLET_STANDING_AUTHORITY_CONFIG_MIGRATION_CODE));
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

#[test]
fn runtime_finality_profile_aliases_resolve_to_exact_versioned_identities() {
    for (consensus, input, expected, canonical) in [
        (
            "Aft",
            "aft",
            RuntimeFinalityProfile::BftConsensusAftV1,
            "bft_consensus_aft_v1",
        ),
        (
            "Solo",
            "solo",
            RuntimeFinalityProfile::SingleAuthorityV1,
            "single_authority_v1",
        ),
    ] {
        let config: OrchestrationConfig = toml::from_str(&format!(
            "consensus_type = \"{consensus}\"\nfinality_profile = \"{input}\"\nrpc_listen_address = \"127.0.0.1:0\"\n"
        ))
        .expect("compatibility label parses");
        assert_eq!(
            config.resolved_finality_profile().expect("resolves"),
            expected
        );
        let serialized = toml::to_string(&config).expect("serializes");
        assert!(
            serialized.contains(&format!("finality_profile = \"{canonical}\"")),
            "canonical identity was not emitted: {serialized}"
        );
    }
}

#[test]
fn aft_is_the_omitted_profile_default_and_single_authority_is_explicit() {
    let aft: OrchestrationConfig =
        toml::from_str("consensus_type = \"Aft\"\nrpc_listen_address = \"127.0.0.1:0\"\n")
            .expect("AFT config parses");
    assert_eq!(
        aft.resolved_finality_profile().expect("AFT resolves"),
        RuntimeFinalityProfile::BftConsensusAftV1
    );

    let solo: OrchestrationConfig =
        toml::from_str("consensus_type = \"Solo\"\nrpc_listen_address = \"127.0.0.1:0\"\n")
            .expect("Solo config parses");
    assert_eq!(
        solo.resolved_finality_profile().expect("Solo resolves"),
        RuntimeFinalityProfile::SingleAuthorityV1
    );
}

#[test]
fn runtime_profile_engine_and_aft_safety_substitutions_refuse() {
    let mut config: OrchestrationConfig = toml::from_str(
        "consensus_type = \"Aft\"\nfinality_profile = \"single_authority_v1\"\nrpc_listen_address = \"127.0.0.1:0\"\n",
    )
    .expect("config parses");
    assert!(config.validate().is_err());

    config.finality_profile = Some(RuntimeFinalityProfile::BftConsensusAftV1);
    config.aft_safety_mode = AftSafetyMode::GuardianMajority;
    let error = config
        .validate()
        .expect_err("guardian majority is not peer-BFT evidence");
    assert!(error.contains("requires classic_bft safety"));
}
