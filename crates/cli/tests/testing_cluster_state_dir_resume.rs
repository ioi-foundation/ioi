#![cfg(all(feature = "consensus-aft", feature = "vm-wasm", feature = "state-iavl"))]

//! Stable-state-dir resume coverage for the testing harness.
//!
//! `TestClusterBuilder::with_state_dir` (or `IOI_TESTING_CLUSTER_STATE_DIR`)
//! keeps all validator durable state under a caller-supplied directory so a
//! SECOND construction from the same directory RESUMES the chain — same chain
//! id, same validator identities and ports, committed nonces intact — instead
//! of re-initializing from genesis. A partial or corrupted directory must
//! refuse outright rather than silently re-initialize over existing state.

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{anyhow, Result};
use ioi_api::crypto::{SerializableKey, SigningKey, SigningKeyPair};
use ioi_cli::testing::{
    rpc::{get_chain_height, query_state_key},
    submit_transaction, wait_for, wait_for_height, TestCluster,
};
use ioi_crypto::sign::eddsa::{Ed25519KeyPair, Ed25519PrivateKey};
use ioi_types::app::wallet_network::{
    VaultSurface, WalletClientRole, WalletClientState, WalletConfigureControlRootParams,
    WalletControlPlaneRootRecord, WalletRegisterClientParams, WalletRegisteredClientRecord,
};
use ioi_types::app::{
    account_id_from_key_material, AccountId, ChainId, ChainTransaction, SignHeader, SignatureProof,
    SignatureSuite, StateEntry, SystemPayload, SystemTransaction,
};
use ioi_types::codec;
use ioi_types::config::ServicePolicy;
use ioi_types::keys::ACCOUNT_NONCE_PREFIX;
use ioi_types::service_configs::MethodPermission;
use parity_scale_codec::{Decode, Encode};

const ROOT_SEED: [u8; 32] = [0x51; 32];

fn keypair(seed: &[u8; 32]) -> Result<Ed25519KeyPair> {
    let private =
        Ed25519PrivateKey::from_bytes(seed).map_err(|error| anyhow!(error.to_string()))?;
    Ed25519KeyPair::from_private_key(&private).map_err(|error| anyhow!(error.to_string()))
}

fn wallet_policy() -> ServicePolicy {
    let methods = ["configure_control_root@v1", "register_client@v1"]
        .into_iter()
        .map(|method| (method.to_string(), MethodPermission::User))
        .collect();
    ServicePolicy {
        methods,
        allowed_system_prefixes: Vec::new(),
    }
}

fn create_call<P: Encode>(
    signer: &Ed25519KeyPair,
    chain_id: ChainId,
    nonce: u64,
    method: &str,
    params: &P,
) -> Result<ChainTransaction> {
    let public_key = signer.public_key().to_bytes();
    let account_id = AccountId(account_id_from_key_material(
        SignatureSuite::ED25519,
        &public_key,
    )?);
    let mut transaction = SystemTransaction {
        header: SignHeader {
            account_id,
            nonce,
            chain_id,
            tx_version: 1,
            session_auth: None,
        },
        payload: SystemPayload::CallService {
            service_id: "wallet_network".to_string(),
            method: method.to_string(),
            params: codec::to_bytes_canonical(params).map_err(|error| anyhow!(error))?,
        },
        signature_proof: SignatureProof::default(),
    };
    let signing_bytes = transaction
        .to_sign_bytes()
        .map_err(|error| anyhow!(error))?;
    transaction.signature_proof = SignatureProof {
        suite: SignatureSuite::ED25519,
        public_key,
        signature: signer
            .private_key()
            .sign(&signing_bytes)
            .map_err(|error| anyhow!(error.to_string()))?
            .to_bytes(),
    };
    Ok(ChainTransaction::System(Box::new(transaction)))
}

fn decode_state_value<T: Decode>(bytes: &[u8], label: &str) -> Result<T> {
    if let Ok(value) = codec::from_bytes_canonical::<T>(bytes) {
        return Ok(value);
    }
    let entry: StateEntry = codec::from_bytes_canonical(bytes)
        .map_err(|error| anyhow!("{label} state wrapper is malformed: {error}"))?;
    codec::from_bytes_canonical(&entry.value)
        .map_err(|error| anyhow!("{label} state value is malformed: {error}"))
}

async fn account_nonce(rpc_addr: &str, account_id: &[u8; 32]) -> Result<u64> {
    let key = [ACCOUNT_NONCE_PREFIX, account_id.as_slice()].concat();
    match query_state_key(rpc_addr, &key).await? {
        Some(bytes) => decode_state_value(&bytes, "account nonce"),
        None => Ok(0),
    }
}

fn cluster_builder(state_dir: &std::path::Path) -> ioi_cli::testing::TestClusterBuilder {
    TestCluster::builder()
        .with_validators(1)
        .with_consensus_type("Aft")
        .with_state_tree("IAVL")
        .with_service_policy("wallet_network", wallet_policy())
        .with_state_dir(state_dir)
}

#[tokio::test]
#[ignore = "boots two real single-validator clusters; run explicitly"]
async fn stable_state_dir_resume_preserves_committed_state() -> Result<()> {
    let scratch = tempfile::tempdir()?;
    let state_dir = scratch.path().join("cluster-state");
    let chain_id = ChainId(1);

    let root = keypair(&ROOT_SEED)?;
    let root_public_key = root.public_key().to_bytes();
    let root_account_id = account_id_from_key_material(SignatureSuite::ED25519, &root_public_key)?;

    // ---- First life: init from genesis, commit a nonce-advancing tx. ----
    let first = cluster_builder(&state_dir).build().await?;
    let first_life: Result<(String, u64)> = async {
        let rpc_addr = first.validators[0].validator().rpc_addr.clone();
        wait_for_height(&rpc_addr, 1, Duration::from_secs(120)).await?;
        assert_eq!(
            account_nonce(&rpc_addr, &root_account_id).await?,
            0,
            "fresh chain must start with a zero nonce"
        );
        let root_record = WalletControlPlaneRootRecord {
            account_id: root_account_id,
            signature_suite: SignatureSuite::ED25519,
            public_key: root_public_key.clone(),
            registered_at_ms: 0,
            updated_at_ms: 0,
            metadata: BTreeMap::from([(
                "fixture".to_owned(),
                "stable-state-dir-resume".to_owned(),
            )]),
        };
        submit_transaction(
            &rpc_addr,
            &create_call(
                &root,
                chain_id,
                0,
                "configure_control_root@v1",
                &WalletConfigureControlRootParams {
                    root: root_record.clone(),
                },
            )?,
        )
        .await?;
        assert_eq!(
            account_nonce(&rpc_addr, &root_account_id).await?,
            1,
            "committed transaction must advance the root nonce pre-drop"
        );
        // Bury the committed nonce behind additional blocks so the resumed
        // chain's restart-safe recovery anchor sits at or above it.
        let committed_height = get_chain_height(&rpc_addr).await?;
        wait_for_height(&rpc_addr, committed_height + 3, Duration::from_secs(120)).await?;
        let pre_drop_height = get_chain_height(&rpc_addr).await?;
        Ok((rpc_addr, pre_drop_height))
    }
    .await;
    first.shutdown().await?;
    let (first_rpc_addr, pre_drop_height) = first_life?;

    // ---- Second life: reopen from the same directory. ----
    let resumed = cluster_builder(&state_dir).build().await?;
    // Diagnostic tail (opt-in): stream the resumed validator's process logs
    // into the test output while the continuity assertions run.
    if std::env::var("IOI_TESTING_RESUME_DEBUG_LOGS").as_deref() == Ok("1") {
        let (mut orch_logs, mut workload_logs, _) =
            resumed.validators[0].validator().subscribe_logs();
        tokio::spawn(async move {
            while let Ok(line) = orch_logs.recv().await {
                println!("[orch] {line}");
            }
        });
        tokio::spawn(async move {
            while let Ok(line) = workload_logs.recv().await {
                println!("[workload] {line}");
            }
        });
    }
    let second_life: Result<()> = async {
        let rpc_addr = resumed.validators[0].validator().rpc_addr.clone();
        assert_eq!(
            rpc_addr, first_rpc_addr,
            "a resumed cluster must come back at its recorded coordinates"
        );
        assert_eq!(
            account_nonce(&rpc_addr, &root_account_id).await?,
            1,
            "resumed chain must expose the pre-drop committed nonce, not a fresh genesis"
        );
        // Height-ceiling continuity: the resumed chain keeps producing above
        // the pre-drop head instead of restarting from genesis.
        wait_for(
            "resumed chain to grow past the pre-drop head",
            Duration::from_millis(500),
            Duration::from_secs(120),
            || async {
                let height = get_chain_height(&rpc_addr).await?;
                Ok((height > pre_drop_height).then_some(()))
            },
        )
        .await?;
        // The resumed chain also accepts NEW authority from the same account
        // at the continued nonce.
        let capability = keypair(&[0x52u8; 32])?;
        let capability_public_key = capability.public_key().to_bytes();
        let capability_account_id =
            account_id_from_key_material(SignatureSuite::ED25519, &capability_public_key)?;
        submit_transaction(
            &rpc_addr,
            &create_call(
                &root,
                chain_id,
                1,
                "register_client@v1",
                &WalletRegisterClientParams {
                    client: WalletRegisteredClientRecord {
                        client_id: capability_account_id,
                        label: "resume continuity client".to_owned(),
                        surface: VaultSurface::Desktop,
                        signature_suite: SignatureSuite::ED25519,
                        public_key: capability_public_key,
                        role: WalletClientRole::Capability,
                        state: WalletClientState::Active,
                        registered_at_ms: 0,
                        updated_at_ms: 0,
                        expires_at_ms: Some(1_850_000_000_000),
                        allowed_provider_families: Vec::new(),
                        metadata: BTreeMap::new(),
                    },
                },
            )?,
        )
        .await?;
        assert_eq!(
            account_nonce(&rpc_addr, &root_account_id).await?,
            2,
            "the resumed chain must continue the nonce sequence"
        );
        Ok(())
    }
    .await;
    resumed.shutdown().await?;
    second_life
}

async fn build_refusal(
    builder: ioi_cli::testing::TestClusterBuilder,
    label: &str,
) -> Result<anyhow::Error> {
    match builder.build().await {
        Ok(cluster) => {
            cluster.shutdown().await?;
            Err(anyhow!("{label} unexpectedly built a cluster"))
        }
        Err(error) => Ok(error),
    }
}

#[tokio::test]
async fn stable_state_dir_refuses_partial_or_corrupt_trees() -> Result<()> {
    // (a) A non-empty directory without a manifest is a partial or foreign
    // tree; initializing over it would destroy unknown state.
    let partial = tempfile::tempdir()?;
    std::fs::write(partial.path().join("stray.bin"), b"partial residue")?;
    let error = build_refusal(
        cluster_builder(partial.path()),
        "a manifest-less non-empty state dir",
    )
    .await?;
    assert!(
        error
            .to_string()
            .contains("refusing to initialize over a partial or foreign tree"),
        "unexpected refusal: {error:#}"
    );

    // (b) A malformed manifest must refuse rather than silently re-init.
    let corrupt = tempfile::tempdir()?;
    std::fs::write(corrupt.path().join("cluster-state.json"), b"{ not json")?;
    let error = build_refusal(cluster_builder(corrupt.path()), "a corrupt manifest").await?;
    assert!(
        error.to_string().contains("malformed"),
        "unexpected refusal: {error:#}"
    );

    // (c) A well-formed manifest whose durable chain state is missing must
    // refuse: launching would silently restart from genesis.
    let hollow = tempfile::tempdir()?;
    let identity_key = libp2p::identity::Keypair::generate_ed25519();
    let manifest = serde_json::json!({
        "schema_version": 1,
        "chain_id": 1,
        "consensus_type": "Aft",
        "state_tree": "IAVL",
        "commitment_scheme": "Hash",
        "aft_safety_mode": "GuardianMajority",
        "num_validators": 1,
        "port_block_start": 20_000,
        "validator_base_ports": [20_000],
        "validator_identity_keys_hex": [hex::encode(identity_key.to_protobuf_encoding()?)],
        "genesis_content": "{\"genesis_state\":{}}",
        "guardian_config_toml": "signature_policy = \"FollowChain\"\nenforce_binary_integrity = false\n",
    });
    std::fs::write(
        hollow.path().join("cluster-state.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    let error = build_refusal(
        cluster_builder(hollow.path()),
        "a manifest without durable chain state",
    )
    .await?;
    assert!(
        error.to_string().contains("requires durable chain state"),
        "unexpected refusal: {error:#}"
    );

    // (d) A recorded chain identity must match the requested builder shape.
    let error = build_refusal(
        cluster_builder(hollow.path()).with_chain_id(9),
        "a chain id mismatch",
    )
    .await?;
    assert!(
        error.to_string().contains("chain_id mismatch"),
        "unexpected refusal: {error:#}"
    );
    Ok(())
}
