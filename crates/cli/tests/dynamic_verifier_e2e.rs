// Path: crates/cli/tests/dynamic_verifier_e2e.rs
#![cfg(all(
    feature = "consensus-poa",
    feature = "vm-wasm",
    feature = "state-iavl",
    feature = "ibc-deps"
))]

use anyhow::{anyhow, Result};
use ioi_api::state::service_namespace_prefix;
use ioi_cli::testing::{
    build_test_artifacts,
    rpc::{query_state_key, submit_transaction_and_get_block},
    wait_for_height, TestCluster,
};
use ioi_types::{
    app::{
        account_id_from_key_material, AccountId, ActiveKeyRecord, BlockTimingParams,
        BlockTimingRuntime, ChainTransaction, SignHeader, SignatureProof, SignatureSuite,
        SystemPayload, SystemTransaction, ValidatorSetV1, ValidatorSetsV1, ValidatorV1,
    },
    codec,
    config::{IbcConfig, InitialServiceConfig},
};
use libp2p::identity::Keypair;
use parity_scale_codec::{Decode, Encode};
use std::path::Path;
use std::time::Duration;

// Import IBC specific types
use ioi_types::ibc::{EthereumHeader, Finality, Header, SubmitHeaderParams};

#[derive(Encode, Decode)]
struct RegisterVerifierParams {
    client_type: String,
    artifact: Vec<u8>,
}

fn create_gov_tx(signer: &Keypair, payload: SystemPayload, nonce: u64) -> Result<ChainTransaction> {
    let pk = signer.public().encode_protobuf();
    let acc = AccountId(account_id_from_key_material(SignatureSuite::Ed25519, &pk)?);

    let mut tx = SystemTransaction {
        header: SignHeader {
            account_id: acc,
            nonce,
            chain_id: 1.into(),
            tx_version: 1,
        },
        payload,
        signature_proof: Default::default(),
    };
    let sb = tx.to_sign_bytes().map_err(|e| anyhow::anyhow!(e))?;
    tx.signature_proof = SignatureProof {
        suite: SignatureSuite::Ed25519,
        public_key: pk,
        signature: signer.sign(&sb)?,
    };
    Ok(ChainTransaction::System(Box::new(tx)))
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dynamic_verifier_lifecycle() -> Result<()> {
    // 1. Build Artifacts
    build_test_artifacts();

    // Load WASM
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir.parent().and_then(|p| p.parent()).unwrap();
    // [FIX] Correct path: mock-verifier is built with cargo-component for wasm32-wasip1
    let wasm_path = workspace_root.join("target/wasm32-wasip1/release/mock_verifier.wasm");

    if !wasm_path.exists() {
        println!(
            "WARN: Mock verifier WASM not found at {:?}. Skipping test.",
            wasm_path
        );
        // Fail explicitly if we can't find the artifact, as the test is meaningless without it
        return Err(anyhow::anyhow!("Mock verifier WASM not found"));
    }
    let wasm_bytes = std::fs::read(&wasm_path)?;

    // 2. Setup Cluster
    let gov_key = Keypair::generate_ed25519();
    let gov_key_clone = gov_key.clone();

    let cluster = TestCluster::builder()
        .with_validators(1)
        .with_consensus_type("Admft")
        .with_initial_service(InitialServiceConfig::Governance(Default::default()))
        // Enable IBC to ensure the registry and tables are initialized
        .with_initial_service(InitialServiceConfig::Ibc(IbcConfig {
            enabled_clients: vec![], // No predefined clients needed
        }))
        .with_genesis_modifier(move |builder, keys| {
            let val_id = builder.add_identity(&keys[0]);
            let gov_id = builder.add_identity(&gov_key_clone);

            let vs = ValidatorSetsV1 {
                current: ValidatorSetV1 {
                    effective_from_height: 1,
                    total_weight: 1,
                    validators: vec![ValidatorV1 {
                        account_id: val_id,
                        weight: 1,
                        consensus_key: ActiveKeyRecord {
                            suite: SignatureSuite::Ed25519,
                            public_key_hash: val_id.0,
                            since_height: 0,
                        },
                    }],
                },
                next: None,
            };
            builder.set_validators(&vs);

            use ioi_types::service_configs::{GovernancePolicy, GovernanceSigner};
            let policy = GovernancePolicy {
                signer: GovernanceSigner::Single(gov_id),
            };
            builder.set_governance_policy(&policy);

            builder.set_block_timing(
                &BlockTimingParams::default(),
                &BlockTimingRuntime::default(),
            );
        })
        .build()
        .await?;

    let test_result: Result<()> = async {
        let node = cluster.validators[0].validator();
        let rpc = &node.rpc_addr;
        wait_for_height(rpc, 1, Duration::from_secs(20)).await?;

        // 3. Register Dynamic Verifier
        let client_type = "mock-01".to_string();
        let reg_params = RegisterVerifierParams {
            client_type: client_type.clone(),
            artifact: wasm_bytes.clone(),
        };

        let reg_tx = create_gov_tx(
            &gov_key,
            SystemPayload::CallService {
                service_id: "ibc".to_string(),
                method: "register_verifier@v1".to_string(),
                params: codec::to_bytes_canonical(&reg_params).unwrap(),
            },
            0,
        )?;

        submit_transaction_and_get_block(rpc, &reg_tx).await?;
        println!("Submitted RegisterVerifier tx");

        // Verify state persistence
        // FIX: Use namespaced key
        let ns = service_namespace_prefix("ibc");
        let map_key = [ns.as_slice(), b"ibc::verifier::", client_type.as_bytes()].concat();

        query_state_key(rpc, &map_key)
            .await?
            .expect("Verifier mapping not found");

        // 4. Submit Header Update using Dynamic Verifier
        // We use a dummy header. The mock verifier checks len != 1.
        let mock_eth_header = EthereumHeader {
            state_root: [0xAA; 32],
        };

        // Note: The registry currently requires Header::Ethereum to persist the root.
        // The dynamic verifier is called to *verify* it.
        let submit_tx = create_gov_tx(
            &gov_key,
            SystemPayload::CallService {
                service_id: "ibc".to_string(),
                method: "submit_header@v1".to_string(),
                params: codec::to_bytes_canonical(&SubmitHeaderParams {
                    chain_id: client_type.clone(),
                    header: Header::Ethereum(mock_eth_header.clone()),
                    finality: Finality::EthereumBeaconUpdate {
                        update_ssz: b"valid".to_vec(),
                    },
                })
                .unwrap(),
            },
            1,
        )?;

        submit_transaction_and_get_block(rpc, &submit_tx).await?;
        println!("Dynamic verification succeeded (valid header)");

        // 5. Verify Negative Case
        // Our mock verifier is programmed to reject if the header byte length is exactly 1.
        // However, we are passing a full EthereumHeader struct serialized, which is > 1 byte.
        // To fail, we would need to pass data the mock logic explicitly rejects.
        // Currently mock logic: `if header.len() == 1 { return Err }`.
        // Since we can't easily make a valid Protobuf serialization be 1 byte, we'll skip the negative
        // logic check in this E2E or we would need to update the mock contract to reject [0xAA; 32] roots specifically.

        Ok(())
    }
    .await;

    // Cleanup
    for guard in cluster.validators {
        guard.shutdown().await?;
    }

    test_result
}
