// Path: crates/cli/tests/workload_control_e2e.rs
#![cfg(all(feature = "consensus-admft", feature = "vm-wasm"))]

use anyhow::{anyhow, Result};
use ioi_cli::testing::{build_test_artifacts, TestCluster};
use ioi_client::shmem::DataPlane;
use ioi_client::{SlicePackager, SlicerConfig};
use ioi_ipc::control::workload_control_client::WorkloadControlClient;
use ioi_ipc::control::{ExecuteJobRequest, LoadModelRequest};
use ioi_ipc::data::{AgentContext, Tensor};
use ioi_services::agentic::leakage::{LeakagePolicy, RegisterPolicyParams};
use ioi_types::{
    app::{
        AccountId, ActiveKeyRecord, BlockTimingParams, BlockTimingRuntime, ChainTransaction,
        SignHeader, SignatureProof, SignatureSuite, SystemPayload, SystemTransaction,
        ValidatorSetV1, ValidatorSetsV1, ValidatorV1,
    },
    codec,
    config::{InitialServiceConfig, ValidatorRole},
    service_configs::MigrationConfig,
};
use std::time::Duration;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};

// Helper to create and submit a policy registration transaction
async fn register_leakage_policy(
    node_rpc: &str,
    keypair: &libp2p::identity::Keypair,
    session_id: [u8; 32],
    nonce: u64,
) -> Result<()> {
    let policy = LeakagePolicy {
        max_tokens_per_epoch: 10_000_000, // Generous limit for test
        entropy_multiplier_percent: 100,
    };
    let params = RegisterPolicyParams { session_id, policy };
    let params_bytes = codec::to_bytes_canonical(&params).map_err(|e| anyhow!(e))?;

    let payload = SystemPayload::CallService {
        service_id: "leakage_controller".to_string(),
        method: "register_policy@v1".to_string(),
        params: params_bytes,
    };

    let pk = keypair.public().encode_protobuf();
    let acc = AccountId(ioi_types::app::account_id_from_key_material(
        SignatureSuite::ED25519,
        &pk,
    )?);

    let mut tx = SystemTransaction {
        header: SignHeader {
            account_id: acc,
            nonce,
            chain_id: 1.into(),
            tx_version: 1,
            session_auth: None,
        },
        payload,
        signature_proof: SignatureProof::default(),
    };
    let sb = tx.to_sign_bytes().map_err(|e| anyhow!(e))?;
    tx.signature_proof = SignatureProof {
        suite: SignatureSuite::ED25519,
        public_key: pk,
        signature: keypair.sign(&sb)?,
    };

    ioi_cli::testing::rpc::submit_transaction(node_rpc, &ChainTransaction::System(Box::new(tx)))
        .await?;
    Ok(())
}

async fn create_secure_channel(addr: &str, certs_dir: &std::path::Path) -> Result<Channel> {
    let ca_pem = std::fs::read(certs_dir.join("ca.pem"))?;
    let client_pem = std::fs::read(certs_dir.join("orchestration.pem"))?;
    let client_key = std::fs::read(certs_dir.join("orchestration.key"))?;

    let ca = Certificate::from_pem(ca_pem);
    let identity = Identity::from_pem(client_pem, client_key);

    let tls = ClientTlsConfig::new()
        .domain_name("workload")
        .ca_certificate(ca)
        .identity(identity);

    let channel = Channel::from_shared(format!("http://{}", addr))?
        .tls_config(tls)?
        .connect()
        .await?;
    Ok(channel)
}

#[tokio::test]
async fn test_workload_control_plane_flow() -> Result<()> {
    // 1. Setup
    build_test_artifacts();

    let cluster = TestCluster::builder()
        .with_validators(1)
        .with_role(
            0,
            ValidatorRole::Compute {
                accelerator_type: "mock-gpu".into(),
                vram_capacity: 16 * 1024 * 1024 * 1024,
            },
        )
        .with_extra_feature("validator-bins")
        .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
            chain_id: 1,
            grace_period_blocks: 5,
            accept_staged_during_grace: true,
            allowed_target_suites: vec![SignatureSuite::ED25519],
            allow_downgrade: false,
        }))
        .with_genesis_modifier(|builder, keys| {
            let key = &keys[0];
            let account_id = builder.add_identity(key);
            let acct_hash = account_id.0;

            let vs = ValidatorSetsV1 {
                current: ValidatorSetV1 {
                    effective_from_height: 1,
                    total_weight: 1,
                    validators: vec![ValidatorV1 {
                        account_id,
                        weight: 1,
                        consensus_key: ActiveKeyRecord {
                            suite: SignatureSuite::ED25519,
                            public_key_hash: acct_hash,
                            since_height: 0,
                        },
                    }],
                },
                next: None,
            };
            builder.set_validators(&vs);

            let timing_params = BlockTimingParams {
                base_interval_secs: 1,
                min_interval_secs: 1,
                max_interval_secs: 10,
                target_gas_per_block: 1_000_000,
                retarget_every_blocks: 0,
                ..Default::default()
            };
            let timing_runtime = BlockTimingRuntime {
                ema_gas_used: 0,
                effective_interval_secs: timing_params.base_interval_secs,
            };
            builder.set_block_timing(&timing_params, &timing_runtime);

            use ioi_types::service_configs::{ActiveServiceMeta, Capabilities, MethodPermission};
            use std::collections::BTreeMap;

            let mut methods = BTreeMap::new();
            methods.insert("register_policy@v1".into(), MethodPermission::User);
            methods.insert("check_and_debit@v1".into(), MethodPermission::Internal);

            let meta = ActiveServiceMeta {
                id: "leakage_controller".into(),
                abi_version: 1,
                state_schema: "v1".into(),
                caps: Capabilities::empty(),
                artifact_hash: [0; 32],
                activated_at: 0,
                methods,
                allowed_system_prefixes: vec!["leakage::".into()],
            };

            let key = ioi_types::keys::active_service_key("leakage_controller");
            builder.insert_typed(key, &meta);
        })
        .build()
        .await?;

    let node = &cluster.validators[0];
    let ipc_addr = node.validator().workload_ipc_addr.clone();
    let rpc_addr = node.validator().rpc_addr.clone();
    let certs_dir = node.validator().certs_dir_path.clone();
    let keypair = node.validator().keypair.clone();

    // Create a dummy model file where the Workload container expects it.
    let models_dir = std::env::current_dir()?.join("models");
    std::fs::create_dir_all(&models_dir)?;

    let model_content = b"dummy_model_bytes";
    // 1. Calculate the REAL hash of the model content.
    let calculated_hash = ioi_crypto::algorithms::hash::sha256(model_content)?;
    let calculated_hex = hex::encode(calculated_hash);

    // 2. Use the hash as the ID so the integrity check (hash(content) == ID) passes.
    let model_id_to_request = calculated_hex;

    let real_model_path = models_dir.join(format!("{}.bin", model_id_to_request));
    std::fs::write(&real_model_path, model_content)?;

    let test_logic = async {
        // 2. Register Policy for the session
        let session_id = [0xBB; 32];

        // Wait for node to be ready before submitting tx
        ioi_cli::testing::wait_for_height(&rpc_addr, 1, Duration::from_secs(30)).await?;

        register_leakage_policy(&rpc_addr, &keypair, session_id, 0).await?;
        println!("Registered leakage policy.");

        tokio::time::sleep(Duration::from_secs(2)).await;

        let channel = create_secure_channel(&ipc_addr, &certs_dir)
            .await
            .map_err(|e| anyhow!("Failed to connect to workload: {}", e))?;
        let mut client = WorkloadControlClient::new(channel);

        // 3. Load Model (Warm start)
        println!("Loading model {}...", model_id_to_request);
        let load_resp = client
            .load_model(LoadModelRequest {
                model_id: model_id_to_request,
                shmem_region_id: "test_shmem".to_string(),
            })
            .await?
            .into_inner();
        assert!(load_resp.success, "LoadModel failed");
        println!("Model loaded successfully.");

        // 4. Prepare Encrypted Data via SlicePackager
        let shmem_id = "ioi_shmem_5000";
        let data_plane = DataPlane::connect(shmem_id)?;

        let input_context = AgentContext {
            session_id: 101,
            embeddings: vec![Tensor {
                shape: [1, 4, 0, 0],
                data: vec![0.1, 0.2, 0.3, 0.4],
            }],
            prompt_tokens: vec![1, 2, 3],
            da_ref: None,
        };
        let input_bytes = rkyv::to_bytes::<_, 1024>(&input_context).unwrap();

        let packager = SlicePackager::new(SlicerConfig::default());
        let master_secret = [0u8; 32]; // Matches mock secret in server
        let policy_hash = [0u8; 32];

        let slices = packager.package(session_id, policy_hash, &master_secret, &input_bytes)?;
        let slice = &slices[0];

        // Write EncryptedSlice to Shmem
        let handle = data_plane.write(slice, None)?;
        println!("Wrote EncryptedSlice to shmem at offset {}", handle.offset);

        // 5. Execute Job - Passing the correct session_id to the server
        let exec_resp = client
            .execute_job(ExecuteJobRequest {
                job_id: 500,
                input_offset: handle.offset,
                input_length: handle.length,
                session_id: session_id.to_vec(),
            })
            .await?
            .into_inner();

        assert!(
            exec_resp.success,
            "ExecuteJob failed: {}",
            exec_resp.error_message
        );
        println!(
            "ExecuteJob success! Output at offset {}",
            exec_resp.output_offset
        );

        Ok::<(), anyhow::Error>(())
    };

    let result = test_logic.await;
    cluster.shutdown().await?;
    result
}
