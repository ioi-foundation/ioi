// Path: crates/forge/tests/workload_control_e2e.rs
#![cfg(all(feature = "consensus-poa", feature = "vm-wasm"))]

use anyhow::{anyhow, Result};
use ioi_client::shmem::DataPlane;
use ioi_forge::testing::{build_test_artifacts, TestCluster};
// [FIX] Import directly from ioi_ipc
use ioi_ipc::control::workload_control_client::WorkloadControlClient;
use ioi_ipc::control::{ExecuteJobRequest, LoadModelRequest};
use ioi_ipc::data::{AgentContext, DaReference, InferenceOutput, Tensor};
use ioi_types::{
    app::SignatureSuite,
    config::{InitialServiceConfig, ValidatorRole},
    service_configs::MigrationConfig,
};
use std::time::Duration;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};
// [FIX] Import for temp file creation
use std::io::Write;
use tempfile::NamedTempFile;

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
        // Ensure shared memory is configured
        .with_extra_feature("validator-bins")
        .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
            chain_id: 1,
            grace_period_blocks: 5,
            accept_staged_during_grace: true,
            // [FIX] Use SignatureSuite constant
            allowed_target_suites: vec![SignatureSuite::ED25519],
            allow_downgrade: false,
        }))
        .build()
        .await?;

    let node = &cluster.validators[0];
    let ipc_addr = node.validator().workload_ipc_addr.clone();
    let certs_dir = node.validator().certs_dir_path.clone();

    // Create a dummy model file
    let mut model_file = NamedTempFile::new()?;
    model_file.write_all(b"dummy_model_bytes")?;
    let model_path = model_file.path().to_string_lossy().to_string();

    // Wrap test logic to ensure cleanup
    let test_logic = async {
        // 2. Connect to Workload Control Plane
        // Wait a moment for mTLS to be ready
        tokio::time::sleep(Duration::from_secs(2)).await;

        let channel = create_secure_channel(&ipc_addr, &certs_dir)
            .await
            .map_err(|e| anyhow!("Failed to connect to workload: {}", e))?;
        let mut client = WorkloadControlClient::new(channel);

        // 3. Test LoadModel
        // [FIX] Pass the real path to the dummy model file
        let model_id = model_path.clone();
        println!("Sending LoadModel request for {}...", model_id);

        let load_resp = client
            .load_model(LoadModelRequest {
                model_id: model_id.clone(),
                shmem_region_id: "test_shmem".to_string(), // Ignored by mock
            })
            .await?
            .into_inner();

        assert!(load_resp.success, "LoadModel failed");
        println!("LoadModel success!");

        // 4. Test ExecuteJob with Shared Memory
        let shmem_id = "ioi_shmem_5000"; // Based on default port for first validator
        println!("Connecting to Data Plane: {}", shmem_id);
        let data_plane = DataPlane::connect(shmem_id)?;

        // Write input to Shared Memory
        let input_context = AgentContext {
            session_id: 101,
            embeddings: vec![Tensor {
                shape: [1, 4, 0, 0],
                data: vec![0.1, 0.2, 0.3, 0.4],
            }],
            prompt_tokens: vec![1, 2, 3],
            da_ref: Some(DaReference {
                provider: "celestia".into(),
                blob_id: vec![0xCA, 0xFE],
                commitment: vec![],
            }),
        };

        let handle = data_plane.write(&input_context, None)?;
        println!("Wrote input to shmem at offset {}", handle.offset);

        // Call ExecuteJob
        println!("Sending ExecuteJob request...");
        let exec_resp = client
            .execute_job(ExecuteJobRequest {
                job_id: 500,
                input_offset: handle.offset,
                input_length: handle.length,
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

        // Read Output from Shared Memory
        let output: InferenceOutput = rkyv::from_bytes::<InferenceOutput>(
            data_plane.read_raw(exec_resp.output_offset, exec_resp.output_length)?,
        )
        .map_err(|e| anyhow!("Failed to deserialize output: {}", e))?;

        assert_eq!(output.stop_reason, 0);

        println!("--- Workload Control Plane E2E Test Passed ---");
        Ok::<(), anyhow::Error>(())
    };

    let result = test_logic.await;

    // Cleanup
    cluster.shutdown().await?;

    result
}
