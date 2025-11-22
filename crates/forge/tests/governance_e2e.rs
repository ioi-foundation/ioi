// Path: crates/forge/tests/governance_e2e.rs

#![cfg(all(feature = "consensus-poa", feature = "vm-wasm"))]

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use ioi_forge::testing::{
    add_genesis_identity, build_test_artifacts, confirm_proposal_passed_state, submit_transaction,
    wait_for_height, TestCluster,
};
use ioi_types::{
    app::{
        account_id_from_key_material, AccountId, ActiveKeyRecord, BlockTimingParams,
        BlockTimingRuntime, ChainId, ChainTransaction, Proposal, ProposalStatus, ProposalType,
        SignHeader, SignatureProof, SignatureSuite, StateEntry, SystemPayload, SystemTransaction,
        ValidatorSetV1, ValidatorSetsV1, ValidatorV1, VoteOption,
    },
    codec,
    config::InitialServiceConfig,
    keys::{
        BLOCK_TIMING_PARAMS_KEY, BLOCK_TIMING_RUNTIME_KEY, GOVERNANCE_KEY,
        GOVERNANCE_PROPOSAL_KEY_PREFIX, VALIDATOR_SET_KEY,
    },
    service_configs::{GovernanceParams, GovernancePolicy, GovernanceSigner, MigrationConfig},
};
use libp2p::identity::{self, Keypair};
use parity_scale_codec::Encode;
use serde_json::json;
use std::time::Duration;

/// Parameters for the `governance` service's `vote@v1` method.
#[derive(Encode)]
struct VoteParams {
    proposal_id: u64,
    option: VoteOption,
}

// Helper function to create a signed `CallService` transaction
fn create_call_service_tx<P: Encode>(
    keypair: &Keypair,
    service_id: &str,
    method: &str,
    params: P,
    nonce: u64,
    chain_id: ChainId,
) -> Result<ChainTransaction> {
    let public_key_bytes = keypair.public().encode_protobuf();
    let account_id_hash =
        account_id_from_key_material(SignatureSuite::Ed25519, &public_key_bytes)?;
    let account_id = AccountId(account_id_hash);

    let payload = SystemPayload::CallService {
        service_id: service_id.to_string(),
        method: method.to_string(),
        params: codec::to_bytes_canonical(&params).map_err(|e| anyhow!(e))?,
    };

    let header = SignHeader {
        account_id,
        nonce,
        chain_id,
        tx_version: 1,
    };

    let mut tx_to_sign = SystemTransaction {
        header,
        payload,
        signature_proof: SignatureProof::default(),
    };
    let sign_bytes = tx_to_sign.to_sign_bytes().map_err(|e| anyhow!(e))?;
    let signature = keypair.sign(&sign_bytes)?;

    tx_to_sign.signature_proof = SignatureProof {
        suite: SignatureSuite::Ed25519,
        public_key: public_key_bytes,
        signature,
    };
    Ok(ChainTransaction::System(Box::new(tx_to_sign)))
}

#[tokio::test]
async fn test_governance_proposal_lifecycle_with_tallying() -> Result<()> {
    // 1. SETUP: Build artifacts and define keypairs
    build_test_artifacts();

    // 2. LAUNCH CLUSTER with a custom genesis state
    let cluster = TestCluster::builder()
        .with_validators(1)
        .with_consensus_type("ProofOfAuthority")
        .with_state_tree("IAVL")
        .with_chain_id(1)
        .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
            chain_id: 1,
            grace_period_blocks: 5,
            accept_staged_during_grace: true,
            allowed_target_suites: vec![SignatureSuite::Ed25519],
            allow_downgrade: false,
        }))
        .with_genesis_modifier(move |genesis, keys| {
            let genesis_state = genesis["genesis_state"].as_object_mut().unwrap();
            
            // --- VALIDATOR IDENTITY ---
            let validator_key = &keys[0];
            // Use the shared helper to insert credentials, key records, and pubkey mapping
            let validator_account_id = add_genesis_identity(genesis_state, validator_key);
            
            // We still need the hash to construct the ActiveKeyRecord inside ValidatorV1 manually
            let validator_account_id_hash = validator_account_id.0;

            // --- GOVERNANCE IDENTITY ---
            let governance_key = identity::Keypair::generate_ed25519();
            // Use the shared helper
            let governance_account_id = add_genesis_identity(genesis_state, &governance_key);

            // --- VALIDATOR SET BLOB ---
            let vs_blob = ioi_types::app::ValidatorSetBlob {
                schema_version: 2,
                payload: ValidatorSetsV1 {
                    current: ValidatorSetV1 {
                        effective_from_height: 1,
                        total_weight: 1_000_000,
                        validators: vec![ValidatorV1 {
                            account_id: validator_account_id,
                            weight: 1_000_000,
                            consensus_key: ActiveKeyRecord {
                                suite: SignatureSuite::Ed25519,
                                public_key_hash: validator_account_id_hash,
                                since_height: 0,
                            },
                        }],
                    },
                    next: None,
                },
            };
            let vs_bytes = ioi_types::app::write_validator_sets(&vs_blob.payload).unwrap();

            genesis_state.insert(
                std::str::from_utf8(VALIDATOR_SET_KEY).unwrap().to_string(),
                json!(format!("b64:{}", BASE64_STANDARD.encode(vs_bytes))),
            );

            // --- GOVERNANCE POLICY ---
            let policy = GovernancePolicy {
                signer: GovernanceSigner::Single(governance_account_id),
            };
            let policy_bytes = codec::to_bytes_canonical(&policy).unwrap();
            genesis_state.insert(
                std::str::from_utf8(GOVERNANCE_KEY).unwrap().to_string(),
                json!(format!("b64:{}", BASE64_STANDARD.encode(policy_bytes))),
            );

            // --- DUMMY PROPOSAL ---
            let proposal = Proposal {
                id: 1,
                title: "Test Proposal".to_string(),
                description: "This proposal should pass.".to_string(),
                proposal_type: ProposalType::Text,
                status: ProposalStatus::VotingPeriod,
                submitter: vec![1, 2, 3],
                submit_height: 0,
                deposit_end_height: 0,
                voting_start_height: 1,
                voting_end_height: 3,
                total_deposit: 10000,
                final_tally: None,
            };
            // Note: We must write this to the governance service namespace
            let proposal_key_bytes = [
                ioi_api::state::service_namespace_prefix("governance").as_slice(),
                GOVERNANCE_PROPOSAL_KEY_PREFIX,
                &1u64.to_le_bytes(),
            ]
            .concat();
            let entry = StateEntry {
                value: codec::to_bytes_canonical(&proposal).unwrap(),
                block_height: 0,
            };
            let entry_bytes = codec::to_bytes_canonical(&entry).unwrap();
            genesis_state.insert(
                format!("b64:{}", BASE64_STANDARD.encode(proposal_key_bytes)),
                json!(format!("b64:{}", BASE64_STANDARD.encode(&entry_bytes))),
            );

            // --- BLOCK TIMING ---
            let timing_params = BlockTimingParams {
                base_interval_secs: 5,
                min_interval_secs: 1,
                max_interval_secs: 30,
                target_gas_per_block: 1_000_000,
                ema_alpha_milli: 0,
                interval_step_bps: 0,
                retarget_every_blocks: 0,
            };
            let timing_runtime = BlockTimingRuntime {
                ema_gas_used: 0,
                effective_interval_secs: timing_params.base_interval_secs,
            };
            genesis_state.insert(
                std::str::from_utf8(BLOCK_TIMING_PARAMS_KEY)
                    .unwrap()
                    .to_string(),
                json!(format!(
                    "b64:{}",
                    BASE64_STANDARD.encode(codec::to_bytes_canonical(&timing_params).unwrap())
                )),
            );
            genesis_state.insert(
                std::str::from_utf8(BLOCK_TIMING_RUNTIME_KEY)
                    .unwrap()
                    .to_string(),
                json!(format!(
                    "b64:{}",
                    BASE64_STANDARD.encode(codec::to_bytes_canonical(&timing_runtime).unwrap())
                )),
            );
        })
        // The governance service must be enabled for the vote transaction to succeed.
        .with_initial_service(InitialServiceConfig::Governance(GovernanceParams::default()))
        .build()
        .await?;

    // Wrap the test logic in an async block to guarantee cleanup
    let test_result: anyhow::Result<()> = async {
        // 3. GET HANDLES to the node
        let node_guard = &cluster.validators[0];
        let node = node_guard.validator();
        let rpc_addr = &node.rpc_addr;
        let validator_key = &node.keypair;

        // 4. SUBMIT a VOTE from the validator using the CallService transaction
        let tx = create_call_service_tx(
            validator_key,
            "governance",
            "vote@v1",
            VoteParams {
                proposal_id: 1,
                option: VoteOption::Yes,
            },
            0, // Use nonce 0 for the validator's first transaction
            1.into(),
        )?;
        submit_transaction(rpc_addr, &tx).await?;

        // 5. Ensure the chain makes progress after submission.
        wait_for_height(rpc_addr, 2, Duration::from_secs(30)).await?;

        // 6. WAIT for the voting period to end (ends at height 3, wait for height 4).
        wait_for_height(rpc_addr, 4, Duration::from_secs(30)).await?;

        // 7. ASSERT the tallying outcome via state.
        confirm_proposal_passed_state(rpc_addr, 1, Duration::from_secs(20)).await?;
        Ok(())
    }
    .await;

    // 8. CLEANUP: Explicitly shut down all validators.
    for guard in cluster.validators {
        guard.shutdown().await?;
    }

    test_result?;

    println!("--- Governance Lifecycle E2E Test Successful ---");
    Ok(())
}