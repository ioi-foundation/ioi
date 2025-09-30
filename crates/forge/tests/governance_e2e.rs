// Path: crates/forge/tests/governance_e2e.rs

#![cfg(all(feature = "consensus-poa", feature = "vm-wasm"))]

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use depin_sdk_forge::testing::{
    build_test_artifacts,
    poll::{confirm_proposal_passed_state, wait_for_height},
    submit_transaction, TestCluster,
};
use depin_sdk_types::{
    app::{
        account_id_from_key_material, AccountId, ActiveKeyRecord, ChainId, ChainTransaction,
        Credential, Proposal, ProposalStatus, ProposalType, SignHeader, SignatureProof,
        SignatureSuite, StateEntry, SystemPayload, SystemTransaction, ValidatorSetBlob,
        ValidatorSetV1, ValidatorSetsV1, ValidatorV1, VoteOption,
    },
    codec,
    config::InitialServiceConfig,
    keys::{
        ACCOUNT_ID_TO_PUBKEY_PREFIX, GOVERNANCE_KEY, GOVERNANCE_PROPOSAL_KEY_PREFIX,
        IDENTITY_CREDENTIALS_PREFIX, VALIDATOR_SET_KEY,
    },
    service_configs::{GovernanceParams, MigrationConfig},
};
use libp2p::identity::{self, Keypair};
use serde_json::json;
use std::time::Duration;

// Helper function to create a signed system transaction
fn create_system_tx(
    keypair: &Keypair,
    payload: SystemPayload,
    nonce: u64,
    chain_id: ChainId,
) -> Result<ChainTransaction> {
    let public_key_bytes = keypair.public().encode_protobuf();
    let account_id_hash = account_id_from_key_material(SignatureSuite::Ed25519, &public_key_bytes)?;
    let account_id = AccountId(account_id_hash);

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
    let sign_bytes = tx_to_sign.to_sign_bytes()?;
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
    let governance_key = identity::Keypair::generate_ed25519();
    let governance_pubkey_b58 =
        bs58::encode(governance_key.public().try_into_ed25519()?.to_bytes()).into_string();

    let governance_key_clone = governance_key.clone();

    // 2. LAUNCH CLUSTER with a custom genesis state
    let mut cluster = TestCluster::builder()
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
        .with_initial_service(InitialServiceConfig::Governance(GovernanceParams::default()))
        .with_genesis_modifier(move |genesis, keys| {
            let genesis_state = genesis["genesis_state"].as_object_mut().unwrap();
            // Setup validator identity
            let validator_key = &keys[0];
            let suite = SignatureSuite::Ed25519;
            let validator_pk_bytes = validator_key.public().encode_protobuf();
            let validator_account_id_hash =
                account_id_from_key_material(suite, &validator_pk_bytes).unwrap();
            let validator_account_id = AccountId(validator_account_id_hash);

            // A. Set the validator set with the validator having stake for voting power
            let vs_blob = ValidatorSetBlob {
                schema_version: 2,
                payload: ValidatorSetsV1 {
                    current: ValidatorSetV1 {
                        effective_from_height: 1,
                        total_weight: 1_000_000,
                        validators: vec![ValidatorV1 {
                            account_id: validator_account_id,
                            weight: 1_000_000,
                            consensus_key: ActiveKeyRecord {
                                suite,
                                pubkey_hash: validator_account_id_hash,
                                since_height: 0,
                            },
                        }],
                    },
                    next: None,
                },
            };
            let vs_bytes = depin_sdk_types::app::write_validator_sets(&vs_blob.payload).unwrap();
            genesis_state.insert(
                std::str::from_utf8(VALIDATOR_SET_KEY).unwrap().to_string(),
                json!(format!("b64:{}", BASE64_STANDARD.encode(vs_bytes))),
            );

            // B. Set the governance key
            genesis_state.insert(
                std::str::from_utf8(GOVERNANCE_KEY).unwrap().to_string(),
                json!(governance_pubkey_b58),
            );

            // C. Create a pre-funded proposal that will end soon
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
                voting_end_height: 3, // Voting ends after block 3
                total_deposit: 10000,
                final_tally: None,
            };
            let proposal_key_bytes = [GOVERNANCE_PROPOSAL_KEY_PREFIX, &1u64.to_le_bytes()].concat();
            let entry = StateEntry {
                value: codec::to_bytes_canonical(&proposal).unwrap(),
                block_height: 0,
            };
            let entry_bytes = codec::to_bytes_canonical(&entry).unwrap();
            genesis_state.insert(
                format!("b64:{}", BASE64_STANDARD.encode(proposal_key_bytes)),
                json!(format!("b64:{}", BASE64_STANDARD.encode(&entry_bytes))),
            );

            // D. Set up identity records needed for signature validation
            let gov_pk_bytes = governance_key_clone.public().encode_protobuf(); // Use the cloned key
            let gov_account_id =
                AccountId(account_id_from_key_material(suite, &gov_pk_bytes).unwrap());

            for (key, acct_id) in [
                (validator_key, validator_account_id),
                (&governance_key_clone, gov_account_id),
            ] {
                let pk_bytes = key.public().encode_protobuf();
                let cred = Credential {
                    suite,
                    public_key_hash: acct_id.0,
                    activation_height: 0,
                    l2_location: None,
                };
                let creds_array: [Option<Credential>; 2] = [Some(cred), None];
                let creds_bytes = codec::to_bytes_canonical(&creds_array).unwrap();
                let creds_key = [IDENTITY_CREDENTIALS_PREFIX, acct_id.as_ref()].concat();
                genesis_state.insert(
                    format!("b64:{}", BASE64_STANDARD.encode(&creds_key)),
                    json!(format!("b64:{}", BASE64_STANDARD.encode(&creds_bytes))),
                );

                let record = ActiveKeyRecord {
                    suite,
                    pubkey_hash: acct_id.0,
                    since_height: 0,
                };
                let record_key = [b"identity::key_record::", acct_id.as_ref()].concat();
                genesis_state.insert(
                    format!("b64:{}", BASE64_STANDARD.encode(&record_key)),
                    json!(format!(
                        "b64:{}",
                        BASE64_STANDARD.encode(codec::to_bytes_canonical(&record).unwrap())
                    )),
                );

                let pubkey_map_key = [ACCOUNT_ID_TO_PUBKEY_PREFIX, acct_id.as_ref()].concat();
                genesis_state.insert(
                    format!("b64:{}", BASE64_STANDARD.encode(&pubkey_map_key)),
                    json!(format!("b64:{}", BASE64_STANDARD.encode(&pk_bytes))),
                );
            }
        })
        .build()
        .await?;

    // 3. GET HANDLES to the node
    let node = &mut cluster.validators[0];
    let rpc_addr = &node.rpc_addr;
    let validator_key = &node.keypair;

    // 4. SUBMIT a VOTE from the validator
    let payload = SystemPayload::Vote {
        proposal_id: 1,
        option: VoteOption::Yes,
    };
    // Use nonce 0 for the validator's first transaction
    let tx = create_system_tx(validator_key, payload, 0, 1.into())?;
    submit_transaction(rpc_addr, &tx).await?;

    // 5. (Non-brittle) Ensure the chain makes progress after submission.
    // If the tx was accepted by the mempool and is valid, we will see the next block produced.
    wait_for_height(rpc_addr, 2, Duration::from_secs(30)).await?;

    // 6. WAIT for the voting period to end. The proposal ends at height 3, so wait for height 4
    // to ensure the OnEndBlock hook for height 3 has been processed and committed.
    wait_for_height(rpc_addr, 4, Duration::from_secs(30)).await?;

    // 7. ASSERT the tallying outcome via state (authoritative and non-brittle).
    confirm_proposal_passed_state(rpc_addr, 1, Duration::from_secs(20)).await?;

    println!("--- Governance Lifecycle E2E Test Successful ---");
    Ok(())
}
