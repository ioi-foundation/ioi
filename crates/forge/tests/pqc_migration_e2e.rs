// Path: crates/forge/tests/pqc_migration_e2e.rs
#![cfg(all(
    any(feature = "consensus-poa", feature = "consensus-pos"),
    feature = "vm-wasm"
))]

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use ioi_api::crypto::{SerializableKey, SigningKeyPair};
use ioi_crypto::security::SecurityLevel;
use ioi_crypto::sign::dilithium::{DilithiumKeyPair, DilithiumScheme};
use ioi_crypto::sign::eddsa::Ed25519KeyPair;
use ioi_forge::testing::{
    add_genesis_identity_custom, build_test_artifacts, rpc::query_state_key, submit_transaction,
    wait_for_height, TestCluster,
};
use ioi_services::{governance::VoteParams, identity::RotateKeyParams};
use ioi_types::{
    app::{
        account_id_from_key_material, AccountId, ActiveKeyRecord, ChainId, ChainTransaction,
        Credential, Proposal, ProposalStatus, ProposalType, RotationProof, SignHeader,
        SignatureProof, SignatureSuite, StateEntry, SystemPayload, SystemTransaction,
        ValidatorSetV1, ValidatorSetsV1, ValidatorV1, VoteOption,
    },
    codec,
    config::InitialServiceConfig,
    keys::{GOVERNANCE_PROPOSAL_KEY_PREFIX, GOVERNANCE_VOTE_KEY_PREFIX, VALIDATOR_SET_KEY},
    service_configs::MigrationConfig,
};
use libp2p::identity::{self, Keypair};
use parity_scale_codec::Encode;
use serde_json::{json, Value};
use std::time::Duration;

// --- Trait to unify signing for different key types in tests ---
trait TestSigner {
    fn public_bytes(&self) -> Vec<u8>;
    fn sign(&self, msg: &[u8]) -> Vec<u8>;
    fn account_id(&self) -> AccountId;
    fn suite(&self) -> SignatureSuite;
    fn libp2p_public_bytes(&self) -> Vec<u8>;
}

impl TestSigner for Ed25519KeyPair {
    fn public_bytes(&self) -> Vec<u8> {
        SigningKeyPair::public_key(self).to_bytes()
    }
    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        SigningKeyPair::sign(self, msg).unwrap().to_bytes()
    }
    fn account_id(&self) -> AccountId {
        let account_hash =
            account_id_from_key_material(self.suite(), &self.libp2p_public_bytes()).unwrap();
        AccountId(account_hash)
    }
    fn suite(&self) -> SignatureSuite {
        SignatureSuite::Ed25519
    }
    fn libp2p_public_bytes(&self) -> Vec<u8> {
        let pk_bytes = self.public_key().to_bytes();
        let libp2p_ed25519_pk =
            libp2p::identity::ed25519::PublicKey::try_from_bytes(&pk_bytes).unwrap();
        let libp2p_pk = libp2p::identity::PublicKey::from(libp2p_ed25519_pk);
        libp2p_pk.encode_protobuf()
    }
}

impl TestSigner for DilithiumKeyPair {
    fn public_bytes(&self) -> Vec<u8> {
        SigningKeyPair::public_key(self).to_bytes()
    }
    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        SigningKeyPair::sign(self, msg).unwrap().to_bytes()
    }
    fn account_id(&self) -> AccountId {
        let account_hash =
            account_id_from_key_material(self.suite(), &self.public_bytes()).unwrap();
        AccountId(account_hash)
    }
    fn suite(&self) -> SignatureSuite {
        SignatureSuite::Dilithium2
    }
    fn libp2p_public_bytes(&self) -> Vec<u8> {
        self.public_bytes()
    }
}

// Updated helper: header.account_id is provided explicitly (stable across rotations)
fn create_call_service_tx<S: TestSigner, P: Encode>(
    signer: &S,
    account_id: AccountId,
    service_id: &str,
    method: &str,
    params: P,
    nonce: u64,
    chain_id: ChainId,
) -> Result<ChainTransaction> {
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
    let signature = TestSigner::sign(signer, &sign_bytes);

    tx_to_sign.signature_proof = SignatureProof {
        suite: signer.suite(),
        public_key: signer.public_bytes(),
        signature,
    };
    Ok(ChainTransaction::System(Box::new(tx_to_sign)))
}

#[tokio::test]
async fn test_pqc_identity_migration_lifecycle() -> Result<()> {
    std::env::set_var("ORCH_BLOCK_INTERVAL_SECS", "2");

    // 1. SETUP
    build_test_artifacts();
    let ed25519_key = Ed25519KeyPair::generate().unwrap();
    let dilithium_scheme = DilithiumScheme::new(SecurityLevel::Level2);
    let dilithium_key = dilithium_scheme.generate_keypair().unwrap();
    let account_id = ed25519_key.account_id();
    let mut nonce = 0;
    let grace_period_blocks = 5u64;
    let chain_id: ChainId = 1.into();

    let validator_keypair = libp2p::identity::Keypair::generate_ed25519();
    let ed25519_key_clone_for_genesis = ed25519_key.clone();

    // 2. LAUNCH CLUSTER
    let cluster = TestCluster::builder()
        .with_validators(1)
        .with_keypairs(vec![validator_keypair.clone()])
        .with_consensus_type("ProofOfStake")
        .with_state_tree("IAVL")
        .with_chain_id(chain_id.into())
        .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
            grace_period_blocks,
            chain_id: chain_id.into(),
            accept_staged_during_grace: true,
            allowed_target_suites: vec![SignatureSuite::Ed25519, SignatureSuite::Dilithium2],
            allow_downgrade: false,
        }))
        .with_initial_service(InitialServiceConfig::Governance(Default::default()))
        .with_genesis_modifier(move |genesis, _keys| {
            let genesis_state = genesis["genesis_state"].as_object_mut().unwrap();

            // Setup identity for the validator
            let validator_account_id = add_genesis_identity_custom(
                genesis_state,
                SignatureSuite::Ed25519,
                &validator_keypair.public().encode_protobuf(),
            );

            // Setup identity for the user account that will rotate its key
            add_genesis_identity_custom(
                genesis_state,
                ed25519_key_clone_for_genesis.suite(),
                &ed25519_key_clone_for_genesis.libp2p_public_bytes(),
            );

            // We still need the hash for the consensus key record manually here because ValidatorV1 needs it
            let validator_pk_hash = validator_account_id.0;

            let initial_stake = 100_000u128;
            let validators = vec![ValidatorV1 {
                account_id: validator_account_id,
                weight: initial_stake,
                consensus_key: ActiveKeyRecord {
                    suite: SignatureSuite::Ed25519,
                    public_key_hash: validator_pk_hash,
                    since_height: 0,
                },
            }];

            let validator_sets = ValidatorSetsV1 {
                current: ValidatorSetV1 {
                    effective_from_height: 1,
                    total_weight: initial_stake,
                    validators,
                },
                next: None,
            };

            let vs_bytes = ioi_types::app::write_validator_sets(&validator_sets).unwrap();
            genesis_state.insert(
                std::str::from_utf8(VALIDATOR_SET_KEY).unwrap().to_string(),
                json!(format!("b64:{}", BASE64_STANDARD.encode(vs_bytes))),
            );

            // Add a dummy proposal so the governance::vote call is valid
            let proposal = Proposal {
                id: 1,
                title: "Dummy Proposal".to_string(),
                description: "".to_string(),
                proposal_type: ProposalType::Text,
                status: ProposalStatus::VotingPeriod,
                submitter: vec![],
                submit_height: 0,
                deposit_end_height: 0,
                voting_start_height: 1,
                voting_end_height: u64::MAX, // Keep it open forever for simplicity
                total_deposit: 0,
                final_tally: None,
            };

            // Write the proposal into the governance service namespace
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
                format!("b64:{}", BASE64_STANDARD.encode(&proposal_key_bytes)),
                json!(format!("b64:{}", BASE64_STANDARD.encode(&entry_bytes))),
            );
        })
        .build()
        .await?;

    let test_result: anyhow::Result<()> = async {
        let node = &cluster.validators[0];
        let rpc_addr = &node.validator().rpc_addr;
        wait_for_height(rpc_addr, 1, Duration::from_secs(20)).await?;

        // 3. INITIATE ROTATION
        let challenge = {
            let mut preimage = b"DePIN-PQ-MIGRATE/v1".to_vec();
            preimage.extend_from_slice(&<ChainId as Into<u32>>::into(chain_id).to_le_bytes());
            preimage.extend_from_slice(account_id.as_ref());
            let rotation_nonce = 0u64;
            preimage.extend_from_slice(&rotation_nonce.to_le_bytes());
            ioi_crypto::algorithms::hash::sha256(&preimage).unwrap()
        };
        let rotation_proof = RotationProof {
            old_public_key: ed25519_key.public_bytes(),
            old_signature: TestSigner::sign(&ed25519_key, &challenge),
            new_public_key: dilithium_key.public_bytes(),
            new_signature: TestSigner::sign(&dilithium_key, &challenge),
            target_suite: SignatureSuite::Dilithium2,
            l2_location: None,
        };
        let rotate_tx = create_call_service_tx(
            &ed25519_key,
            account_id,
            "identity_hub",
            "rotate_key@v1",
            RotateKeyParams {
                proof: rotation_proof,
            },
            nonce,
            chain_id,
        )?;
        submit_transaction(rpc_addr, &rotate_tx).await?;
        nonce += 1;

        wait_for_height(rpc_addr, 2, Duration::from_secs(20)).await?;

        // 4. TEST GRACE PERIOD
        // Send with old key (nonce=1)
        let old_key_tx = create_call_service_tx(
            &ed25519_key,
            account_id,
            "governance",
            "vote@v1",
            VoteParams {
                proposal_id: 1,
                option: VoteOption::Yes,
            },
            nonce,
            chain_id,
        )?;
        submit_transaction(rpc_addr, &old_key_tx).await?;
        nonce += 1;

        wait_for_height(rpc_addr, 3, Duration::from_secs(20)).await?;

        // Send with new key (nonce=2)
        let new_key_tx = create_call_service_tx(
            &dilithium_key,
            account_id,
            "governance",
            "vote@v1",
            VoteParams {
                proposal_id: 1,
                option: VoteOption::No,
            },
            nonce,
            chain_id,
        )?;
        submit_transaction(rpc_addr, &new_key_tx).await?;
        nonce += 1;

        wait_for_height(rpc_addr, 4, Duration::from_secs(20)).await?;

        // 5. TEST POST-GRACE PERIOD
        wait_for_height(rpc_addr, 8, Duration::from_secs(60)).await?;

        // 5a. Submit tx with OLD, EXPIRED key. It should be rejected.
        let old_key_tx = create_call_service_tx(
            &ed25519_key,
            account_id,
            "governance",
            "vote@v1",
            VoteParams {
                proposal_id: 1,
                option: VoteOption::Yes,
            },
            nonce,
            chain_id,
        )?;
        let _ = submit_transaction(rpc_addr, &old_key_tx).await;

        // 5b. Submit tx with NEW, ACTIVE key with the same nonce. This should succeed.
        let new_key_tx = create_call_service_tx(
            &dilithium_key,
            account_id,
            "governance",
            "vote@v1",
            VoteParams {
                proposal_id: 1,
                option: VoteOption::NoWithVeto, // Use a different vote to ensure state changes
            },
            nonce,
            chain_id,
        )?;
        submit_transaction(rpc_addr, &new_key_tx).await?;
        nonce += 1;

        // 5c. VERIFY THE STATE
        let current_height = ioi_forge::testing::rpc::get_chain_height(rpc_addr).await?;
        wait_for_height(rpc_addr, current_height + 2, Duration::from_secs(20)).await?;

        // Use the correct namespaced key to query the vote
        let vote_key = [
            ioi_api::state::service_namespace_prefix("governance").as_slice(),
            GOVERNANCE_VOTE_KEY_PREFIX,
            &1u64.to_le_bytes(), // proposal_id
            b"::",
            account_id.as_ref(),
        ]
        .concat();

        let vote_val_bytes = query_state_key(rpc_addr, &vote_key)
            .await?
            .ok_or_else(|| anyhow!("Vote from new active key must be present in state"))?;
        let vote_option: VoteOption = codec::from_bytes_canonical(&vote_val_bytes)
            .map_err(|e| anyhow!("Failed to decode vote option from state: {}", e))?;
        assert_eq!(
            vote_option,
            VoteOption::NoWithVeto,
            "The vote should reflect the last successful transaction from the new key"
        );

        println!("SUCCESS: State correctly mutated by new PQC key post-grace period, and not by expired key.");

        // 5d. Final check that the new key can continue to submit transactions.
        let final_tx = create_call_service_tx(
            &dilithium_key,
            account_id,
            "governance",
            "vote@v1",
            VoteParams {
                proposal_id: 1,
                option: VoteOption::Abstain,
            },
            nonce,
            chain_id,
        )?;
        submit_transaction(rpc_addr, &final_tx).await?;
        let final_height = ioi_forge::testing::rpc::get_chain_height(rpc_addr).await?;
        wait_for_height(rpc_addr, final_height + 1, Duration::from_secs(20)).await?;

        Ok(())
    }
    .await;

    for guard in cluster.validators {
        guard.shutdown().await?;
    }

    test_result?;

    println!("--- PQC Identity Migration E2E Test Passed ---");
    Ok(())
}
