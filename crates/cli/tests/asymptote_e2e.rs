#![cfg(all(feature = "consensus-aft", feature = "vm-wasm", feature = "state-iavl"))]

use anyhow::Result;
use ioi_cli::testing::{build_test_artifacts, rpc, wait_for_height, TestCluster};
use ioi_types::{
    app::{
        aft_bulletin_commitment_key, sealed_finality_proof_observer_binding, BulletinCommitment,
        CanonicalOrderProofSystem,
    },
    codec,
    config::AftSafetyMode,
};
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_asymptote_live_cluster_emits_sealed_finality_proofs() -> Result<()> {
    build_test_artifacts();

    let cluster = TestCluster::builder()
        .with_validators(3)
        .with_consensus_type("Aft")
        .with_state_tree("IAVL")
        .with_chain_id(19)
        .with_aft_safety_mode(AftSafetyMode::Asymptote)
        .build()
        .await?;

    let rpc_addr = cluster.validators[0].validator().rpc_addr.clone();

    let test_logic = async {
        let target_height = 8;
        let check_start_height = 4;
        wait_for_height(&rpc_addr, target_height, Duration::from_secs(60)).await?;

        // The first few live slots can still reflect bootstrap-era collapse state while the
        // cluster finishes converging on peer visibility and publication surfaces. Validate the
        // stable post-convergence window instead of the startup boundary.
        for height in check_start_height..=target_height {
            let mut sealed = None;
            for _ in 0..20 {
                let block = rpc::get_block_by_height_resilient(&rpc_addr, height)
                    .await?
                    .ok_or_else(|| anyhow::anyhow!("missing block at height {height}"))?;
                if block.header.sealed_finality_proof.is_some() {
                    sealed = Some(block);
                    break;
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }

            let block = sealed.ok_or_else(|| {
                anyhow::anyhow!("missing sealed finality proof at height {height}")
            })?;
            let proof = block
                .header
                .sealed_finality_proof
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("missing sealed proof at height {height}"))?;
            let order_certificate = block
                .header
                .canonical_order_certificate
                .as_ref()
                .ok_or_else(|| {
                    anyhow::anyhow!("missing canonical order certificate at height {height}")
                })?;
            assert_eq!(
                proof.finality_tier,
                ioi_types::app::FinalityTier::SealedFinal
            );
            assert_eq!(
                proof.collapse_state,
                ioi_types::app::CollapseState::SealedFinal
            );
            assert!(
                proof.witness_certificates.is_empty(),
                "observer-mode asymptote proof should not carry witness certificates at height {}",
                height
            );
            assert!(
                proof.observer_canonical_close.is_some(),
                "expected canonical observer close in sealed proof at height {}",
                height
            );
            assert!(
                proof.observer_canonical_abort.is_none(),
                "sealed-final asymptote proof may not carry a canonical observer abort at height {}",
                height
            );
            assert!(
                proof.veto_proofs.is_empty(),
                "sealed-final asymptote proof should not carry veto proofs at height {}",
                height
            );
            let observer_binding =
                sealed_finality_proof_observer_binding(proof).map_err(anyhow::Error::msg)?;
            if let Some(close) = proof.observer_canonical_close.as_ref() {
                assert_eq!(close.height, height);
                assert_eq!(
                    close.transcript_count,
                    proof.observer_transcripts.len() as u16
                );
                assert_eq!(
                    close.challenge_count,
                    proof.observer_challenges.len() as u16
                );
                assert_eq!(
                    observer_binding.resolution_hash,
                    ioi_types::app::canonical_asymptote_observer_canonical_close_hash(close)
                        .map_err(anyhow::Error::msg)?
                );
            }
            assert_eq!(order_certificate.height, height);
            assert_eq!(order_certificate.bulletin_commitment.height, height);
            assert!(order_certificate.omission_proofs.is_empty());
            assert_eq!(
                order_certificate.proof.proof_system,
                CanonicalOrderProofSystem::CommittedSurfaceV1
            );
            assert_eq!(
                order_certificate.ordered_transactions_root_hash,
                ioi_types::app::to_root_hash(&block.header.transactions_root)?
            );
            assert_eq!(
                order_certificate.resulting_state_root_hash,
                ioi_types::app::to_root_hash(&block.header.state_root.0)?
            );

            let bulletin_key = aft_bulletin_commitment_key(height);
            let stored_bulletin = rpc::query_state_key(&rpc_addr, &bulletin_key)
                .await?
                .ok_or_else(|| {
                    anyhow::anyhow!("missing on-chain bulletin commitment at height {height}")
                })?;
            let restored_bulletin: BulletinCommitment =
                codec::from_bytes_canonical(&stored_bulletin).map_err(anyhow::Error::msg)?;
            assert_eq!(restored_bulletin, order_certificate.bulletin_commitment);
        }
        Ok(())
    };

    let result = test_logic.await;
    if let Err(error) = cluster.shutdown().await {
        eprintln!("Error shutting down cluster: {}", error);
    }
    result
}
