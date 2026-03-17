#![cfg(all(feature = "consensus-aft", feature = "vm-wasm", feature = "state-iavl"))]

use anyhow::Result;
use ioi_cli::testing::{build_test_artifacts, rpc, wait_for_height, TestCluster};
use ioi_types::{
    app::{
        aft_bulletin_commitment_key, aft_order_certificate_key, BulletinCommitment,
        CanonicalOrderCertificate, CanonicalOrderProofSystem,
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
        let target_height = 6;
        wait_for_height(&rpc_addr, target_height, Duration::from_secs(60)).await?;

        for height in 2..=target_height {
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
                proof.observer_certificates.len() >= 2,
                "expected multiple equal-authority observer confirmations at height {}",
                height
            );
            assert!(
                proof.witness_certificates.is_empty(),
                "observer-mode asymptote proof should not carry witness certificates at height {}",
                height
            );
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

        for height in 1..target_height {
            let block = rpc::get_block_by_height_resilient(&rpc_addr, height)
                .await?
                .ok_or_else(|| anyhow::anyhow!("missing block at height {height}"))?;
            let expected_certificate = block
                .header
                .canonical_order_certificate
                .clone()
                .ok_or_else(|| {
                    anyhow::anyhow!("missing canonical order certificate at height {height}")
                })?;
            let certificate_key = aft_order_certificate_key(height);
            let stored_certificate = rpc::query_state_key(&rpc_addr, &certificate_key)
                .await?
                .ok_or_else(|| {
                    anyhow::anyhow!("missing on-chain order certificate at height {height}")
                })?;
            let restored_certificate: CanonicalOrderCertificate =
                codec::from_bytes_canonical(&stored_certificate).map_err(anyhow::Error::msg)?;
            assert_eq!(restored_certificate, expected_certificate);
        }

        Ok(())
    };

    let result = test_logic.await;
    if let Err(error) = cluster.shutdown().await {
        eprintln!("Error shutting down cluster: {}", error);
    }
    result
}
