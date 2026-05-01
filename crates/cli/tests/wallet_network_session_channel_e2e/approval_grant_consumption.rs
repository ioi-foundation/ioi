use super::*;

#[tokio::test]
async fn wallet_network_approval_grant_consumption_via_real_callservice_txs() -> Result<()> {
    let _guard = E2E_TEST_LOCK.lock().expect("lock");
    build_test_artifacts();

    let cluster = TestCluster::builder()
        .with_validators(1)
        .with_consensus_type("Aft")
        .with_state_tree("IAVL")
        .with_service_policy("wallet_network", wallet_network_user_policy())
        .build()
        .await?;

    let test_result: Result<()> = async {
        let node = cluster.validators[0].validator();
        let rpc_addr = &node.rpc_addr;
        let keypair = &node.keypair;
        let chain_id: ChainId = 1.into();
        let mut nonce = 0u64;
        let approval_signer = new_approval_signer()?;
        let tx_signer_audience = account_id_from_key_material(
            SignatureSuite::ED25519,
            &keypair.public().encode_protobuf(),
        )?;

        wait_for_height(rpc_addr, 1, Duration::from_secs(30)).await?;

        let request_hash_1 = unique_id("wallet_network_approval_request_1");
        let session_id_1 = unique_id("wallet_network_approval_session_1");
        let policy_hash_1 = unique_id("wallet_network_approval_policy_1");

        let interception_1 = WalletInterceptionContext {
            session_id: Some(session_id_1),
            request_hash: request_hash_1,
            target: ioi_types::app::ActionTarget::WebRetrieve,
            policy_hash: policy_hash_1,
            value_usd_micros: Some(42),
            reason: "manual approval required".to_string(),
            intercepted_at_ms: 4_100_000_000_000,
        };
        submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "record_interception@v1",
            interception_1,
        )
        .await?;
        nonce += 1;

        register_wallet_approval_authority(
            &cluster,
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            &approval_signer,
        )
        .await?;
        nonce += 1;

        let approval_1 = WalletApprovalDecision {
            interception: WalletInterceptionContext {
                session_id: Some(session_id_1),
                request_hash: request_hash_1,
                target: ioi_types::app::ActionTarget::WebRetrieve,
                policy_hash: policy_hash_1,
                value_usd_micros: Some(42),
                reason: "manual approval required".to_string(),
                intercepted_at_ms: 4_100_000_000_000,
            },
            decision: WalletApprovalDecisionKind::ApprovedByHuman,
            approval_grant: Some(signed_wallet_approval_grant(
                &approval_signer,
                request_hash_1,
                policy_hash_1,
                tx_signer_audience,
                unique_id("wallet_network_approval_grant_nonce_1"),
                1,
                Some(1),
                4_200_000_000_000,
            )?),
            surface: VaultSurface::Desktop,
            decided_at_ms: 4_100_000_000_500,
        };
        submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "record_approval@v1",
            approval_1,
        )
        .await?;
        nonce += 1;

        let stored_approval: WalletApprovalDecision =
            load_wallet_value(rpc_addr, &approval_storage_key(&request_hash_1)).await?;
        assert!(stored_approval.approval_grant.is_some());

        let consume_1 = ConsumeApprovalGrantParams {
            request_hash: request_hash_1,
            consumed_at_ms: 4_100_000_001_000,
        };
        submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "consume_approval_grant@v1",
            consume_1,
        )
        .await?;
        nonce += 1;

        let consumed_once: ApprovalConsumptionState =
            load_wallet_value(rpc_addr, &approval_consumption_storage_key(&request_hash_1)).await?;
        assert_eq!(consumed_once.max_usages, 1);
        assert_eq!(consumed_once.uses_consumed, 1);
        assert_eq!(consumed_once.remaining_usages, 0);
        assert_eq!(consumed_once.bound_audience, Some(tx_signer_audience));

        let consume_again = ConsumeApprovalGrantParams {
            request_hash: request_hash_1,
            consumed_at_ms: 4_100_000_002_000,
        };
        // Rejected wallet calls do not advance on-chain nonce, so keep the same nonce for the
        // next successful transaction and assert the invariant via state.
        let _ = submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "consume_approval_grant@v1",
            consume_again,
        )
        .await;

        let consumed_after_reuse: ApprovalConsumptionState =
            load_wallet_value(rpc_addr, &approval_consumption_storage_key(&request_hash_1)).await?;
        assert_eq!(consumed_after_reuse.uses_consumed, 1);
        assert_eq!(consumed_after_reuse.remaining_usages, 0);

        let request_hash_2 = unique_id("wallet_network_approval_request_2");
        let policy_hash_2 = unique_id("wallet_network_approval_policy_2");
        let interception_2 = WalletInterceptionContext {
            session_id: None,
            request_hash: request_hash_2,
            target: ioi_types::app::ActionTarget::NetFetch,
            policy_hash: policy_hash_2,
            value_usd_micros: None,
            reason: "manual approval required".to_string(),
            intercepted_at_ms: 4_100_000_003_000,
        };
        submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "record_interception@v1",
            interception_2,
        )
        .await?;
        nonce += 1;

        let approval_2 = WalletApprovalDecision {
            interception: WalletInterceptionContext {
                session_id: None,
                request_hash: request_hash_2,
                target: ioi_types::app::ActionTarget::NetFetch,
                policy_hash: policy_hash_2,
                value_usd_micros: None,
                reason: "manual approval required".to_string(),
                intercepted_at_ms: 4_100_000_003_000,
            },
            decision: WalletApprovalDecisionKind::ApprovedByHuman,
            approval_grant: Some(signed_wallet_approval_grant(
                &approval_signer,
                request_hash_2,
                policy_hash_2,
                tx_signer_audience,
                unique_id("wallet_network_approval_grant_nonce_2"),
                2,
                Some(1),
                4_200_000_000_000,
            )?),
            surface: VaultSurface::Desktop,
            decided_at_ms: 4_100_000_003_500,
        };
        submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "record_approval@v1",
            approval_2,
        )
        .await?;
        nonce += 1;

        submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "panic_stop@v1",
            BumpRevocationEpochParams {
                reason: "e2e revoke".to_string(),
            },
        )
        .await?;
        nonce += 1;

        let consume_revoked = ConsumeApprovalGrantParams {
            request_hash: request_hash_2,
            consumed_at_ms: 4_100_000_004_000,
        };
        let _ = submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "consume_approval_grant@v1",
            consume_revoked,
        )
        .await;

        let consumed_revoked: ApprovalConsumptionState =
            load_wallet_value(rpc_addr, &approval_consumption_storage_key(&request_hash_2)).await?;
        assert_eq!(consumed_revoked.uses_consumed, 0);
        assert_eq!(consumed_revoked.remaining_usages, 1);
        assert!(consumed_revoked.last_consumed_at_ms.is_none());

        let epoch: u64 = load_wallet_value(rpc_addr, b"revocation_epoch").await?;
        assert!(epoch >= 1);

        Ok(())
    }
    .await;

    let shutdown_result = cluster.shutdown().await;
    shutdown_result?;
    test_result
}
