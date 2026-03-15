use super::*;

#[tokio::test]
async fn wallet_network_bridge_records_firewall_interceptions_from_ingestion() -> Result<()> {
    let _guard = E2E_TEST_LOCK.lock().expect("lock");
    build_test_artifacts();

    let cluster = TestCluster::builder()
        .with_validators(1)
        .with_consensus_type("Convergent")
        .with_state_tree("IAVL")
        .with_service_policy("wallet_network", wallet_network_user_policy())
        .with_service_policy("desktop_agent", desktop_agent_user_policy())
        .build()
        .await?;

    let test_result: Result<()> = async {
        let node = cluster.validators[0].validator();
        let rpc_addr = &node.rpc_addr;
        let keypair = &node.keypair;
        let chain_id: ChainId = 1.into();
        let nonce = 0u64;

        wait_for_height(rpc_addr, 1, Duration::from_secs(30)).await?;

        let start_params = StartAgentParams {
            session_id: [0x91u8; 32],
            goal: "Open calculator".to_string(),
            max_steps: 1,
            parent_session_id: None,
            initial_budget: 1_000_000,
            mode: AgentMode::Agent,
        };
        let tx = create_call_service_tx(
            keypair,
            "desktop_agent",
            "start@v1",
            start_params,
            nonce,
            chain_id,
        )?;
        let request_hash = tx.hash()?;

        submit_transaction_no_wait(rpc_addr, &tx).await?;

        let lookup_key = service_key(&interception_storage_key(&request_hash));
        let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
        let mut found: Option<WalletInterceptionContext> = None;
        while tokio::time::Instant::now() < deadline {
            if let Some(bytes) = query_state_key(rpc_addr, &lookup_key).await? {
                let decoded: WalletInterceptionContext =
                    codec::from_bytes_canonical(&bytes).map_err(|e| anyhow!(e))?;
                found = Some(decoded);
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }

        let interception = found.ok_or_else(|| {
            anyhow!(
                "wallet_network interception record not found for request hash {}",
                hex::encode(request_hash)
            )
        })?;
        assert_eq!(interception.request_hash, request_hash);
        assert_eq!(interception.session_id, None);
        assert_eq!(
            interception.target.canonical_label(),
            "start@v1".to_string()
        );
        assert_eq!(interception.reason, "manual approval required".to_string());

        Ok(())
    }
    .await;

    let shutdown_result = cluster.shutdown().await;
    shutdown_result?;
    test_result
}
