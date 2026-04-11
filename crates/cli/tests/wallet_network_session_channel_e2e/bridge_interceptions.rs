use super::*;
use ioi_types::keys::active_service_key;
use ioi_types::service_configs::{ActiveServiceMeta, Capabilities};

async fn drain_recent_logs(
    receiver: &mut tokio::sync::broadcast::Receiver<String>,
    sink: &mut Vec<String>,
    label: &str,
) {
    loop {
        match receiver.try_recv() {
            Ok(line) => sink.push(format!("[{label}] {line}")),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty) => break,
            Err(tokio::sync::broadcast::error::TryRecvError::Lagged(skipped)) => {
                sink.push(format!("[{label}] <lagged {skipped} log lines>"));
            }
            Err(tokio::sync::broadcast::error::TryRecvError::Closed) => break,
        }
    }
}

#[tokio::test]
async fn wallet_network_bridge_records_firewall_interceptions_from_ingestion() -> Result<()> {
    let _guard = E2E_TEST_LOCK.lock().expect("lock");
    build_test_artifacts();

    let cluster = TestCluster::builder()
        .with_validators(1)
        .with_consensus_type("Aft")
        .with_state_tree("IAVL")
        .with_service_policy("wallet_network", wallet_network_user_policy())
        .with_service_policy("desktop_agent", desktop_agent_user_policy())
        .with_genesis_modifier(|genesis, _| {
            let policy = desktop_agent_user_policy();
            let meta = ActiveServiceMeta {
                id: "desktop_agent".to_string(),
                abi_version: 1,
                state_schema: "v1".to_string(),
                caps: Capabilities::empty(),
                artifact_hash: [0u8; 32],
                activated_at: 0,
                methods: policy.methods,
                allowed_system_prefixes: policy.allowed_system_prefixes,
                generation_id: 0,
                parent_hash: None,
                author: None,
                context_filter: None,
            };
            genesis.insert_typed(active_service_key("desktop_agent"), &meta);
        })
        .build()
        .await?;

    let test_result: Result<()> = async {
        let node = cluster.validators[0].validator();
        let (mut orch_logs, mut workload_logs, _) = node.subscribe_logs();
        let mut recent_logs = Vec::new();
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
        let request_hash = tx.hash().map_err(|e| anyhow!(e))?;
        let tx_hash = submit_transaction_no_wait(rpc_addr, &tx).await?;
        assert_eq!(tx_hash, hex::encode(request_hash));

        let lookup_key = service_key(&interception_storage_key(&request_hash));
        let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
        let mut found: Option<WalletInterceptionContext> = None;
        while tokio::time::Instant::now() < deadline {
            drain_recent_logs(&mut orch_logs, &mut recent_logs, "orch").await;
            drain_recent_logs(&mut workload_logs, &mut recent_logs, "work").await;
            if let Some(bytes) = query_state_key(rpc_addr, &lookup_key).await? {
                let decoded: WalletInterceptionContext =
                    codec::from_bytes_canonical(&bytes).map_err(|e| anyhow!(e))?;
                found = Some(decoded);
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }

        let interception = found.ok_or_else(|| {
            let tail = recent_logs
                .iter()
                .rev()
                .take(20)
                .cloned()
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect::<Vec<_>>()
                .join("\n");
            anyhow!(
                "wallet_network interception record not found for request hash {}\nrecent logs:\n{}",
                hex::encode(request_hash),
                tail
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
