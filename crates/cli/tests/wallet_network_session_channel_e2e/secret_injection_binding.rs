use super::*;

#[tokio::test]
async fn wallet_network_secret_injection_requires_attested_request_binding() -> Result<()> {
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

        wait_for_height(rpc_addr, 1, Duration::from_secs(30)).await?;

        let secret_record = VaultSecretRecord {
            secret_id: "gmail-refresh-prod".to_string(),
            alias: "gmail".to_string(),
            kind: SecretKind::AccessToken,
            ciphertext: vec![1, 2, 3, 4],
            metadata: BTreeMap::new(),
            created_at_ms: 4_100_000_000_000,
            rotated_at_ms: None,
        };
        submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "store_secret_record@v1",
            secret_record,
        )
        .await?;
        nonce += 1;

        let request_id = unique_id("wallet_network_secret_injection_request");
        let premature_grant = SecretInjectionGrant {
            request_id,
            secret_id: "gmail-refresh-prod".to_string(),
            envelope: SecretInjectionEnvelope {
                algorithm: "xchacha20poly1305".to_string(),
                ciphertext: vec![9, 9, 9],
                aad: vec![],
            },
            issued_at_ms: 4_100_000_000_100,
            expires_at_ms: 4_100_000_060_000,
        };
        submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "grant_secret_injection@v1",
            premature_grant,
        )
        .await?;
        nonce += 1;

        let premature_lookup = service_key(&injection_grant_storage_key(&request_id));
        let premature_grant_state = query_state_key(rpc_addr, &premature_lookup).await?;
        assert!(
            premature_grant_state.is_none(),
            "grant state was persisted before attested request was recorded"
        );

        let attestation_nonce = unique_id("wallet_network_secret_injection_attestation_nonce");
        let request_record = SecretInjectionRequestRecord {
            request: SecretInjectionRequest {
                request_id,
                session_id: unique_id("wallet_network_secret_injection_session"),
                agent_id: "mail-agent".to_string(),
                secret_alias: "gmail".to_string(),
                target: ioi_types::app::ActionTarget::NetFetch,
                attestation_nonce,
                requested_at_ms: 4_100_000_000_000,
            },
            attestation: GuardianAttestation {
                quote_hash: unique_id("wallet_network_secret_injection_quote"),
                measurement_hash: unique_id("wallet_network_secret_injection_measurement"),
                guardian_ephemeral_public_key: vec![7, 7, 7],
                nonce: attestation_nonce,
                verifier_id: String::new(),
                manifest_hash: [0u8; 32],
                issued_at_ms: 4_099_999_999_000,
                expires_at_ms: 4_200_000_000_000,
                evidence: None,
            },
        };
        submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "record_secret_injection_request@v1",
            request_record,
        )
        .await?;
        nonce += 1;

        let stored_request: SecretInjectionRequest =
            load_wallet_value(rpc_addr, &injection_request_storage_key(&request_id)).await?;
        assert_eq!(stored_request.request_id, request_id);
        assert_eq!(stored_request.secret_alias, "gmail".to_string());

        let valid_grant = SecretInjectionGrant {
            request_id,
            secret_id: "gmail-refresh-prod".to_string(),
            envelope: SecretInjectionEnvelope {
                algorithm: "xchacha20poly1305".to_string(),
                ciphertext: vec![8, 8, 8, 8],
                aad: vec![1],
            },
            issued_at_ms: 4_100_000_000_200,
            expires_at_ms: 4_100_000_060_000,
        };
        submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "grant_secret_injection@v1",
            valid_grant,
        )
        .await?;

        let stored_grant: SecretInjectionGrant =
            load_wallet_value(rpc_addr, &injection_grant_storage_key(&request_id)).await?;
        assert_eq!(stored_grant.request_id, request_id);
        assert_eq!(stored_grant.secret_id, "gmail-refresh-prod".to_string());

        Ok(())
    }
    .await;

    let shutdown_result = cluster.shutdown().await;
    shutdown_result?;
    test_result
}
