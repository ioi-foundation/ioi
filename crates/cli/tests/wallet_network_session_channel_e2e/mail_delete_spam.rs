use super::*;

#[tokio::test]
async fn wallet_network_mail_delete_spam_via_real_callservice_txs() -> Result<()> {
    let _guard = E2E_TEST_LOCK.lock().expect("lock");
    build_test_artifacts();

    let cluster = TestCluster::builder()
        .with_validators(1)
        .with_consensus_type("Admft")
        .with_state_tree("IAVL")
        .with_service_policy("wallet_network", wallet_network_user_policy())
        .build()
        .await?;

    let test_result: Result<()> = async {
        let node = cluster.validators[0].validator();
        let rpc_addr = &node.rpc_addr;
        let keypair = &node.keypair;
        let chain_id: ChainId = 1.into();
        let signer_account_id = account_id_from_key_material(
            SignatureSuite::ED25519,
            &keypair.public().encode_protobuf(),
        )?;
        let mut nonce = 0u64;
        let lc_signer = new_hybrid_signer()?;
        let rc_signer = new_hybrid_signer()?;

        wait_for_height(rpc_addr, 1, Duration::from_secs(30)).await?;

        let channel_id = [0x91u8; 32];
        let lease_id = [0x92u8; 32];
        let envelope = SessionChannelEnvelope {
            channel_id,
            lc_id: lc_signer.signer_id,
            rc_id: rc_signer.signer_id,
            ordering: SessionChannelOrdering::Ordered,
            mode: SessionChannelMode::RemoteRequestLocalExecution,
            policy_hash: [0x93u8; 32],
            policy_version: 3,
            root_grant_id: [0x94u8; 32],
            capability_set: vec!["mail.write".to_string()],
            constraints: BTreeMap::from([("mailbox".to_string(), "spam".to_string())]),
            delegation_rules: SessionChannelDelegationRules {
                max_depth: 1,
                can_redelegate: false,
                issuance_budget: Some(2),
            },
            revocation_epoch: 0,
            expires_at_ms: 4_300_000_000_000,
        };
        let envelope_hash = hash_channel_envelope(&envelope)?;

        let mut open_init = SessionChannelOpenInit {
            envelope: envelope.clone(),
            lc_kem_ephemeral_pub_classical: vec![41, 42, 43],
            lc_kem_ephemeral_pub_pq: vec![44, 45, 46],
            nonce_lc: [0x95u8; 32],
            sig_hybrid_lc: Vec::new(),
        };
        let mut open_init_unsigned = open_init.clone();
        open_init_unsigned.sig_hybrid_lc.clear();
        open_init.sig_hybrid_lc =
            sign_hybrid_payload(&lc_signer, &encode_canonical(&open_init_unsigned)?)?;
        submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "open_channel_init@v1",
            open_init,
        )
        .await?;
        nonce += 1;

        let mut open_try = SessionChannelOpenTry {
            channel_id,
            envelope_hash,
            rc_attestation_evidence: vec![47, 48],
            rc_attestation_pub: vec![49, 50],
            rc_kem_ephemeral_pub_classical: vec![51, 52],
            rc_kem_ciphertext_pq: vec![53, 54],
            nonce_rc: [0x96u8; 32],
            sig_hybrid_rc: Vec::new(),
        };
        let mut open_try_unsigned = open_try.clone();
        open_try_unsigned.sig_hybrid_rc.clear();
        open_try.sig_hybrid_rc =
            sign_hybrid_payload(&rc_signer, &encode_canonical(&open_try_unsigned)?)?;
        submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "open_channel_try@v1",
            open_try,
        )
        .await?;
        nonce += 1;

        let mut open_ack = SessionChannelOpenAck {
            channel_id,
            envelope_hash,
            nonce_lc2: [0x97u8; 32],
            sig_hybrid_lc: Vec::new(),
        };
        let mut open_ack_unsigned = open_ack.clone();
        open_ack_unsigned.sig_hybrid_lc.clear();
        open_ack.sig_hybrid_lc =
            sign_hybrid_payload(&lc_signer, &encode_canonical(&open_ack_unsigned)?)?;
        submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "open_channel_ack@v1",
            open_ack,
        )
        .await?;
        nonce += 1;

        let mut open_confirm = SessionChannelOpenConfirm {
            channel_id,
            envelope_hash,
            nonce_rc2: [0x98u8; 32],
            sig_hybrid_rc: Vec::new(),
        };
        let mut open_confirm_unsigned = open_confirm.clone();
        open_confirm_unsigned.sig_hybrid_rc.clear();
        open_confirm.sig_hybrid_rc =
            sign_hybrid_payload(&rc_signer, &encode_canonical(&open_confirm_unsigned)?)?;
        submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "open_channel_confirm@v1",
            open_confirm,
        )
        .await?;
        nonce += 1;

        let channel: SessionChannelRecord =
            load_wallet_value(rpc_addr, &channel_storage_key(&channel_id)).await?;
        assert_eq!(channel.state, SessionChannelState::Open);

        for (secret_id, alias, value) in [
            (
                "mail-imap-user-delete",
                "mail.imap.user.delete",
                "agent@example.com",
            ),
            (
                "mail-imap-pass-delete",
                "mail.imap.pass.delete",
                "imap-password",
            ),
            (
                "mail-smtp-user-delete",
                "mail.smtp.user.delete",
                "agent@example.com",
            ),
            (
                "mail-smtp-pass-delete",
                "mail.smtp.pass.delete",
                "smtp-password",
            ),
        ] {
            submit_wallet_call(
                rpc_addr,
                keypair,
                chain_id,
                nonce,
                "store_secret_record@v1",
                VaultSecretRecord {
                    secret_id: secret_id.to_string(),
                    alias: alias.to_string(),
                    kind: SecretKind::AccessToken,
                    ciphertext: value.as_bytes().to_vec(),
                    metadata: BTreeMap::new(),
                    created_at_ms: 4_100_000_000_000,
                    rotated_at_ms: None,
                },
            )
            .await?;
            nonce += 1;
        }

        submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "mail_connector_upsert@v1",
            MailConnectorUpsertParams {
                mailbox: "spam".to_string(),
                config: MailConnectorConfig {
                    provider: MailConnectorProvider::ImapSmtp,
                    auth_mode: MailConnectorAuthMode::Password,
                    account_email: "agent@example.com".to_string(),
                    sender_display_name: None,
                    imap: MailConnectorEndpoint {
                        host: "mock.local".to_string(),
                        port: 993,
                        tls_mode: MailConnectorTlsMode::Tls,
                    },
                    smtp: MailConnectorEndpoint {
                        host: "mock.local".to_string(),
                        port: 465,
                        tls_mode: MailConnectorTlsMode::Tls,
                    },
                    secret_aliases: MailConnectorSecretAliases {
                        imap_username_alias: "mail.imap.user.delete".to_string(),
                        imap_password_alias: "mail.imap.pass.delete".to_string(),
                        smtp_username_alias: "mail.smtp.user.delete".to_string(),
                        smtp_password_alias: "mail.smtp.pass.delete".to_string(),
                    },
                    metadata: BTreeMap::from([("driver".to_string(), "mock".to_string())]),
                },
            },
        )
        .await?;
        nonce += 1;

        let mut lease = SessionLease {
            lease_id,
            channel_id,
            issuer_id: lc_signer.signer_id,
            subject_id: [0x99u8; 32],
            policy_hash: envelope.policy_hash,
            grant_id: [0x9au8; 32],
            capability_subset: vec!["mail.write".to_string()],
            constraints_subset: BTreeMap::from([("mailbox".to_string(), "spam".to_string())]),
            mode: SessionLeaseMode::Lease,
            expires_at_ms: 4_250_000_000_000,
            revocation_epoch: 0,
            audience: signer_account_id,
            nonce: [0x9bu8; 32],
            counter: 1,
            issued_at_ms: 4_100_000_000_000,
            sig_hybrid_lc: Vec::new(),
        };
        let mut lease_unsigned = lease.clone();
        lease_unsigned.sig_hybrid_lc.clear();
        lease.sig_hybrid_lc = sign_hybrid_payload(&lc_signer, &encode_canonical(&lease_unsigned)?)?;
        submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "issue_session_lease@v1",
            lease.clone(),
        )
        .await?;
        nonce += 1;

        let delete_op1 = [0xa1u8; 32];
        submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "mail_delete_spam@v1",
            MailDeleteSpamParams {
                operation_id: delete_op1,
                channel_id,
                lease_id,
                op_seq: 1,
                op_nonce: Some([0xa2u8; 32]),
                mailbox: "spam".to_string(),
                max_delete: 7,
                requested_at_ms: 4_100_000_000_010,
            },
        )
        .await?;
        nonce += 1;

        let delete_receipt1: MailDeleteSpamReceipt =
            load_wallet_value(rpc_addr, &mail_delete_receipt_storage_key(&delete_op1)).await?;
        assert_eq!(delete_receipt1.channel_id, channel_id);
        assert_eq!(delete_receipt1.lease_id, lease_id);
        assert_eq!(delete_receipt1.mailbox, "spam");
        assert_eq!(delete_receipt1.deleted_count, 7);
        assert_eq!(delete_receipt1.high_confidence_deleted_count, 7);
        assert!(delete_receipt1.evaluated_count >= delete_receipt1.deleted_count);
        assert!(delete_receipt1.spam_confidence_threshold_bps > 0);
        assert!(!delete_receipt1.ontology_version.trim().is_empty());

        let constrained_op = [0xa3u8; 32];
        let _ = submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "mail_delete_spam@v1",
            MailDeleteSpamParams {
                operation_id: constrained_op,
                channel_id,
                lease_id,
                op_seq: 2,
                op_nonce: Some([0xa4u8; 32]),
                mailbox: "junk".to_string(),
                max_delete: 2,
                requested_at_ms: 4_100_000_000_020,
            },
        )
        .await;
        nonce += 1;
        let constrained_lookup = service_key(&mail_delete_receipt_storage_key(&constrained_op));
        assert!(query_state_key(rpc_addr, &constrained_lookup)
            .await?
            .is_none());

        let delete_op2 = [0xa5u8; 32];
        submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "mail_delete_spam@v1",
            MailDeleteSpamParams {
                operation_id: delete_op2,
                channel_id,
                lease_id,
                op_seq: 2,
                op_nonce: Some([0xa6u8; 32]),
                mailbox: "spam".to_string(),
                max_delete: 3,
                requested_at_ms: 4_100_000_000_030,
            },
        )
        .await?;
        nonce += 1;

        let delete_receipt2: MailDeleteSpamReceipt =
            load_wallet_value(rpc_addr, &mail_delete_receipt_storage_key(&delete_op2)).await?;
        assert_eq!(delete_receipt2.deleted_count, 3);
        assert_eq!(delete_receipt2.high_confidence_deleted_count, 3);
        assert!(delete_receipt2.evaluated_count >= delete_receipt2.deleted_count);

        let replay_op = [0xa7u8; 32];
        let _ = submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "mail_delete_spam@v1",
            MailDeleteSpamParams {
                operation_id: replay_op,
                channel_id,
                lease_id,
                op_seq: 2,
                op_nonce: Some([0xa8u8; 32]),
                mailbox: "spam".to_string(),
                max_delete: 1,
                requested_at_ms: 4_100_000_000_040,
            },
        )
        .await;
        let replay_lookup = service_key(&mail_delete_receipt_storage_key(&replay_op));
        assert!(query_state_key(rpc_addr, &replay_lookup).await?.is_none());

        let consumption: LeaseConsumptionState = load_wallet_value(
            rpc_addr,
            &lease_consumption_storage_key(&channel_id, &lease_id),
        )
        .await?;
        assert_eq!(consumption.consumed_count, 2);

        Ok(())
    }
    .await;

    let shutdown_result = cluster.shutdown().await;
    shutdown_result?;
    test_result
}
