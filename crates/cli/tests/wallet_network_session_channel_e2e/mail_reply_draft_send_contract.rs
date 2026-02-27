use super::*;

#[tokio::test]
async fn wallet_network_mail_reply_draft_send_contract_replay_window_via_real_callservice_txs(
) -> Result<()> {
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
        let tx_signer_audience = account_id_from_key_material(
            SignatureSuite::ED25519,
            &keypair.public().encode_protobuf(),
        )?;
        let mut nonce = 0u64;
        let lc_signer = new_hybrid_signer()?;
        let rc_signer = new_hybrid_signer()?;
        let approval_signer = new_hybrid_signer()?;

        wait_for_height(rpc_addr, 1, Duration::from_secs(30)).await?;

        let channel_id = [0xc1u8; 32];
        let lease_id = [0xc2u8; 32];
        let envelope = SessionChannelEnvelope {
            channel_id,
            lc_id: lc_signer.signer_id,
            rc_id: rc_signer.signer_id,
            ordering: SessionChannelOrdering::Ordered,
            mode: SessionChannelMode::RemoteRequestLocalExecution,
            policy_hash: [0xc3u8; 32],
            policy_version: 5,
            root_grant_id: [0xc4u8; 32],
            capability_set: vec!["mail.write".to_string()],
            constraints: BTreeMap::from([("mailbox".to_string(), "primary".to_string())]),
            delegation_rules: SessionChannelDelegationRules {
                max_depth: 1,
                can_redelegate: false,
                issuance_budget: Some(4),
            },
            revocation_epoch: 0,
            expires_at_ms: 4_310_000_000_000,
        };
        let envelope_hash = hash_channel_envelope(&envelope)?;

        let mut open_init = SessionChannelOpenInit {
            envelope: envelope.clone(),
            lc_kem_ephemeral_pub_classical: vec![81, 82, 83],
            lc_kem_ephemeral_pub_pq: vec![84, 85, 86],
            nonce_lc: [0xc5u8; 32],
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
            rc_attestation_evidence: vec![87, 88],
            rc_attestation_pub: vec![89, 90],
            rc_kem_ephemeral_pub_classical: vec![91, 92],
            rc_kem_ciphertext_pq: vec![93, 94],
            nonce_rc: [0xc6u8; 32],
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
            nonce_lc2: [0xc7u8; 32],
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
            nonce_rc2: [0xc8u8; 32],
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
                "mail-imap-user-reply-contract",
                "mail.imap.user.reply.contract",
                "agent@example.com",
            ),
            (
                "mail-imap-pass-reply-contract",
                "mail.imap.pass.reply.contract",
                "imap-password",
            ),
            (
                "mail-smtp-user-reply-contract",
                "mail.smtp.user.reply.contract",
                "agent@example.com",
            ),
            (
                "mail-smtp-pass-reply-contract",
                "mail.smtp.pass.reply.contract",
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
                mailbox: "primary".to_string(),
                config: MailConnectorConfig {
                    provider: MailConnectorProvider::ImapSmtp,
                    auth_mode: MailConnectorAuthMode::Password,
                    account_email: "agent@example.com".to_string(),
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
                        imap_username_alias: "mail.imap.user.reply.contract".to_string(),
                        imap_password_alias: "mail.imap.pass.reply.contract".to_string(),
                        smtp_username_alias: "mail.smtp.user.reply.contract".to_string(),
                        smtp_password_alias: "mail.smtp.pass.reply.contract".to_string(),
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
            subject_id: [0xc9u8; 32],
            policy_hash: envelope.policy_hash,
            grant_id: [0xcau8; 32],
            capability_subset: vec!["mail.write".to_string()],
            constraints_subset: BTreeMap::from([("mailbox".to_string(), "primary".to_string())]),
            mode: SessionLeaseMode::Lease,
            expires_at_ms: 4_260_000_000_000,
            revocation_epoch: 0,
            audience: tx_signer_audience,
            nonce: [0xcbu8; 32],
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
            lease,
        )
        .await?;
        nonce += 1;

        let approval_request_hash =
            unique_id("wallet_network_mail_reply_contract_approval_request");
        let approval_session_id = unique_id("wallet_network_mail_reply_contract_approval_session");
        let interception = WalletInterceptionContext {
            session_id: Some(approval_session_id),
            request_hash: approval_request_hash,
            target: ioi_types::app::ActionTarget::Custom("mail::reply".to_string()),
            value_usd_micros: None,
            reason: "manual approval required".to_string(),
            intercepted_at_ms: 4_100_000_010_000,
        };
        submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "record_interception@v1",
            interception.clone(),
        )
        .await?;
        nonce += 1;

        let approval = sign_wallet_approval_decision(
            WalletApprovalDecision {
                interception: interception.clone(),
                decision: WalletApprovalDecisionKind::ApprovedByHuman,
                approval_token: Some(ApprovalToken {
                    schema_version: 2,
                    request_hash: approval_request_hash,
                    audience: tx_signer_audience,
                    revocation_epoch: 0,
                    nonce: unique_id("wallet_network_mail_reply_contract_approval_nonce"),
                    counter: 1,
                    scope: ApprovalScope {
                        expires_at: 4_200_000_000_000,
                        max_usages: Some(1),
                    },
                    visual_hash: None,
                    pii_action: None,
                    scoped_exception: None,
                    approver_sig: vec![],
                    approver_suite: SignatureSuite::HYBRID_ED25519_ML_DSA_44,
                }),
                surface: VaultSurface::Desktop,
                decided_at_ms: 4_100_000_010_500,
            },
            &approval_signer,
        )?;
        submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "record_approval@v1",
            approval,
        )
        .await?;
        nonce += 1;

        submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "consume_approval_token@v1",
            ConsumeApprovalTokenParams {
                request_hash: approval_request_hash,
                consumed_at_ms: 4_100_000_011_000,
            },
        )
        .await?;
        nonce += 1;

        let approval_consumed: ApprovalConsumptionState = load_wallet_value(
            rpc_addr,
            &approval_consumption_storage_key(&approval_request_hash),
        )
        .await?;
        assert_eq!(approval_consumed.uses_consumed, 1);
        assert_eq!(approval_consumed.remaining_usages, 0);

        let draft_reply_op = [0xccu8; 32];
        submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "mail_reply@v1",
            MailReplyParams {
                operation_id: draft_reply_op,
                channel_id,
                lease_id,
                op_seq: 1,
                op_nonce: Some([0xcdu8; 32]),
                mailbox: "primary".to_string(),
                to: "drafts@example.com".to_string(),
                subject: "[Draft] Weekly update".to_string(),
                body: "Initial draft content for review.".to_string(),
                reply_to_message_id: None,
                requested_at_ms: 4_100_000_011_500,
            },
        )
        .await?;
        nonce += 1;

        let draft_receipt: MailReplyReceipt =
            load_wallet_value(rpc_addr, &mail_reply_receipt_storage_key(&draft_reply_op)).await?;
        assert_eq!(draft_receipt.subject, "[Draft] Weekly update");
        assert_eq!(draft_receipt.to, "drafts@example.com");
        assert!(!draft_receipt.sent_message_id.trim().is_empty());

        let send_reply_op = [0xceu8; 32];
        submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "mail_reply@v1",
            MailReplyParams {
                operation_id: send_reply_op,
                channel_id,
                lease_id,
                op_seq: 2,
                op_nonce: Some([0xcfu8; 32]),
                mailbox: "primary".to_string(),
                to: "team@example.com".to_string(),
                subject: "Weekly update".to_string(),
                body: "Finalized update ready to send.".to_string(),
                reply_to_message_id: Some("msg-weekly-42".to_string()),
                requested_at_ms: 4_100_000_012_000,
            },
        )
        .await?;
        nonce += 1;

        let send_receipt: MailReplyReceipt =
            load_wallet_value(rpc_addr, &mail_reply_receipt_storage_key(&send_reply_op)).await?;
        assert_eq!(send_receipt.subject, "Weekly update");
        assert_eq!(send_receipt.to, "team@example.com");
        assert!(!send_receipt.sent_message_id.trim().is_empty());
        assert_ne!(draft_receipt.sent_message_id, send_receipt.sent_message_id);

        let duplicate_nonce_op = [0xd0u8; 32];
        let _ = submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "mail_reply@v1",
            MailReplyParams {
                operation_id: duplicate_nonce_op,
                channel_id,
                lease_id,
                op_seq: 3,
                op_nonce: Some([0xcfu8; 32]),
                mailbox: "primary".to_string(),
                to: "team@example.com".to_string(),
                subject: "Duplicate nonce should fail".to_string(),
                body: "This should fail nonce replay checks.".to_string(),
                reply_to_message_id: None,
                requested_at_ms: 4_100_000_012_500,
            },
        )
        .await;
        nonce += 1;
        let duplicate_nonce_lookup =
            service_key(&mail_reply_receipt_storage_key(&duplicate_nonce_op));
        assert!(query_state_key(rpc_addr, &duplicate_nonce_lookup)
            .await?
            .is_none());

        let seq_gap_op = [0xd1u8; 32];
        let _ = submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "mail_reply@v1",
            MailReplyParams {
                operation_id: seq_gap_op,
                channel_id,
                lease_id,
                op_seq: 5,
                op_nonce: Some([0xd2u8; 32]),
                mailbox: "primary".to_string(),
                to: "team@example.com".to_string(),
                subject: "Seq gap should fail".to_string(),
                body: "This should fail ordered sequence checks.".to_string(),
                reply_to_message_id: None,
                requested_at_ms: 4_100_000_013_000,
            },
        )
        .await;
        nonce += 1;
        let seq_gap_lookup = service_key(&mail_reply_receipt_storage_key(&seq_gap_op));
        assert!(query_state_key(rpc_addr, &seq_gap_lookup).await?.is_none());

        let valid_after_failures_op = [0xd3u8; 32];
        submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "mail_reply@v1",
            MailReplyParams {
                operation_id: valid_after_failures_op,
                channel_id,
                lease_id,
                op_seq: 3,
                op_nonce: Some([0xd4u8; 32]),
                mailbox: "primary".to_string(),
                to: "team@example.com".to_string(),
                subject: "Recovered ordered seq".to_string(),
                body: "This should pass to prove failures did not advance replay state."
                    .to_string(),
                reply_to_message_id: None,
                requested_at_ms: 4_100_000_013_500,
            },
        )
        .await?;
        nonce += 1;
        let recovered_receipt: MailReplyReceipt = load_wallet_value(
            rpc_addr,
            &mail_reply_receipt_storage_key(&valid_after_failures_op),
        )
        .await?;
        assert_eq!(recovered_receipt.subject, "Recovered ordered seq");

        let duplicate_seq_op = [0xd5u8; 32];
        let _ = submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "mail_reply@v1",
            MailReplyParams {
                operation_id: duplicate_seq_op,
                channel_id,
                lease_id,
                op_seq: 3,
                op_nonce: Some([0xd6u8; 32]),
                mailbox: "primary".to_string(),
                to: "team@example.com".to_string(),
                subject: "Duplicate seq should fail".to_string(),
                body: "This should fail due ordered op_seq replay.".to_string(),
                reply_to_message_id: None,
                requested_at_ms: 4_100_000_014_000,
            },
        )
        .await;
        let duplicate_seq_lookup = service_key(&mail_reply_receipt_storage_key(&duplicate_seq_op));
        assert!(query_state_key(rpc_addr, &duplicate_seq_lookup)
            .await?
            .is_none());

        let _ = submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "consume_approval_token@v1",
            ConsumeApprovalTokenParams {
                request_hash: approval_request_hash,
                consumed_at_ms: 4_100_000_014_500,
            },
        )
        .await;
        let approval_consumed_after_reuse: ApprovalConsumptionState = load_wallet_value(
            rpc_addr,
            &approval_consumption_storage_key(&approval_request_hash),
        )
        .await?;
        assert_eq!(approval_consumed_after_reuse.uses_consumed, 1);
        assert_eq!(approval_consumed_after_reuse.remaining_usages, 0);

        let lease_consumption: LeaseConsumptionState = load_wallet_value(
            rpc_addr,
            &lease_consumption_storage_key(&channel_id, &lease_id),
        )
        .await?;
        assert_eq!(lease_consumption.consumed_count, 3);

        Ok(())
    }
    .await;

    let shutdown_result = cluster.shutdown().await;
    shutdown_result?;
    test_result
}
