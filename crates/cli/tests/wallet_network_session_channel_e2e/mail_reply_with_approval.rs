use super::*;

#[tokio::test]
async fn wallet_network_mail_reply_via_real_callservice_txs_with_approval_write_intent(
) -> Result<()> {
    let _guard = E2E_TEST_LOCK.lock().expect("lock");
    build_test_artifacts();
    let Some(mail_runtime) = maybe_wallet_mail_runtime_config()? else {
        eprintln!(
            "skipping wallet_network_mail_reply_via_real_callservice_txs_with_approval_write_intent: MAIL_E2E_* not configured"
        );
        return Ok(());
    };

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
        let tx_signer_audience = account_id_from_key_material(
            SignatureSuite::ED25519,
            &keypair.public().encode_protobuf(),
        )?;
        let mut nonce = 0u64;
        let lc_signer = new_hybrid_signer()?;
        let rc_signer = new_hybrid_signer()?;
        let approval_signer = new_hybrid_signer()?;

        wait_for_height(rpc_addr, 1, Duration::from_secs(30)).await?;

        let channel_id = [0xb1u8; 32];
        let lease_id = [0xb2u8; 32];
        let envelope = SessionChannelEnvelope {
            channel_id,
            lc_id: lc_signer.signer_id,
            rc_id: rc_signer.signer_id,
            ordering: SessionChannelOrdering::Ordered,
            mode: SessionChannelMode::RemoteRequestLocalExecution,
            policy_hash: [0xb3u8; 32],
            policy_version: 4,
            root_grant_id: [0xb4u8; 32],
            capability_set: vec!["mail.write".to_string()],
            constraints: BTreeMap::from([("mailbox".to_string(), "primary".to_string())]),
            delegation_rules: SessionChannelDelegationRules {
                max_depth: 1,
                can_redelegate: false,
                issuance_budget: Some(3),
            },
            revocation_epoch: 0,
            expires_at_ms: 4_300_000_000_000,
        };
        let envelope_hash = hash_channel_envelope(&envelope)?;

        let mut open_init = SessionChannelOpenInit {
            envelope: envelope.clone(),
            lc_kem_ephemeral_pub_classical: vec![61, 62, 63],
            lc_kem_ephemeral_pub_pq: vec![64, 65, 66],
            nonce_lc: [0xb5u8; 32],
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
            rc_attestation_evidence: vec![67, 68],
            rc_attestation_pub: vec![69, 70],
            rc_kem_ephemeral_pub_classical: vec![71, 72],
            rc_kem_ciphertext_pq: vec![73, 74],
            nonce_rc: [0xb6u8; 32],
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
            nonce_lc2: [0xb7u8; 32],
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
            nonce_rc2: [0xb8u8; 32],
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

        let secret_kind = wallet_mail_secret_kind(mail_runtime.auth_mode);
        store_wallet_secret_record(
            rpc_addr,
            keypair,
            chain_id,
            &mut nonce,
            "mail-imap-user-reply",
            "mail.imap.user.reply",
            SecretKind::Custom("username".to_string()),
            &mail_runtime.imap_username,
        )
        .await?;
        store_wallet_secret_record(
            rpc_addr,
            keypair,
            chain_id,
            &mut nonce,
            "mail-imap-pass-reply",
            "mail.imap.pass.reply",
            secret_kind.clone(),
            &mail_runtime.imap_secret,
        )
        .await?;
        store_wallet_secret_record(
            rpc_addr,
            keypair,
            chain_id,
            &mut nonce,
            "mail-smtp-user-reply",
            "mail.smtp.user.reply",
            SecretKind::Custom("username".to_string()),
            &mail_runtime.smtp_username,
        )
        .await?;
        store_wallet_secret_record(
            rpc_addr,
            keypair,
            chain_id,
            &mut nonce,
            "mail-smtp-pass-reply",
            "mail.smtp.pass.reply",
            secret_kind,
            &mail_runtime.smtp_secret,
        )
        .await?;

        submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "mail_connector_upsert@v1",
            MailConnectorUpsertParams {
                mailbox: "primary".to_string(),
                config: build_wallet_mail_connector_config(
                    &mail_runtime,
                    "mail.imap.user.reply",
                    "mail.imap.pass.reply",
                    "mail.smtp.user.reply",
                    "mail.smtp.pass.reply",
                ),
            },
        )
        .await?;
        nonce += 1;

        let mut lease = SessionLease {
            lease_id,
            channel_id,
            issuer_id: lc_signer.signer_id,
            subject_id: [0xb9u8; 32],
            policy_hash: envelope.policy_hash,
            grant_id: [0xbau8; 32],
            capability_subset: vec!["mail.write".to_string()],
            constraints_subset: BTreeMap::from([("mailbox".to_string(), "primary".to_string())]),
            mode: SessionLeaseMode::Lease,
            expires_at_ms: 4_250_000_000_000,
            revocation_epoch: 0,
            audience: tx_signer_audience,
            nonce: [0xbbu8; 32],
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

        let approval_request_hash = unique_id("wallet_network_mail_reply_write_intent_request");
        let approval_session_id = unique_id("wallet_network_mail_reply_write_intent_session");
        let interception = WalletInterceptionContext {
            session_id: Some(approval_session_id),
            request_hash: approval_request_hash,
            target: ioi_types::app::ActionTarget::Custom("mail::reply".to_string()),
            value_usd_micros: None,
            reason: "manual approval required".to_string(),
            intercepted_at_ms: 4_100_000_001_000,
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
                    nonce: unique_id("wallet_network_mail_reply_write_intent_nonce"),
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
                decided_at_ms: 4_100_000_001_500,
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

        let consume_once = ConsumeApprovalTokenParams {
            request_hash: approval_request_hash,
            consumed_at_ms: 4_100_000_002_000,
        };
        submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "consume_approval_token@v1",
            consume_once,
        )
        .await?;
        nonce += 1;

        let consumed_once: ApprovalConsumptionState = load_wallet_value(
            rpc_addr,
            &approval_consumption_storage_key(&approval_request_hash),
        )
        .await?;
        assert_eq!(consumed_once.uses_consumed, 1);
        assert_eq!(consumed_once.remaining_usages, 0);
        assert_eq!(consumed_once.bound_audience, Some(tx_signer_audience));

        let reply_op_1 = [0xbcu8; 32];
        submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "mail_reply@v1",
            MailReplyParams {
                operation_id: reply_op_1,
                channel_id,
                lease_id,
                op_seq: 1,
                op_nonce: Some([0xbdu8; 32]),
                mailbox: "primary".to_string(),
                to: "bob@example.com".to_string(),
                subject: "E2E reply status".to_string(),
                body: "Acknowledged in wallet_network e2e.".to_string(),
                reply_to_message_id: Some("msg-abc".to_string()),
                requested_at_ms: 4_100_000_002_500,
            },
        )
        .await?;
        nonce += 1;

        let reply_receipt: MailReplyReceipt =
            load_wallet_value(rpc_addr, &mail_reply_receipt_storage_key(&reply_op_1)).await?;
        assert_eq!(reply_receipt.channel_id, channel_id);
        assert_eq!(reply_receipt.lease_id, lease_id);
        assert_eq!(reply_receipt.mailbox, "primary");
        assert_eq!(reply_receipt.to, "bob@example.com");
        assert_eq!(reply_receipt.subject, "E2E reply status");
        assert!(!reply_receipt.sent_message_id.trim().is_empty());

        let reply_replay_op = [0xbeu8; 32];
        let _ = submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "mail_reply@v1",
            MailReplyParams {
                operation_id: reply_replay_op,
                channel_id,
                lease_id,
                op_seq: 1,
                op_nonce: Some([0xbfu8; 32]),
                mailbox: "primary".to_string(),
                to: "bob@example.com".to_string(),
                subject: "Replay should fail".to_string(),
                body: "This should not be sent.".to_string(),
                reply_to_message_id: None,
                requested_at_ms: 4_100_000_002_600,
            },
        )
        .await;
        let replay_lookup = service_key(&mail_reply_receipt_storage_key(&reply_replay_op));
        assert!(query_state_key(rpc_addr, &replay_lookup).await?.is_none());

        let consume_again = ConsumeApprovalTokenParams {
            request_hash: approval_request_hash,
            consumed_at_ms: 4_100_000_003_000,
        };
        let _ = submit_wallet_call(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            "consume_approval_token@v1",
            consume_again,
        )
        .await;

        let consumed_after_reuse: ApprovalConsumptionState = load_wallet_value(
            rpc_addr,
            &approval_consumption_storage_key(&approval_request_hash),
        )
        .await?;
        assert_eq!(consumed_after_reuse.uses_consumed, 1);
        assert_eq!(consumed_after_reuse.remaining_usages, 0);

        let lease_consumption: LeaseConsumptionState = load_wallet_value(
            rpc_addr,
            &lease_consumption_storage_key(&channel_id, &lease_id),
        )
        .await?;
        assert_eq!(lease_consumption.consumed_count, 1);

        Ok(())
    }
    .await;

    let shutdown_result = cluster.shutdown().await;
    shutdown_result?;
    test_result
}
