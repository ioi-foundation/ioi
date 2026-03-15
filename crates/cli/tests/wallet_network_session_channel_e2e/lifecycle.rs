use super::*;

async fn exercise_grant_delegation_scenarios(
    rpc_addr: &str,
    keypair: &Keypair,
    chain_id: ChainId,
    mut nonce: u64,
    root_session_id: [u8; 32],
    child_session_id: [u8; 32],
    budget_reject_session_id: [u8; 32],
    depth_reject_session_id: [u8; 32],
) -> Result<u64> {
    let grant_scope = SessionScope {
        expires_at_ms: 4_200_000_000_000,
        max_actions: Some(20),
        max_spend_usd_micros: Some(1_000_000),
        action_allowlist: vec![
            ioi_types::app::ActionTarget::WebRetrieve,
            ioi_types::app::ActionTarget::NetFetch,
        ],
        domain_allowlist: vec!["status.vendor-a.com".to_string()],
    };
    let root_grant = SessionGrant {
        session_id: root_session_id,
        vault_id: [0x9au8; 32],
        agent_id: "wallet-e2e-agent".to_string(),
        purpose: "wallet contract e2e".to_string(),
        scope: grant_scope.clone(),
        guardian_ephemeral_public_key: vec![1, 2, 3, 4],
        issued_at_ms: 4_100_000_000_000,
    };
    submit_wallet_call(
        rpc_addr,
        keypair,
        chain_id,
        nonce,
        "issue_session_grant@v1",
        IssueSessionGrantParams {
            grant: root_grant,
            parent_session_id: None,
            delegation_rules: Some(SessionChannelDelegationRules {
                max_depth: 1,
                can_redelegate: true,
                issuance_budget: Some(1),
            }),
        },
    )
    .await?;
    nonce += 1;

    let child_grant = SessionGrant {
        session_id: child_session_id,
        vault_id: [0x9au8; 32],
        agent_id: "wallet-e2e-agent-child".to_string(),
        purpose: "wallet contract e2e child".to_string(),
        scope: SessionScope {
            expires_at_ms: 4_150_000_000_000,
            max_actions: Some(5),
            max_spend_usd_micros: Some(250_000),
            action_allowlist: vec![ioi_types::app::ActionTarget::WebRetrieve],
            domain_allowlist: vec!["status.vendor-a.com".to_string()],
        },
        guardian_ephemeral_public_key: vec![5, 6, 7],
        issued_at_ms: 4_100_000_000_100,
    };
    submit_wallet_call(
        rpc_addr,
        keypair,
        chain_id,
        nonce,
        "issue_session_grant@v1",
        IssueSessionGrantParams {
            grant: child_grant.clone(),
            parent_session_id: Some(root_session_id),
            delegation_rules: None,
        },
    )
    .await?;
    nonce += 1;

    let budget_reject_grant = SessionGrant {
        session_id: budget_reject_session_id,
        vault_id: [0x9au8; 32],
        agent_id: "wallet-e2e-agent-budget-reject".to_string(),
        purpose: "budget reject".to_string(),
        scope: SessionScope {
            expires_at_ms: 4_140_000_000_000,
            max_actions: Some(4),
            max_spend_usd_micros: Some(200_000),
            action_allowlist: vec![ioi_types::app::ActionTarget::WebRetrieve],
            domain_allowlist: vec!["status.vendor-a.com".to_string()],
        },
        guardian_ephemeral_public_key: vec![8, 9],
        issued_at_ms: 4_100_000_000_200,
    };
    let _ = submit_wallet_call(
        rpc_addr,
        keypair,
        chain_id,
        nonce,
        "issue_session_grant@v1",
        IssueSessionGrantParams {
            grant: budget_reject_grant,
            parent_session_id: Some(root_session_id),
            delegation_rules: None,
        },
    )
    .await;
    nonce += 1;

    let depth_reject_grant = SessionGrant {
        session_id: depth_reject_session_id,
        vault_id: [0x9au8; 32],
        agent_id: "wallet-e2e-agent-depth-reject".to_string(),
        purpose: "depth reject".to_string(),
        scope: SessionScope {
            expires_at_ms: 4_130_000_000_000,
            max_actions: Some(3),
            max_spend_usd_micros: Some(100_000),
            action_allowlist: vec![ioi_types::app::ActionTarget::WebRetrieve],
            domain_allowlist: vec!["status.vendor-a.com".to_string()],
        },
        guardian_ephemeral_public_key: vec![10, 11],
        issued_at_ms: 4_100_000_000_300,
    };
    let _ = submit_wallet_call(
        rpc_addr,
        keypair,
        chain_id,
        nonce,
        "issue_session_grant@v1",
        IssueSessionGrantParams {
            grant: depth_reject_grant,
            parent_session_id: Some(child_session_id),
            delegation_rules: None,
        },
    )
    .await;
    nonce += 1;

    let root_delegation: SessionDelegationState =
        load_wallet_value(rpc_addr, &session_delegation_storage_key(&root_session_id)).await?;
    assert_eq!(root_delegation.depth, 0);
    assert_eq!(root_delegation.max_depth, 1);
    assert_eq!(root_delegation.remaining_issuance_budget, Some(0));
    assert_eq!(root_delegation.children_issued, 1);
    assert!(!root_delegation.can_redelegate);

    let child_delegation: SessionDelegationState =
        load_wallet_value(rpc_addr, &session_delegation_storage_key(&child_session_id)).await?;
    assert_eq!(child_delegation.root_session_id, root_session_id);
    assert_eq!(child_delegation.depth, 1);

    let budget_reject_lookup = service_key(&session_storage_key(&budget_reject_session_id));
    let depth_reject_lookup = service_key(&session_storage_key(&depth_reject_session_id));
    assert!(query_state_key(rpc_addr, &budget_reject_lookup)
        .await?
        .is_none());
    assert!(query_state_key(rpc_addr, &depth_reject_lookup)
        .await?
        .is_none());
    Ok(nonce)
}

async fn exercise_ordered_channel_scenarios(
    rpc_addr: &str,
    keypair: &Keypair,
    chain_id: ChainId,
    mut nonce: u64,
    lc_signer: &HybridSigner,
    rc_signer: &HybridSigner,
    signer_account_id: [u8; 32],
) -> Result<u64> {
    let channel_id = [0x11u8; 32];
    let lease_id = [0x41u8; 32];
    let envelope = SessionChannelEnvelope {
        channel_id,
        lc_id: lc_signer.signer_id,
        rc_id: rc_signer.signer_id,
        ordering: SessionChannelOrdering::Ordered,
        mode: SessionChannelMode::RemoteRequestLocalExecution,
        policy_hash: [0x23u8; 32],
        policy_version: 7,
        root_grant_id: [0x24u8; 32],
        capability_set: vec!["email:read".to_string(), "email:search".to_string()],
        constraints: BTreeMap::from([
            ("mailbox".to_string(), "primary".to_string()),
            ("max_results".to_string(), "1".to_string()),
        ]),
        delegation_rules: SessionChannelDelegationRules {
            max_depth: 1,
            can_redelegate: false,
            issuance_budget: Some(4),
        },
        revocation_epoch: 0,
        expires_at_ms: 4_200_000_000_000,
    };
    let envelope_hash = hash_channel_envelope(&envelope)?;

    let mut open_init = SessionChannelOpenInit {
        envelope: envelope.clone(),
        lc_kem_ephemeral_pub_classical: vec![1, 2, 3],
        lc_kem_ephemeral_pub_pq: vec![4, 5, 6],
        nonce_lc: [0x31u8; 32],
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

    let mut channel: SessionChannelRecord =
        load_wallet_value(rpc_addr, &channel_storage_key(&channel_id)).await?;
    assert_eq!(channel.state, SessionChannelState::OpenInit);
    assert_eq!(channel.envelope_hash, envelope_hash);

    let mut open_try = SessionChannelOpenTry {
        channel_id,
        envelope_hash,
        rc_attestation_evidence: vec![10, 11],
        rc_attestation_pub: vec![12, 13],
        rc_kem_ephemeral_pub_classical: vec![14, 15],
        rc_kem_ciphertext_pq: vec![16, 17],
        nonce_rc: [0x32u8; 32],
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

    channel = load_wallet_value(rpc_addr, &channel_storage_key(&channel_id)).await?;
    assert_eq!(channel.state, SessionChannelState::OpenTry);

    let mut open_ack = SessionChannelOpenAck {
        channel_id,
        envelope_hash,
        nonce_lc2: [0x33u8; 32],
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

    channel = load_wallet_value(rpc_addr, &channel_storage_key(&channel_id)).await?;
    assert_eq!(channel.state, SessionChannelState::OpenAck);

    let mut open_confirm = SessionChannelOpenConfirm {
        channel_id,
        envelope_hash,
        nonce_rc2: [0x34u8; 32],
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

    channel = load_wallet_value(rpc_addr, &channel_storage_key(&channel_id)).await?;
    assert_eq!(channel.state, SessionChannelState::Open);
    assert!(channel.opened_at_ms.is_some());

    let channel_key_state: SessionChannelKeyState =
        load_wallet_value(rpc_addr, &channel_key_state_storage_key(&channel_id)).await?;
    assert!(channel_key_state.ready);
    assert_eq!(channel_key_state.key_epoch, 1);
    assert!(channel_key_state.derived_channel_secret_hash.is_some());
    assert_eq!(channel_key_state.nonce_rc, Some([0x32u8; 32]));
    assert_eq!(channel_key_state.nonce_lc2, Some([0x33u8; 32]));
    assert_eq!(channel_key_state.nonce_rc2, Some([0x34u8; 32]));
    assert_eq!(channel_key_state.transcript_version, 1);
    assert_ne!(channel_key_state.kem_transcript_hash, [0u8; 32]);

    for (secret_id, alias, value) in [
        (
            "mail-imap-username",
            "mail.imap.username",
            "agent@example.com",
        ),
        ("mail-imap-password", "mail.imap.password", "imap-password"),
        (
            "mail-smtp-username",
            "mail.smtp.username",
            "agent@example.com",
        ),
        ("mail-smtp-password", "mail.smtp.password", "smtp-password"),
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
                    imap_username_alias: "mail.imap.username".to_string(),
                    imap_password_alias: "mail.imap.password".to_string(),
                    smtp_username_alias: "mail.smtp.username".to_string(),
                    smtp_password_alias: "mail.smtp.password".to_string(),
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
        subject_id: [0x43u8; 32],
        policy_hash: envelope.policy_hash,
        grant_id: [0x44u8; 32],
        capability_subset: vec!["email:read".to_string()],
        constraints_subset: BTreeMap::from([("mailbox".to_string(), "primary".to_string())]),
        mode: SessionLeaseMode::OneShot,
        expires_at_ms: 4_150_000_000_000,
        revocation_epoch: 0,
        audience: signer_account_id,
        nonce: [0x46u8; 32],
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

    let stored_lease: SessionLease =
        load_wallet_value(rpc_addr, &lease_storage_key(&channel_id, &lease_id)).await?;
    assert_eq!(stored_lease.channel_id, channel_id);
    assert_eq!(
        stored_lease.capability_subset,
        vec!["email:read".to_string()]
    );
    assert_eq!(stored_lease.constraints_subset, lease.constraints_subset);

    let first_mail_read_operation_id = [0x57u8; 32];
    submit_wallet_call(
        rpc_addr,
        keypair,
        chain_id,
        nonce,
        "mail_read_latest@v1",
        MailReadLatestParams {
            operation_id: first_mail_read_operation_id,
            channel_id,
            lease_id,
            op_seq: 1,
            op_nonce: Some([0x5au8; 32]),
            mailbox: "primary".to_string(),
            requested_at_ms: 4_100_000_000_010,
        },
    )
    .await?;
    nonce += 1;

    let mail_receipt: MailReadLatestReceipt = load_wallet_value(
        rpc_addr,
        &mail_read_receipt_storage_key(&first_mail_read_operation_id),
    )
    .await?;
    assert_eq!(mail_receipt.channel_id, channel_id);
    assert_eq!(mail_receipt.lease_id, lease_id);
    assert_eq!(mail_receipt.mailbox, "primary");
    assert_eq!(mail_receipt.audience, signer_account_id);

    let lease_consumption: LeaseConsumptionState = load_wallet_value(
        rpc_addr,
        &lease_consumption_storage_key(&channel_id, &lease_id),
    )
    .await?;
    assert_eq!(lease_consumption.channel_id, channel_id);
    assert_eq!(lease_consumption.lease_id, lease_id);
    assert_eq!(lease_consumption.consumed_count, 1);

    let second_mail_read_operation_id = [0x58u8; 32];
    let _ = submit_wallet_call(
        rpc_addr,
        keypair,
        chain_id,
        nonce,
        "mail_read_latest@v1",
        MailReadLatestParams {
            operation_id: second_mail_read_operation_id,
            channel_id,
            lease_id,
            op_seq: 2,
            op_nonce: Some([0x5bu8; 32]),
            mailbox: "primary".to_string(),
            requested_at_ms: 4_100_000_000_020,
        },
    )
    .await;
    nonce += 1;

    let second_mail_receipt_lookup = service_key(&mail_read_receipt_storage_key(
        &second_mail_read_operation_id,
    ));
    assert!(query_state_key(rpc_addr, &second_mail_receipt_lookup)
        .await?
        .is_none());

    let mut lease_counter_replay = lease.clone();
    lease_counter_replay.lease_id = [0x47u8; 32];
    lease_counter_replay.counter = 1;
    lease_counter_replay.nonce = [0x48u8; 32];
    lease_counter_replay.sig_hybrid_lc.clear();
    let mut lease_counter_replay_unsigned = lease_counter_replay.clone();
    lease_counter_replay_unsigned.sig_hybrid_lc.clear();
    lease_counter_replay.sig_hybrid_lc = sign_hybrid_payload(
        &lc_signer,
        &encode_canonical(&lease_counter_replay_unsigned)?,
    )?;
    let _ = submit_wallet_call(
        rpc_addr,
        keypair,
        chain_id,
        nonce,
        "issue_session_lease@v1",
        lease_counter_replay,
    )
    .await;
    nonce += 1;

    let mut lease_counter_gap = lease.clone();
    lease_counter_gap.lease_id = [0x4au8; 32];
    lease_counter_gap.counter = 3;
    lease_counter_gap.nonce = [0x4bu8; 32];
    lease_counter_gap.sig_hybrid_lc.clear();
    let mut lease_counter_gap_unsigned = lease_counter_gap.clone();
    lease_counter_gap_unsigned.sig_hybrid_lc.clear();
    lease_counter_gap.sig_hybrid_lc =
        sign_hybrid_payload(&lc_signer, &encode_canonical(&lease_counter_gap_unsigned)?)?;
    let _ = submit_wallet_call(
        rpc_addr,
        keypair,
        chain_id,
        nonce,
        "issue_session_lease@v1",
        lease_counter_gap,
    )
    .await;
    nonce += 1;

    let mut lease_nonce_replay = lease.clone();
    lease_nonce_replay.lease_id = [0x49u8; 32];
    lease_nonce_replay.counter = 2;
    lease_nonce_replay.nonce = lease.nonce;
    lease_nonce_replay.sig_hybrid_lc.clear();
    let mut lease_nonce_replay_unsigned = lease_nonce_replay.clone();
    lease_nonce_replay_unsigned.sig_hybrid_lc.clear();
    lease_nonce_replay.sig_hybrid_lc =
        sign_hybrid_payload(&lc_signer, &encode_canonical(&lease_nonce_replay_unsigned)?)?;
    let _ = submit_wallet_call(
        rpc_addr,
        keypair,
        chain_id,
        nonce,
        "issue_session_lease@v1",
        lease_nonce_replay,
    )
    .await;
    nonce += 1;

    let lease_counter_replay_lookup = service_key(&lease_storage_key(&channel_id, &[0x47u8; 32]));
    let lease_counter_gap_lookup = service_key(&lease_storage_key(&channel_id, &[0x4au8; 32]));
    let lease_nonce_replay_lookup = service_key(&lease_storage_key(&channel_id, &[0x49u8; 32]));
    assert!(query_state_key(rpc_addr, &lease_counter_replay_lookup)
        .await?
        .is_none());
    assert!(query_state_key(rpc_addr, &lease_counter_gap_lookup)
        .await?
        .is_none());
    assert!(query_state_key(rpc_addr, &lease_nonce_replay_lookup)
        .await?
        .is_none());

    let mut ordered_sequence_lease = lease.clone();
    ordered_sequence_lease.lease_id = [0x5cu8; 32];
    ordered_sequence_lease.mode = SessionLeaseMode::Lease;
    ordered_sequence_lease.counter = 2;
    ordered_sequence_lease.nonce = [0x5du8; 32];
    ordered_sequence_lease.sig_hybrid_lc.clear();
    let mut ordered_sequence_lease_unsigned = ordered_sequence_lease.clone();
    ordered_sequence_lease_unsigned.sig_hybrid_lc.clear();
    ordered_sequence_lease.sig_hybrid_lc = sign_hybrid_payload(
        &lc_signer,
        &encode_canonical(&ordered_sequence_lease_unsigned)?,
    )?;
    submit_wallet_call(
        rpc_addr,
        keypair,
        chain_id,
        nonce,
        "issue_session_lease@v1",
        ordered_sequence_lease.clone(),
    )
    .await?;
    nonce += 1;

    let ordered_seq1_operation_id = [0x5eu8; 32];
    submit_wallet_call(
        rpc_addr,
        keypair,
        chain_id,
        nonce,
        "mail_read_latest@v1",
        MailReadLatestParams {
            operation_id: ordered_seq1_operation_id,
            channel_id,
            lease_id: ordered_sequence_lease.lease_id,
            op_seq: 1,
            op_nonce: Some([0x5fu8; 32]),
            mailbox: "primary".to_string(),
            requested_at_ms: 4_100_000_000_030,
        },
    )
    .await?;
    nonce += 1;

    let ordered_list_operation_id = [0x81u8; 32];
    submit_wallet_call(
        rpc_addr,
        keypair,
        chain_id,
        nonce,
        "mail_list_recent@v1",
        MailListRecentParams {
            operation_id: ordered_list_operation_id,
            channel_id,
            lease_id: ordered_sequence_lease.lease_id,
            op_seq: 2,
            op_nonce: Some([0x82u8; 32]),
            mailbox: "primary".to_string(),
            limit: 2,
            requested_at_ms: 4_100_000_000_035,
        },
    )
    .await?;
    nonce += 1;

    let ordered_list_receipt: MailListRecentReceipt = load_wallet_value(
        rpc_addr,
        &mail_list_receipt_storage_key(&ordered_list_operation_id),
    )
    .await?;
    assert_eq!(ordered_list_receipt.channel_id, channel_id);
    assert_eq!(
        ordered_list_receipt.lease_id,
        ordered_sequence_lease.lease_id
    );
    assert_eq!(ordered_list_receipt.mailbox, "primary");
    assert_eq!(ordered_list_receipt.messages.len(), 2);
    assert!(ordered_list_receipt.requested_limit >= 2);
    assert!(ordered_list_receipt.evaluated_count >= 2);
    assert!(ordered_list_receipt.parse_confidence_bps > 0);
    assert!(!ordered_list_receipt.parse_volume_band.trim().is_empty());
    assert!(!ordered_list_receipt.ontology_version.trim().is_empty());

    let ordered_duplicate_operation_id = [0x60u8; 32];
    let _ = submit_wallet_call(
        rpc_addr,
        keypair,
        chain_id,
        nonce,
        "mail_read_latest@v1",
        MailReadLatestParams {
            operation_id: ordered_duplicate_operation_id,
            channel_id,
            lease_id: ordered_sequence_lease.lease_id,
            op_seq: 1,
            op_nonce: Some([0x61u8; 32]),
            mailbox: "primary".to_string(),
            requested_at_ms: 4_100_000_000_040,
        },
    )
    .await;
    nonce += 1;

    let ordered_gap_operation_id = [0x62u8; 32];
    let _ = submit_wallet_call(
        rpc_addr,
        keypair,
        chain_id,
        nonce,
        "mail_read_latest@v1",
        MailReadLatestParams {
            operation_id: ordered_gap_operation_id,
            channel_id,
            lease_id: ordered_sequence_lease.lease_id,
            op_seq: 4,
            op_nonce: Some([0x63u8; 32]),
            mailbox: "primary".to_string(),
            requested_at_ms: 4_100_000_000_050,
        },
    )
    .await;
    nonce += 1;

    let ordered_duplicate_lookup = service_key(&mail_read_receipt_storage_key(
        &ordered_duplicate_operation_id,
    ));
    let ordered_gap_lookup = service_key(&mail_read_receipt_storage_key(&ordered_gap_operation_id));
    assert!(query_state_key(rpc_addr, &ordered_duplicate_lookup)
        .await?
        .is_none());
    assert!(query_state_key(rpc_addr, &ordered_gap_lookup)
        .await?
        .is_none());

    let mut commit = SessionReceiptCommit {
        commit_id: [0u8; 32],
        channel_id,
        direction: SessionReceiptCommitDirection::LocalToRemote,
        start_seq: 0,
        end_seq: 7,
        merkle_root: [0x51u8; 32],
        committed_at_ms: 0,
        signer_id: rc_signer.signer_id,
        sig_hybrid_sender: Vec::new(),
    };
    let mut commit_unsigned = commit.clone();
    commit_unsigned.sig_hybrid_sender.clear();
    commit.sig_hybrid_sender =
        sign_hybrid_payload(&rc_signer, &encode_canonical(&commit_unsigned)?)?;
    submit_wallet_call(
        rpc_addr,
        keypair,
        chain_id,
        nonce,
        "commit_receipt_root@v1",
        commit.clone(),
    )
    .await?;
    nonce += 1;

    let stored_commit: SessionReceiptCommit = load_wallet_value(
        rpc_addr,
        &receipt_commit_storage_key(
            &channel_id,
            SessionReceiptCommitDirection::LocalToRemote,
            commit.end_seq,
        ),
    )
    .await?;
    assert_eq!(stored_commit.channel_id, channel_id);
    assert_eq!(stored_commit.end_seq, 7);
    assert_ne!(stored_commit.commit_id, [0u8; 32]);

    let mut out_of_order_commit = commit.clone();
    out_of_order_commit.commit_id = [0u8; 32];
    out_of_order_commit.start_seq = 9;
    out_of_order_commit.end_seq = 10;
    out_of_order_commit.merkle_root = [0x52u8; 32];
    out_of_order_commit.sig_hybrid_sender.clear();
    let mut out_of_order_commit_unsigned = out_of_order_commit.clone();
    out_of_order_commit_unsigned.sig_hybrid_sender.clear();
    out_of_order_commit.sig_hybrid_sender = sign_hybrid_payload(
        &rc_signer,
        &encode_canonical(&out_of_order_commit_unsigned)?,
    )?;
    let _ = submit_wallet_call(
        rpc_addr,
        keypair,
        chain_id,
        nonce,
        "commit_receipt_root@v1",
        out_of_order_commit,
    )
    .await;
    nonce += 1;

    let out_of_order_lookup = service_key(&receipt_commit_storage_key(
        &channel_id,
        SessionReceiptCommitDirection::LocalToRemote,
        10,
    ));
    assert!(query_state_key(rpc_addr, &out_of_order_lookup)
        .await?
        .is_none());

    channel = load_wallet_value(rpc_addr, &channel_storage_key(&channel_id)).await?;
    assert_eq!(channel.state, SessionChannelState::Open);
    assert_eq!(channel.last_seq, 7);

    let mut close = SessionChannelClose {
        channel_id,
        reason: SessionChannelCloseReason::Manual,
        final_seq: 9,
        closed_at_ms: 4_100_000_100_000,
        sig_hybrid_sender: Vec::new(),
    };
    let mut close_unsigned = close.clone();
    close_unsigned.sig_hybrid_sender.clear();
    close.sig_hybrid_sender = sign_hybrid_payload(&lc_signer, &encode_canonical(&close_unsigned)?)?;
    submit_wallet_call(
        rpc_addr,
        keypair,
        chain_id,
        nonce,
        "close_channel@v1",
        close,
    )
    .await?;
    nonce += 1;

    channel = load_wallet_value(rpc_addr, &channel_storage_key(&channel_id)).await?;
    assert_eq!(channel.state, SessionChannelState::Closed);
    assert_eq!(channel.last_seq, 9);
    assert_eq!(
        channel.close_reason,
        Some(SessionChannelCloseReason::Manual)
    );
    assert!(channel.closed_at_ms.is_some());

    let closed_channel_key_state: SessionChannelKeyState =
        load_wallet_value(rpc_addr, &channel_key_state_storage_key(&channel_id)).await?;
    assert!(!closed_channel_key_state.ready);
    Ok(nonce)
}

async fn exercise_unordered_channel_scenarios(
    rpc_addr: &str,
    keypair: &Keypair,
    chain_id: ChainId,
    mut nonce: u64,
    lc_signer: &HybridSigner,
    rc_signer: &HybridSigner,
    signer_account_id: [u8; 32],
) -> Result<u64> {
    let unordered_channel_id = [0x12u8; 32];
    let unordered_envelope = SessionChannelEnvelope {
        channel_id: unordered_channel_id,
        lc_id: lc_signer.signer_id,
        rc_id: rc_signer.signer_id,
        ordering: SessionChannelOrdering::Unordered,
        mode: SessionChannelMode::RemoteRequestLocalExecution,
        policy_hash: [0x33u8; 32],
        policy_version: 9,
        root_grant_id: [0x34u8; 32],
        capability_set: vec!["email:read".to_string(), "email:search".to_string()],
        constraints: BTreeMap::from([("mailbox".to_string(), "primary".to_string())]),
        delegation_rules: SessionChannelDelegationRules {
            max_depth: 2,
            can_redelegate: true,
            issuance_budget: Some(8),
        },
        revocation_epoch: 0,
        expires_at_ms: 4_250_000_000_000,
    };
    let unordered_envelope_hash = hash_channel_envelope(&unordered_envelope)?;

    let mut unordered_open_init = SessionChannelOpenInit {
        envelope: unordered_envelope.clone(),
        lc_kem_ephemeral_pub_classical: vec![21, 22, 23],
        lc_kem_ephemeral_pub_pq: vec![24, 25, 26],
        nonce_lc: [0x61u8; 32],
        sig_hybrid_lc: Vec::new(),
    };
    let mut unordered_open_init_unsigned = unordered_open_init.clone();
    unordered_open_init_unsigned.sig_hybrid_lc.clear();
    unordered_open_init.sig_hybrid_lc = sign_hybrid_payload(
        &lc_signer,
        &encode_canonical(&unordered_open_init_unsigned)?,
    )?;
    submit_wallet_call(
        rpc_addr,
        keypair,
        chain_id,
        nonce,
        "open_channel_init@v1",
        unordered_open_init,
    )
    .await?;
    nonce += 1;

    let mut unordered_open_try = SessionChannelOpenTry {
        channel_id: unordered_channel_id,
        envelope_hash: unordered_envelope_hash,
        rc_attestation_evidence: vec![27, 28],
        rc_attestation_pub: vec![29, 30],
        rc_kem_ephemeral_pub_classical: vec![31, 32],
        rc_kem_ciphertext_pq: vec![33, 34],
        nonce_rc: [0x62u8; 32],
        sig_hybrid_rc: Vec::new(),
    };
    let mut unordered_open_try_unsigned = unordered_open_try.clone();
    unordered_open_try_unsigned.sig_hybrid_rc.clear();
    unordered_open_try.sig_hybrid_rc =
        sign_hybrid_payload(&rc_signer, &encode_canonical(&unordered_open_try_unsigned)?)?;
    submit_wallet_call(
        rpc_addr,
        keypair,
        chain_id,
        nonce,
        "open_channel_try@v1",
        unordered_open_try,
    )
    .await?;
    nonce += 1;

    let mut unordered_open_ack = SessionChannelOpenAck {
        channel_id: unordered_channel_id,
        envelope_hash: unordered_envelope_hash,
        nonce_lc2: [0x63u8; 32],
        sig_hybrid_lc: Vec::new(),
    };
    let mut unordered_open_ack_unsigned = unordered_open_ack.clone();
    unordered_open_ack_unsigned.sig_hybrid_lc.clear();
    unordered_open_ack.sig_hybrid_lc =
        sign_hybrid_payload(&lc_signer, &encode_canonical(&unordered_open_ack_unsigned)?)?;
    submit_wallet_call(
        rpc_addr,
        keypair,
        chain_id,
        nonce,
        "open_channel_ack@v1",
        unordered_open_ack,
    )
    .await?;
    nonce += 1;

    let mut unordered_open_confirm = SessionChannelOpenConfirm {
        channel_id: unordered_channel_id,
        envelope_hash: unordered_envelope_hash,
        nonce_rc2: [0x64u8; 32],
        sig_hybrid_rc: Vec::new(),
    };
    let mut unordered_open_confirm_unsigned = unordered_open_confirm.clone();
    unordered_open_confirm_unsigned.sig_hybrid_rc.clear();
    unordered_open_confirm.sig_hybrid_rc = sign_hybrid_payload(
        &rc_signer,
        &encode_canonical(&unordered_open_confirm_unsigned)?,
    )?;
    submit_wallet_call(
        rpc_addr,
        keypair,
        chain_id,
        nonce,
        "open_channel_confirm@v1",
        unordered_open_confirm,
    )
    .await?;
    nonce += 1;

    let sign_lease = |mut lease: SessionLease| -> Result<SessionLease> {
        let mut unsigned = lease.clone();
        unsigned.sig_hybrid_lc.clear();
        lease.sig_hybrid_lc = sign_hybrid_payload(&lc_signer, &encode_canonical(&unsigned)?)?;
        Ok(lease)
    };

    let unordered_lease_high = sign_lease(SessionLease {
        lease_id: [0x65u8; 32],
        channel_id: unordered_channel_id,
        issuer_id: lc_signer.signer_id,
        subject_id: [0x66u8; 32],
        policy_hash: unordered_envelope.policy_hash,
        grant_id: [0x67u8; 32],
        capability_subset: vec!["email:read".to_string()],
        constraints_subset: BTreeMap::from([("mailbox".to_string(), "primary".to_string())]),
        mode: SessionLeaseMode::Lease,
        expires_at_ms: 4_220_000_000_000,
        revocation_epoch: 0,
        audience: [0x68u8; 32],
        nonce: [0x69u8; 32],
        counter: 600,
        issued_at_ms: 4_100_000_200_000,
        sig_hybrid_lc: Vec::new(),
    })?;
    submit_wallet_call(
        rpc_addr,
        keypair,
        chain_id,
        nonce,
        "issue_session_lease@v1",
        unordered_lease_high,
    )
    .await?;
    nonce += 1;

    let unordered_lease_out_of_order = sign_lease(SessionLease {
        lease_id: [0x6au8; 32],
        channel_id: unordered_channel_id,
        issuer_id: lc_signer.signer_id,
        subject_id: [0x66u8; 32],
        policy_hash: unordered_envelope.policy_hash,
        grant_id: [0x6bu8; 32],
        capability_subset: vec!["email:read".to_string()],
        constraints_subset: BTreeMap::from([("mailbox".to_string(), "primary".to_string())]),
        mode: SessionLeaseMode::Lease,
        expires_at_ms: 4_220_000_000_000,
        revocation_epoch: 0,
        audience: [0x68u8; 32],
        nonce: [0x6cu8; 32],
        counter: 550,
        issued_at_ms: 4_100_000_200_100,
        sig_hybrid_lc: Vec::new(),
    })?;
    submit_wallet_call(
        rpc_addr,
        keypair,
        chain_id,
        nonce,
        "issue_session_lease@v1",
        unordered_lease_out_of_order,
    )
    .await?;
    nonce += 1;

    let unordered_lease_counter_replay = sign_lease(SessionLease {
        lease_id: [0x6du8; 32],
        channel_id: unordered_channel_id,
        issuer_id: lc_signer.signer_id,
        subject_id: [0x66u8; 32],
        policy_hash: unordered_envelope.policy_hash,
        grant_id: [0x6eu8; 32],
        capability_subset: vec!["email:read".to_string()],
        constraints_subset: BTreeMap::from([("mailbox".to_string(), "primary".to_string())]),
        mode: SessionLeaseMode::Lease,
        expires_at_ms: 4_220_000_000_000,
        revocation_epoch: 0,
        audience: [0x68u8; 32],
        nonce: [0x6fu8; 32],
        counter: 550,
        issued_at_ms: 4_100_000_200_200,
        sig_hybrid_lc: Vec::new(),
    })?;
    let _ = submit_wallet_call(
        rpc_addr,
        keypair,
        chain_id,
        nonce,
        "issue_session_lease@v1",
        unordered_lease_counter_replay,
    )
    .await;
    nonce += 1;

    let unordered_lease_outside_window = sign_lease(SessionLease {
        lease_id: [0x70u8; 32],
        channel_id: unordered_channel_id,
        issuer_id: lc_signer.signer_id,
        subject_id: [0x66u8; 32],
        policy_hash: unordered_envelope.policy_hash,
        grant_id: [0x71u8; 32],
        capability_subset: vec!["email:read".to_string()],
        constraints_subset: BTreeMap::from([("mailbox".to_string(), "primary".to_string())]),
        mode: SessionLeaseMode::Lease,
        expires_at_ms: 4_220_000_000_000,
        revocation_epoch: 0,
        audience: [0x68u8; 32],
        nonce: [0x72u8; 32],
        counter: 200,
        issued_at_ms: 4_100_000_200_300,
        sig_hybrid_lc: Vec::new(),
    })?;
    let _ = submit_wallet_call(
        rpc_addr,
        keypair,
        chain_id,
        nonce,
        "issue_session_lease@v1",
        unordered_lease_outside_window,
    )
    .await;
    nonce += 1;

    let unordered_high: SessionLease = load_wallet_value(
        rpc_addr,
        &lease_storage_key(&unordered_channel_id, &[0x65u8; 32]),
    )
    .await?;
    assert_eq!(unordered_high.counter, 600);

    let unordered_out_of_order: SessionLease = load_wallet_value(
        rpc_addr,
        &lease_storage_key(&unordered_channel_id, &[0x6au8; 32]),
    )
    .await?;
    assert_eq!(unordered_out_of_order.counter, 550);

    let counter_replay_lookup =
        service_key(&lease_storage_key(&unordered_channel_id, &[0x6du8; 32]));
    let outside_window_lookup =
        service_key(&lease_storage_key(&unordered_channel_id, &[0x70u8; 32]));
    assert!(query_state_key(rpc_addr, &counter_replay_lookup)
        .await?
        .is_none());
    assert!(query_state_key(rpc_addr, &outside_window_lookup)
        .await?
        .is_none());

    let unordered_mail_lease = sign_lease(SessionLease {
        lease_id: [0x73u8; 32],
        channel_id: unordered_channel_id,
        issuer_id: lc_signer.signer_id,
        subject_id: [0x74u8; 32],
        policy_hash: unordered_envelope.policy_hash,
        grant_id: [0x75u8; 32],
        capability_subset: vec!["email:read".to_string()],
        constraints_subset: BTreeMap::from([("mailbox".to_string(), "primary".to_string())]),
        mode: SessionLeaseMode::Lease,
        expires_at_ms: 4_220_000_000_000,
        revocation_epoch: 0,
        audience: signer_account_id,
        nonce: [0x76u8; 32],
        counter: 601,
        issued_at_ms: 4_100_000_200_400,
        sig_hybrid_lc: Vec::new(),
    })?;
    submit_wallet_call(
        rpc_addr,
        keypair,
        chain_id,
        nonce,
        "issue_session_lease@v1",
        unordered_mail_lease.clone(),
    )
    .await?;
    nonce += 1;

    submit_wallet_call(
        rpc_addr,
        keypair,
        chain_id,
        nonce,
        "mail_read_latest@v1",
        MailReadLatestParams {
            operation_id: [0x77u8; 32],
            channel_id: unordered_channel_id,
            lease_id: unordered_mail_lease.lease_id,
            op_seq: 3,
            op_nonce: Some([0x78u8; 32]),
            mailbox: "primary".to_string(),
            requested_at_ms: 4_100_000_200_410,
        },
    )
    .await?;
    nonce += 1;

    submit_wallet_call(
        rpc_addr,
        keypair,
        chain_id,
        nonce,
        "mail_read_latest@v1",
        MailReadLatestParams {
            operation_id: [0x79u8; 32],
            channel_id: unordered_channel_id,
            lease_id: unordered_mail_lease.lease_id,
            op_seq: 1,
            op_nonce: Some([0x7au8; 32]),
            mailbox: "primary".to_string(),
            requested_at_ms: 4_100_000_200_420,
        },
    )
    .await?;
    nonce += 1;

    let unordered_duplicate_op = [0x7bu8; 32];
    let _ = submit_wallet_call(
        rpc_addr,
        keypair,
        chain_id,
        nonce,
        "mail_read_latest@v1",
        MailReadLatestParams {
            operation_id: unordered_duplicate_op,
            channel_id: unordered_channel_id,
            lease_id: unordered_mail_lease.lease_id,
            op_seq: 1,
            op_nonce: Some([0x7cu8; 32]),
            mailbox: "primary".to_string(),
            requested_at_ms: 4_100_000_200_430,
        },
    )
    .await;
    nonce += 1;

    submit_wallet_call(
        rpc_addr,
        keypair,
        chain_id,
        nonce,
        "mail_read_latest@v1",
        MailReadLatestParams {
            operation_id: [0x7du8; 32],
            channel_id: unordered_channel_id,
            lease_id: unordered_mail_lease.lease_id,
            op_seq: 700,
            op_nonce: Some([0x7eu8; 32]),
            mailbox: "primary".to_string(),
            requested_at_ms: 4_100_000_200_440,
        },
    )
    .await?;
    nonce += 1;

    let unordered_stale_op = [0x7fu8; 32];
    let _ = submit_wallet_call(
        rpc_addr,
        keypair,
        chain_id,
        nonce,
        "mail_read_latest@v1",
        MailReadLatestParams {
            operation_id: unordered_stale_op,
            channel_id: unordered_channel_id,
            lease_id: unordered_mail_lease.lease_id,
            op_seq: 100,
            op_nonce: Some([0x80u8; 32]),
            mailbox: "primary".to_string(),
            requested_at_ms: 4_100_000_200_450,
        },
    )
    .await;

    let unordered_duplicate_lookup =
        service_key(&mail_read_receipt_storage_key(&unordered_duplicate_op));
    let unordered_stale_lookup = service_key(&mail_read_receipt_storage_key(&unordered_stale_op));
    assert!(query_state_key(rpc_addr, &unordered_duplicate_lookup)
        .await?
        .is_none());
    assert!(query_state_key(rpc_addr, &unordered_stale_lookup)
        .await?
        .is_none());
    Ok(nonce)
}

#[tokio::test]
async fn wallet_network_session_channel_lifecycle_via_real_callservice_txs() -> Result<()> {
    let _guard = E2E_TEST_LOCK.lock().expect("lock");
    build_test_artifacts();

    let cluster = TestCluster::builder()
        .with_validators(1)
        .with_consensus_type("Convergent")
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

        let root_session_id = unique_id("wallet_network_root_session");
        let child_session_id = unique_id("wallet_network_child_session");
        let budget_reject_session_id = unique_id("wallet_network_budget_reject");
        let depth_reject_session_id = unique_id("wallet_network_depth_reject");

        nonce = exercise_grant_delegation_scenarios(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            root_session_id,
            child_session_id,
            budget_reject_session_id,
            depth_reject_session_id,
        )
        .await?;

        nonce = exercise_ordered_channel_scenarios(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            &lc_signer,
            &rc_signer,
            signer_account_id,
        )
        .await?;

        let _final_nonce = exercise_unordered_channel_scenarios(
            rpc_addr,
            keypair,
            chain_id,
            nonce,
            &lc_signer,
            &rc_signer,
            signer_account_id,
        )
        .await?;

        Ok(())
    }
    .await;

    let shutdown_result = cluster.shutdown().await;
    shutdown_result?;
    test_result
}
