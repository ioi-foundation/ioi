use super::*;

#[test]
fn mail_read_latest_consumes_one_shot_lease_once() {
    let service = WalletNetworkService;
    let mut state = MockState::default();
    let lc_signer = new_hybrid_signer();
    let rc_signer = new_hybrid_signer();
    let channel_id = [0xa1u8; 32];
    let lease_id = [0xa2u8; 32];
    let signer_audience = [0xa3u8; 32];
    open_channel(&service, &mut state, channel_id, &lc_signer, &rc_signer);

    with_ctx_signer(signer_audience, |ctx| {
        let mut lease = SessionLease {
            lease_id,
            channel_id,
            issuer_id: lc_signer.signer_id,
            subject_id: [0xa4u8; 32],
            policy_hash: [23u8; 32],
            grant_id: [0xa5u8; 32],
            capability_subset: vec!["email:read".to_string()],
            constraints_subset: BTreeMap::new(),
            mode: SessionLeaseMode::OneShot,
            expires_at_ms: 1_800_000_000_000,
            revocation_epoch: 0,
            audience: signer_audience,
            nonce: [0xa6u8; 32],
            counter: 1,
            issued_at_ms: 1_750_000_000_000,
            sig_hybrid_lc: Vec::new(),
        };
        let mut lease_unsigned = lease.clone();
        lease_unsigned.sig_hybrid_lc.clear();
        lease.sig_hybrid_lc = sign_hybrid_payload(
            &lc_signer,
            &codec::to_bytes_canonical(&lease_unsigned).expect("encode"),
        );
        let lease_params = codec::to_bytes_canonical(&lease).expect("encode");
        run_async(service.handle_service_call(
            &mut state,
            "issue_session_lease@v1",
            &lease_params,
            ctx,
        ))
        .expect("issue lease");

        let first_read = MailReadLatestParams {
            operation_id: [0xa7u8; 32],
            channel_id,
            lease_id,
            op_seq: 1,
            op_nonce: Some([0xa9u8; 32]),
            mailbox: "primary".to_string(),
            requested_at_ms: 1_750_000_000_010,
        };
        let first_read_params = codec::to_bytes_canonical(&first_read).expect("encode");
        run_async(service.handle_service_call(
            &mut state,
            "mail_read_latest@v1",
            &first_read_params,
            ctx,
        ))
        .expect("first one-shot read must succeed");

        let second_read = MailReadLatestParams {
            operation_id: [0xa8u8; 32],
            channel_id,
            lease_id,
            op_seq: 2,
            op_nonce: Some([0xaau8; 32]),
            mailbox: "primary".to_string(),
            requested_at_ms: 1_750_000_000_020,
        };
        let second_read_params = codec::to_bytes_canonical(&second_read).expect("encode");
        let err = run_async(service.handle_service_call(
            &mut state,
            "mail_read_latest@v1",
            &second_read_params,
            ctx,
        ))
        .expect_err("second use of one-shot lease must fail");
        assert!(err.to_string().to_ascii_lowercase().contains("one-shot"));
    });

    let receipt: MailReadLatestReceipt = codec::from_bytes_canonical(
        &state
            .get(&mail_read_receipt_key(&[0xa7u8; 32]))
            .expect("state")
            .expect("receipt"),
    )
    .expect("decode");
    assert_eq!(receipt.channel_id, channel_id);
    assert_eq!(receipt.lease_id, lease_id);
    assert_eq!(receipt.mailbox, "primary");
    assert!(receipt.message.spam_confidence_bps > 0);
    assert!(!receipt.message.spam_confidence_band.trim().is_empty());
    assert!(!receipt.message.spam_signal_tags.is_empty());

    let consumption: LeaseConsumptionState = codec::from_bytes_canonical(
        &state
            .get(&lease_consumption_key(&channel_id, &lease_id))
            .expect("state")
            .expect("lease consumption"),
    )
    .expect("decode");
    assert_eq!(consumption.consumed_count, 1);
    assert_eq!(consumption.consumed_operation_ids.len(), 1);
}

#[test]
fn mail_read_latest_rejects_signer_audience_mismatch() {
    let service = WalletNetworkService;
    let mut state = MockState::default();
    let lc_signer = new_hybrid_signer();
    let rc_signer = new_hybrid_signer();
    let channel_id = [0xb1u8; 32];
    let lease_id = [0xb2u8; 32];
    open_channel(&service, &mut state, channel_id, &lc_signer, &rc_signer);

    with_ctx_signer([0xb3u8; 32], |ctx| {
        let mut lease = SessionLease {
            lease_id,
            channel_id,
            issuer_id: lc_signer.signer_id,
            subject_id: [0xb4u8; 32],
            policy_hash: [23u8; 32],
            grant_id: [0xb5u8; 32],
            capability_subset: vec!["email:read".to_string()],
            constraints_subset: BTreeMap::new(),
            mode: SessionLeaseMode::Lease,
            expires_at_ms: 1_800_000_000_000,
            revocation_epoch: 0,
            audience: [0xb6u8; 32],
            nonce: [0xb7u8; 32],
            counter: 1,
            issued_at_ms: 1_750_000_000_000,
            sig_hybrid_lc: Vec::new(),
        };
        let mut lease_unsigned = lease.clone();
        lease_unsigned.sig_hybrid_lc.clear();
        lease.sig_hybrid_lc = sign_hybrid_payload(
            &lc_signer,
            &codec::to_bytes_canonical(&lease_unsigned).expect("encode"),
        );
        let lease_params = codec::to_bytes_canonical(&lease).expect("encode");
        run_async(service.handle_service_call(
            &mut state,
            "issue_session_lease@v1",
            &lease_params,
            ctx,
        ))
        .expect("issue lease");

        let read = MailReadLatestParams {
            operation_id: [0xb8u8; 32],
            channel_id,
            lease_id,
            op_seq: 1,
            op_nonce: Some([0xb9u8; 32]),
            mailbox: "primary".to_string(),
            requested_at_ms: 1_750_000_000_010,
        };
        let read_params = codec::to_bytes_canonical(&read).expect("encode");
        let err = run_async(service.handle_service_call(
            &mut state,
            "mail_read_latest@v1",
            &read_params,
            ctx,
        ))
        .expect_err("audience mismatch must fail");
        assert!(err.to_string().to_ascii_lowercase().contains("audience"));
    });

    assert!(state
        .get(&mail_read_receipt_key(&[0xb8u8; 32]))
        .expect("state")
        .is_none());
}

#[test]
fn mail_read_latest_enforces_ordered_action_sequences() {
    let service = WalletNetworkService;
    let mut state = MockState::default();
    let lc_signer = new_hybrid_signer();
    let rc_signer = new_hybrid_signer();
    let channel_id = [0xc1u8; 32];
    let lease_id = [0xc2u8; 32];
    let signer_audience = [0xc3u8; 32];
    open_channel(&service, &mut state, channel_id, &lc_signer, &rc_signer);

    with_ctx_signer(signer_audience, |ctx| {
        let mut lease = SessionLease {
            lease_id,
            channel_id,
            issuer_id: lc_signer.signer_id,
            subject_id: [0xc4u8; 32],
            policy_hash: [23u8; 32],
            grant_id: [0xc5u8; 32],
            capability_subset: vec!["email:read".to_string()],
            constraints_subset: BTreeMap::new(),
            mode: SessionLeaseMode::Lease,
            expires_at_ms: 1_800_000_000_000,
            revocation_epoch: 0,
            audience: signer_audience,
            nonce: [0xc6u8; 32],
            counter: 1,
            issued_at_ms: 1_750_000_000_000,
            sig_hybrid_lc: Vec::new(),
        };
        let mut lease_unsigned = lease.clone();
        lease_unsigned.sig_hybrid_lc.clear();
        lease.sig_hybrid_lc = sign_hybrid_payload(
            &lc_signer,
            &codec::to_bytes_canonical(&lease_unsigned).expect("encode"),
        );
        let lease_params = codec::to_bytes_canonical(&lease).expect("encode");
        run_async(service.handle_service_call(
            &mut state,
            "issue_session_lease@v1",
            &lease_params,
            ctx,
        ))
        .expect("issue lease");

        let seq1 = MailReadLatestParams {
            operation_id: [0xc7u8; 32],
            channel_id,
            lease_id,
            op_seq: 1,
            op_nonce: Some([0xc8u8; 32]),
            mailbox: "primary".to_string(),
            requested_at_ms: 1_750_000_000_010,
        };
        let seq1_params = codec::to_bytes_canonical(&seq1).expect("encode");
        run_async(service.handle_service_call(
            &mut state,
            "mail_read_latest@v1",
            &seq1_params,
            ctx,
        ))
        .expect("seq=1 should succeed");

        let duplicate_seq1 = MailReadLatestParams {
            operation_id: [0xc9u8; 32],
            channel_id,
            lease_id,
            op_seq: 1,
            op_nonce: Some([0xcau8; 32]),
            mailbox: "primary".to_string(),
            requested_at_ms: 1_750_000_000_020,
        };
        let duplicate_params = codec::to_bytes_canonical(&duplicate_seq1).expect("encode");
        let duplicate_err = run_async(service.handle_service_call(
            &mut state,
            "mail_read_latest@v1",
            &duplicate_params,
            ctx,
        ))
        .expect_err("ordered duplicate seq must fail");
        assert!(duplicate_err
            .to_string()
            .to_ascii_lowercase()
            .contains("ordered action op_seq"));

        let gap_seq = MailReadLatestParams {
            operation_id: [0xcbu8; 32],
            channel_id,
            lease_id,
            op_seq: 3,
            op_nonce: Some([0xccu8; 32]),
            mailbox: "primary".to_string(),
            requested_at_ms: 1_750_000_000_030,
        };
        let gap_params = codec::to_bytes_canonical(&gap_seq).expect("encode");
        let gap_err = run_async(service.handle_service_call(
            &mut state,
            "mail_read_latest@v1",
            &gap_params,
            ctx,
        ))
        .expect_err("ordered seq gap must fail");
        assert!(gap_err
            .to_string()
            .to_ascii_lowercase()
            .contains("ordered action op_seq"));
    });
}

#[test]
fn mail_read_latest_allows_unordered_sequences_but_rejects_replay_and_stale() {
    let service = WalletNetworkService;
    let mut state = MockState::default();
    let lc_signer = new_hybrid_signer();
    let rc_signer = new_hybrid_signer();
    let channel_id = [0xd1u8; 32];
    let lease_id = [0xd2u8; 32];
    let signer_audience = [0xd3u8; 32];
    open_channel_with_ordering(
        &service,
        &mut state,
        channel_id,
        &lc_signer,
        &rc_signer,
        ioi_types::app::wallet_network::SessionChannelOrdering::Unordered,
    );

    with_ctx_signer(signer_audience, |ctx| {
        let mut lease = SessionLease {
            lease_id,
            channel_id,
            issuer_id: lc_signer.signer_id,
            subject_id: [0xd4u8; 32],
            policy_hash: [23u8; 32],
            grant_id: [0xd5u8; 32],
            capability_subset: vec!["email:read".to_string()],
            constraints_subset: BTreeMap::new(),
            mode: SessionLeaseMode::Lease,
            expires_at_ms: 1_800_000_000_000,
            revocation_epoch: 0,
            audience: signer_audience,
            nonce: [0xd6u8; 32],
            counter: 1,
            issued_at_ms: 1_750_000_000_000,
            sig_hybrid_lc: Vec::new(),
        };
        let mut lease_unsigned = lease.clone();
        lease_unsigned.sig_hybrid_lc.clear();
        lease.sig_hybrid_lc = sign_hybrid_payload(
            &lc_signer,
            &codec::to_bytes_canonical(&lease_unsigned).expect("encode"),
        );
        let lease_params = codec::to_bytes_canonical(&lease).expect("encode");
        run_async(service.handle_service_call(
            &mut state,
            "issue_session_lease@v1",
            &lease_params,
            ctx,
        ))
        .expect("issue lease");

        for (operation_id, op_seq, op_nonce) in [
            ([0xd7u8; 32], 3u64, [0xd8u8; 32]),
            ([0xd9u8; 32], 1u64, [0xdau8; 32]),
            ([0xdbu8; 32], 700u64, [0xdcu8; 32]),
        ] {
            let req = MailReadLatestParams {
                operation_id,
                channel_id,
                lease_id,
                op_seq,
                op_nonce: Some(op_nonce),
                mailbox: "primary".to_string(),
                requested_at_ms: 1_750_000_000_010 + op_seq,
            };
            let req_params = codec::to_bytes_canonical(&req).expect("encode");
            run_async(service.handle_service_call(
                &mut state,
                "mail_read_latest@v1",
                &req_params,
                ctx,
            ))
            .expect("unordered sequence should be accepted");
        }

        let replay_req = MailReadLatestParams {
            operation_id: [0xddu8; 32],
            channel_id,
            lease_id,
            op_seq: 1,
            op_nonce: Some([0xdeu8; 32]),
            mailbox: "primary".to_string(),
            requested_at_ms: 1_750_000_000_999,
        };
        let replay_params = codec::to_bytes_canonical(&replay_req).expect("encode");
        let replay_err = run_async(service.handle_service_call(
            &mut state,
            "mail_read_latest@v1",
            &replay_params,
            ctx,
        ))
        .expect_err("unordered replay seq must fail");
        assert!(replay_err
            .to_string()
            .to_ascii_lowercase()
            .contains("replay"));

        let stale_req = MailReadLatestParams {
            operation_id: [0xdfu8; 32],
            channel_id,
            lease_id,
            op_seq: 100,
            op_nonce: Some([0xe0u8; 32]),
            mailbox: "primary".to_string(),
            requested_at_ms: 1_750_000_001_000,
        };
        let stale_params = codec::to_bytes_canonical(&stale_req).expect("encode");
        let stale_err = run_async(service.handle_service_call(
            &mut state,
            "mail_read_latest@v1",
            &stale_params,
            ctx,
        ))
        .expect_err("unordered stale seq outside replay window must fail");
        assert!(stale_err
            .to_string()
            .to_ascii_lowercase()
            .contains("outside replay window"));
    });
}

#[test]
fn mail_list_recent_uses_shared_replay_window_and_nonce_binding() {
    let service = WalletNetworkService;
    let mut state = MockState::default();
    let lc_signer = new_hybrid_signer();
    let rc_signer = new_hybrid_signer();
    let channel_id = [0xe1u8; 32];
    let lease_id = [0xe2u8; 32];
    let signer_audience = [0xe3u8; 32];
    open_channel(&service, &mut state, channel_id, &lc_signer, &rc_signer);

    with_ctx_signer(signer_audience, |ctx| {
        let mut lease = SessionLease {
            lease_id,
            channel_id,
            issuer_id: lc_signer.signer_id,
            subject_id: [0xe4u8; 32],
            policy_hash: [23u8; 32],
            grant_id: [0xe5u8; 32],
            capability_subset: vec!["email:read".to_string()],
            constraints_subset: BTreeMap::new(),
            mode: SessionLeaseMode::Lease,
            expires_at_ms: 1_800_000_000_000,
            revocation_epoch: 0,
            audience: signer_audience,
            nonce: [0xe6u8; 32],
            counter: 1,
            issued_at_ms: 1_750_000_000_000,
            sig_hybrid_lc: Vec::new(),
        };
        let mut lease_unsigned = lease.clone();
        lease_unsigned.sig_hybrid_lc.clear();
        lease.sig_hybrid_lc = sign_hybrid_payload(
            &lc_signer,
            &codec::to_bytes_canonical(&lease_unsigned).expect("encode"),
        );
        let lease_params = codec::to_bytes_canonical(&lease).expect("encode");
        run_async(service.handle_service_call(
            &mut state,
            "issue_session_lease@v1",
            &lease_params,
            ctx,
        ))
        .expect("issue lease");

        let list_seq1 = MailListRecentParams {
            operation_id: [0xe7u8; 32],
            channel_id,
            lease_id,
            op_seq: 1,
            op_nonce: Some([0xe8u8; 32]),
            mailbox: "primary".to_string(),
            limit: 3,
            requested_at_ms: 1_750_000_000_010,
        };
        let list_seq1_params = codec::to_bytes_canonical(&list_seq1).expect("encode");
        run_async(service.handle_service_call(
            &mut state,
            "mail_list_recent@v1",
            &list_seq1_params,
            ctx,
        ))
        .expect("mail list seq=1 should succeed");

        let read_seq1 = MailReadLatestParams {
            operation_id: [0xe9u8; 32],
            channel_id,
            lease_id,
            op_seq: 1,
            op_nonce: Some([0xeau8; 32]),
            mailbox: "primary".to_string(),
            requested_at_ms: 1_750_000_000_020,
        };
        let read_seq1_params = codec::to_bytes_canonical(&read_seq1).expect("encode");
        let read_seq1_err = run_async(service.handle_service_call(
            &mut state,
            "mail_read_latest@v1",
            &read_seq1_params,
            ctx,
        ))
        .expect_err("shared replay window must reject stale ordered op_seq");
        assert!(read_seq1_err
            .to_string()
            .to_ascii_lowercase()
            .contains("ordered action op_seq"));

        let list_seq2_nonce_replay = MailListRecentParams {
            operation_id: [0xebu8; 32],
            channel_id,
            lease_id,
            op_seq: 2,
            op_nonce: Some([0xe8u8; 32]),
            mailbox: "primary".to_string(),
            limit: 2,
            requested_at_ms: 1_750_000_000_030,
        };
        let list_seq2_nonce_replay_params =
            codec::to_bytes_canonical(&list_seq2_nonce_replay).expect("encode");
        let nonce_replay_err = run_async(service.handle_service_call(
            &mut state,
            "mail_list_recent@v1",
            &list_seq2_nonce_replay_params,
            ctx,
        ))
        .expect_err("op_nonce replay must fail");
        assert!(nonce_replay_err
            .to_string()
            .to_ascii_lowercase()
            .contains("op_nonce replay"));

        let list_seq2 = MailListRecentParams {
            operation_id: [0xecu8; 32],
            channel_id,
            lease_id,
            op_seq: 2,
            op_nonce: Some([0xedu8; 32]),
            mailbox: "primary".to_string(),
            limit: 2,
            requested_at_ms: 1_750_000_000_040,
        };
        let list_seq2_params = codec::to_bytes_canonical(&list_seq2).expect("encode");
        run_async(service.handle_service_call(
            &mut state,
            "mail_list_recent@v1",
            &list_seq2_params,
            ctx,
        ))
        .expect("seq=2 with fresh nonce should succeed");
    });

    let list_receipt: MailListRecentReceipt = codec::from_bytes_canonical(
        &state
            .get(&mail_list_receipt_key(&[0xe7u8; 32]))
            .expect("state")
            .expect("list receipt"),
    )
    .expect("decode");
    assert_eq!(list_receipt.channel_id, channel_id);
    assert_eq!(list_receipt.lease_id, lease_id);
    assert_eq!(list_receipt.mailbox, "primary");
    assert_eq!(list_receipt.messages.len(), 3);
    assert!(list_receipt.requested_limit >= 3);
    assert!(list_receipt.evaluated_count >= 3);
    assert!(list_receipt.parse_confidence_bps > 0);
    assert!(!list_receipt.parse_volume_band.trim().is_empty());
    assert!(!list_receipt.ontology_version.trim().is_empty());
    assert!(list_receipt
        .messages
        .iter()
        .all(|message| message.spam_confidence_bps > 0));

    let consumption: LeaseConsumptionState = codec::from_bytes_canonical(
        &state
            .get(&lease_consumption_key(&channel_id, &lease_id))
            .expect("state")
            .expect("lease consumption"),
    )
    .expect("decode");
    assert_eq!(consumption.consumed_count, 2);
}

#[test]
fn mailbox_total_count_uses_connector_path_and_shared_replay_window() {
    let service = WalletNetworkService;
    let mut state = MockState::default();
    let lc_signer = new_hybrid_signer();
    let rc_signer = new_hybrid_signer();
    let channel_id = [0xd1u8; 32];
    let lease_id = [0xd2u8; 32];
    let signer_audience = [0xd3u8; 32];
    open_channel(&service, &mut state, channel_id, &lc_signer, &rc_signer);

    with_ctx_signer(signer_audience, |ctx| {
        let mut lease = SessionLease {
            lease_id,
            channel_id,
            issuer_id: lc_signer.signer_id,
            subject_id: [0xd4u8; 32],
            policy_hash: [23u8; 32],
            grant_id: [0xd5u8; 32],
            capability_subset: vec!["email:read".to_string()],
            constraints_subset: BTreeMap::new(),
            mode: SessionLeaseMode::Lease,
            expires_at_ms: 1_800_000_000_000,
            revocation_epoch: 0,
            audience: signer_audience,
            nonce: [0xd6u8; 32],
            counter: 1,
            issued_at_ms: 1_750_000_000_000,
            sig_hybrid_lc: Vec::new(),
        };
        let mut lease_unsigned = lease.clone();
        lease_unsigned.sig_hybrid_lc.clear();
        lease.sig_hybrid_lc = sign_hybrid_payload(
            &lc_signer,
            &codec::to_bytes_canonical(&lease_unsigned).expect("encode"),
        );
        let lease_params = codec::to_bytes_canonical(&lease).expect("encode");
        run_async(service.handle_service_call(
            &mut state,
            "issue_session_lease@v1",
            &lease_params,
            ctx,
        ))
        .expect("issue lease");

        let count_req = MailboxTotalCountParams {
            operation_id: [0xd7u8; 32],
            channel_id,
            lease_id,
            op_seq: 1,
            op_nonce: Some([0xd8u8; 32]),
            mailbox: "primary".to_string(),
            requested_at_ms: 1_750_000_000_010,
        };
        let count_params = codec::to_bytes_canonical(&count_req).expect("encode");
        run_async(service.handle_service_call(
            &mut state,
            "mailbox_total_count@v1",
            &count_params,
            ctx,
        ))
        .expect("mailbox_total_count should succeed");

        let list_req = MailListRecentParams {
            operation_id: [0xd9u8; 32],
            channel_id,
            lease_id,
            op_seq: 2,
            op_nonce: Some([0xdau8; 32]),
            mailbox: "primary".to_string(),
            limit: 2,
            requested_at_ms: 1_750_000_000_020,
        };
        let list_params = codec::to_bytes_canonical(&list_req).expect("encode");
        run_async(service.handle_service_call(
            &mut state,
            "mail_list_recent@v1",
            &list_params,
            ctx,
        ))
        .expect("mail_list_recent should succeed after count");

        let stale_seq_req = MailboxTotalCountParams {
            operation_id: [0xdbu8; 32],
            channel_id,
            lease_id,
            op_seq: 2,
            op_nonce: Some([0xdcu8; 32]),
            mailbox: "primary".to_string(),
            requested_at_ms: 1_750_000_000_030,
        };
        let stale_seq_params = codec::to_bytes_canonical(&stale_seq_req).expect("encode");
        let err = run_async(service.handle_service_call(
            &mut state,
            "mailbox_total_count@v1",
            &stale_seq_params,
            ctx,
        ))
        .expect_err("ordered replay seq must fail across read operations");
        assert!(err
            .to_string()
            .to_ascii_lowercase()
            .contains("ordered action op_seq"));
    });

    let count_receipt: MailboxTotalCountReceipt = codec::from_bytes_canonical(
        &state
            .get(&mail_count_receipt_key(&[0xd7u8; 32]))
            .expect("state")
            .expect("count receipt"),
    )
    .expect("decode");
    assert_eq!(count_receipt.channel_id, channel_id);
    assert_eq!(count_receipt.lease_id, lease_id);
    assert_eq!(count_receipt.mailbox, "primary");
    assert!(count_receipt.mailbox_total_count > 0);
    assert!(!count_receipt.provenance.freshness_marker.trim().is_empty());
    assert!(
        count_receipt.provenance.status_exists.is_some()
            || count_receipt.provenance.select_exists.is_some()
            || count_receipt.provenance.uid_search_count.is_some()
            || count_receipt.provenance.search_count.is_some()
    );

    let consumption: LeaseConsumptionState = codec::from_bytes_canonical(
        &state
            .get(&lease_consumption_key(&channel_id, &lease_id))
            .expect("state")
            .expect("lease consumption"),
    )
    .expect("decode");
    assert_eq!(consumption.consumed_count, 2);
}

#[test]
fn mail_write_operations_route_through_shared_lease_replay_window() {
    let service = WalletNetworkService;
    let mut state = MockState::default();
    let lc_signer = new_hybrid_signer();
    let rc_signer = new_hybrid_signer();
    let channel_id = [0xf1u8; 32];
    let lease_id = [0xf2u8; 32];
    let signer_audience = [0xf3u8; 32];
    open_channel(&service, &mut state, channel_id, &lc_signer, &rc_signer);

    with_ctx_signer(signer_audience, |ctx| {
        let mut lease = SessionLease {
            lease_id,
            channel_id,
            issuer_id: lc_signer.signer_id,
            subject_id: [0xf4u8; 32],
            policy_hash: [23u8; 32],
            grant_id: [0xf5u8; 32],
            capability_subset: vec!["mail.write".to_string()],
            constraints_subset: BTreeMap::new(),
            mode: SessionLeaseMode::Lease,
            expires_at_ms: 1_800_000_000_000,
            revocation_epoch: 0,
            audience: signer_audience,
            nonce: [0xf6u8; 32],
            counter: 1,
            issued_at_ms: 1_750_000_000_000,
            sig_hybrid_lc: Vec::new(),
        };
        let mut lease_unsigned = lease.clone();
        lease_unsigned.sig_hybrid_lc.clear();
        lease.sig_hybrid_lc = sign_hybrid_payload(
            &lc_signer,
            &codec::to_bytes_canonical(&lease_unsigned).expect("encode"),
        );
        let lease_params = codec::to_bytes_canonical(&lease).expect("encode");
        run_async(service.handle_service_call(
            &mut state,
            "issue_session_lease@v1",
            &lease_params,
            ctx,
        ))
        .expect("issue lease");

        let delete_req = MailDeleteSpamParams {
            operation_id: [0xf7u8; 32],
            channel_id,
            lease_id,
            op_seq: 1,
            op_nonce: Some([0xf8u8; 32]),
            mailbox: "spam".to_string(),
            max_delete: 12,
            requested_at_ms: 1_750_000_000_010,
        };
        let delete_params = codec::to_bytes_canonical(&delete_req).expect("encode");
        run_async(service.handle_service_call(
            &mut state,
            "mail_delete_spam@v1",
            &delete_params,
            ctx,
        ))
        .expect("mail delete should succeed");

        let reply_req = MailReplyParams {
            operation_id: [0xf9u8; 32],
            channel_id,
            lease_id,
            op_seq: 2,
            op_nonce: Some([0xfau8; 32]),
            mailbox: "primary".to_string(),
            to: "bob@example.com".to_string(),
            subject: "Status update".to_string(),
            body: "Acknowledged.".to_string(),
            reply_to_message_id: Some("msg-123".to_string()),
            requested_at_ms: 1_750_000_000_020,
        };
        let reply_params = codec::to_bytes_canonical(&reply_req).expect("encode");
        run_async(service.handle_service_call(&mut state, "mail_reply@v1", &reply_params, ctx))
            .expect("mail reply should succeed");

        let replay_seq_req = MailDeleteSpamParams {
            operation_id: [0xfbu8; 32],
            channel_id,
            lease_id,
            op_seq: 2,
            op_nonce: Some([0xfcu8; 32]),
            mailbox: "spam".to_string(),
            max_delete: 3,
            requested_at_ms: 1_750_000_000_030,
        };
        let replay_seq_params = codec::to_bytes_canonical(&replay_seq_req).expect("encode");
        let replay_err = run_async(service.handle_service_call(
            &mut state,
            "mail_delete_spam@v1",
            &replay_seq_params,
            ctx,
        ))
        .expect_err("ordered replay seq must fail across write operations");
        assert!(replay_err
            .to_string()
            .to_ascii_lowercase()
            .contains("ordered action op_seq"));
    });

    let delete_receipt: MailDeleteSpamReceipt = codec::from_bytes_canonical(
        &state
            .get(&mail_delete_receipt_key(&[0xf7u8; 32]))
            .expect("state")
            .expect("delete receipt"),
    )
    .expect("decode");
    assert_eq!(delete_receipt.deleted_count, 12);
    assert_eq!(delete_receipt.high_confidence_deleted_count, 12);
    assert!(delete_receipt.evaluated_count >= delete_receipt.deleted_count);
    assert!(delete_receipt.spam_confidence_threshold_bps > 0);
    assert!(!delete_receipt.ontology_version.trim().is_empty());
    assert_eq!(delete_receipt.cleanup_scope, "spam_mailbox");
    assert_eq!(delete_receipt.preserved_transactional_or_personal_count, 0);
    assert_eq!(delete_receipt.preserved_trusted_system_count, 0);
    assert_eq!(delete_receipt.preserved_low_confidence_other_count, 0);
    assert_eq!(delete_receipt.preserved_due_to_delete_cap_count, 0);

    let reply_receipt: MailReplyReceipt = codec::from_bytes_canonical(
        &state
            .get(&mail_reply_receipt_key(&[0xf9u8; 32]))
            .expect("state")
            .expect("reply receipt"),
    )
    .expect("decode");
    assert_eq!(reply_receipt.to, "bob@example.com");

    let consumption: LeaseConsumptionState = codec::from_bytes_canonical(
        &state
            .get(&lease_consumption_key(&channel_id, &lease_id))
            .expect("state")
            .expect("lease consumption"),
    )
    .expect("decode");
    assert_eq!(consumption.consumed_count, 2);
}

#[test]
fn mail_delete_spam_rejects_non_cleanup_mailbox_target() {
    let service = WalletNetworkService;
    let mut state = MockState::default();
    let lc_signer = new_hybrid_signer();
    let rc_signer = new_hybrid_signer();
    let channel_id = [0x91u8; 32];
    let lease_id = [0x92u8; 32];
    let signer_audience = [0x93u8; 32];
    open_channel(&service, &mut state, channel_id, &lc_signer, &rc_signer);

    with_ctx_signer(signer_audience, |ctx| {
        let mut lease = SessionLease {
            lease_id,
            channel_id,
            issuer_id: lc_signer.signer_id,
            subject_id: [0x94u8; 32],
            policy_hash: [23u8; 32],
            grant_id: [0x95u8; 32],
            capability_subset: vec!["mail.write".to_string()],
            constraints_subset: BTreeMap::new(),
            mode: SessionLeaseMode::Lease,
            expires_at_ms: 1_800_000_000_000,
            revocation_epoch: 0,
            audience: signer_audience,
            nonce: [0x96u8; 32],
            counter: 1,
            issued_at_ms: 1_750_000_000_000,
            sig_hybrid_lc: Vec::new(),
        };
        let mut lease_unsigned = lease.clone();
        lease_unsigned.sig_hybrid_lc.clear();
        lease.sig_hybrid_lc = sign_hybrid_payload(
            &lc_signer,
            &codec::to_bytes_canonical(&lease_unsigned).expect("encode"),
        );
        let lease_params = codec::to_bytes_canonical(&lease).expect("encode");
        run_async(service.handle_service_call(
            &mut state,
            "issue_session_lease@v1",
            &lease_params,
            ctx,
        ))
        .expect("issue lease");

        let primary_delete_req = MailDeleteSpamParams {
            operation_id: [0x96u8; 32],
            channel_id,
            lease_id,
            op_seq: 1,
            op_nonce: Some([0x97u8; 32]),
            mailbox: "primary".to_string(),
            max_delete: 5,
            requested_at_ms: 1_750_000_000_010,
        };
        let primary_delete_params = codec::to_bytes_canonical(&primary_delete_req).expect("encode");
        run_async(service.handle_service_call(
            &mut state,
            "mail_delete_spam@v1",
            &primary_delete_params,
            ctx,
        ))
        .expect("mail_delete_spam should allow primary target");
        let primary_receipt: MailDeleteSpamReceipt = codec::from_bytes_canonical(
            &state
                .get(&mail_delete_receipt_key(&[0x96u8; 32]))
                .expect("state")
                .expect("primary delete receipt"),
        )
        .expect("decode receipt");
        assert_eq!(primary_receipt.cleanup_scope, "primary_inbox");
        assert!(primary_receipt.preserved_transactional_or_personal_count > 0);
        assert!(primary_receipt.evaluated_count >= primary_receipt.deleted_count);

        let delete_req = MailDeleteSpamParams {
            operation_id: [0x97u8; 32],
            channel_id,
            lease_id,
            op_seq: 2,
            op_nonce: Some([0x98u8; 32]),
            mailbox: "archive".to_string(),
            max_delete: 5,
            requested_at_ms: 1_750_000_000_010,
        };
        let delete_params = codec::to_bytes_canonical(&delete_req).expect("encode");
        let err = run_async(service.handle_service_call(
            &mut state,
            "mail_delete_spam@v1",
            &delete_params,
            ctx,
        ))
        .expect_err("mail_delete_spam should reject non-cleanup mailbox");
        assert!(err
            .to_string()
            .to_ascii_lowercase()
            .contains("primary/inbox or spam/junk mailbox target"));
    });

    assert!(state
        .get(&mail_delete_receipt_key(&[0x97u8; 32]))
        .expect("state")
        .is_none());
}
