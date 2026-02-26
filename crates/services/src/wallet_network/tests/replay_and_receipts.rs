use super::*;

#[test]
fn lease_replay_rejects_counter_regression_and_nonce_reuse() {
    let service = WalletNetworkService;
    let mut state = MockState::default();
    let lc_signer = new_hybrid_signer();
    let rc_signer = new_hybrid_signer();
    let channel_id = [0x75u8; 32];
    open_channel(&service, &mut state, channel_id, &lc_signer, &rc_signer);

    with_ctx(|ctx| {
        let mut lease_one = SessionLease {
            lease_id: [0x76u8; 32],
            channel_id,
            issuer_id: lc_signer.signer_id,
            subject_id: [0x77u8; 32],
            policy_hash: [23u8; 32],
            grant_id: [0x78u8; 32],
            capability_subset: vec!["email:read".to_string()],
            constraints_subset: BTreeMap::from([("max_usd".to_string(), "50".to_string())]),
            mode: ioi_types::app::wallet_network::SessionLeaseMode::Lease,
            expires_at_ms: 1_800_000_000_000,
            revocation_epoch: 0,
            audience: [0x79u8; 32],
            nonce: [0x7au8; 32],
            counter: 1,
            issued_at_ms: 1_750_000_000_000,
            sig_hybrid_lc: Vec::new(),
        };
        let mut lease_one_unsigned = lease_one.clone();
        lease_one_unsigned.sig_hybrid_lc.clear();
        lease_one.sig_hybrid_lc = sign_hybrid_payload(
            &lc_signer,
            &codec::to_bytes_canonical(&lease_one_unsigned).expect("encode"),
        );
        run_async(service.handle_service_call(
            &mut state,
            "issue_session_lease@v1",
            &codec::to_bytes_canonical(&lease_one).expect("encode"),
            ctx,
        ))
        .expect("lease one");

        let mut stale_counter = lease_one.clone();
        stale_counter.lease_id = [0x7bu8; 32];
        stale_counter.counter = 1;
        stale_counter.nonce = [0x7cu8; 32];
        stale_counter.sig_hybrid_lc.clear();
        let mut stale_counter_unsigned = stale_counter.clone();
        stale_counter_unsigned.sig_hybrid_lc.clear();
        stale_counter.sig_hybrid_lc = sign_hybrid_payload(
            &lc_signer,
            &codec::to_bytes_canonical(&stale_counter_unsigned).expect("encode"),
        );
        let stale_counter_err = run_async(service.handle_service_call(
            &mut state,
            "issue_session_lease@v1",
            &codec::to_bytes_canonical(&stale_counter).expect("encode"),
            ctx,
        ))
        .expect_err("counter replay should fail");
        assert!(stale_counter_err
            .to_string()
            .to_ascii_lowercase()
            .contains("counter"));

        let mut nonce_replay = lease_one.clone();
        nonce_replay.lease_id = [0x7du8; 32];
        nonce_replay.counter = 2;
        nonce_replay.nonce = [0x7au8; 32];
        nonce_replay.sig_hybrid_lc.clear();
        let mut nonce_replay_unsigned = nonce_replay.clone();
        nonce_replay_unsigned.sig_hybrid_lc.clear();
        nonce_replay.sig_hybrid_lc = sign_hybrid_payload(
            &lc_signer,
            &codec::to_bytes_canonical(&nonce_replay_unsigned).expect("encode"),
        );
        let nonce_replay_err = run_async(service.handle_service_call(
            &mut state,
            "issue_session_lease@v1",
            &codec::to_bytes_canonical(&nonce_replay).expect("encode"),
            ctx,
        ))
        .expect_err("nonce replay should fail");
        assert!(nonce_replay_err
            .to_string()
            .to_ascii_lowercase()
            .contains("nonce"));
    });

    let replay: LeaseReplayState =
        load_typed(&state, &lease_replay_key(&channel_id, &lc_signer.signer_id))
            .expect("load")
            .expect("lease replay state");
    assert_eq!(replay.last_counter, 1);
    assert_eq!(replay.seen_nonces, vec![[0x7au8; 32]]);
}

#[test]
fn lease_replay_ordered_rejects_counter_gaps() {
    let service = WalletNetworkService;
    let mut state = MockState::default();
    let lc_signer = new_hybrid_signer();
    let rc_signer = new_hybrid_signer();
    let channel_id = [0x7eu8; 32];
    open_channel(&service, &mut state, channel_id, &lc_signer, &rc_signer);

    with_ctx(|ctx| {
        let mut lease_one = SessionLease {
            lease_id: [0x90u8; 32],
            channel_id,
            issuer_id: lc_signer.signer_id,
            subject_id: [0x91u8; 32],
            policy_hash: [23u8; 32],
            grant_id: [0x92u8; 32],
            capability_subset: vec!["email:read".to_string()],
            constraints_subset: BTreeMap::from([("max_usd".to_string(), "50".to_string())]),
            mode: ioi_types::app::wallet_network::SessionLeaseMode::Lease,
            expires_at_ms: 1_800_000_000_000,
            revocation_epoch: 0,
            audience: [0x93u8; 32],
            nonce: [0x94u8; 32],
            counter: 1,
            issued_at_ms: 1_750_000_000_000,
            sig_hybrid_lc: Vec::new(),
        };
        let mut lease_one_unsigned = lease_one.clone();
        lease_one_unsigned.sig_hybrid_lc.clear();
        lease_one.sig_hybrid_lc = sign_hybrid_payload(
            &lc_signer,
            &codec::to_bytes_canonical(&lease_one_unsigned).expect("encode"),
        );
        run_async(service.handle_service_call(
            &mut state,
            "issue_session_lease@v1",
            &codec::to_bytes_canonical(&lease_one).expect("encode"),
            ctx,
        ))
        .expect("lease one");

        let mut counter_gap = lease_one.clone();
        counter_gap.lease_id = [0x95u8; 32];
        counter_gap.counter = 3;
        counter_gap.nonce = [0x96u8; 32];
        counter_gap.sig_hybrid_lc.clear();
        let mut counter_gap_unsigned = counter_gap.clone();
        counter_gap_unsigned.sig_hybrid_lc.clear();
        counter_gap.sig_hybrid_lc = sign_hybrid_payload(
            &lc_signer,
            &codec::to_bytes_canonical(&counter_gap_unsigned).expect("encode"),
        );
        let gap_err = run_async(service.handle_service_call(
            &mut state,
            "issue_session_lease@v1",
            &codec::to_bytes_canonical(&counter_gap).expect("encode"),
            ctx,
        ))
        .expect_err("ordered gap should fail");
        assert!(gap_err
            .to_string()
            .to_ascii_lowercase()
            .contains("expected"));
    });

    let replay: LeaseReplayState =
        load_typed(&state, &lease_replay_key(&channel_id, &lc_signer.signer_id))
            .expect("load")
            .expect("lease replay state");
    assert_eq!(replay.last_counter, 1);

    let counter_window: LeaseCounterReplayWindowState = load_typed(
        &state,
        &lease_counter_window_key(&channel_id, &lc_signer.signer_id),
    )
    .expect("load")
    .expect("counter window");
    assert_eq!(
        counter_window.ordering,
        ioi_types::app::wallet_network::SessionChannelOrdering::Ordered
    );
    assert_eq!(counter_window.highest_counter, 1);
    assert!(counter_window.seen_counters.contains(&1));
}

#[test]
fn lease_replay_unordered_window_allows_out_of_order_and_rejects_replay() {
    let service = WalletNetworkService;
    let mut state = MockState::default();
    let lc_signer = new_hybrid_signer();
    let rc_signer = new_hybrid_signer();
    let channel_id = [0xa0u8; 32];
    open_channel_with_ordering(
        &service,
        &mut state,
        channel_id,
        &lc_signer,
        &rc_signer,
        ioi_types::app::wallet_network::SessionChannelOrdering::Unordered,
    );

    with_ctx(|ctx| {
        let build_signed_lease = |lease_id: [u8; 32], counter: u64, nonce: [u8; 32]| {
            let mut lease = SessionLease {
                lease_id,
                channel_id,
                issuer_id: lc_signer.signer_id,
                subject_id: [0xa1u8; 32],
                policy_hash: [23u8; 32],
                grant_id: [0xa2u8; 32],
                capability_subset: vec!["email:read".to_string()],
                constraints_subset: BTreeMap::from([("max_usd".to_string(), "50".to_string())]),
                mode: ioi_types::app::wallet_network::SessionLeaseMode::Lease,
                expires_at_ms: 1_800_000_000_000,
                revocation_epoch: 0,
                audience: [0xa3u8; 32],
                nonce,
                counter,
                issued_at_ms: 1_750_000_000_000,
                sig_hybrid_lc: Vec::new(),
            };
            let mut unsigned = lease.clone();
            unsigned.sig_hybrid_lc.clear();
            lease.sig_hybrid_lc = sign_hybrid_payload(
                &lc_signer,
                &codec::to_bytes_canonical(&unsigned).expect("encode"),
            );
            lease
        };

        let lease_high = build_signed_lease([0xa4u8; 32], 600, [0xa5u8; 32]);
        run_async(service.handle_service_call(
            &mut state,
            "issue_session_lease@v1",
            &codec::to_bytes_canonical(&lease_high).expect("encode"),
            ctx,
        ))
        .expect("high counter lease");

        let lease_out_of_order = build_signed_lease([0xa6u8; 32], 550, [0xa7u8; 32]);
        run_async(service.handle_service_call(
            &mut state,
            "issue_session_lease@v1",
            &codec::to_bytes_canonical(&lease_out_of_order).expect("encode"),
            ctx,
        ))
        .expect("out-of-order lease within window");

        let lease_counter_replay = build_signed_lease([0xa8u8; 32], 550, [0xa9u8; 32]);
        let counter_replay_err = run_async(service.handle_service_call(
            &mut state,
            "issue_session_lease@v1",
            &codec::to_bytes_canonical(&lease_counter_replay).expect("encode"),
            ctx,
        ))
        .expect_err("unordered counter replay should fail");
        assert!(counter_replay_err
            .to_string()
            .to_ascii_lowercase()
            .contains("replay"));

        let lease_outside_window = build_signed_lease([0xaau8; 32], 200, [0xabu8; 32]);
        let outside_window_err = run_async(service.handle_service_call(
            &mut state,
            "issue_session_lease@v1",
            &codec::to_bytes_canonical(&lease_outside_window).expect("encode"),
            ctx,
        ))
        .expect_err("unordered stale counter should fail");
        assert!(outside_window_err
            .to_string()
            .to_ascii_lowercase()
            .contains("window"));
    });

    let replay: LeaseReplayState =
        load_typed(&state, &lease_replay_key(&channel_id, &lc_signer.signer_id))
            .expect("load")
            .expect("lease replay state");
    assert_eq!(replay.last_counter, 600);
    assert_eq!(replay.seen_nonces, vec![[0xa5u8; 32], [0xa7u8; 32]]);

    let counter_window: LeaseCounterReplayWindowState = load_typed(
        &state,
        &lease_counter_window_key(&channel_id, &lc_signer.signer_id),
    )
    .expect("load")
    .expect("counter window");
    assert_eq!(
        counter_window.ordering,
        ioi_types::app::wallet_network::SessionChannelOrdering::Unordered
    );
    assert_eq!(counter_window.highest_counter, 600);
    assert!(counter_window.seen_counters.contains(&600));
    assert!(counter_window.seen_counters.contains(&550));
    assert!(!counter_window.seen_counters.contains(&200));
}

#[test]
fn ordered_receipt_commits_require_contiguous_sequences() {
    let service = WalletNetworkService;
    let mut state = MockState::default();
    let lc_signer = new_hybrid_signer();
    let rc_signer = new_hybrid_signer();
    let channel_id = [0x81u8; 32];
    open_channel(&service, &mut state, channel_id, &lc_signer, &rc_signer);

    with_ctx(|ctx| {
        let mut first = ioi_types::app::wallet_network::SessionReceiptCommit {
            commit_id: [0u8; 32],
            channel_id,
            direction: ioi_types::app::wallet_network::SessionReceiptCommitDirection::LocalToRemote,
            start_seq: 0,
            end_seq: 2,
            merkle_root: [0x82u8; 32],
            committed_at_ms: 0,
            signer_id: rc_signer.signer_id,
            sig_hybrid_sender: Vec::new(),
        };
        let mut first_unsigned = first.clone();
        first_unsigned.sig_hybrid_sender.clear();
        first.sig_hybrid_sender = sign_hybrid_payload(
            &rc_signer,
            &codec::to_bytes_canonical(&first_unsigned).expect("encode"),
        );
        run_async(service.handle_service_call(
            &mut state,
            "commit_receipt_root@v1",
            &codec::to_bytes_canonical(&first).expect("encode"),
            ctx,
        ))
        .expect("first commit");

        let mut gap = first.clone();
        gap.start_seq = 4;
        gap.end_seq = 6;
        gap.merkle_root = [0x83u8; 32];
        gap.commit_id = [0u8; 32];
        gap.sig_hybrid_sender.clear();
        let mut gap_unsigned = gap.clone();
        gap_unsigned.sig_hybrid_sender.clear();
        gap.sig_hybrid_sender = sign_hybrid_payload(
            &rc_signer,
            &codec::to_bytes_canonical(&gap_unsigned).expect("encode"),
        );
        let gap_err = run_async(service.handle_service_call(
            &mut state,
            "commit_receipt_root@v1",
            &codec::to_bytes_canonical(&gap).expect("encode"),
            ctx,
        ))
        .expect_err("gap should fail for ordered channel");
        assert!(gap_err
            .to_string()
            .to_ascii_lowercase()
            .contains("expected"));

        let mut contiguous = first.clone();
        contiguous.start_seq = 3;
        contiguous.end_seq = 4;
        contiguous.merkle_root = [0x84u8; 32];
        contiguous.commit_id = [0u8; 32];
        contiguous.sig_hybrid_sender.clear();
        let mut contiguous_unsigned = contiguous.clone();
        contiguous_unsigned.sig_hybrid_sender.clear();
        contiguous.sig_hybrid_sender = sign_hybrid_payload(
            &rc_signer,
            &codec::to_bytes_canonical(&contiguous_unsigned).expect("encode"),
        );
        run_async(service.handle_service_call(
            &mut state,
            "commit_receipt_root@v1",
            &codec::to_bytes_canonical(&contiguous).expect("encode"),
            ctx,
        ))
        .expect("contiguous commit");
    });

    let window: ReceiptReplayWindowState = load_typed(
        &state,
        &receipt_window_key(
            &[0x81u8; 32],
            ioi_types::app::wallet_network::SessionReceiptCommitDirection::LocalToRemote,
        ),
    )
    .expect("load")
    .expect("window");
    assert_eq!(window.highest_end_seq, 4);
}

#[test]
fn unordered_receipt_commits_allow_out_of_order_but_reject_replay() {
    let service = WalletNetworkService;
    let mut state = MockState::default();
    let lc_signer = new_hybrid_signer();
    let rc_signer = new_hybrid_signer();
    let channel_id = [0x85u8; 32];
    open_channel_with_ordering(
        &service,
        &mut state,
        channel_id,
        &lc_signer,
        &rc_signer,
        ioi_types::app::wallet_network::SessionChannelOrdering::Unordered,
    );

    with_ctx(|ctx| {
        let mut first = ioi_types::app::wallet_network::SessionReceiptCommit {
            commit_id: [0u8; 32],
            channel_id,
            direction: ioi_types::app::wallet_network::SessionReceiptCommitDirection::LocalToRemote,
            start_seq: 100,
            end_seq: 100,
            merkle_root: [0x86u8; 32],
            committed_at_ms: 0,
            signer_id: rc_signer.signer_id,
            sig_hybrid_sender: Vec::new(),
        };
        let mut first_unsigned = first.clone();
        first_unsigned.sig_hybrid_sender.clear();
        first.sig_hybrid_sender = sign_hybrid_payload(
            &rc_signer,
            &codec::to_bytes_canonical(&first_unsigned).expect("encode"),
        );
        run_async(service.handle_service_call(
            &mut state,
            "commit_receipt_root@v1",
            &codec::to_bytes_canonical(&first).expect("encode"),
            ctx,
        ))
        .expect("unordered commit one");

        let mut out_of_order = first.clone();
        out_of_order.start_seq = 3;
        out_of_order.end_seq = 3;
        out_of_order.merkle_root = [0x87u8; 32];
        out_of_order.commit_id = [0u8; 32];
        out_of_order.sig_hybrid_sender.clear();
        let mut out_of_order_unsigned = out_of_order.clone();
        out_of_order_unsigned.sig_hybrid_sender.clear();
        out_of_order.sig_hybrid_sender = sign_hybrid_payload(
            &rc_signer,
            &codec::to_bytes_canonical(&out_of_order_unsigned).expect("encode"),
        );
        run_async(service.handle_service_call(
            &mut state,
            "commit_receipt_root@v1",
            &codec::to_bytes_canonical(&out_of_order).expect("encode"),
            ctx,
        ))
        .expect("unordered out-of-order commit");

        let mut replay = first.clone();
        replay.merkle_root = [0x88u8; 32];
        replay.commit_id = [0u8; 32];
        replay.sig_hybrid_sender.clear();
        let mut replay_unsigned = replay.clone();
        replay_unsigned.sig_hybrid_sender.clear();
        replay.sig_hybrid_sender = sign_hybrid_payload(
            &rc_signer,
            &codec::to_bytes_canonical(&replay_unsigned).expect("encode"),
        );
        let replay_err = run_async(service.handle_service_call(
            &mut state,
            "commit_receipt_root@v1",
            &codec::to_bytes_canonical(&replay).expect("encode"),
            ctx,
        ))
        .expect_err("unordered end_seq replay should fail");
        assert!(replay_err
            .to_string()
            .to_ascii_lowercase()
            .contains("replay"));
    });

    let window: ReceiptReplayWindowState = load_typed(
        &state,
        &receipt_window_key(
            &[0x85u8; 32],
            ioi_types::app::wallet_network::SessionReceiptCommitDirection::LocalToRemote,
        ),
    )
    .expect("load")
    .expect("window");
    assert_eq!(window.highest_end_seq, 100);
    assert!(window.seen_end_seqs.contains(&100));
    assert!(window.seen_end_seqs.contains(&3));
}
