use super::*;

#[test]
fn channel_handshake_reaches_open_state() {
    let service = WalletNetworkService;
    let mut state = MockState::default();
    let lc_signer = new_hybrid_signer();
    let rc_signer = new_hybrid_signer();
    let channel_id = [31u8; 32];
    open_channel(&service, &mut state, channel_id, &lc_signer, &rc_signer);

    let stored: SessionChannelRecord = codec::from_bytes_canonical(
        &state
            .get(&channel_key(&channel_id))
            .expect("state")
            .expect("channel"),
    )
    .expect("decode");
    assert_eq!(stored.state, SessionChannelState::Open);
    assert!(stored.opened_at_ms.is_some());

    let key_state: SessionChannelKeyState = codec::from_bytes_canonical(
        &state
            .get(&channel_key_state_key(&channel_id))
            .expect("state")
            .expect("channel key state"),
    )
    .expect("decode key state");
    assert_eq!(key_state.channel_id, channel_id);
    assert_eq!(key_state.transcript_version, 1);
    assert!(key_state.ready);
    assert_eq!(key_state.key_epoch, 1);
    assert!(key_state.derived_channel_secret_hash.is_some());
    assert_ne!(key_state.kem_transcript_hash, [0u8; 32]);
    assert!(key_state.rc_kem_ephemeral_pub_classical_hash.is_some());
    assert!(key_state.rc_kem_ciphertext_pq_hash.is_some());
    assert_eq!(key_state.nonce_rc, Some([26u8; 32]));
    assert_eq!(key_state.nonce_lc2, Some([27u8; 32]));
    assert_eq!(key_state.nonce_rc2, Some([28u8; 32]));
}

#[test]
fn channel_open_init_rejects_non_hybrid_signature_payload() {
    let service = WalletNetworkService;
    let mut state = MockState::default();
    let channel_id = [32u8; 32];
    let lc_signer = new_hybrid_signer();
    let rc_signer = new_hybrid_signer();
    let mut open_init = make_channel_open_init(
        channel_id,
        &lc_signer,
        &rc_signer,
        ioi_types::app::wallet_network::SessionChannelOrdering::Ordered,
    );
    open_init.sig_hybrid_lc = vec![1, 2, 3];
    let params = codec::to_bytes_canonical(&open_init).expect("encode");

    with_ctx(|ctx| {
        let err = run_async(service.handle_service_call(
            &mut state,
            "open_channel_init@v1",
            &params,
            ctx,
        ))
        .expect_err("invalid hybrid signature payload must fail");
        let err_text = err.to_string().to_ascii_lowercase();
        assert!(
            err_text.contains("hybrid")
                || err_text.contains("deserialize")
                || err_text.contains("decode")
                || err_text.contains("sig_hybrid_lc")
        );
    });
}

#[test]
fn lease_must_be_subset_of_channel_capabilities_and_constraints() {
    let service = WalletNetworkService;
    let mut state = MockState::default();
    let lc_signer = new_hybrid_signer();
    let rc_signer = new_hybrid_signer();
    let channel_id = [33u8; 32];
    open_channel(&service, &mut state, channel_id, &lc_signer, &rc_signer);

    with_ctx(|ctx| {
        let mut bad_lease = SessionLease {
            lease_id: [34u8; 32],
            channel_id,
            issuer_id: lc_signer.signer_id,
            subject_id: [36u8; 32],
            policy_hash: [23u8; 32],
            grant_id: [37u8; 32],
            capability_subset: vec!["email:send".to_string()],
            constraints_subset: BTreeMap::from([("max_usd".to_string(), "999".to_string())]),
            mode: ioi_types::app::wallet_network::SessionLeaseMode::Lease,
            expires_at_ms: 1_800_000_000_000,
            revocation_epoch: 0,
            audience: [38u8; 32],
            nonce: [39u8; 32],
            counter: 1,
            issued_at_ms: 1_750_000_000_000,
            sig_hybrid_lc: Vec::new(),
        };
        let mut bad_lease_unsigned = bad_lease.clone();
        bad_lease_unsigned.sig_hybrid_lc.clear();
        bad_lease.sig_hybrid_lc = sign_hybrid_payload(
            &lc_signer,
            &codec::to_bytes_canonical(&bad_lease_unsigned).expect("encode"),
        );
        let bad_params = codec::to_bytes_canonical(&bad_lease).expect("encode");
        let err = run_async(service.handle_service_call(
            &mut state,
            "issue_session_lease@v1",
            &bad_params,
            ctx,
        ))
        .expect_err("widened lease must fail");
        assert!(err.to_string().contains("subset"));

        let mut good_lease = SessionLease {
            lease_id: [40u8; 32],
            channel_id,
            issuer_id: lc_signer.signer_id,
            subject_id: [36u8; 32],
            policy_hash: [23u8; 32],
            grant_id: [37u8; 32],
            capability_subset: vec!["email:read".to_string()],
            constraints_subset: BTreeMap::from([("max_usd".to_string(), "50".to_string())]),
            mode: ioi_types::app::wallet_network::SessionLeaseMode::Lease,
            expires_at_ms: 1_800_000_000_000,
            revocation_epoch: 0,
            audience: [38u8; 32],
            nonce: [40u8; 32],
            counter: 1,
            issued_at_ms: 1_750_000_000_000,
            sig_hybrid_lc: Vec::new(),
        };
        let mut good_lease_unsigned = good_lease.clone();
        good_lease_unsigned.sig_hybrid_lc.clear();
        good_lease.sig_hybrid_lc = sign_hybrid_payload(
            &lc_signer,
            &codec::to_bytes_canonical(&good_lease_unsigned).expect("encode"),
        );
        let good_params = codec::to_bytes_canonical(&good_lease).expect("encode");
        run_async(service.handle_service_call(
            &mut state,
            "issue_session_lease@v1",
            &good_params,
            ctx,
        ))
        .expect("valid lease");
    });

    let stored: SessionLease = codec::from_bytes_canonical(
        &state
            .get(&lease_key(&channel_id, &[40u8; 32]))
            .expect("state")
            .expect("lease"),
    )
    .expect("decode");
    assert_eq!(stored.capability_subset, vec!["email:read".to_string()]);
}
