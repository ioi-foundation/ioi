use super::*;

#[test]
fn approved_decision_requires_token() {
    let service = WalletNetworkService;
    let mut state = MockState::default();
    let approval = WalletApprovalDecision {
        interception: WalletInterceptionContext {
            session_id: Some([5u8; 32]),
            request_hash: [6u8; 32],
            target: ActionTarget::WebRetrieve,
            value_usd_micros: Some(10),
            reason: "step-up".to_string(),
            intercepted_at_ms: 1_750_000_000_000,
        },
        decision: ioi_types::app::wallet_network::WalletApprovalDecisionKind::ApprovedByHuman,
        approval_token: None,
        surface: ioi_types::app::wallet_network::VaultSurface::Desktop,
        decided_at_ms: 1_750_000_000_500,
    };
    let params = codec::to_bytes_canonical(&approval).expect("encode");

    with_ctx(|ctx| {
        let err =
            run_async(service.handle_service_call(&mut state, "record_approval@v1", &params, ctx))
                .expect_err("approved decision without token must fail");
        assert!(err.to_string().contains("approval_token"));
    });
}

#[test]
fn record_approval_rejects_non_hybrid_approver_signature_suite() {
    let service = WalletNetworkService;
    let mut state = MockState::default();
    let approval = WalletApprovalDecision {
        interception: WalletInterceptionContext {
            session_id: Some([15u8; 32]),
            request_hash: [16u8; 32],
            target: ActionTarget::WebRetrieve,
            value_usd_micros: Some(10),
            reason: "step-up".to_string(),
            intercepted_at_ms: 1_750_000_000_000,
        },
        decision: ioi_types::app::wallet_network::WalletApprovalDecisionKind::ApprovedByHuman,
        approval_token: Some(ApprovalToken {
            schema_version: 2,
            request_hash: [16u8; 32],
            audience: [7u8; 32],
            revocation_epoch: 0,
            nonce: [0x41u8; 32],
            counter: 1,
            scope: ApprovalScope {
                expires_at: 1_750_000_010_000,
                max_usages: Some(1),
            },
            visual_hash: None,
            pii_action: None,
            scoped_exception: None,
            approver_sig: vec![1, 2, 3],
            approver_suite: SignatureSuite::ED25519,
        }),
        surface: ioi_types::app::wallet_network::VaultSurface::Desktop,
        decided_at_ms: 1_750_000_000_500,
    };
    let params = codec::to_bytes_canonical(&approval).expect("encode");

    with_ctx(|ctx| {
        let err =
            run_async(service.handle_service_call(&mut state, "record_approval@v1", &params, ctx))
                .expect_err("non-hybrid approval token must fail");
        assert!(err
            .to_string()
            .contains("approver_suite must be HYBRID_ED25519_ML_DSA_44"));
    });
}

#[test]
fn panic_stop_bumps_revocation_epoch_and_sets_flag() {
    let service = WalletNetworkService;
    let mut state = MockState::default();
    let params = codec::to_bytes_canonical(&BumpRevocationEpochParams {
        reason: "operator panic".to_string(),
    })
    .expect("encode");

    with_ctx(|ctx| {
        run_async(service.handle_service_call(&mut state, "panic_stop@v1", &params, ctx))
            .expect("panic stop");
        run_async(service.handle_service_call(&mut state, "panic_stop@v1", &params, ctx))
            .expect("panic stop");
    });

    let epoch: u64 = codec::from_bytes_canonical(
        &state
            .get(REVOCATION_EPOCH_KEY)
            .expect("state")
            .expect("epoch"),
    )
    .expect("decode");
    let panic_flag: bool =
        codec::from_bytes_canonical(&state.get(PANIC_FLAG_KEY).expect("state").expect("flag"))
            .expect("decode");
    assert_eq!(epoch, 2);
    assert!(panic_flag);
}

#[test]
fn record_approval_initializes_consumption_state_and_consumes_by_usage() {
    let service = WalletNetworkService;
    let mut state = MockState::default();
    let request_hash = [11u8; 32];
    let session_id = Some([12u8; 32]);
    let approver = new_hybrid_signer();

    let approval = sign_wallet_approval_decision(
        WalletApprovalDecision {
            interception: WalletInterceptionContext {
                session_id,
                request_hash,
                target: ActionTarget::WebRetrieve,
                value_usd_micros: None,
                reason: "step-up".to_string(),
                intercepted_at_ms: 1_750_000_000_000,
            },
            decision: ioi_types::app::wallet_network::WalletApprovalDecisionKind::ApprovedByHuman,
            approval_token: Some(ApprovalToken {
                schema_version: 2,
                request_hash,
                audience: [7u8; 32],
                revocation_epoch: 0,
                nonce: [0x42u8; 32],
                counter: 7,
                scope: ApprovalScope {
                    expires_at: 1_750_000_060_000,
                    max_usages: Some(2),
                },
                visual_hash: None,
                pii_action: None,
                scoped_exception: None,
                approver_sig: vec![],
                approver_suite: SignatureSuite::HYBRID_ED25519_ML_DSA_44,
            }),
            surface: ioi_types::app::wallet_network::VaultSurface::Desktop,
            decided_at_ms: 1_750_000_000_500,
        },
        &approver,
    );

    with_ctx(|ctx| {
        let params = codec::to_bytes_canonical(&approval).expect("encode");
        run_async(service.handle_service_call(&mut state, "record_approval@v1", &params, ctx))
            .expect("valid approval");

        let consume_1 = ConsumeApprovalTokenParams {
            request_hash,
            consumed_at_ms: 1_750_000_010_000,
        };
        let consume_1_params = codec::to_bytes_canonical(&consume_1).expect("encode");
        run_async(service.handle_service_call(
            &mut state,
            "consume_approval_token@v1",
            &consume_1_params,
            ctx,
        ))
        .expect("first consume should succeed");

        let consume_2 = ConsumeApprovalTokenParams {
            request_hash,
            consumed_at_ms: 1_750_000_020_000,
        };
        let consume_2_params = codec::to_bytes_canonical(&consume_2).expect("encode");
        run_async(service.handle_service_call(
            &mut state,
            "consume_approval_token@v1",
            &consume_2_params,
            ctx,
        ))
        .expect("second consume should succeed");

        let consume_3 = ConsumeApprovalTokenParams {
            request_hash,
            consumed_at_ms: 1_750_000_030_000,
        };
        let consume_3_params = codec::to_bytes_canonical(&consume_3).expect("encode");
        let err = run_async(service.handle_service_call(
            &mut state,
            "consume_approval_token@v1",
            &consume_3_params,
            ctx,
        ))
        .expect_err("third consume should fail (max usages reached)");
        assert!(err.to_string().contains("remaining usages"));
    });

    let stored_approval: WalletApprovalDecision = load_typed(&state, &approval_key(&request_hash))
        .expect("load")
        .expect("approval");
    assert_eq!(stored_approval.interception.request_hash, request_hash);

    let consumption: ApprovalConsumptionState =
        load_typed(&state, &approval_consumption_key(&request_hash))
            .expect("load")
            .expect("consumption");
    assert_eq!(consumption.max_usages, 2);
    assert_eq!(consumption.uses_consumed, 2);
    assert_eq!(consumption.remaining_usages, 0);
    assert_eq!(consumption.bound_audience, Some([7u8; 32]));
}

#[test]
fn consume_approval_token_enforces_revocation_epoch_and_audience_binding() {
    let service = WalletNetworkService;
    let mut state = MockState::default();
    let request_hash = [21u8; 32];
    let approver = new_hybrid_signer();

    let approval = sign_wallet_approval_decision(
        WalletApprovalDecision {
            interception: WalletInterceptionContext {
                session_id: None,
                request_hash,
                target: ActionTarget::NetFetch,
                value_usd_micros: None,
                reason: "step-up".to_string(),
                intercepted_at_ms: 1_750_000_000_000,
            },
            decision: ioi_types::app::wallet_network::WalletApprovalDecisionKind::ApprovedByHuman,
            approval_token: Some(ApprovalToken {
                schema_version: 2,
                request_hash,
                audience: [7u8; 32],
                revocation_epoch: 0,
                nonce: [0x43u8; 32],
                counter: 9,
                scope: ApprovalScope {
                    expires_at: 1_850_000_000_000,
                    max_usages: Some(1),
                },
                visual_hash: None,
                pii_action: None,
                scoped_exception: None,
                approver_sig: vec![],
                approver_suite: SignatureSuite::HYBRID_ED25519_ML_DSA_44,
            }),
            surface: ioi_types::app::wallet_network::VaultSurface::Desktop,
            decided_at_ms: 1_750_000_000_500,
        },
        &approver,
    );

    with_ctx(|ctx| {
        let approval_params = codec::to_bytes_canonical(&approval).expect("encode");
        run_async(service.handle_service_call(
            &mut state,
            "record_approval@v1",
            &approval_params,
            ctx,
        ))
        .expect("approval");

        let consume_bind = ConsumeApprovalTokenParams {
            request_hash,
            consumed_at_ms: 1_750_000_001_000,
        };
        let consume_bind_params = codec::to_bytes_canonical(&consume_bind).expect("encode");
        run_async(service.handle_service_call(
            &mut state,
            "consume_approval_token@v1",
            &consume_bind_params,
            ctx,
        ))
        .expect("consume should bind audience");

        // Re-record with fresh token so we can exercise epoch invalidation path.
        let request_hash_2 = [22u8; 32];
        let approval_2 = sign_wallet_approval_decision(
            WalletApprovalDecision {
                interception: WalletInterceptionContext {
                    session_id: None,
                    request_hash: request_hash_2,
                    target: ActionTarget::NetFetch,
                    value_usd_micros: None,
                    reason: "step-up".to_string(),
                    intercepted_at_ms: 1_750_000_000_000,
                },
                decision:
                    ioi_types::app::wallet_network::WalletApprovalDecisionKind::ApprovedByHuman,
                approval_token: Some(ApprovalToken {
                    schema_version: 2,
                    request_hash: request_hash_2,
                    audience: [7u8; 32],
                    revocation_epoch: 0,
                    nonce: [0x44u8; 32],
                    counter: 10,
                    scope: ApprovalScope {
                        expires_at: 1_850_000_000_000,
                        max_usages: Some(1),
                    },
                    visual_hash: None,
                    pii_action: None,
                    scoped_exception: None,
                    approver_sig: vec![],
                    approver_suite: SignatureSuite::HYBRID_ED25519_ML_DSA_44,
                }),
                surface: ioi_types::app::wallet_network::VaultSurface::Desktop,
                decided_at_ms: 1_750_000_000_500,
            },
            &approver,
        );
        let approval_2_params = codec::to_bytes_canonical(&approval_2).expect("encode");
        run_async(service.handle_service_call(
            &mut state,
            "record_approval@v1",
            &approval_2_params,
            ctx,
        ))
        .expect("approval 2");

        let panic_params = codec::to_bytes_canonical(&BumpRevocationEpochParams {
            reason: "rotate all approvals".to_string(),
        })
        .expect("encode");
        run_async(service.handle_service_call(&mut state, "panic_stop@v1", &panic_params, ctx))
            .expect("panic stop");

        let consume_revoked = ConsumeApprovalTokenParams {
            request_hash: request_hash_2,
            consumed_at_ms: 1_750_000_002_000,
        };
        let consume_revoked_params = codec::to_bytes_canonical(&consume_revoked).expect("encode");
        let err = run_async(service.handle_service_call(
            &mut state,
            "consume_approval_token@v1",
            &consume_revoked_params,
            ctx,
        ))
        .expect_err("epoch-bumped approval should fail");
        assert!(err.to_string().contains("revocation epoch"));
    });
}

#[test]
fn consume_approval_token_rejects_signer_audience_mismatch() {
    let service = WalletNetworkService;
    let mut state = MockState::default();
    let request_hash = [31u8; 32];
    let approver = new_hybrid_signer();

    let approval = sign_wallet_approval_decision(
        WalletApprovalDecision {
            interception: WalletInterceptionContext {
                session_id: None,
                request_hash,
                target: ActionTarget::NetFetch,
                value_usd_micros: None,
                reason: "step-up".to_string(),
                intercepted_at_ms: 1_750_000_000_000,
            },
            decision: ioi_types::app::wallet_network::WalletApprovalDecisionKind::ApprovedByHuman,
            approval_token: Some(ApprovalToken {
                schema_version: 2,
                request_hash,
                audience: [7u8; 32],
                revocation_epoch: 0,
                nonce: [0x45u8; 32],
                counter: 1,
                scope: ApprovalScope {
                    expires_at: 1_850_000_000_000,
                    max_usages: Some(1),
                },
                visual_hash: None,
                pii_action: None,
                scoped_exception: None,
                approver_sig: vec![],
                approver_suite: SignatureSuite::HYBRID_ED25519_ML_DSA_44,
            }),
            surface: ioi_types::app::wallet_network::VaultSurface::Desktop,
            decided_at_ms: 1_750_000_000_500,
        },
        &approver,
    );

    with_ctx(|ctx| {
        let approval_params = codec::to_bytes_canonical(&approval).expect("encode");
        run_async(service.handle_service_call(
            &mut state,
            "record_approval@v1",
            &approval_params,
            ctx,
        ))
        .expect("approval");
    });

    with_ctx_signer([8u8; 32], |ctx| {
        let consume = ConsumeApprovalTokenParams {
            request_hash,
            consumed_at_ms: 1_750_000_001_000,
        };
        let consume_params = codec::to_bytes_canonical(&consume).expect("encode");
        let err = run_async(service.handle_service_call(
            &mut state,
            "consume_approval_token@v1",
            &consume_params,
            ctx,
        ))
        .expect_err("signer mismatch should fail");
        assert!(err.to_string().contains("audience"));
    });
}

#[test]
fn secret_injection_grant_requires_attested_request_and_alias_binding() {
    let service = WalletNetworkService;
    let mut state = MockState::default();
    let secret_record = VaultSecretRecord {
        secret_id: "openai-prod".to_string(),
        alias: "OpenAI".to_string(),
        kind: ioi_types::app::wallet_network::SecretKind::ApiKey,
        ciphertext: vec![1, 2, 3, 4],
        metadata: BTreeMap::new(),
        created_at_ms: 1_750_000_000_000,
        rotated_at_ms: None,
    };
    let request_id = [61u8; 32];
    let request = SecretInjectionRequest {
        request_id,
        session_id: [62u8; 32],
        agent_id: "agent-mail".to_string(),
        secret_alias: "openai".to_string(),
        target: ActionTarget::NetFetch,
        attestation_nonce: [63u8; 32],
        requested_at_ms: 1_750_000_000_000,
    };
    let attestation = GuardianAttestation {
        quote_hash: [64u8; 32],
        measurement_hash: [65u8; 32],
        guardian_ephemeral_public_key: vec![10, 11, 12],
        nonce: [63u8; 32],
        issued_at_ms: 1_749_999_999_000,
        expires_at_ms: 1_850_000_000_000,
    };

    with_ctx(|ctx| {
        let secret_params = codec::to_bytes_canonical(&secret_record).expect("encode secret");
        run_async(service.handle_service_call(
            &mut state,
            "store_secret_record@v1",
            &secret_params,
            ctx,
        ))
        .expect("store secret");

        let premature_grant = SecretInjectionGrant {
            request_id,
            secret_id: "openai-prod".to_string(),
            envelope: ioi_types::app::wallet_network::SecretInjectionEnvelope {
                algorithm: "xchacha20poly1305".to_string(),
                ciphertext: vec![9, 9, 9],
                aad: vec![],
            },
            issued_at_ms: 1_750_000_000_100,
            expires_at_ms: 1_750_000_060_000,
        };
        let premature_params = codec::to_bytes_canonical(&premature_grant).expect("encode");
        let premature_err = run_async(service.handle_service_call(
            &mut state,
            "grant_secret_injection@v1",
            &premature_params,
            ctx,
        ))
        .expect_err("grant without attested request must fail");
        assert!(premature_err
            .to_string()
            .contains("requires prior attested request"));

        let request_record = SecretInjectionRequestRecord {
            request: request.clone(),
            attestation,
        };
        let request_params = codec::to_bytes_canonical(&request_record).expect("encode");
        run_async(service.handle_service_call(
            &mut state,
            "record_secret_injection_request@v1",
            &request_params,
            ctx,
        ))
        .expect("record request");

        let valid_grant = SecretInjectionGrant {
            request_id,
            secret_id: "openai-prod".to_string(),
            envelope: ioi_types::app::wallet_network::SecretInjectionEnvelope {
                algorithm: "xchacha20poly1305".to_string(),
                ciphertext: vec![9, 9, 9],
                aad: vec![],
            },
            issued_at_ms: 1_750_000_000_100,
            expires_at_ms: 1_750_000_060_000,
        };
        let valid_params = codec::to_bytes_canonical(&valid_grant).expect("encode");
        run_async(service.handle_service_call(
            &mut state,
            "grant_secret_injection@v1",
            &valid_params,
            ctx,
        ))
        .expect("valid grant");
    });

    let stored: SecretInjectionGrant = codec::from_bytes_canonical(
        &state
            .get(&injection_grant_key(&request_id))
            .expect("state")
            .expect("grant"),
    )
    .expect("decode");
    assert_eq!(stored.secret_id, "openai-prod");
}
