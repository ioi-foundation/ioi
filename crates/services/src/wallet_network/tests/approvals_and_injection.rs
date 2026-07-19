use super::*;
use crate::wallet_network::keys::registered_client_key;
use ioi_api::services::BlockchainService;
use ioi_types::app::wallet_network::{
    IssuePrincipalAuthorityBindingParams, PrincipalAuthorityBindingProofV1,
    PrincipalAuthorityBindingStatementV1, PrincipalAuthorityBindingStatus, PrincipalAuthorityKind,
    RevokePrincipalAuthorityBindingParams, VaultSurface, WalletClientRole, WalletClientState,
    WalletControlPlaneRootRecord, WalletRegisteredClientRecord,
    PRINCIPAL_AUTHORITY_BINDING_SCHEMA_VERSION,
};

const EFFECT_PRINCIPAL_REF: &str = "org://wallet-network/effect-owner";
const EFFECT_REQUIRED_SCOPE: &str = "wallet_network.approval";
const EFFECT_NOW_MS: u64 = 1_750_000_000_000;

struct EffectBindingFixture {
    root_keypair: Ed25519KeyPair,
    root: WalletControlPlaneRootRecord,
    proof: PrincipalAuthorityBindingProofV1,
    expected: ExpectedPrincipalAuthorityBinding,
}

fn effect_binding_proof(
    root_keypair: &Ed25519KeyPair,
    root: &WalletControlPlaneRootRecord,
    authority: &ApprovalAuthority,
    status: PrincipalAuthorityBindingStatus,
    previous: Option<&PrincipalAuthorityBindingProofV1>,
    expires_at_ms: u64,
) -> PrincipalAuthorityBindingProofV1 {
    let previous_coordinates = previous.map(PrincipalAuthorityBindingProofV1::coordinates);
    let statement = PrincipalAuthorityBindingStatementV1 {
        schema_version: PRINCIPAL_AUTHORITY_BINDING_SCHEMA_VERSION,
        principal_ref: EFFECT_PRINCIPAL_REF.to_string(),
        authority_kind: PrincipalAuthorityKind::Approval,
        binding_version: previous_coordinates
            .as_ref()
            .map(|coordinates| coordinates.binding_version + 1)
            .unwrap_or(1),
        status,
        authority_id: authority.authority_id,
        authority_public_key: authority.public_key.clone(),
        authority_signature_suite: authority.signature_suite,
        approval_authority_snapshot_hash: authority.artifact_hash().expect("authority hash"),
        previous_binding_ref: previous_coordinates
            .as_ref()
            .map(|coordinates| coordinates.binding_ref.clone()),
        previous_binding_hash: previous_coordinates
            .as_ref()
            .map(|coordinates| coordinates.binding_hash),
        signed_at_ms: EFFECT_NOW_MS,
        expires_at_ms: Some(expires_at_ms),
        issuer_root_account_id: root.account_id,
        reason: Some(match status {
            PrincipalAuthorityBindingStatus::Active => "effect binding".to_string(),
            PrincipalAuthorityBindingStatus::Revoked => "effect binding revoked".to_string(),
        }),
    };
    let signature = root_keypair
        .sign(&statement.signing_bytes().expect("binding signing bytes"))
        .expect("sign binding")
        .to_bytes();
    PrincipalAuthorityBindingProofV1::new(
        statement,
        SignatureProof {
            suite: SignatureSuite::ED25519,
            public_key: root.public_key.clone(),
            signature,
        },
    )
    .expect("binding proof")
}

fn install_effect_binding(
    service: &WalletNetworkService,
    state: &mut MockState,
    authority: &ApprovalAuthority,
    expires_at_ms: u64,
) -> EffectBindingFixture {
    let root_keypair = Ed25519KeyPair::generate().expect("root keypair");
    let root_public_key = root_keypair.public_key().to_bytes();
    let root = WalletControlPlaneRootRecord {
        account_id: account_id_from_key_material(SignatureSuite::ED25519, &root_public_key)
            .expect("root id"),
        signature_suite: SignatureSuite::ED25519,
        public_key: root_public_key,
        registered_at_ms: 0,
        updated_at_ms: 0,
        metadata: BTreeMap::new(),
    };
    let proof = effect_binding_proof(
        &root_keypair,
        &root,
        authority,
        PrincipalAuthorityBindingStatus::Active,
        None,
        expires_at_ms,
    );
    let expected = ExpectedPrincipalAuthorityBinding {
        principal_ref: EFFECT_PRINCIPAL_REF.to_string(),
        required_scope: EFFECT_REQUIRED_SCOPE.to_string(),
        coordinates: proof.coordinates(),
        approval_authority: authority.clone(),
        approval_authority_snapshot_hash: proof.statement.approval_authority_snapshot_hash,
    };
    let fixture = EffectBindingFixture {
        root_keypair,
        root: root.clone(),
        proof,
        expected,
    };

    with_ctx_signer(root.account_id, |ctx| {
        run_async(
            service.handle_service_call(
                state,
                "configure_control_root@v1",
                &codec::to_bytes_canonical(&WalletConfigureControlRootParams {
                    root: root.clone(),
                })
                .expect("encode root"),
                ctx,
            ),
        )
        .expect("configure root");
    });
    let client = WalletRegisteredClientRecord {
        client_id: [7u8; 32],
        label: "effect consumer".to_string(),
        surface: VaultSurface::Desktop,
        signature_suite: SignatureSuite::ED25519,
        public_key: vec![7u8; 32],
        role: WalletClientRole::ControlPlaneAdmin,
        state: WalletClientState::Active,
        registered_at_ms: EFFECT_NOW_MS,
        updated_at_ms: EFFECT_NOW_MS,
        expires_at_ms: Some(1_900_000_000_000),
        allowed_provider_families: Vec::new(),
        metadata: BTreeMap::new(),
    };
    state
        .insert(
            &registered_client_key(&client.client_id),
            &codec::to_bytes_canonical(&client).expect("encode client"),
        )
        .expect("store effect client");
    with_ctx_signer(root.account_id, |ctx| {
        run_async(
            service.handle_service_call(
                state,
                "issue_principal_authority_binding@v1",
                &codec::to_bytes_canonical(&IssuePrincipalAuthorityBindingParams {
                    proof: fixture.proof.clone(),
                })
                .expect("encode binding"),
                ctx,
            ),
        )
        .expect("issue effect binding");
    });
    fixture
}

fn mutate_effect_binding(
    service: &WalletNetworkService,
    state: &mut MockState,
    fixture: &EffectBindingFixture,
    authority: &ApprovalAuthority,
    status: PrincipalAuthorityBindingStatus,
) -> PrincipalAuthorityBindingProofV1 {
    let proof = effect_binding_proof(
        &fixture.root_keypair,
        &fixture.root,
        authority,
        status,
        Some(&fixture.proof),
        1_850_000_000_000,
    );
    with_ctx_signer(fixture.root.account_id, |ctx| {
        if status == PrincipalAuthorityBindingStatus::Active {
            run_async(
                service.handle_service_call(
                    state,
                    "issue_principal_authority_binding@v1",
                    &codec::to_bytes_canonical(&IssuePrincipalAuthorityBindingParams {
                        proof: proof.clone(),
                    })
                    .expect("encode rotation"),
                    ctx,
                ),
            )
            .expect("rotate effect binding");
        } else {
            run_async(
                service.handle_service_call(
                    state,
                    "revoke_principal_authority_binding@v1",
                    &codec::to_bytes_canonical(&RevokePrincipalAuthorityBindingParams {
                        predecessor_binding_ref: fixture.proof.binding_ref.clone(),
                        proof: proof.clone(),
                    })
                    .expect("encode revocation"),
                    ctx,
                ),
            )
            .expect("revoke effect binding");
        }
    });
    proof
}

fn effect_consume_params(
    request_hash: [u8; 32],
    grant_hash: [u8; 32],
    consumption_id: [u8; 32],
    expected: &ExpectedPrincipalAuthorityBinding,
) -> ConsumeApprovalGrantForEffectParams {
    ConsumeApprovalGrantForEffectParams {
        request_hash,
        grant_hash,
        consumption_id,
        expected_principal_authority: expected.clone(),
    }
}

fn consume_effect_at(
    service: &WalletNetworkService,
    state: &mut MockState,
    params: &ConsumeApprovalGrantForEffectParams,
    now_ms: u64,
) -> Result<(), ioi_types::error::TransactionError> {
    let encoded = codec::to_bytes_canonical(params).expect("encode effect consumption");
    let mut result = None;
    with_ctx(|ctx| {
        ctx.block_timestamp = now_ms.saturating_mul(1_000_000);
        result = Some(run_async(service.handle_service_call(
            state,
            "consume_approval_grant_for_effect@v1",
            &encoded,
            ctx,
        )));
    });
    result.expect("effect consumption result")
}

#[test]
fn approved_decision_requires_grant() {
    let service = WalletNetworkService;
    let mut state = MockState::default();
    let approval = WalletApprovalDecision {
        interception: WalletInterceptionContext {
            session_id: Some([5u8; 32]),
            request_hash: [6u8; 32],
            target: ActionTarget::WebRetrieve,
            policy_hash: [9u8; 32],
            value_usd_micros: Some(10),
            reason: "step-up".to_string(),
            intercepted_at_ms: 1_750_000_000_000,
        },
        decision: ioi_types::app::wallet_network::WalletApprovalDecisionKind::ApprovedByHuman,
        approval_grant: None,
        surface: ioi_types::app::wallet_network::VaultSurface::Desktop,
        decided_at_ms: 1_750_000_000_500,
    };
    let params = codec::to_bytes_canonical(&approval).expect("encode");

    with_ctx(|ctx| {
        let err =
            run_async(service.handle_service_call(&mut state, "record_approval@v1", &params, ctx))
                .expect_err("approved decision without token must fail");
        assert!(err.to_string().contains("approval_grant"));
    });
}

#[test]
fn record_approval_rejects_unregistered_approval_authority() {
    let service = WalletNetworkService;
    let mut state = MockState::default();
    let signer = new_approval_signer();
    let approval = WalletApprovalDecision {
        interception: WalletInterceptionContext {
            session_id: Some([15u8; 32]),
            request_hash: [16u8; 32],
            target: ActionTarget::WebRetrieve,
            policy_hash: [17u8; 32],
            value_usd_micros: Some(10),
            reason: "step-up".to_string(),
            intercepted_at_ms: 1_750_000_000_000,
        },
        decision: ioi_types::app::wallet_network::WalletApprovalDecisionKind::ApprovedByHuman,
        approval_grant: Some(signed_wallet_approval_grant(
            &signer,
            [16u8; 32],
            [17u8; 32],
            [7u8; 32],
            [0x41u8; 32],
            1,
            Some(1),
            1_750_000_010_000,
        )),
        surface: ioi_types::app::wallet_network::VaultSurface::Desktop,
        decided_at_ms: 1_750_000_000_500,
    };
    let params = codec::to_bytes_canonical(&approval).expect("encode");

    with_ctx(|ctx| {
        let err =
            run_async(service.handle_service_call(&mut state, "record_approval@v1", &params, ctx))
                .expect_err("unregistered approval authority must fail");
        assert!(err.to_string().contains("not registered"));
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
    let approver = new_approval_signer();

    let approval = WalletApprovalDecision {
        interception: WalletInterceptionContext {
            session_id,
            request_hash,
            target: ActionTarget::WebRetrieve,
            policy_hash: [19u8; 32],
            value_usd_micros: None,
            reason: "step-up".to_string(),
            intercepted_at_ms: 1_750_000_000_000,
        },
        decision: ioi_types::app::wallet_network::WalletApprovalDecisionKind::ApprovedByHuman,
        approval_grant: Some(signed_wallet_approval_grant(
            &approver,
            request_hash,
            [19u8; 32],
            [7u8; 32],
            [0x42u8; 32],
            7,
            Some(2),
            1_750_000_060_000,
        )),
        surface: ioi_types::app::wallet_network::VaultSurface::Desktop,
        decided_at_ms: 1_750_000_000_500,
    };
    let grant_hash = approval
        .approval_grant
        .as_ref()
        .expect("grant")
        .artifact_hash()
        .expect("grant hash");

    with_ctx(|ctx| {
        let register = RegisterApprovalAuthorityParams {
            authority: approver.authority.clone(),
        };
        let register_params = codec::to_bytes_canonical(&register).expect("encode");
        run_async(service.handle_service_call(
            &mut state,
            "register_approval_authority@v1",
            &register_params,
            ctx,
        ))
        .expect("register approval authority");

        let params = codec::to_bytes_canonical(&approval).expect("encode");
        run_async(service.handle_service_call(&mut state, "record_approval@v1", &params, ctx))
            .expect("valid approval");

        let consume_1 = ConsumeApprovalGrantParams {
            request_hash,
            consumed_at_ms: 1_750_000_010_000,
        };
        let consume_1_params = codec::to_bytes_canonical(&consume_1).expect("encode");
        run_async(service.handle_service_call(
            &mut state,
            "consume_approval_grant@v1",
            &consume_1_params,
            ctx,
        ))
        .expect("first consume should succeed");

        let consume_2 = ConsumeApprovalGrantParams {
            request_hash,
            consumed_at_ms: 1_750_000_020_000,
        };
        let consume_2_params = codec::to_bytes_canonical(&consume_2).expect("encode");
        run_async(service.handle_service_call(
            &mut state,
            "consume_approval_grant@v1",
            &consume_2_params,
            ctx,
        ))
        .expect("second consume should succeed");

        let consume_3 = ConsumeApprovalGrantParams {
            request_hash,
            consumed_at_ms: 1_750_000_030_000,
        };
        let consume_3_params = codec::to_bytes_canonical(&consume_3).expect("encode");
        let err = run_async(service.handle_service_call(
            &mut state,
            "consume_approval_grant@v1",
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
    let exact_grant: ApprovalGrantState =
        load_typed(&state, &approval_grant_state_key(&grant_hash))
            .expect("load")
            .expect("exact grant state");
    assert_eq!(exact_grant.grant_hash, grant_hash);
    assert_eq!(exact_grant.uses_consumed, 0);
}

#[test]
fn effect_consumption_is_idempotent_only_for_the_same_durable_intent() {
    let service = WalletNetworkService;
    let mut state = MockState::default();
    let request_hash = [0x51u8; 32];
    let consumption_id = [0x52u8; 32];
    let approver = new_approval_signer();
    let approval = WalletApprovalDecision {
        interception: WalletInterceptionContext {
            session_id: Some([0x53u8; 32]),
            request_hash,
            target: ActionTarget::NetFetch,
            policy_hash: [0x54u8; 32],
            value_usd_micros: None,
            reason: "governed effect".to_string(),
            intercepted_at_ms: 1_750_000_000_000,
        },
        decision: ioi_types::app::wallet_network::WalletApprovalDecisionKind::ApprovedByHuman,
        approval_grant: Some(signed_wallet_approval_grant(
            &approver,
            request_hash,
            [0x54u8; 32],
            [7u8; 32],
            [0x55u8; 32],
            11,
            Some(1),
            1_850_000_000_000,
        )),
        surface: ioi_types::app::wallet_network::VaultSurface::Desktop,
        decided_at_ms: 1_750_000_000_500,
    };
    let grant_hash = approval
        .approval_grant
        .as_ref()
        .expect("grant")
        .artifact_hash()
        .expect("grant hash");

    with_ctx(|ctx| {
        let register = RegisterApprovalAuthorityParams {
            authority: approver.authority.clone(),
        };
        run_async(service.handle_service_call(
            &mut state,
            "register_approval_authority@v1",
            &codec::to_bytes_canonical(&register).expect("encode"),
            ctx,
        ))
        .expect("register authority");
        run_async(service.handle_service_call(
            &mut state,
            "record_approval@v1",
            &codec::to_bytes_canonical(&approval).expect("encode"),
            ctx,
        ))
        .expect("record approval");
    });

    let binding =
        install_effect_binding(&service, &mut state, &approver.authority, 1_850_000_000_000);
    with_ctx(|ctx| {
        let consume =
            effect_consume_params(request_hash, grant_hash, consumption_id, &binding.expected);
        let consume_bytes = codec::to_bytes_canonical(&consume).expect("encode");
        run_async(service.handle_service_call(
            &mut state,
            "consume_approval_grant_for_effect@v1",
            &consume_bytes,
            ctx,
        ))
        .expect("first intent consumption");
        run_async(service.handle_service_call(
            &mut state,
            "consume_approval_grant_for_effect@v1",
            &consume_bytes,
            ctx,
        ))
        .expect("same intent replay is idempotent");

        let mut foreign_authority = consume.clone();
        foreign_authority
            .expected_principal_authority
            .required_scope = "wallet_network.foreign".to_string();
        let error = run_async(service.handle_service_call(
            &mut state,
            "consume_approval_grant_for_effect@v1",
            &codec::to_bytes_canonical(&foreign_authority).expect("encode"),
            ctx,
        ))
        .expect_err("same durable id cannot replay with a different authority tuple");
        assert!(error.to_string().contains("different principal authority"));

        let foreign_intent =
            effect_consume_params(request_hash, grant_hash, [0x56u8; 32], &binding.expected);
        let error = run_async(service.handle_service_call(
            &mut state,
            "consume_approval_grant_for_effect@v1",
            &codec::to_bytes_canonical(&foreign_intent).expect("encode"),
            ctx,
        ))
        .expect_err("a different intent cannot reuse the exhausted grant");
        assert!(error.to_string().contains("remaining usages"));

        run_async(service.handle_service_call(
            &mut state,
            "record_approval@v1",
            &codec::to_bytes_canonical(&approval).expect("encode"),
            ctx,
        ))
        .expect("re-recording the exact grant is idempotent");
        let panic_params = codec::to_bytes_canonical(&BumpRevocationEpochParams {
            reason: "prove consumed-receipt replay".to_string(),
        })
        .expect("encode");
        run_async(service.handle_service_call(&mut state, "panic_stop@v1", &panic_params, ctx))
            .expect("bump revocation epoch");
        run_async(service.handle_service_call(
            &mut state,
            "consume_approval_grant_for_effect@v1",
            &consume_bytes,
            ctx,
        ))
        .expect("exact consumed intent remains replayable after revocation");
        let conflicting_tuple = effect_consume_params(
            request_hash,
            [0x57u8; 32],
            consumption_id,
            &binding.expected,
        );
        let error = run_async(service.handle_service_call(
            &mut state,
            "consume_approval_grant_for_effect@v1",
            &codec::to_bytes_canonical(&conflicting_tuple).expect("encode"),
            ctx,
        ))
        .expect_err("the same consumption id cannot name a different grant");
        assert!(error.to_string().contains("different request or grant"));
    });

    let consumption: ApprovalGrantState =
        load_typed(&state, &approval_grant_state_key(&grant_hash))
            .expect("load")
            .expect("consumption state");
    assert_eq!(consumption.uses_consumed, 1);
    assert_eq!(consumption.remaining_usages, 0);

    let receipt: ApprovalGrantConsumptionReceipt = load_typed(
        &state,
        &approval_effect_consumption_receipt_key(&consumption_id),
    )
    .expect("load")
    .expect("effect receipt");
    assert_eq!(receipt.request_hash, request_hash);
    assert_eq!(receipt.consumption_id, consumption_id);
    assert_eq!(receipt.usage_ordinal, 1);
    assert_eq!(receipt.remaining_usages, 0);
    assert_ne!(receipt.receipt_hash, [0u8; 32]);
    assert_eq!(receipt.grant_hash, grant_hash);
    assert!(state
        .get(&approval_effect_consumption_receipt_key(&[0x56u8; 32]))
        .expect("state")
        .is_none());
}

#[test]
fn distinct_grants_for_one_request_keep_independent_usage_state() {
    let service = WalletNetworkService;
    let mut state = MockState::default();
    let request_hash = [0x58u8; 32];
    let policy_hash = [0x59u8; 32];
    let approver = new_approval_signer();
    let approval_for = |nonce: [u8; 32], counter: u64| WalletApprovalDecision {
        interception: WalletInterceptionContext {
            session_id: Some([0x5au8; 32]),
            request_hash,
            target: ActionTarget::NetFetch,
            policy_hash,
            value_usd_micros: None,
            reason: "independent governed effect grant".to_string(),
            intercepted_at_ms: 1_750_000_000_000,
        },
        decision: ioi_types::app::wallet_network::WalletApprovalDecisionKind::ApprovedByHuman,
        approval_grant: Some(signed_wallet_approval_grant(
            &approver,
            request_hash,
            policy_hash,
            [7u8; 32],
            nonce,
            counter,
            Some(1),
            1_850_000_000_000,
        )),
        surface: ioi_types::app::wallet_network::VaultSurface::Desktop,
        decided_at_ms: 1_750_000_000_500,
    };
    let first = approval_for([0x5bu8; 32], 21);
    let second = approval_for([0x5cu8; 32], 22);
    let first_hash = first
        .approval_grant
        .as_ref()
        .expect("first grant")
        .artifact_hash()
        .expect("first grant hash");
    let second_hash = second
        .approval_grant
        .as_ref()
        .expect("second grant")
        .artifact_hash()
        .expect("second grant hash");
    assert_ne!(first_hash, second_hash);

    with_ctx(|ctx| {
        run_async(
            service.handle_service_call(
                &mut state,
                "register_approval_authority@v1",
                &codec::to_bytes_canonical(&RegisterApprovalAuthorityParams {
                    authority: approver.authority.clone(),
                })
                .expect("encode"),
                ctx,
            ),
        )
        .expect("register authority");

        for approval in [&first, &second] {
            run_async(service.handle_service_call(
                &mut state,
                "record_approval@v1",
                &codec::to_bytes_canonical(approval).expect("encode"),
                ctx,
            ))
            .expect("record distinct grant");
        }
    });

    let binding =
        install_effect_binding(&service, &mut state, &approver.authority, 1_850_000_000_000);
    with_ctx(|ctx| {
        for (grant_hash, consumption_id) in
            [(first_hash, [0x5du8; 32]), (second_hash, [0x5eu8; 32])]
        {
            run_async(
                service.handle_service_call(
                    &mut state,
                    "consume_approval_grant_for_effect@v1",
                    &codec::to_bytes_canonical(&effect_consume_params(
                        request_hash,
                        grant_hash,
                        consumption_id,
                        &binding.expected,
                    ))
                    .expect("encode"),
                    ctx,
                ),
            )
            .expect("consume distinct grant");
        }

        run_async(
            service.handle_service_call(
                &mut state,
                "consume_approval_grant_for_effect@v1",
                &codec::to_bytes_canonical(&effect_consume_params(
                    request_hash,
                    first_hash,
                    [0x5du8; 32],
                    &binding.expected,
                ))
                .expect("encode"),
                ctx,
            ),
        )
        .expect("first grant's exact receipt remains replayable after recording the second");
    });

    for hash in [first_hash, second_hash] {
        let grant_state: ApprovalGrantState = load_typed(&state, &approval_grant_state_key(&hash))
            .expect("load")
            .expect("grant state");
        assert_eq!(grant_state.uses_consumed, 1);
        assert_eq!(grant_state.remaining_usages, 0);
    }
}

#[test]
fn effect_consumption_rejects_a_conflicting_occupied_receipt_slot() {
    let service = WalletNetworkService;
    let mut state = MockState::default();
    let request_hash = [0x61u8; 32];
    let consumption_id = [0x62u8; 32];
    let approver = new_approval_signer();
    let approval = WalletApprovalDecision {
        interception: WalletInterceptionContext {
            session_id: None,
            request_hash,
            target: ActionTarget::WebRetrieve,
            policy_hash: [0x63u8; 32],
            value_usd_micros: None,
            reason: "governed effect".to_string(),
            intercepted_at_ms: 1_750_000_000_000,
        },
        decision: ioi_types::app::wallet_network::WalletApprovalDecisionKind::ApprovedByHuman,
        approval_grant: Some(signed_wallet_approval_grant(
            &approver,
            request_hash,
            [0x63u8; 32],
            [7u8; 32],
            [0x64u8; 32],
            12,
            Some(1),
            1_850_000_000_000,
        )),
        surface: ioi_types::app::wallet_network::VaultSurface::Desktop,
        decided_at_ms: 1_750_000_000_500,
    };
    let grant_hash = approval
        .approval_grant
        .as_ref()
        .expect("grant")
        .artifact_hash()
        .expect("grant hash");

    with_ctx(|ctx| {
        let register = RegisterApprovalAuthorityParams {
            authority: approver.authority.clone(),
        };
        run_async(service.handle_service_call(
            &mut state,
            "register_approval_authority@v1",
            &codec::to_bytes_canonical(&register).expect("encode"),
            ctx,
        ))
        .expect("register authority");
        run_async(service.handle_service_call(
            &mut state,
            "record_approval@v1",
            &codec::to_bytes_canonical(&approval).expect("encode"),
            ctx,
        ))
        .expect("record approval");
    });
    let binding =
        install_effect_binding(&service, &mut state, &approver.authority, 1_850_000_000_000);

    let receipt_key = approval_effect_consumption_receipt_key(&consumption_id);
    state
        .insert(&receipt_key, b"foreign occupant")
        .expect("plant conflicting slot");

    with_ctx(|ctx| {
        let consume =
            effect_consume_params(request_hash, grant_hash, consumption_id, &binding.expected);
        let error = run_async(service.handle_service_call(
            &mut state,
            "consume_approval_grant_for_effect@v1",
            &codec::to_bytes_canonical(&consume).expect("encode"),
            ctx,
        ))
        .expect_err("foreign occupied receipt slot must refuse");
        assert!(error.to_string().contains("receipt is unreadable"));
    });

    let consumption: ApprovalGrantState =
        load_typed(&state, &approval_grant_state_key(&grant_hash))
            .expect("load")
            .expect("consumption state");
    assert_eq!(consumption.uses_consumed, 0);
    assert_eq!(consumption.remaining_usages, 1);
    assert_eq!(
        state.get(&receipt_key).expect("state"),
        Some(b"foreign occupant".to_vec())
    );
}

#[derive(Clone, Copy)]
enum EffectBindingChange {
    Rotation,
    Revocation,
    Expiry,
    CoordinateMismatch,
    SnapshotMismatch,
}

#[test]
fn effect_consumption_atomically_validates_principal_authority_and_replays_consumed_receipts() {
    struct Case {
        name: &'static str,
        change: EffectBindingChange,
        consume_before_change: bool,
        expected_error: Option<&'static str>,
    }

    let cases = [
        Case {
            name: "rotation before first consumption",
            change: EffectBindingChange::Rotation,
            consume_before_change: false,
            expected_error: Some("binding_coordinates_stale"),
        },
        Case {
            name: "revocation before first consumption",
            change: EffectBindingChange::Revocation,
            consume_before_change: false,
            expected_error: Some("binding_coordinates_stale"),
        },
        Case {
            name: "binding expiry before first consumption",
            change: EffectBindingChange::Expiry,
            consume_before_change: false,
            expected_error: Some("binding_expired"),
        },
        Case {
            name: "coordinate mismatch on first consumption",
            change: EffectBindingChange::CoordinateMismatch,
            consume_before_change: false,
            expected_error: Some("binding_coordinates_stale"),
        },
        Case {
            name: "snapshot mismatch on first consumption",
            change: EffectBindingChange::SnapshotMismatch,
            consume_before_change: false,
            expected_error: Some("snapshot_stale"),
        },
        Case {
            name: "consumed receipt replay after rotation",
            change: EffectBindingChange::Rotation,
            consume_before_change: true,
            expected_error: None,
        },
        Case {
            name: "consumed receipt replay after revocation",
            change: EffectBindingChange::Revocation,
            consume_before_change: true,
            expected_error: None,
        },
        Case {
            name: "consumed receipt replay after binding expiry",
            change: EffectBindingChange::Expiry,
            consume_before_change: true,
            expected_error: None,
        },
    ];

    for (index, case) in cases.into_iter().enumerate() {
        let service = WalletNetworkService;
        let mut state = MockState::default();
        let approver = new_approval_signer();
        let request_hash = [0x70u8.saturating_add(index as u8); 32];
        let consumption_id = [0x80u8.saturating_add(index as u8); 32];
        let approval = WalletApprovalDecision {
            interception: WalletInterceptionContext {
                session_id: None,
                request_hash,
                target: ActionTarget::NetFetch,
                policy_hash: [0x90u8.saturating_add(index as u8); 32],
                value_usd_micros: None,
                reason: "atomic principal binding".to_string(),
                intercepted_at_ms: EFFECT_NOW_MS,
            },
            decision: ioi_types::app::wallet_network::WalletApprovalDecisionKind::ApprovedByHuman,
            approval_grant: Some(signed_wallet_approval_grant(
                &approver,
                request_hash,
                [0x90u8.saturating_add(index as u8); 32],
                [7u8; 32],
                [0xa0u8.saturating_add(index as u8); 32],
                100 + index as u64,
                Some(1),
                1_850_000_000_000,
            )),
            surface: VaultSurface::Desktop,
            decided_at_ms: EFFECT_NOW_MS,
        };
        let grant_hash = approval
            .approval_grant
            .as_ref()
            .expect("approval grant")
            .artifact_hash()
            .expect("grant hash");
        with_ctx(|ctx| {
            run_async(
                service.handle_service_call(
                    &mut state,
                    "register_approval_authority@v1",
                    &codec::to_bytes_canonical(&RegisterApprovalAuthorityParams {
                        authority: approver.authority.clone(),
                    })
                    .expect("encode authority"),
                    ctx,
                ),
            )
            .unwrap_or_else(|error| panic!("{}: register authority: {error}", case.name));
            run_async(service.handle_service_call(
                &mut state,
                "record_approval@v1",
                &codec::to_bytes_canonical(&approval).expect("encode approval"),
                ctx,
            ))
            .unwrap_or_else(|error| panic!("{}: record approval: {error}", case.name));
        });
        let binding = install_effect_binding(
            &service,
            &mut state,
            &approver.authority,
            EFFECT_NOW_MS + 1_000,
        );
        let mut consume =
            effect_consume_params(request_hash, grant_hash, consumption_id, &binding.expected);
        if case.consume_before_change {
            consume_effect_at(&service, &mut state, &consume, EFFECT_NOW_MS)
                .unwrap_or_else(|error| panic!("{}: initial consumption: {error}", case.name));
        }

        match case.change {
            EffectBindingChange::Rotation => {
                let rotated = new_approval_signer();
                with_ctx_signer(binding.root.account_id, |ctx| {
                    run_async(
                        service.handle_service_call(
                            &mut state,
                            "register_approval_authority@v1",
                            &codec::to_bytes_canonical(&RegisterApprovalAuthorityParams {
                                authority: rotated.authority.clone(),
                            })
                            .expect("encode rotated authority"),
                            ctx,
                        ),
                    )
                    .unwrap_or_else(|error| {
                        panic!("{}: register rotated authority: {error}", case.name)
                    });
                });
                mutate_effect_binding(
                    &service,
                    &mut state,
                    &binding,
                    &rotated.authority,
                    PrincipalAuthorityBindingStatus::Active,
                );
            }
            EffectBindingChange::Revocation => {
                mutate_effect_binding(
                    &service,
                    &mut state,
                    &binding,
                    &approver.authority,
                    PrincipalAuthorityBindingStatus::Revoked,
                );
            }
            EffectBindingChange::Expiry => {}
            EffectBindingChange::CoordinateMismatch => {
                consume
                    .expected_principal_authority
                    .coordinates
                    .binding_version += 1;
            }
            EffectBindingChange::SnapshotMismatch => {
                consume
                    .expected_principal_authority
                    .approval_authority_snapshot_hash[0] ^= 0xff;
            }
        }

        let consume_at = if matches!(case.change, EffectBindingChange::Expiry) {
            EFFECT_NOW_MS + 1_001
        } else {
            EFFECT_NOW_MS
        };
        let result = consume_effect_at(&service, &mut state, &consume, consume_at);
        let grant_state: ApprovalGrantState =
            load_typed(&state, &approval_grant_state_key(&grant_hash))
                .expect("load grant state")
                .expect("grant state");
        match case.expected_error {
            Some(expected_error) => {
                let error = result
                    .err()
                    .unwrap_or_else(|| panic!("{}: first consumption succeeded", case.name));
                assert!(
                    error.to_string().contains(expected_error),
                    "{}: unexpected error: {error}",
                    case.name
                );
                assert_eq!(grant_state.uses_consumed, 0, "{}", case.name);
                assert_eq!(grant_state.remaining_usages, 1, "{}", case.name);
                assert!(
                    state
                        .get(&approval_effect_consumption_receipt_key(&consumption_id))
                        .expect("read receipt")
                        .is_none(),
                    "{}",
                    case.name
                );
            }
            None => {
                result.unwrap_or_else(|error| panic!("{}: replay failed: {error}", case.name));
                assert_eq!(grant_state.uses_consumed, 1, "{}", case.name);
                assert_eq!(grant_state.remaining_usages, 0, "{}", case.name);
                let receipt: ApprovalGrantConsumptionReceipt = load_typed(
                    &state,
                    &approval_effect_consumption_receipt_key(&consumption_id),
                )
                .expect("load receipt")
                .expect("receipt");
                assert_eq!(
                    receipt.principal_authority, binding.expected,
                    "{}",
                    case.name
                );
            }
        }
    }
}

#[test]
fn consume_approval_grant_enforces_revocation_epoch_and_audience_binding() {
    let service = WalletNetworkService;
    let mut state = MockState::default();
    let request_hash = [21u8; 32];
    let approver = new_approval_signer();

    let approval = WalletApprovalDecision {
        interception: WalletInterceptionContext {
            session_id: None,
            request_hash,
            target: ActionTarget::NetFetch,
            policy_hash: [29u8; 32],
            value_usd_micros: None,
            reason: "step-up".to_string(),
            intercepted_at_ms: 1_750_000_000_000,
        },
        decision: ioi_types::app::wallet_network::WalletApprovalDecisionKind::ApprovedByHuman,
        approval_grant: Some(signed_wallet_approval_grant(
            &approver,
            request_hash,
            [29u8; 32],
            [7u8; 32],
            [0x43u8; 32],
            9,
            Some(1),
            1_850_000_000_000,
        )),
        surface: ioi_types::app::wallet_network::VaultSurface::Desktop,
        decided_at_ms: 1_750_000_000_500,
    };

    with_ctx(|ctx| {
        let register = RegisterApprovalAuthorityParams {
            authority: approver.authority.clone(),
        };
        let register_params = codec::to_bytes_canonical(&register).expect("encode");
        run_async(service.handle_service_call(
            &mut state,
            "register_approval_authority@v1",
            &register_params,
            ctx,
        ))
        .expect("register approval authority");

        let approval_params = codec::to_bytes_canonical(&approval).expect("encode");
        run_async(service.handle_service_call(
            &mut state,
            "record_approval@v1",
            &approval_params,
            ctx,
        ))
        .expect("approval");

        let consume_bind = ConsumeApprovalGrantParams {
            request_hash,
            consumed_at_ms: 1_750_000_001_000,
        };
        let consume_bind_params = codec::to_bytes_canonical(&consume_bind).expect("encode");
        run_async(service.handle_service_call(
            &mut state,
            "consume_approval_grant@v1",
            &consume_bind_params,
            ctx,
        ))
        .expect("consume should bind audience");

        // Re-record with fresh grant so we can exercise epoch invalidation path.
        let request_hash_2 = [22u8; 32];
        let approval_2 = WalletApprovalDecision {
            interception: WalletInterceptionContext {
                session_id: None,
                request_hash: request_hash_2,
                target: ActionTarget::NetFetch,
                policy_hash: [30u8; 32],
                value_usd_micros: None,
                reason: "step-up".to_string(),
                intercepted_at_ms: 1_750_000_000_000,
            },
            decision: ioi_types::app::wallet_network::WalletApprovalDecisionKind::ApprovedByHuman,
            approval_grant: Some(signed_wallet_approval_grant(
                &approver,
                request_hash_2,
                [30u8; 32],
                [7u8; 32],
                [0x44u8; 32],
                10,
                Some(1),
                1_850_000_000_000,
            )),
            surface: ioi_types::app::wallet_network::VaultSurface::Desktop,
            decided_at_ms: 1_750_000_000_500,
        };
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

        let consume_revoked = ConsumeApprovalGrantParams {
            request_hash: request_hash_2,
            consumed_at_ms: 1_750_000_002_000,
        };
        let consume_revoked_params = codec::to_bytes_canonical(&consume_revoked).expect("encode");
        let err = run_async(service.handle_service_call(
            &mut state,
            "consume_approval_grant@v1",
            &consume_revoked_params,
            ctx,
        ))
        .expect_err("epoch-bumped approval should fail");
        assert!(err.to_string().contains("revocation epoch"));
    });
}

#[test]
fn consume_approval_grant_rejects_signer_audience_mismatch() {
    let service = WalletNetworkService;
    let mut state = MockState::default();
    let request_hash = [31u8; 32];
    let approver = new_approval_signer();

    let approval = WalletApprovalDecision {
        interception: WalletInterceptionContext {
            session_id: None,
            request_hash,
            target: ActionTarget::NetFetch,
            policy_hash: [39u8; 32],
            value_usd_micros: None,
            reason: "step-up".to_string(),
            intercepted_at_ms: 1_750_000_000_000,
        },
        decision: ioi_types::app::wallet_network::WalletApprovalDecisionKind::ApprovedByHuman,
        approval_grant: Some(signed_wallet_approval_grant(
            &approver,
            request_hash,
            [39u8; 32],
            [7u8; 32],
            [0x45u8; 32],
            1,
            Some(1),
            1_850_000_000_000,
        )),
        surface: ioi_types::app::wallet_network::VaultSurface::Desktop,
        decided_at_ms: 1_750_000_000_500,
    };

    with_ctx(|ctx| {
        let register = RegisterApprovalAuthorityParams {
            authority: approver.authority.clone(),
        };
        let register_params = codec::to_bytes_canonical(&register).expect("encode");
        run_async(service.handle_service_call(
            &mut state,
            "register_approval_authority@v1",
            &register_params,
            ctx,
        ))
        .expect("register approval authority");

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
        let consume = ConsumeApprovalGrantParams {
            request_hash,
            consumed_at_ms: 1_750_000_001_000,
        };
        let consume_params = codec::to_bytes_canonical(&consume).expect("encode");
        let err = run_async(service.handle_service_call(
            &mut state,
            "consume_approval_grant@v1",
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
        verifier_id: String::new(),
        manifest_hash: [0u8; 32],
        issued_at_ms: 1_749_999_999_000,
        expires_at_ms: 1_850_000_000_000,
        evidence: None,
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

#[test]
fn software_guardian_attestation_requires_registered_manifest() {
    let state = MockState::default();
    let attestation = GuardianAttestation {
        quote_hash: [11u8; 32],
        measurement_hash: [12u8; 32],
        guardian_ephemeral_public_key: vec![1, 2, 3],
        nonce: [13u8; 32],
        verifier_id: "software-guardian".to_string(),
        manifest_hash: [14u8; 32],
        issued_at_ms: 10,
        expires_at_ms: 100,
        evidence: Some(ioi_types::app::GuardianAttestationEvidence {
            verifier: ioi_types::app::GuardianAttestationVerifierKind::SoftwareGuardian,
            manifest_hash: [14u8; 32],
            measurement_root: [12u8; 32],
            checkpoint: None,
            inclusion_proof: vec![1],
            evidence: vec![2],
        }),
    };

    let err = super::super::validation::validate_guardian_attestation(&state, &attestation, 50)
        .expect_err("missing manifest must fail");
    assert!(err.to_string().contains("manifest not found"));
}

#[test]
fn software_guardian_attestation_accepts_registered_manifest_and_measurement() {
    let mut state = MockState::default();
    let registry = crate::guardian_registry::GuardianRegistry::new(
        ioi_types::config::GuardianRegistryParams {
            enabled: true,
            minimum_committee_size: 1,
            minimum_witness_committee_size: 1,
            minimum_provider_diversity: 1,
            minimum_region_diversity: 1,
            minimum_host_class_diversity: 1,
            minimum_backend_diversity: 0,
            require_even_committee_sizes: false,
            require_checkpoint_anchoring: true,
            max_checkpoint_staleness_ms: 120_000,
            max_committee_outage_members: 0,
            asymptote_required_witness_strata: vec!["stratum-a".into()],
            asymptote_escalation_witness_strata: vec!["stratum-a".into()],
            asymptote_high_risk_effect_tier: ioi_types::app::FinalityTier::SealedFinal,
            apply_accountable_membership_updates: true,
        },
    );
    let manifest = ioi_types::app::GuardianCommitteeManifest {
        validator_account_id: AccountId([21u8; 32]),
        epoch: 1,
        threshold: 1,
        members: vec![ioi_types::app::GuardianCommitteeMember {
            member_id: "guardian-1".to_string(),
            signature_suite: SignatureSuite::ED25519,
            public_key: vec![7, 7, 7],
            endpoint: Some("https://guardian-1.example".to_string()),
            provider: Some("provider-a".to_string()),
            region: Some("us-east-1".to_string()),
            host_class: Some("amd-sev".to_string()),
            key_authority_kind: None,
        }],
        measurement_profile_root: [22u8; 32],
        policy_hash: [23u8; 32],
        transparency_log_id: "default".to_string(),
    };
    let manifest_hash = crate::guardian_registry::GuardianRegistry::manifest_hash(&manifest)
        .expect("manifest hash");
    let profile = ioi_types::app::GuardianMeasurementProfile {
        profile_id: "default".to_string(),
        allowed_measurement_roots: vec![[24u8; 32]],
        policy_hash: [25u8; 32],
    };

    with_ctx(|ctx| {
        let manifest_params = codec::to_bytes_canonical(&manifest).expect("encode manifest");
        run_async(registry.handle_service_call(
            &mut state,
            "register_guardian_committee@v1",
            &manifest_params,
            ctx,
        ))
        .expect("register manifest");

        let profile_params = codec::to_bytes_canonical(&profile).expect("encode profile");
        run_async(registry.handle_service_call(
            &mut state,
            "publish_measurement_profile@v1",
            &profile_params,
            ctx,
        ))
        .expect("publish profile");
    });

    let attestation = GuardianAttestation {
        quote_hash: [26u8; 32],
        measurement_hash: [24u8; 32],
        guardian_ephemeral_public_key: vec![8, 8, 8],
        nonce: [27u8; 32],
        verifier_id: "software-guardian".to_string(),
        manifest_hash,
        issued_at_ms: 100,
        expires_at_ms: 1_000,
        evidence: Some(ioi_types::app::GuardianAttestationEvidence {
            verifier: ioi_types::app::GuardianAttestationVerifierKind::SoftwareGuardian,
            manifest_hash,
            measurement_root: [24u8; 32],
            checkpoint: None,
            inclusion_proof: vec![9],
            evidence: vec![10],
        }),
    };

    super::super::validation::validate_guardian_attestation(&state, &attestation, 500)
        .expect("registered software guardian attestation should validate");
}
