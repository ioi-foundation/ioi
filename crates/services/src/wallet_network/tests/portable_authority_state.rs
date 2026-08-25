use super::*;
use crate::wallet_network::keys::{
    portable_authority_effect_admission_receipt_v2_key, registered_client_key,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ioi_api::services::BlockchainService;
use ioi_types::app::wallet_network::{
    IssuePrincipalAuthorityBindingParams, PrincipalAuthorityBindingProofV1,
    PrincipalAuthorityBindingStatementV1, PrincipalAuthorityBindingStatus, PrincipalAuthorityKind,
    VaultSurface, WalletClientRole, WalletClientState, WalletControlPlaneRootRecord,
    WalletRegisteredClientRecord, PRINCIPAL_AUTHORITY_BINDING_SCHEMA_VERSION,
};

const PORTABLE_NOW_MS: u64 = 1_787_587_300_000;
const PORTABLE_SCOPE: &str = "scope:wallet.authority.portable.issue";

fn with_portable_ctx<F>(signer: [u8; 32], f: F)
where
    F: FnOnce(&mut TxContext<'_>),
{
    let services = ServiceDirectory::new(Vec::new());
    let mut ctx = TxContext {
        block_height: 4242,
        block_timestamp: PORTABLE_NOW_MS * 1_000_000,
        chain_id: ChainId(1),
        signer_account_id: AccountId(signer),
        services: &services,
        simulation: false,
        is_internal: false,
    };
    f(&mut ctx);
}

fn install_portable_issuer(
    service: &WalletNetworkService,
    state: &mut MockState,
    principal_ref: &str,
    public_key: Vec<u8>,
) -> (
    ExpectedPrincipalAuthorityBinding,
    WalletControlPlaneRootRecord,
    Ed25519KeyPair,
) {
    let authority = ApprovalAuthority {
        schema_version: 1,
        authority_id: account_id_from_key_material(SignatureSuite::ED25519, &public_key)
            .expect("authority id"),
        public_key,
        signature_suite: SignatureSuite::ED25519,
        expires_at: PORTABLE_NOW_MS + 60_000,
        revoked: false,
        scope_allowlist: vec![PORTABLE_SCOPE.to_owned()],
    };
    let root_keypair = Ed25519KeyPair::generate().expect("root keypair");
    let root_public_key = root_keypair.public_key().to_bytes();
    let root = WalletControlPlaneRootRecord {
        account_id: account_id_from_key_material(SignatureSuite::ED25519, &root_public_key)
            .expect("root id"),
        signature_suite: SignatureSuite::ED25519,
        public_key: root_public_key,
        registered_at_ms: PORTABLE_NOW_MS - 10_000,
        updated_at_ms: PORTABLE_NOW_MS - 10_000,
        metadata: BTreeMap::new(),
    };
    with_portable_ctx(root.account_id, |ctx| {
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
        client_id: [7; 32],
        label: "portable authority test".to_owned(),
        surface: VaultSurface::Desktop,
        signature_suite: SignatureSuite::ED25519,
        public_key: vec![7; 32],
        role: WalletClientRole::ControlPlaneAdmin,
        state: WalletClientState::Active,
        registered_at_ms: PORTABLE_NOW_MS - 10_000,
        updated_at_ms: PORTABLE_NOW_MS - 10_000,
        expires_at_ms: Some(PORTABLE_NOW_MS + 60_000),
        allowed_provider_families: Vec::new(),
        metadata: BTreeMap::new(),
    };
    state
        .insert(
            &registered_client_key(&client.client_id),
            &codec::to_bytes_canonical(&client).expect("encode client"),
        )
        .expect("store client");
    with_portable_ctx([7; 32], |ctx| {
        run_async(
            service.handle_service_call(
                state,
                "register_approval_authority@v1",
                &codec::to_bytes_canonical(&RegisterApprovalAuthorityParams {
                    authority: authority.clone(),
                })
                .expect("encode authority"),
                ctx,
            ),
        )
        .expect("register authority");
    });
    let statement = PrincipalAuthorityBindingStatementV1 {
        schema_version: PRINCIPAL_AUTHORITY_BINDING_SCHEMA_VERSION,
        principal_ref: principal_ref.to_owned(),
        authority_kind: PrincipalAuthorityKind::Approval,
        binding_version: 1,
        status: PrincipalAuthorityBindingStatus::Active,
        authority_id: authority.authority_id,
        authority_public_key: authority.public_key.clone(),
        authority_signature_suite: authority.signature_suite,
        approval_authority_snapshot_hash: authority.artifact_hash().expect("authority hash"),
        previous_binding_ref: None,
        previous_binding_hash: None,
        signed_at_ms: PORTABLE_NOW_MS - 1_000,
        expires_at_ms: Some(PORTABLE_NOW_MS + 60_000),
        issuer_root_account_id: root.account_id,
        reason: Some("portable issuer".to_owned()),
    };
    let signature = root_keypair
        .sign(&statement.signing_bytes().expect("binding bytes"))
        .expect("binding signature")
        .to_bytes();
    let proof = PrincipalAuthorityBindingProofV1::new(
        statement,
        SignatureProof {
            suite: SignatureSuite::ED25519,
            public_key: root.public_key.clone(),
            signature,
        },
    )
    .expect("binding proof");
    with_portable_ctx(root.account_id, |ctx| {
        run_async(
            service.handle_service_call(
                state,
                "issue_principal_authority_binding@v1",
                &codec::to_bytes_canonical(&IssuePrincipalAuthorityBindingParams {
                    proof: proof.clone(),
                })
                .expect("encode binding"),
                ctx,
            ),
        )
        .expect("issue binding");
    });
    (
        ExpectedPrincipalAuthorityBinding {
            principal_ref: principal_ref.to_owned(),
            required_scope: PORTABLE_SCOPE.to_owned(),
            coordinates: proof.coordinates(),
            approval_authority_snapshot_hash: proof.statement.approval_authority_snapshot_hash,
            approval_authority: authority,
        },
        root,
        root_keypair,
    )
}

fn rotate_portable_issuer(
    service: &WalletNetworkService,
    state: &mut MockState,
    binding: &ExpectedPrincipalAuthorityBinding,
    root: &WalletControlPlaneRootRecord,
    root_keypair: &Ed25519KeyPair,
) {
    let rotated_keypair = Ed25519KeyPair::generate().expect("rotated issuer keypair");
    let rotated_authority = ApprovalAuthority {
        schema_version: 1,
        authority_id: account_id_from_key_material(
            SignatureSuite::ED25519,
            &rotated_keypair.public_key().to_bytes(),
        )
        .expect("rotated authority id"),
        public_key: rotated_keypair.public_key().to_bytes(),
        signature_suite: SignatureSuite::ED25519,
        expires_at: PORTABLE_NOW_MS + 60_000,
        revoked: false,
        scope_allowlist: vec![PORTABLE_SCOPE.to_owned()],
    };
    with_portable_ctx([7; 32], |ctx| {
        run_async(
            service.handle_service_call(
                state,
                "register_approval_authority@v1",
                &codec::to_bytes_canonical(&RegisterApprovalAuthorityParams {
                    authority: rotated_authority.clone(),
                })
                .expect("encode rotated authority"),
                ctx,
            ),
        )
        .expect("register rotated authority");
    });

    let statement = PrincipalAuthorityBindingStatementV1 {
        schema_version: PRINCIPAL_AUTHORITY_BINDING_SCHEMA_VERSION,
        principal_ref: binding.principal_ref.clone(),
        authority_kind: PrincipalAuthorityKind::Approval,
        binding_version: binding.coordinates.binding_version + 1,
        status: PrincipalAuthorityBindingStatus::Active,
        authority_id: rotated_authority.authority_id,
        authority_public_key: rotated_authority.public_key.clone(),
        authority_signature_suite: rotated_authority.signature_suite,
        approval_authority_snapshot_hash: rotated_authority
            .artifact_hash()
            .expect("rotated authority hash"),
        previous_binding_ref: Some(binding.coordinates.binding_ref.clone()),
        previous_binding_hash: Some(binding.coordinates.binding_hash),
        signed_at_ms: PORTABLE_NOW_MS,
        expires_at_ms: Some(PORTABLE_NOW_MS + 60_000),
        issuer_root_account_id: root.account_id,
        reason: Some("recovery rotates portable issuer authority".to_owned()),
    };
    let signature = root_keypair
        .sign(&statement.signing_bytes().expect("rotated binding bytes"))
        .expect("rotated binding signature")
        .to_bytes();
    let proof = PrincipalAuthorityBindingProofV1::new(
        statement,
        SignatureProof {
            suite: SignatureSuite::ED25519,
            public_key: root.public_key.clone(),
            signature,
        },
    )
    .expect("rotated binding proof");
    with_portable_ctx(root.account_id, |ctx| {
        run_async(
            service.handle_service_call(
                state,
                "issue_principal_authority_binding@v1",
                &codec::to_bytes_canonical(&IssuePrincipalAuthorityBindingParams { proof })
                    .expect("encode rotated binding"),
                ctx,
            ),
        )
        .expect("rotate issuer binding");
    });
}

fn canonical(value: &Value) -> Vec<u8> {
    serde_jcs::to_vec(value).expect("canonical JSON")
}

fn ref_hash(value: &Value, pointer: &str) -> [u8; 32] {
    let encoded = value
        .pointer(pointer)
        .and_then(Value::as_str)
        .and_then(|value| value.strip_prefix("sha256:"))
        .expect("sha256 ref");
    let decoded = hex::decode(encoded).expect("hex hash");
    decoded.try_into().expect("32-byte hash")
}

fn admission_context() -> PortableAuthorityEffectAdmissionContextV1 {
    PortableAuthorityEffectAdmissionContextV1 {
        decision_profile_ref: "policy://tests/portable-effect-admission/v1".to_owned(),
        policy_hash: [0x41; 32],
        temporal_verification_profile_ref: "policy://tests/temporal/portable/v1".to_owned(),
        temporal_verification_profile_hash: [0x42; 32],
        temporal_validity_evaluation_ref: "evidence://tests/temporal/portable/1".to_owned(),
        temporal_validity_evaluation_hash: [0x43; 32],
        temporal_posture: PortableAuthorityTemporalPostureV1::OnlineFresh,
        continuity_floor_evidence_refs: vec!["evidence://tests/continuity/portable/1".to_owned()],
        principal_authority_revalidation_receipt_ref: None,
        principal_authority_revalidation_receipt_hash: None,
    }
}

fn record_params(
    request: &Value,
    context: &Value,
    review: &Value,
    grant: &Value,
    key_set: &Value,
    snapshot: &Value,
    binding: ExpectedPrincipalAuthorityBinding,
) -> RecordPortableAuthorityGrantV3Params {
    RecordPortableAuthorityGrantV3Params {
        grant_chain_json: vec![canonical(grant)],
        trusted_key_sets_json: vec![canonical(key_set)],
        revocation_snapshots_json: vec![canonical(snapshot)],
        delegation_closure_json: None,
        authority_request_json: canonical(request),
        approval_ceremony_context_json: canonical(context),
        authority_review_receipt_json: canonical(review),
        issuer_authorities: vec![PortableAuthorityIssuerBindingV1 {
            issuer_id: grant["issuer_id"].as_str().unwrap().to_owned(),
            current_authority: binding,
        }],
        audience_client_id: [7; 32],
    }
}

#[test]
fn portable_registration_consumes_ceremony_and_effect_atomically_and_idempotently() {
    let service = WalletNetworkService;
    let mut state = MockState::default();
    let (request, context, review, grant, key_set, snapshot) =
        crate::wallet_network::portable_authority::tests::issuance_fixture();
    let public_key = URL_SAFE_NO_PAD
        .decode(key_set["keys"][0]["public_key"].as_str().unwrap())
        .expect("issuer public key");
    let (binding, root, root_keypair) = install_portable_issuer(
        &service,
        &mut state,
        "org://wallet-network/portable-issuer",
        public_key,
    );
    let record = record_params(
        &request,
        &context,
        &review,
        &grant,
        &key_set,
        &snapshot,
        binding.clone(),
    );
    with_portable_ctx([7; 32], |ctx| {
        let bytes = codec::to_bytes_canonical(&record).expect("record bytes");
        run_async(service.handle_service_call(
            &mut state,
            "record_portable_authority_grant_v3@v1",
            &bytes,
            ctx,
        ))
        .expect("record portable grant");
        run_async(service.handle_service_call(
            &mut state,
            "record_portable_authority_grant_v3@v1",
            &bytes,
            ctx,
        ))
        .expect("record replay is idempotent");
    });

    let grant_hash = ref_hash(&grant, "/body_hash");
    let stored: PortableAuthorityGrantV3State =
        load_typed(&state, &portable_authority_grant_v3_state_key(&grant_hash))
            .expect("load state")
            .expect("portable state");
    assert_eq!(stored.remaining_calls, 1);
    let ceremony_hash =
        crate::wallet_network::portable_authority::approval_ceremony_context_v1_hash(&context)
            .expect("ceremony hash");
    let ceremony_hash: [u8; 32] = hex::decode(ceremony_hash.trim_start_matches("sha256:"))
        .expect("ceremony hex")
        .try_into()
        .expect("ceremony hash bytes");
    let ceremony: PortableAuthorityCeremonyConsumptionV1 = load_typed(
        &state,
        &portable_authority_ceremony_consumption_key(&ceremony_hash),
    )
    .expect("load ceremony")
    .expect("ceremony consumption");
    assert_eq!(ceremony.grant_hash, grant_hash);

    let effect_hash = ref_hash(
        &grant,
        "/request_commitment/authorization_subject/subject_hash",
    );
    let consume = ConsumePortableAuthorityGrantV3ForEffectParams {
        grant_hash,
        consumption_id: [0x91; 32],
        expected_audience: grant["audience"].as_str().unwrap().to_owned(),
        expected_holder_id: grant["holder_id"].as_str().unwrap().to_owned(),
        expected_holder_key_id: grant["holder_key_id"].as_str().unwrap().to_owned(),
        actual_effect_ref: grant
            .pointer("/request_commitment/authorization_subject/subject_ref")
            .and_then(Value::as_str)
            .unwrap()
            .to_owned(),
        actual_effect_hash: effect_hash,
        admission: admission_context(),
    };
    let foreign_client = WalletRegisteredClientRecord {
        client_id: [8; 32],
        label: "foreign portable capability client".to_owned(),
        surface: VaultSurface::Desktop,
        signature_suite: SignatureSuite::ED25519,
        public_key: vec![8; 32],
        role: WalletClientRole::Capability,
        state: WalletClientState::Active,
        registered_at_ms: PORTABLE_NOW_MS - 10_000,
        updated_at_ms: PORTABLE_NOW_MS - 10_000,
        expires_at_ms: Some(PORTABLE_NOW_MS + 60_000),
        allowed_provider_families: Vec::new(),
        metadata: BTreeMap::new(),
    };
    state
        .insert(
            &registered_client_key(&foreign_client.client_id),
            &codec::to_bytes_canonical(&foreign_client).expect("encode foreign client"),
        )
        .expect("store foreign client");
    with_portable_ctx(foreign_client.client_id, |ctx| {
        let error = run_async(service.handle_service_call(
            &mut state,
            "consume_portable_authority_grant_v3_for_effect@v1",
            &codec::to_bytes_canonical(&consume).expect("foreign consume bytes"),
            ctx,
        ))
        .expect_err("a different capability client cannot borrow the portable audience");
        assert!(
            matches!(error, TransactionError::UnauthorizedByCredentials),
            "{error}"
        );
    });
    let before_owner_use: PortableAuthorityGrantV3State =
        load_typed(&state, &portable_authority_grant_v3_state_key(&grant_hash))
            .expect("load state")
            .expect("portable state");
    assert_eq!(before_owner_use.uses_consumed, 0);
    assert_eq!(before_owner_use.remaining_calls, 1);
    assert!(load_typed::<PortableAuthorityGrantV3ConsumptionReceipt>(
        &state,
        &portable_authority_effect_consumption_receipt_key(&consume.consumption_id)
    )
    .expect("load foreign receipt")
    .is_none());
    with_portable_ctx([7; 32], |ctx| {
        let bytes = codec::to_bytes_canonical(&consume).expect("consume bytes");
        run_async(service.handle_service_call(
            &mut state,
            "consume_portable_authority_grant_v3_for_effect@v1",
            &bytes,
            ctx,
        ))
        .expect("consume portable grant");
        run_async(service.handle_service_call(
            &mut state,
            "consume_portable_authority_grant_v3_for_effect@v1",
            &bytes,
            ctx,
        ))
        .expect("same durable intent is idempotent");

        let mut replay = consume.clone();
        replay.consumption_id = [0x92; 32];
        let error = run_async(service.handle_service_call(
            &mut state,
            "consume_portable_authority_grant_v3_for_effect@v1",
            &codec::to_bytes_canonical(&replay).expect("replay bytes"),
            ctx,
        ))
        .expect_err("exhausted grant cannot authorize a second intent");
        assert!(
            error.to_string().contains("unavailable for new use"),
            "{error}"
        );

        let mut conflict = consume.clone();
        conflict.actual_effect_ref = "effect://tests/conflicting-intent".to_owned();
        let error = run_async(service.handle_service_call(
            &mut state,
            "consume_portable_authority_grant_v3_for_effect@v1",
            &codec::to_bytes_canonical(&conflict).expect("conflict bytes"),
            ctx,
        ))
        .expect_err("one consumption id cannot be rebound to a different intent");
        assert!(
            error.to_string().contains("different effect ref")
                || error.to_string().contains("daemon-derived exact effect"),
            "{error}"
        );

        let mut policy_conflict = consume.clone();
        policy_conflict.admission.policy_hash = [0x44; 32];
        let error = run_async(service.handle_service_call(
            &mut state,
            "consume_portable_authority_grant_v3_for_effect@v1",
            &codec::to_bytes_canonical(&policy_conflict).expect("policy conflict bytes"),
            ctx,
        ))
        .expect_err("one consumption id cannot be rebound to different policy evidence");
        assert!(
            error.to_string().contains("different policy hash"),
            "{error}"
        );
    });

    let stored: PortableAuthorityGrantV3State =
        load_typed(&state, &portable_authority_grant_v3_state_key(&grant_hash))
            .expect("load state")
            .expect("portable state");
    assert_eq!(stored.uses_consumed, 1);
    assert_eq!(stored.remaining_calls, 0);
    assert_eq!(stored.status, PortableAuthorityGrantV3Status::Exhausted);
    let receipt: PortableAuthorityGrantV3ConsumptionReceipt = load_typed(
        &state,
        &portable_authority_effect_consumption_receipt_key(&consume.consumption_id),
    )
    .expect("load receipt")
    .expect("portable consumption receipt");
    assert_eq!(receipt.actual_effect_hash, effect_hash);
    assert_eq!(receipt.usage_ordinal, 1);
    assert_eq!(receipt.remaining_calls, 0);
    assert_ne!(receipt.receipt_hash, [0; 32]);
    assert_ne!(receipt.admission_receipt_hash, [0; 32]);
    let admission: PortableAuthorityEffectAdmissionReceiptV2Record = load_typed(
        &state,
        &portable_authority_effect_admission_receipt_v2_key(&consume.consumption_id),
    )
    .expect("load admission")
    .expect("portable admission receipt");
    assert_eq!(admission.receipt_hash, receipt.admission_receipt_hash);
    let admission_json: Value =
        serde_json::from_slice(&admission.receipt_json).expect("admission JSON");
    crate::wallet_network::portable_authority::verify_authority_effect_admission_receipt_v2(
        &admission_json,
    )
    .expect("registered admission receipt revalidates");
    assert_eq!(
        admission_json["body"]["actual_effect_hash"],
        format!("sha256:{}", hex::encode(effect_hash))
    );

    rotate_portable_issuer(&service, &mut state, &binding, &root, &root_keypair);
    with_portable_ctx([7; 32], |ctx| {
        let error = run_async(service.handle_service_call(
            &mut state,
            "consume_portable_authority_grant_v3_for_effect@v1",
            &codec::to_bytes_canonical(&consume).expect("post-recovery replay bytes"),
            ctx,
        ))
        .expect_err("issuer recovery must invalidate even an already consumed grant before effect");
        assert!(
            error.to_string().contains("current") || error.to_string().contains("binding"),
            "{error}"
        );
    });
    let after_recovery: PortableAuthorityGrantV3State =
        load_typed(&state, &portable_authority_grant_v3_state_key(&grant_hash))
            .expect("load post-recovery state")
            .expect("portable state");
    assert_eq!(after_recovery.uses_consumed, 1);
    assert_eq!(after_recovery.remaining_calls, 0);
    assert_eq!(
        load_typed::<PortableAuthorityGrantV3ConsumptionReceipt>(
            &state,
            &portable_authority_effect_consumption_receipt_key(&consume.consumption_id)
        )
        .expect("load retained post-recovery receipt"),
        Some(receipt)
    );
    assert_eq!(
        load_typed::<PortableAuthorityEffectAdmissionReceiptV2Record>(
            &state,
            &portable_authority_effect_admission_receipt_v2_key(&consume.consumption_id)
        )
        .expect("load retained post-recovery admission"),
        Some(admission)
    );
}

#[test]
fn portable_registration_rejects_request_carried_key_substitution_without_state() {
    let service = WalletNetworkService;
    let mut state = MockState::default();
    let (request, context, review, grant, mut key_set, snapshot) =
        crate::wallet_network::portable_authority::tests::issuance_fixture();
    let public_key = URL_SAFE_NO_PAD
        .decode(key_set["keys"][0]["public_key"].as_str().unwrap())
        .expect("issuer public key");
    let (binding, _root, _root_keypair) = install_portable_issuer(
        &service,
        &mut state,
        "org://wallet-network/portable-issuer",
        public_key,
    );
    key_set["keys"][0]["public_key"] = serde_json::json!(URL_SAFE_NO_PAD.encode([0x44; 32]));
    let record = record_params(
        &request, &context, &review, &grant, &key_set, &snapshot, binding,
    );

    with_portable_ctx([7; 32], |ctx| {
        let error = run_async(service.handle_service_call(
            &mut state,
            "record_portable_authority_grant_v3@v1",
            &codec::to_bytes_canonical(&record).expect("record bytes"),
            ctx,
        ))
        .expect_err("request-carried key must not replace current owner authority");
        assert!(
            error
                .to_string()
                .contains("differs from current owner authority"),
            "{error}"
        );
    });

    let grant_hash = ref_hash(&grant, "/body_hash");
    assert!(
        load_typed::<PortableAuthorityGrantV3State>(
            &state,
            &portable_authority_grant_v3_state_key(&grant_hash)
        )
        .expect("load state")
        .is_none(),
        "failed owner-authority validation must not persist portable state"
    );
    let ceremony_hash =
        crate::wallet_network::portable_authority::approval_ceremony_context_v1_hash(&context)
            .expect("ceremony hash");
    let ceremony_hash: [u8; 32] = hex::decode(ceremony_hash.trim_start_matches("sha256:"))
        .expect("ceremony hex")
        .try_into()
        .expect("ceremony hash bytes");
    assert!(
        load_typed::<PortableAuthorityCeremonyConsumptionV1>(
            &state,
            &portable_authority_ceremony_consumption_key(&ceremony_hash)
        )
        .expect("load ceremony")
        .is_none(),
        "failed owner-authority validation must not consume the ceremony"
    );
}

#[test]
fn portable_evidence_refresh_recovery_and_revocation_fail_closed_without_counter_mutation() {
    let service = WalletNetworkService;
    let mut state = MockState::default();
    let (request, context, review, grant, key_set, snapshot) =
        crate::wallet_network::portable_authority::tests::issuance_fixture();
    let public_key = URL_SAFE_NO_PAD
        .decode(key_set["keys"][0]["public_key"].as_str().unwrap())
        .expect("issuer public key");
    let (binding, root, root_keypair) = install_portable_issuer(
        &service,
        &mut state,
        "org://wallet-network/portable-issuer",
        public_key,
    );
    let record = record_params(
        &request,
        &context,
        &review,
        &grant,
        &key_set,
        &snapshot,
        binding.clone(),
    );
    with_portable_ctx([7; 32], |ctx| {
        run_async(service.handle_service_call(
            &mut state,
            "record_portable_authority_grant_v3@v1",
            &codec::to_bytes_canonical(&record).expect("record bytes"),
            ctx,
        ))
        .expect("record portable grant");
    });

    let grant_hash = ref_hash(&grant, "/body_hash");
    let state_key = portable_authority_grant_v3_state_key(&grant_hash);
    let before: PortableAuthorityGrantV3State = load_typed(&state, &state_key)
        .expect("load state")
        .expect("portable state");
    let issuer_authorities = vec![PortableAuthorityIssuerBindingV1 {
        issuer_id: grant["issuer_id"].as_str().unwrap().to_owned(),
        current_authority: binding.clone(),
    }];
    let mut forged_snapshot = snapshot.clone();
    forged_snapshot["signature"] = serde_json::json!("A".repeat(86));
    let forged_refresh = RefreshPortableAuthorityGrantV3EvidenceParams {
        grant_hash,
        trusted_key_sets_json: vec![canonical(&key_set)],
        revocation_snapshots_json: vec![canonical(&forged_snapshot)],
        delegation_closure_json: None,
        issuer_authorities: issuer_authorities.clone(),
    };
    with_portable_ctx([7; 32], |ctx| {
        let error = run_async(service.handle_service_call(
            &mut state,
            "refresh_portable_authority_grant_v3_evidence@v1",
            &codec::to_bytes_canonical(&forged_refresh).expect("forged refresh bytes"),
            ctx,
        ))
        .expect_err("forged refreshed snapshot must be rejected");
        assert!(error.to_string().contains("snapshot"), "{error}");
    });
    let after_failed_refresh: PortableAuthorityGrantV3State = load_typed(&state, &state_key)
        .expect("load state")
        .expect("portable state");
    assert_eq!(after_failed_refresh, before);

    let refresh = RefreshPortableAuthorityGrantV3EvidenceParams {
        grant_hash,
        trusted_key_sets_json: vec![canonical(&key_set)],
        revocation_snapshots_json: vec![canonical(&snapshot)],
        delegation_closure_json: None,
        issuer_authorities,
    };
    with_portable_ctx([7; 32], |ctx| {
        let bytes = codec::to_bytes_canonical(&refresh).expect("refresh bytes");
        run_async(service.handle_service_call(
            &mut state,
            "refresh_portable_authority_grant_v3_evidence@v1",
            &bytes,
            ctx,
        ))
        .expect("refresh portable evidence");
        run_async(service.handle_service_call(
            &mut state,
            "refresh_portable_authority_grant_v3_evidence@v1",
            &bytes,
            ctx,
        ))
        .expect("evidence refresh replay remains valid");

        rotate_portable_issuer(&service, &mut state, &binding, &root, &root_keypair);

        let effect_hash = ref_hash(
            &grant,
            "/request_commitment/authorization_subject/subject_hash",
        );
        let consume_after_recovery = ConsumePortableAuthorityGrantV3ForEffectParams {
            grant_hash,
            consumption_id: [0x92; 32],
            expected_audience: grant["audience"].as_str().unwrap().to_owned(),
            expected_holder_id: grant["holder_id"].as_str().unwrap().to_owned(),
            expected_holder_key_id: grant["holder_key_id"].as_str().unwrap().to_owned(),
            actual_effect_ref: grant
                .pointer("/request_commitment/authorization_subject/subject_ref")
                .and_then(Value::as_str)
                .unwrap()
                .to_owned(),
            actual_effect_hash: effect_hash,
            admission: admission_context(),
        };
        let error = run_async(
            service.handle_service_call(
                &mut state,
                "consume_portable_authority_grant_v3_for_effect@v1",
                &codec::to_bytes_canonical(&consume_after_recovery)
                    .expect("post-recovery consume bytes"),
                ctx,
            ),
        )
        .expect_err("issuer recovery must not preserve an old portable grant");
        assert!(
            error.to_string().contains("current") || error.to_string().contains("binding"),
            "{error}"
        );
        let after_recovery: PortableAuthorityGrantV3State = load_typed(&state, &state_key)
            .expect("load post-recovery state")
            .expect("portable state");
        assert_eq!(after_recovery.uses_consumed, 0);
        assert_eq!(after_recovery.remaining_calls, after_recovery.max_calls);
        assert!(load_typed::<PortableAuthorityGrantV3ConsumptionReceipt>(
            &state,
            &portable_authority_effect_consumption_receipt_key(
                &consume_after_recovery.consumption_id
            )
        )
        .expect("load post-recovery consumption")
        .is_none());
        assert!(
            load_typed::<PortableAuthorityEffectAdmissionReceiptV2Record>(
                &state,
                &portable_authority_effect_admission_receipt_v2_key(
                    &consume_after_recovery.consumption_id
                )
            )
            .expect("load post-recovery admission")
            .is_none()
        );

        let revoke =
            codec::to_bytes_canonical(&RevokePortableAuthorityGrantV3Params { grant_hash })
                .expect("revoke bytes");
        run_async(service.handle_service_call(
            &mut state,
            "revoke_portable_authority_grant_v3@v1",
            &revoke,
            ctx,
        ))
        .expect("revoke portable grant");
        run_async(service.handle_service_call(
            &mut state,
            "revoke_portable_authority_grant_v3@v1",
            &revoke,
            ctx,
        ))
        .expect("revocation replay is idempotent");
    });

    let effect_hash = ref_hash(
        &grant,
        "/request_commitment/authorization_subject/subject_hash",
    );
    let consume = ConsumePortableAuthorityGrantV3ForEffectParams {
        grant_hash,
        consumption_id: [0x93; 32],
        expected_audience: grant["audience"].as_str().unwrap().to_owned(),
        expected_holder_id: grant["holder_id"].as_str().unwrap().to_owned(),
        expected_holder_key_id: grant["holder_key_id"].as_str().unwrap().to_owned(),
        actual_effect_ref: grant
            .pointer("/request_commitment/authorization_subject/subject_ref")
            .and_then(Value::as_str)
            .unwrap()
            .to_owned(),
        actual_effect_hash: effect_hash,
        admission: admission_context(),
    };
    with_portable_ctx([7; 32], |ctx| {
        let error = run_async(service.handle_service_call(
            &mut state,
            "consume_portable_authority_grant_v3_for_effect@v1",
            &codec::to_bytes_canonical(&consume).expect("consume bytes"),
            ctx,
        ))
        .expect_err("revoked grant must not consume");
        assert!(error.to_string().contains("revoked"), "{error}");
    });
    let revoked: PortableAuthorityGrantV3State = load_typed(&state, &state_key)
        .expect("load state")
        .expect("portable state");
    assert_eq!(revoked.status, PortableAuthorityGrantV3Status::Revoked);
    assert_eq!(revoked.uses_consumed, 0);
    assert_eq!(revoked.remaining_calls, revoked.max_calls);
    assert!(load_typed::<PortableAuthorityGrantV3ConsumptionReceipt>(
        &state,
        &portable_authority_effect_consumption_receipt_key(&consume.consumption_id)
    )
    .expect("load receipt")
    .is_none());
}
