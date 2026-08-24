use super::*;
use crate::wallet_network::keys::registered_client_key;
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
) -> ExpectedPrincipalAuthorityBinding {
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
            public_key: root.public_key,
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
    ExpectedPrincipalAuthorityBinding {
        principal_ref: principal_ref.to_owned(),
        required_scope: PORTABLE_SCOPE.to_owned(),
        coordinates: proof.coordinates(),
        approval_authority_snapshot_hash: proof.statement.approval_authority_snapshot_hash,
        approval_authority: authority,
    }
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
    let binding = install_portable_issuer(
        &service,
        &mut state,
        "org://wallet-network/portable-issuer",
        public_key,
    );
    let record = record_params(
        &request, &context, &review, &grant, &key_set, &snapshot, binding,
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
    };
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
        assert!(error.to_string().contains("exhausted"), "{error}");

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
            error.to_string().contains("bound to a different grant"),
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
    let binding = install_portable_issuer(
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
