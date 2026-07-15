use super::*;
use crate::wallet_network::keys::{
    approval_authority_key, audit_key, principal_authority_binding_head_key,
    principal_authority_binding_key, principal_authority_latest_mutation_key,
    principal_authority_lookup_receipt_key, principal_authority_resolution_receipt_key,
    principal_authority_version_index_key, AUDIT_NEXT_SEQ_KEY, CONTROL_ROOT_KEY,
};
use crate::wallet_network::support::{hash_bytes, store_typed};
use ioi_api::services::BlockchainService;
use ioi_types::app::wallet_network::{
    IssuePrincipalAuthorityBindingParams, LookupPrincipalAuthorityBindingParams,
    LookupPrincipalAuthorityBindingReceipt, PrincipalAuthorityBindingCoordinates,
    PrincipalAuthorityBindingHeadV1, PrincipalAuthorityBindingProofV1,
    PrincipalAuthorityBindingStatementV1, PrincipalAuthorityBindingStatus, PrincipalAuthorityKind,
    PrincipalAuthorityResolutionReceipt, ResolvePrincipalAuthorityParams,
    RevokePrincipalAuthorityBindingParams, VaultAuditEvent, VaultAuditEventKind, VaultSurface,
    WalletClientRole, WalletClientState, WalletConfigureControlRootParams,
    WalletControlPlaneRootRecord, WalletRegisterClientParams, WalletRegisteredClientRecord,
    PRINCIPAL_AUTHORITY_BINDING_SCHEMA_VERSION,
};
use parity_scale_codec::Encode;

const NOW_MS: u64 = 1_750_000_000_000;

struct BindingRootSigner {
    keypair: Ed25519KeyPair,
    record: WalletControlPlaneRootRecord,
}

fn new_binding_root() -> BindingRootSigner {
    let keypair = Ed25519KeyPair::generate().expect("root keypair");
    let public_key = keypair.public_key().to_bytes();
    let account_id = account_id_from_key_material(SignatureSuite::ED25519, &public_key)
        .expect("root account id");
    BindingRootSigner {
        keypair,
        record: WalletControlPlaneRootRecord {
            account_id,
            signature_suite: SignatureSuite::ED25519,
            public_key,
            registered_at_ms: 0,
            updated_at_ms: 0,
            metadata: BTreeMap::new(),
        },
    }
}

fn call<T: Encode>(
    service: &WalletNetworkService,
    state: &mut MockState,
    signer: [u8; 32],
    method: &str,
    params: &T,
) -> Result<(), ioi_types::error::TransactionError> {
    let encoded = codec::to_bytes_canonical(params).expect("encode service params");
    let mut result = None;
    with_ctx_signer(signer, |ctx| {
        result = Some(run_async(
            service.handle_service_call(state, method, &encoded, ctx),
        ));
    });
    result.expect("service result")
}

fn configure_root(service: &WalletNetworkService, state: &mut MockState, root: &BindingRootSigner) {
    call(
        service,
        state,
        root.record.account_id,
        "configure_control_root@v1",
        &WalletConfigureControlRootParams {
            root: root.record.clone(),
        },
    )
    .expect("configure root");
}

fn register_authority(
    service: &WalletNetworkService,
    state: &mut MockState,
    root: &BindingRootSigner,
    authority: &ApprovalAuthority,
) {
    call(
        service,
        state,
        root.record.account_id,
        "register_approval_authority@v1",
        &RegisterApprovalAuthorityParams {
            authority: authority.clone(),
        },
    )
    .expect("register approval authority");
}

fn signed_binding(
    root: &BindingRootSigner,
    principal_ref: &str,
    authority: &ApprovalAuthority,
    status: PrincipalAuthorityBindingStatus,
    previous: Option<&PrincipalAuthorityBindingProofV1>,
) -> PrincipalAuthorityBindingProofV1 {
    let previous_coordinates = previous.map(PrincipalAuthorityBindingProofV1::coordinates);
    let statement = PrincipalAuthorityBindingStatementV1 {
        schema_version: PRINCIPAL_AUTHORITY_BINDING_SCHEMA_VERSION,
        principal_ref: principal_ref.to_string(),
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
        signed_at_ms: NOW_MS,
        expires_at_ms: Some(1_800_000_000_000),
        issuer_root_account_id: root.record.account_id,
        reason: Some(match status {
            PrincipalAuthorityBindingStatus::Active => "bind or rotate".to_string(),
            PrincipalAuthorityBindingStatus::Revoked => "explicit revocation".to_string(),
        }),
    };
    let message = statement.signing_bytes().expect("binding signing bytes");
    let signature = root
        .keypair
        .sign(&message)
        .expect("sign binding")
        .to_bytes();
    PrincipalAuthorityBindingProofV1::new(
        statement,
        SignatureProof {
            suite: SignatureSuite::ED25519,
            public_key: root.record.public_key.clone(),
            signature,
        },
    )
    .expect("build binding proof")
}

fn issue(
    service: &WalletNetworkService,
    state: &mut MockState,
    root: &BindingRootSigner,
    proof: &PrincipalAuthorityBindingProofV1,
) -> Result<(), ioi_types::error::TransactionError> {
    call(
        service,
        state,
        root.record.account_id,
        "issue_principal_authority_binding@v1",
        &IssuePrincipalAuthorityBindingParams {
            proof: proof.clone(),
        },
    )
}

fn resolve(
    service: &WalletNetworkService,
    state: &mut MockState,
    signer: [u8; 32],
    request_id: [u8; 32],
    principal_ref: &str,
    expected_coordinates: Option<PrincipalAuthorityBindingCoordinates>,
) -> Result<(), ioi_types::error::TransactionError> {
    call(
        service,
        state,
        signer,
        "resolve_principal_authority@v1",
        &ResolvePrincipalAuthorityParams {
            request_id,
            principal_ref: principal_ref.to_string(),
            authority_kind: PrincipalAuthorityKind::Approval,
            required_scope: "wallet_network.approval".to_string(),
            expected_coordinates,
        },
    )
}

#[test]
fn principal_authority_methods_fail_closed_without_initialized_root_or_correct_signer() {
    let service = WalletNetworkService;
    let mut state = MockState::default();
    let root = new_binding_root();
    let approver = new_approval_signer();
    let proof = signed_binding(
        &root,
        "domain://host.example",
        &approver.authority,
        PrincipalAuthorityBindingStatus::Active,
        None,
    );

    let no_root_issue = issue(&service, &mut state, &root, &proof)
        .expect_err("uninitialized wallet must reject issue");
    assert!(matches!(
        no_root_issue,
        ioi_types::error::TransactionError::UnauthorizedByCredentials
    ));
    let no_root_resolve = resolve(
        &service,
        &mut state,
        [0x91; 32],
        [0x01; 32],
        "domain://host.example",
        None,
    )
    .expect_err("uninitialized wallet must reject resolve");
    assert!(matches!(
        no_root_resolve,
        ioi_types::error::TransactionError::UnauthorizedByCredentials
    ));

    configure_root(&service, &mut state, &root);
    register_authority(&service, &mut state, &root, &approver.authority);
    let wrong_signer = call(
        &service,
        &mut state,
        [0x92; 32],
        "issue_principal_authority_binding@v1",
        &IssuePrincipalAuthorityBindingParams {
            proof: proof.clone(),
        },
    )
    .expect_err("non-root signer must reject issue");
    assert!(matches!(
        wrong_signer,
        ioi_types::error::TransactionError::UnauthorizedByCredentials
    ));
    assert!(load_proof_by_hash_for_test(&state, &proof.binding_hash).is_none());

    issue(&service, &mut state, &root, &proof).expect("root issue");
    let unregistered_reader = resolve(
        &service,
        &mut state,
        [0x93; 32],
        [0x02; 32],
        "domain://host.example",
        None,
    )
    .expect_err("unregistered reader must reject resolve");
    assert!(matches!(
        unregistered_reader,
        ioi_types::error::TransactionError::UnauthorizedByCredentials
    ));
}

#[test]
fn active_registered_capability_client_can_resolve_but_does_not_select_authority() {
    let service = WalletNetworkService;
    let mut state = MockState::default();
    let root = new_binding_root();
    let approver = new_approval_signer();
    configure_root(&service, &mut state, &root);
    register_authority(&service, &mut state, &root, &approver.authority);
    let proof = signed_binding(
        &root,
        "service://participant-a",
        &approver.authority,
        PrincipalAuthorityBindingStatus::Active,
        None,
    );
    issue(&service, &mut state, &root, &proof).expect("issue");

    let client_keypair = Ed25519KeyPair::generate().expect("client keypair");
    let client_public_key = client_keypair.public_key().to_bytes();
    let client_id = account_id_from_key_material(SignatureSuite::ED25519, &client_public_key)
        .expect("client id");
    call(
        &service,
        &mut state,
        root.record.account_id,
        "register_client@v1",
        &WalletRegisterClientParams {
            client: WalletRegisteredClientRecord {
                client_id,
                label: "resolver client".to_string(),
                surface: VaultSurface::Desktop,
                signature_suite: SignatureSuite::ED25519,
                public_key: client_public_key,
                role: WalletClientRole::Capability,
                state: WalletClientState::Active,
                registered_at_ms: 0,
                updated_at_ms: 0,
                expires_at_ms: Some(1_800_000_000_000),
                allowed_provider_families: Vec::new(),
                metadata: BTreeMap::new(),
            },
        },
    )
    .expect("register resolver client");

    resolve(
        &service,
        &mut state,
        client_id,
        [0x11; 32],
        "service://participant-a",
        Some(proof.coordinates()),
    )
    .expect("active capability client resolves");
    let receipt: PrincipalAuthorityResolutionReceipt = load_typed(
        &state,
        &principal_authority_resolution_receipt_key(&[0x11; 32]),
    )
    .expect("load receipt")
    .expect("resolution receipt");
    assert_eq!(
        receipt.resolution.authority_id,
        approver.authority.authority_id
    );
    assert_eq!(receipt.resolution.coordinates, proof.coordinates());
}

#[test]
fn binding_rotation_stale_cas_revocation_and_historical_get_are_fail_closed() {
    let service = WalletNetworkService;
    let mut state = MockState::default();
    let root = new_binding_root();
    let first_authority = new_approval_signer();
    let second_authority = new_approval_signer();
    configure_root(&service, &mut state, &root);
    register_authority(&service, &mut state, &root, &first_authority.authority);
    let first = signed_binding(
        &root,
        "domain://room-host",
        &first_authority.authority,
        PrincipalAuthorityBindingStatus::Active,
        None,
    );
    issue(&service, &mut state, &root, &first).expect("first binding");
    let first_key = principal_authority_binding_key(&first.binding_hash);
    let first_bytes = state
        .get(&first_key)
        .expect("read first")
        .expect("first proof bytes");

    register_authority(&service, &mut state, &root, &second_authority.authority);
    let second = signed_binding(
        &root,
        "domain://room-host",
        &second_authority.authority,
        PrincipalAuthorityBindingStatus::Active,
        Some(&first),
    );
    issue(&service, &mut state, &root, &second).expect("rotate binding");
    // Exact replay is idempotent and does not append a new version.
    issue(&service, &mut state, &root, &second).expect("exact replay");

    let stale = signed_binding(
        &root,
        "domain://room-host",
        &first_authority.authority,
        PrincipalAuthorityBindingStatus::Active,
        Some(&first),
    );
    let stale_error =
        issue(&service, &mut state, &root, &stale).expect_err("stale competing version must fail");
    assert!(stale_error.to_string().contains("cas_failed"));

    resolve(
        &service,
        &mut state,
        root.record.account_id,
        [0x21; 32],
        "domain://room-host",
        Some(first.coordinates()),
    )
    .expect_err("old exact coordinates must fail");
    resolve(
        &service,
        &mut state,
        root.record.account_id,
        [0x22; 32],
        "domain://room-host",
        Some(second.coordinates()),
    )
    .expect("current coordinates resolve");
    let resolution_receipt: PrincipalAuthorityResolutionReceipt = load_typed(
        &state,
        &principal_authority_resolution_receipt_key(&[0x22; 32]),
    )
    .expect("load resolution receipt")
    .expect("resolution receipt");
    assert_eq!(
        resolution_receipt.resolution.required_scope,
        "wallet_network.approval"
    );
    assert_eq!(
        resolution_receipt.resolution.matched_scope,
        "wallet_network.approval"
    );
    assert_eq!(
        resolution_receipt.resolution.approval_authority,
        second_authority.authority
    );

    let revoked = signed_binding(
        &root,
        "domain://room-host",
        &second_authority.authority,
        PrincipalAuthorityBindingStatus::Revoked,
        Some(&second),
    );
    let predecessor_mismatch = call(
        &service,
        &mut state,
        root.record.account_id,
        "revoke_principal_authority_binding@v1",
        &RevokePrincipalAuthorityBindingParams {
            predecessor_binding_ref: first.binding_ref.clone(),
            proof: revoked.clone(),
        },
    )
    .expect_err("request predecessor must exactly agree with the proof");
    assert!(predecessor_mismatch
        .to_string()
        .contains("binding_predecessor_mismatch"));
    call(
        &service,
        &mut state,
        root.record.account_id,
        "revoke_principal_authority_binding@v1",
        &RevokePrincipalAuthorityBindingParams {
            predecessor_binding_ref: second.binding_ref.clone(),
            proof: revoked.clone(),
        },
    )
    .expect("append revocation");
    let revoked_resolution = resolve(
        &service,
        &mut state,
        root.record.account_id,
        [0x23; 32],
        "domain://room-host",
        None,
    )
    .expect_err("revoked current head must not resolve");
    assert!(revoked_resolution.to_string().contains("binding_revoked"));

    call(
        &service,
        &mut state,
        root.record.account_id,
        "lookup_principal_authority_binding@v1",
        &LookupPrincipalAuthorityBindingParams {
            request_id: [0x24; 32],
            binding_ref: first.binding_ref.clone(),
            expected_binding_hash: Some(first.binding_hash),
        },
    )
    .expect("historical proof remains readable");
    let get_receipt: LookupPrincipalAuthorityBindingReceipt =
        load_typed(&state, &principal_authority_lookup_receipt_key(&[0x24; 32]))
            .expect("load lookup receipt")
            .expect("lookup receipt");
    assert_eq!(get_receipt.proof, first);
    assert_eq!(
        state.get(&first_key).expect("read first after lifecycle"),
        Some(first_bytes),
        "rotation and revocation must never rewrite historical proof bytes"
    );

    let principal_hash = hash_bytes(b"domain://room-host").expect("principal hash");
    let head: PrincipalAuthorityBindingHeadV1 = load_typed(
        &state,
        &principal_authority_binding_head_key(&principal_hash),
    )
    .expect("load head")
    .expect("head");
    assert_eq!(head.coordinates, revoked.coordinates());
    assert_eq!(head.status, PrincipalAuthorityBindingStatus::Revoked);
    assert!(state
        .get(&principal_authority_version_index_key(&principal_hash, 3))
        .expect("read immutable revocation index")
        .is_some());
}

#[test]
fn resolution_is_operation_scoped_and_refuses_empty_or_foreign_scope() {
    let service = WalletNetworkService;
    let mut state = MockState::default();
    let root = new_binding_root();
    let mut approver = new_approval_signer();
    approver.authority.scope_allowlist.clear();
    configure_root(&service, &mut state, &root);
    register_authority(&service, &mut state, &root, &approver.authority);
    let proof = signed_binding(
        &root,
        "service://scope-denied",
        &approver.authority,
        PrincipalAuthorityBindingStatus::Active,
        None,
    );
    issue(&service, &mut state, &root, &proof).expect("scope-empty authority may be bound");

    let empty_scope_error = resolve(
        &service,
        &mut state,
        root.record.account_id,
        [0x25; 32],
        "service://scope-denied",
        Some(proof.coordinates()),
    )
    .expect_err("an empty scope allowlist authorizes no operation");
    assert!(empty_scope_error
        .to_string()
        .contains("principal_authority_scope_denied"));

    let mut scoped_approver = new_approval_signer();
    scoped_approver.authority.scope_allowlist = vec!["room_participation.admit".to_string()];
    register_authority(&service, &mut state, &root, &scoped_approver.authority);
    let scoped = signed_binding(
        &root,
        "service://scope-bound",
        &scoped_approver.authority,
        PrincipalAuthorityBindingStatus::Active,
        None,
    );
    issue(&service, &mut state, &root, &scoped).expect("scope-bound authority");
    let foreign_scope_error = call(
        &service,
        &mut state,
        root.record.account_id,
        "resolve_principal_authority@v1",
        &ResolvePrincipalAuthorityParams {
            request_id: [0x26; 32],
            principal_ref: "service://scope-bound".to_string(),
            authority_kind: PrincipalAuthorityKind::Approval,
            required_scope: "room_participation.reject".to_string(),
            expected_coordinates: Some(scoped.coordinates()),
        },
    )
    .expect_err("foreign operation scope must not resolve");
    assert!(foreign_scope_error
        .to_string()
        .contains("principal_authority_scope_denied"));

    let wildcard_request_error = call(
        &service,
        &mut state,
        root.record.account_id,
        "resolve_principal_authority@v1",
        &ResolvePrincipalAuthorityParams {
            request_id: [0x27; 32],
            principal_ref: "service://scope-bound".to_string(),
            authority_kind: PrincipalAuthorityKind::Approval,
            required_scope: "*".to_string(),
            expected_coordinates: Some(scoped.coordinates()),
        },
    )
    .expect_err("required_scope must name an exact operation, not a wildcard");
    assert!(wildcard_request_error
        .to_string()
        .contains("required_scope_invalid"));
}

#[test]
fn resolution_revalidates_authority_drift_revocation_and_expiry() {
    let service = WalletNetworkService;
    let mut state = MockState::default();
    let root = new_binding_root();
    let approver = new_approval_signer();
    configure_root(&service, &mut state, &root);
    register_authority(&service, &mut state, &root, &approver.authority);
    let proof = signed_binding(
        &root,
        "org://alloy-lab",
        &approver.authority,
        PrincipalAuthorityBindingStatus::Active,
        None,
    );
    issue(&service, &mut state, &root, &proof).expect("issue binding");
    let authority_key = approval_authority_key(&approver.authority.authority_id);

    let mut drifted = approver.authority.clone();
    drifted.scope_allowlist.push("unexpected.scope".to_string());
    store_typed(&mut state, &authority_key, &drifted).expect("store drifted authority");
    let drift_error = resolve(
        &service,
        &mut state,
        root.record.account_id,
        [0x31; 32],
        "org://alloy-lab",
        None,
    )
    .expect_err("authority drift must fail");
    assert!(drift_error.to_string().contains("authority_drifted"));

    let mut revoked = approver.authority.clone();
    revoked.revoked = true;
    store_typed(&mut state, &authority_key, &revoked).expect("store revoked authority");
    let revoke_error = resolve(
        &service,
        &mut state,
        root.record.account_id,
        [0x32; 32],
        "org://alloy-lab",
        None,
    )
    .expect_err("revoked authority must fail");
    assert!(revoke_error.to_string().contains("authority_revoked"));

    let mut expired = approver.authority.clone();
    expired.expires_at = NOW_MS - 1;
    store_typed(&mut state, &authority_key, &expired).expect("store expired authority");
    let expiry_error = resolve(
        &service,
        &mut state,
        root.record.account_id,
        [0x33; 32],
        "org://alloy-lab",
        None,
    )
    .expect_err("expired authority must fail");
    assert!(expiry_error.to_string().contains("authority_expired"));

    for request_id in [[0x31; 32], [0x32; 32], [0x33; 32]] {
        assert!(state
            .get(&principal_authority_resolution_receipt_key(&request_id))
            .expect("read receipt slot")
            .is_none());
    }
}

#[test]
fn successor_append_validates_current_head_and_permits_explicit_repair_rotation() {
    let service = WalletNetworkService;
    let mut state = MockState::default();
    let root = new_binding_root();
    let foreign_root = new_binding_root();
    let first_authority = new_approval_signer();
    let replacement_authority = new_approval_signer();
    configure_root(&service, &mut state, &root);
    register_authority(&service, &mut state, &root, &first_authority.authority);
    register_authority(
        &service,
        &mut state,
        &root,
        &replacement_authority.authority,
    );

    let first = signed_binding(
        &root,
        "domain://repairable-host",
        &first_authority.authority,
        PrincipalAuthorityBindingStatus::Active,
        None,
    );
    issue(&service, &mut state, &root, &first).expect("initial binding");
    let replacement = signed_binding(
        &root,
        "domain://repairable-host",
        &replacement_authority.authority,
        PrincipalAuthorityBindingStatus::Active,
        Some(&first),
    );
    let first_key = principal_authority_binding_key(&first.binding_hash);
    let principal_hash = hash_bytes(b"domain://repairable-host").expect("principal hash");
    let head_key = principal_authority_binding_head_key(&principal_hash);
    let original_head: PrincipalAuthorityBindingHeadV1 = load_typed(&state, &head_key)
        .expect("load head")
        .expect("head");

    ioi_api::state::StateAccess::delete(&mut state, &first_key).expect("delete predecessor");
    let missing_error = issue(&service, &mut state, &root, &replacement)
        .expect_err("head with missing proof must refuse advancement");
    assert!(missing_error.to_string().contains("proof_missing"));
    assert!(load_proof_by_hash_for_test(&state, &replacement.binding_hash).is_none());
    store_typed(&mut state, &first_key, &first).expect("restore predecessor");

    let mut zero_mutation_head = original_head.clone();
    zero_mutation_head.mutation_audit_event_id = [0u8; 32];
    store_typed(&mut state, &head_key, &zero_mutation_head).expect("store malformed head");
    let zero_mutation_error = issue(&service, &mut state, &root, &replacement)
        .expect_err("head without mutation evidence must refuse advancement");
    assert!(zero_mutation_error
        .to_string()
        .contains("head_audit_invalid"));

    let audit_event_key = audit_key(original_head.mutation_audit_seq);
    let original_audit_event: VaultAuditEvent = load_typed(&state, &audit_event_key)
        .expect("load mutation audit")
        .expect("mutation audit");
    let mut tampered_audit_event = original_audit_event.clone();
    tampered_audit_event.metadata.insert(
        "binding_ref".to_string(),
        "wallet.network://principal-authority-binding/tampered".to_string(),
    );
    store_typed(&mut state, &audit_event_key, &tampered_audit_event)
        .expect("store tampered mutation event");
    store_typed(&mut state, &head_key, &original_head).expect("restore head");
    let audit_error = issue(&service, &mut state, &root, &replacement)
        .expect_err("tampered mutation audit must refuse advancement");
    assert!(audit_error.to_string().contains("head_audit_invalid"));
    store_typed(&mut state, &audit_event_key, &original_audit_event)
        .expect("restore mutation audit");

    let mut relocated_head = original_head.clone();
    relocated_head.coordinates.binding_ref = format!(
        "wallet.network://principal-authority-binding/{}",
        "00".repeat(32)
    );
    store_typed(&mut state, &head_key, &relocated_head).expect("store relocated head");
    let relocated_error = issue(&service, &mut state, &root, &replacement)
        .expect_err("head ref/hash disagreement must refuse advancement");
    assert!(relocated_error.to_string().contains("coordinates_invalid"));

    // Restore the authentic immutable head, then prove repair does not depend
    // on the old mutable authority remaining active.
    store_typed(&mut state, &head_key, &original_head).expect("restore authentic head");
    let mut revoked_old_authority = first_authority.authority.clone();
    revoked_old_authority.revoked = true;
    store_typed(
        &mut state,
        &approval_authority_key(&revoked_old_authority.authority_id),
        &revoked_old_authority,
    )
    .expect("revoke old mutable authority");
    issue(&service, &mut state, &root, &replacement)
        .expect("root may rotate to a valid replacement over authentic immutable history");

    // A historically well-formed head from a different wallet root still
    // cannot be adopted after the configured-root record changes.
    let mut foreign_state = MockState::default();
    configure_root(&service, &mut foreign_state, &foreign_root);
    register_authority(
        &service,
        &mut foreign_state,
        &foreign_root,
        &first_authority.authority,
    );
    let foreign_first = signed_binding(
        &foreign_root,
        "domain://foreign-history",
        &first_authority.authority,
        PrincipalAuthorityBindingStatus::Active,
        None,
    );
    issue(&service, &mut foreign_state, &foreign_root, &foreign_first)
        .expect("foreign-root history is internally authentic before root changes");
    store_typed(&mut foreign_state, CONTROL_ROOT_KEY, &root.record)
        .expect("install a different configured root");
    register_authority(
        &service,
        &mut foreign_state,
        &root,
        &replacement_authority.authority,
    );
    let foreign_successor = signed_binding(
        &root,
        "domain://foreign-history",
        &replacement_authority.authority,
        PrincipalAuthorityBindingStatus::Active,
        Some(&foreign_first),
    );
    let foreign_error = issue(&service, &mut foreign_state, &root, &foreign_successor)
        .expect_err("foreign-root predecessor must refuse advancement");
    assert!(foreign_error.to_string().contains("root_mismatch"));
}

#[test]
fn resolution_and_successor_append_verify_the_complete_immutable_chain() {
    let service = WalletNetworkService;
    let mut state = MockState::default();
    let root = new_binding_root();
    let first_authority = new_approval_signer();
    let second_authority = new_approval_signer();
    let third_authority = new_approval_signer();
    configure_root(&service, &mut state, &root);
    register_authority(&service, &mut state, &root, &first_authority.authority);
    register_authority(&service, &mut state, &root, &second_authority.authority);
    register_authority(&service, &mut state, &root, &third_authority.authority);

    let first = signed_binding(
        &root,
        "service://chain-verifier",
        &first_authority.authority,
        PrincipalAuthorityBindingStatus::Active,
        None,
    );
    let second = signed_binding(
        &root,
        "service://chain-verifier",
        &second_authority.authority,
        PrincipalAuthorityBindingStatus::Active,
        Some(&first),
    );
    let third = signed_binding(
        &root,
        "service://chain-verifier",
        &third_authority.authority,
        PrincipalAuthorityBindingStatus::Active,
        Some(&second),
    );
    issue(&service, &mut state, &root, &first).expect("first");
    issue(&service, &mut state, &root, &second).expect("second");

    let first_key = principal_authority_binding_key(&first.binding_hash);
    ioi_api::state::StateAccess::delete(&mut state, &first_key).expect("delete v1");
    let missing_resolution = resolve(
        &service,
        &mut state,
        root.record.account_id,
        [0x41; 32],
        "service://chain-verifier",
        Some(second.coordinates()),
    )
    .expect_err("valid head with missing predecessor must not resolve");
    assert!(missing_resolution.to_string().contains("chain_missing"));
    let missing_append = issue(&service, &mut state, &root, &third)
        .expect_err("valid head with missing predecessor must not advance");
    assert!(missing_append.to_string().contains("chain_missing"));

    let mut tampered_first = first.clone();
    tampered_first.statement.reason = Some("tampered history".to_string());
    store_typed(&mut state, &first_key, &tampered_first).expect("store tampered predecessor");
    let tampered_resolution = resolve(
        &service,
        &mut state,
        root.record.account_id,
        [0x42; 32],
        "service://chain-verifier",
        Some(second.coordinates()),
    )
    .expect_err("tampered predecessor must not resolve");
    assert!(tampered_resolution.to_string().contains("proof_invalid"));

    store_typed(&mut state, &first_key, &first).expect("restore v1");
    resolve(
        &service,
        &mut state,
        root.record.account_id,
        [0x43; 32],
        "service://chain-verifier",
        Some(second.coordinates()),
    )
    .expect("complete authentic chain resolves");
}

#[test]
fn latest_mutation_commitment_refuses_old_missing_malformed_and_relocated_heads() {
    let service = WalletNetworkService;
    let mut state = MockState::default();
    let root = new_binding_root();
    let first_authority = new_approval_signer();
    let second_authority = new_approval_signer();
    configure_root(&service, &mut state, &root);
    register_authority(&service, &mut state, &root, &first_authority.authority);
    register_authority(&service, &mut state, &root, &second_authority.authority);

    let principal_ref = "domain://rollback-resistant";
    let first = signed_binding(
        &root,
        principal_ref,
        &first_authority.authority,
        PrincipalAuthorityBindingStatus::Active,
        None,
    );
    issue(&service, &mut state, &root, &first).expect("first");
    let principal_hash = hash_bytes(principal_ref.as_bytes()).expect("principal hash");
    let head_key = principal_authority_binding_head_key(&principal_hash);
    let first_head: PrincipalAuthorityBindingHeadV1 = load_typed(&state, &head_key)
        .expect("load v1 head")
        .expect("v1 head");
    let latest_mutation_key = principal_authority_latest_mutation_key(&principal_hash);
    let first_latest_mutation_bytes = state
        .get(&latest_mutation_key)
        .expect("read v1 latest mutation")
        .expect("v1 latest mutation");

    let second = signed_binding(
        &root,
        principal_ref,
        &second_authority.authority,
        PrincipalAuthorityBindingStatus::Active,
        Some(&first),
    );
    issue(&service, &mut state, &root, &second).expect("second");
    let second_head: PrincipalAuthorityBindingHeadV1 = load_typed(&state, &head_key)
        .expect("load v2 head")
        .expect("v2 head");
    let latest_mutation_bytes = state
        .get(&latest_mutation_key)
        .expect("read latest mutation")
        .expect("latest mutation");

    store_typed(&mut state, &head_key, &first_head).expect("restore authentic v1 head");
    ioi_api::state::StateAccess::insert(
        &mut state,
        &latest_mutation_key,
        &first_latest_mutation_bytes,
    )
    .expect("restore authentic v1 latest mutation");
    let coupled_rollback_error = resolve(
        &service,
        &mut state,
        root.record.account_id,
        [0x44; 32],
        principal_ref,
        None,
    )
    .expect_err("restoring both authentic mutable v1 records must still fail closed");
    assert!(coupled_rollback_error
        .to_string()
        .contains("binding_head_rolled_back"));
    assert!(state
        .get(&principal_authority_resolution_receipt_key(&[0x44; 32]))
        .expect("read coupled rollback receipt")
        .is_none());
    store_typed(&mut state, &head_key, &second_head).expect("restore current v2 head");
    ioi_api::state::StateAccess::insert(&mut state, &latest_mutation_key, &latest_mutation_bytes)
        .expect("restore current latest mutation");
    let second_index_key = principal_authority_version_index_key(&principal_hash, 2);
    let second_index_bytes = state
        .get(&second_index_key)
        .expect("read v2 index")
        .expect("v2 index");
    ioi_api::state::StateAccess::insert(&mut state, &second_index_key, &[0xff, 0x00])
        .expect("store malformed v2 index");
    let malformed_index_error = resolve(
        &service,
        &mut state,
        root.record.account_id,
        [0x4c; 32],
        principal_ref,
        Some(second.coordinates()),
    )
    .expect_err("malformed immutable index must fail closed");
    assert!(malformed_index_error
        .to_string()
        .contains("version_index_malformed"));
    ioi_api::state::StateAccess::insert(&mut state, &second_index_key, &second_index_bytes)
        .expect("restore v2 index");

    ioi_api::state::StateAccess::delete(&mut state, &head_key).expect("delete current head");
    let orphaned_commitment_error = resolve(
        &service,
        &mut state,
        root.record.account_id,
        [0x45; 32],
        principal_ref,
        None,
    )
    .expect_err("surviving commitment must make a vanished head unreadable");
    assert!(orphaned_commitment_error
        .to_string()
        .contains("latest_mutation_orphaned"));

    ioi_api::state::StateAccess::insert(&mut state, &head_key, &[0xff, 0x00])
        .expect("store malformed head");
    let malformed_head_error = resolve(
        &service,
        &mut state,
        root.record.account_id,
        [0x46; 32],
        principal_ref,
        None,
    )
    .expect_err("surviving commitment must not hide an unreadable head");
    assert!(malformed_head_error
        .to_string()
        .contains("binding_head_malformed"));
    store_typed(&mut state, &head_key, &second_head).expect("restore current v2 head");

    store_typed(&mut state, &head_key, &first_head).expect("restore authentic v1 head");
    let rollback_error = resolve(
        &service,
        &mut state,
        root.record.account_id,
        [0x47; 32],
        principal_ref,
        None,
    )
    .expect_err("un-pinned resolution must not accept a restored old head");
    assert!(rollback_error
        .to_string()
        .contains("latest_mutation_mismatch"));
    assert!(state
        .get(&principal_authority_resolution_receipt_key(&[0x47; 32]))
        .expect("read rollback receipt")
        .is_none());

    store_typed(&mut state, &head_key, &second_head).expect("restore current v2 head");
    ioi_api::state::StateAccess::delete(&mut state, &latest_mutation_key)
        .expect("delete latest-mutation commitment");
    let missing_commitment_error = resolve(
        &service,
        &mut state,
        root.record.account_id,
        [0x48; 32],
        principal_ref,
        Some(second.coordinates()),
    )
    .expect_err("missing latest-mutation commitment must fail closed");
    assert!(missing_commitment_error
        .to_string()
        .contains("latest_mutation_missing"));

    ioi_api::state::StateAccess::insert(&mut state, &latest_mutation_key, &[0xff, 0x00])
        .expect("store malformed latest-mutation commitment");
    let malformed_commitment_error = resolve(
        &service,
        &mut state,
        root.record.account_id,
        [0x49; 32],
        principal_ref,
        Some(second.coordinates()),
    )
    .expect_err("malformed latest-mutation commitment must fail closed");
    assert!(malformed_commitment_error
        .to_string()
        .contains("latest_mutation_malformed"));

    ioi_api::state::StateAccess::insert(&mut state, &latest_mutation_key, &latest_mutation_bytes)
        .expect("restore latest-mutation commitment");
    let other_principal = "domain://relocated-marker-source";
    let other = signed_binding(
        &root,
        other_principal,
        &second_authority.authority,
        PrincipalAuthorityBindingStatus::Active,
        None,
    );
    issue(&service, &mut state, &root, &other).expect("issue other principal");
    let other_principal_hash =
        hash_bytes(other_principal.as_bytes()).expect("other principal hash");
    let other_commitment_bytes = state
        .get(&principal_authority_latest_mutation_key(
            &other_principal_hash,
        ))
        .expect("read other commitment")
        .expect("other commitment");
    ioi_api::state::StateAccess::insert(&mut state, &latest_mutation_key, &other_commitment_bytes)
        .expect("relocate another principal commitment");
    let relocated_commitment_error = resolve(
        &service,
        &mut state,
        root.record.account_id,
        [0x4a; 32],
        principal_ref,
        Some(second.coordinates()),
    )
    .expect_err("relocated latest-mutation commitment must fail closed");
    assert!(relocated_commitment_error
        .to_string()
        .contains("latest_mutation_relocated"));

    ioi_api::state::StateAccess::insert(&mut state, &latest_mutation_key, &latest_mutation_bytes)
        .expect("restore current commitment");
    resolve(
        &service,
        &mut state,
        root.record.account_id,
        [0x4b; 32],
        principal_ref,
        Some(second.coordinates()),
    )
    .expect("current head resolves after the exact commitment is restored");
}

#[test]
fn lookup_request_ids_are_no_clobber_and_historical_get_is_audited_atomically() {
    let service = WalletNetworkService;
    let mut state = MockState::default();
    let root = new_binding_root();
    let approver = new_approval_signer();
    configure_root(&service, &mut state, &root);
    register_authority(&service, &mut state, &root, &approver.authority);
    let proof = signed_binding(
        &root,
        "worker://receipt-owner",
        &approver.authority,
        PrincipalAuthorityBindingStatus::Active,
        None,
    );
    issue(&service, &mut state, &root, &proof).expect("issue");

    let resolve_request_id = [0x51; 32];
    resolve(
        &service,
        &mut state,
        root.record.account_id,
        resolve_request_id,
        "worker://receipt-owner",
        Some(proof.coordinates()),
    )
    .expect("first resolution");
    let resolution_key = principal_authority_resolution_receipt_key(&resolve_request_id);
    let resolution_bytes = state
        .get(&resolution_key)
        .expect("read resolution")
        .expect("resolution receipt");
    let seq_after_resolution: u64 = load_typed(&state, AUDIT_NEXT_SEQ_KEY)
        .expect("load audit seq")
        .expect("audit seq");
    let resolution_replay = resolve(
        &service,
        &mut state,
        root.record.account_id,
        resolve_request_id,
        "worker://receipt-owner",
        None,
    )
    .expect_err("resolution request id must be single use");
    assert!(resolution_replay.to_string().contains("request_id_replay"));
    assert_eq!(state.get(&resolution_key).unwrap(), Some(resolution_bytes));
    assert_eq!(
        load_typed::<u64>(&state, AUDIT_NEXT_SEQ_KEY).unwrap(),
        Some(seq_after_resolution),
        "replay must not append audit evidence"
    );

    let get_request_id = [0x52; 32];
    let seq_before_get: u64 = load_typed(&state, AUDIT_NEXT_SEQ_KEY)
        .expect("load audit seq")
        .expect("audit seq");
    let get_params = LookupPrincipalAuthorityBindingParams {
        request_id: get_request_id,
        binding_ref: proof.binding_ref.clone(),
        expected_binding_hash: Some(proof.binding_hash),
    };
    call(
        &service,
        &mut state,
        root.record.account_id,
        "lookup_principal_authority_binding@v1",
        &get_params,
    )
    .expect("first historical get");
    let get_key = principal_authority_lookup_receipt_key(&get_request_id);
    let get_bytes = state.get(&get_key).expect("read get").expect("get receipt");
    let get_event: VaultAuditEvent = load_typed(&state, &audit_key(seq_before_get))
        .expect("load get audit event")
        .expect("get audit event");
    assert_eq!(
        get_event.kind,
        VaultAuditEventKind::PrincipalAuthorityBindingFetched
    );
    assert_eq!(
        load_typed::<u64>(&state, AUDIT_NEXT_SEQ_KEY).unwrap(),
        Some(seq_before_get + 1)
    );
    let get_replay = call(
        &service,
        &mut state,
        root.record.account_id,
        "lookup_principal_authority_binding@v1",
        &get_params,
    )
    .expect_err("get request id must be single use");
    assert!(get_replay.to_string().contains("request_id_replay"));
    assert_eq!(state.get(&get_key).unwrap(), Some(get_bytes));
    assert_eq!(
        load_typed::<u64>(&state, AUDIT_NEXT_SEQ_KEY).unwrap(),
        Some(seq_before_get + 1),
        "get replay must not append audit evidence"
    );
}

#[test]
fn hybrid_wallet_root_signature_is_cryptographically_verified() {
    let service = WalletNetworkService;
    let mut state = MockState::default();
    let hybrid = new_hybrid_signer();
    let mut hybrid_public_key = hybrid.ed25519.public_key().to_bytes();
    hybrid_public_key.extend_from_slice(&hybrid.mldsa.public_key().to_bytes());
    let root = WalletControlPlaneRootRecord {
        account_id: hybrid.signer_id,
        signature_suite: SignatureSuite::HYBRID_ED25519_ML_DSA_44,
        public_key: hybrid_public_key.clone(),
        registered_at_ms: 0,
        updated_at_ms: 0,
        metadata: BTreeMap::new(),
    };
    call(
        &service,
        &mut state,
        hybrid.signer_id,
        "configure_control_root@v1",
        &WalletConfigureControlRootParams { root: root.clone() },
    )
    .expect("configure hybrid root");
    let approver = new_approval_signer();
    call(
        &service,
        &mut state,
        hybrid.signer_id,
        "register_approval_authority@v1",
        &RegisterApprovalAuthorityParams {
            authority: approver.authority.clone(),
        },
    )
    .expect("register authority");

    let statement = PrincipalAuthorityBindingStatementV1 {
        schema_version: PRINCIPAL_AUTHORITY_BINDING_SCHEMA_VERSION,
        principal_ref: "agentgres://domain/hybrid-host".to_string(),
        authority_kind: PrincipalAuthorityKind::Approval,
        binding_version: 1,
        status: PrincipalAuthorityBindingStatus::Active,
        authority_id: approver.authority.authority_id,
        authority_public_key: approver.authority.public_key.clone(),
        authority_signature_suite: approver.authority.signature_suite,
        approval_authority_snapshot_hash: approver
            .authority
            .artifact_hash()
            .expect("authority hash"),
        previous_binding_ref: None,
        previous_binding_hash: None,
        signed_at_ms: NOW_MS,
        expires_at_ms: Some(1_800_000_000_000),
        issuer_root_account_id: hybrid.signer_id,
        reason: Some("hybrid-root issuance".to_string()),
    };
    let message = statement.signing_bytes().expect("signing bytes");
    let hybrid_signature_proof: SignatureProof =
        codec::from_bytes_canonical(&sign_hybrid_payload(&hybrid, &message))
            .expect("decode hybrid signature proof");
    let proof = PrincipalAuthorityBindingProofV1::new(statement, hybrid_signature_proof)
        .expect("hybrid binding proof");
    call(
        &service,
        &mut state,
        hybrid.signer_id,
        "issue_principal_authority_binding@v1",
        &IssuePrincipalAuthorityBindingParams {
            proof: proof.clone(),
        },
    )
    .expect("hybrid root proof verifies");
    resolve(
        &service,
        &mut state,
        hybrid.signer_id,
        [0x61; 32],
        "agentgres://domain/hybrid-host",
        Some(proof.coordinates()),
    )
    .expect("hybrid-root binding resolves");
}

#[test]
fn root_signature_and_content_address_are_verified_not_trusted_on_first_use() {
    let service = WalletNetworkService;
    let mut state = MockState::default();
    let root = new_binding_root();
    let foreign_root = new_binding_root();
    let approver = new_approval_signer();
    configure_root(&service, &mut state, &root);
    register_authority(&service, &mut state, &root, &approver.authority);

    let foreign = signed_binding(
        &foreign_root,
        "worker://foreign-signer",
        &approver.authority,
        PrincipalAuthorityBindingStatus::Active,
        None,
    );
    let foreign_error = call(
        &service,
        &mut state,
        root.record.account_id,
        "issue_principal_authority_binding@v1",
        &IssuePrincipalAuthorityBindingParams { proof: foreign },
    )
    .expect_err("foreign embedded root must fail even under a root-signed transaction");
    assert!(foreign_error.to_string().contains("root_mismatch"));

    let mut tampered = signed_binding(
        &root,
        "worker://bound-signer",
        &approver.authority,
        PrincipalAuthorityBindingStatus::Active,
        None,
    );
    tampered.binding_ref = format!(
        "wallet.network://principal-authority-binding/{}",
        "00".repeat(32)
    );
    let tamper_error = issue(&service, &mut state, &root, &tampered)
        .expect_err("tampered content address must fail");
    assert!(tamper_error.to_string().contains("proof_invalid"));
}

fn load_proof_by_hash_for_test(
    state: &MockState,
    binding_hash: &[u8; 32],
) -> Option<PrincipalAuthorityBindingProofV1> {
    load_typed(state, &principal_authority_binding_key(binding_hash)).expect("load proof")
}
