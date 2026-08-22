use super::handlers::channel::hash_channel_envelope;
use super::keys::{
    approval_consumption_key, approval_effect_consumption_receipt_key, approval_grant_state_key,
    approval_key, channel_key, channel_key_state_key, connector_auth_export_receipt_key,
    connector_auth_get_receipt_key, connector_auth_import_receipt_key, connector_auth_key,
    connector_auth_list_receipt_key, injection_grant_key, lease_consumption_key,
    lease_counter_window_key, lease_key, lease_replay_key, mail_connector_binding_receipt_key,
    mail_connector_get_receipt_key, mail_connector_key, mail_count_receipt_key,
    mail_delete_receipt_key, mail_list_receipt_key, mail_read_receipt_key, mail_reply_receipt_key,
    policy_key, receipt_window_key, secret_alias_key, secret_key, session_delegation_key,
    session_key, standing_approval_consumption_receipt_key, standing_approval_grant_state_key,
    standing_approval_settlement_receipt_key, PANIC_FLAG_KEY, REVOCATION_EPOCH_KEY,
};
use super::support::load_typed;
use super::*;
use dcrypt::algorithms::hash::{HashFunction, Sha256};
use ioi_api::crypto::{SerializableKey, SigningKeyPair};
use ioi_api::services::access::ServiceDirectory;
use ioi_api::state::StateScanIter;
use ioi_api::transaction::context::TxContext;
use ioi_crypto::security::SecurityLevel;
use ioi_crypto::sign::dilithium::{MldsaKeyPair, MldsaScheme};
use ioi_crypto::sign::eddsa::Ed25519KeyPair;
use ioi_types::app::action::{ApprovalAuthority, ApprovalGrant, StandingApprovalGrant};
use ioi_types::app::wallet_network::{
    ConnectorAuthExportParams, ConnectorAuthExportReceipt, ConnectorAuthGetParams,
    ConnectorAuthGetReceipt, ConnectorAuthImportParams, ConnectorAuthImportReceipt,
    ConnectorAuthListParams, ConnectorAuthListReceipt, ConnectorAuthProtocol, ConnectorAuthRecord,
    ConnectorAuthState, ConnectorAuthUpsertParams, GuardianAttestation, MailConnectorAuthMode,
    MailConnectorConfig, MailConnectorEndpoint, MailConnectorEnsureBindingParams,
    MailConnectorEnsureBindingReceipt, MailConnectorGetParams, MailConnectorGetReceipt,
    MailConnectorProvider, MailConnectorRecord, MailConnectorSecretAliases, MailConnectorTlsMode,
    MailConnectorUpsertParams, MailDeleteSpamParams, MailDeleteSpamReceipt, MailListRecentParams,
    MailListRecentReceipt, MailReadLatestParams, MailReadLatestReceipt, MailReplyParams,
    MailReplyReceipt, MailboxTotalCountParams, MailboxTotalCountReceipt, SecretInjectionGrant,
    SecretInjectionRequest, SecretInjectionRequestRecord, SessionChannelKeyState,
    SessionChannelOpenAck, SessionChannelOpenConfirm, SessionChannelOpenInit,
    SessionChannelOpenTry, SessionChannelRecord, SessionChannelState, SessionGrant, SessionLease,
    SessionLeaseMode, VaultPolicyRule, VaultSecretRecord, WalletApprovalDecision,
    WalletInterceptionContext,
};
use ioi_types::app::{
    account_id_from_key_material, AccountId, ActionTarget, ChainId, SignatureProof, SignatureSuite,
};
use ioi_types::error::StateError;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Arc;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

#[derive(Default)]
struct MockState {
    data: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl ioi_api::state::StateAccess for MockState {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
        Ok(self.data.get(key).cloned())
    }

    fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
        self.data.insert(key.to_vec(), value.to_vec());
        Ok(())
    }

    fn delete(&mut self, key: &[u8]) -> Result<(), StateError> {
        self.data.remove(key);
        Ok(())
    }

    fn batch_set(&mut self, updates: &[(Vec<u8>, Vec<u8>)]) -> Result<(), StateError> {
        for (key, value) in updates {
            self.insert(key, value)?;
        }
        Ok(())
    }

    fn batch_get(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>, StateError> {
        keys.iter().map(|key| self.get(key)).collect()
    }

    fn batch_apply(
        &mut self,
        inserts: &[(Vec<u8>, Vec<u8>)],
        deletes: &[Vec<u8>],
    ) -> Result<(), StateError> {
        for key in deletes {
            self.delete(key)?;
        }
        for (key, value) in inserts {
            self.insert(key, value)?;
        }
        Ok(())
    }

    fn prefix_scan(&self, prefix: &[u8]) -> Result<StateScanIter<'_>, StateError> {
        let rows: Vec<_> = self
            .data
            .iter()
            .filter(|(key, _)| key.starts_with(prefix))
            .map(|(key, value)| Ok((Arc::from(key.as_slice()), Arc::from(value.as_slice()))))
            .collect();
        Ok(Box::new(rows.into_iter()))
    }
}

fn with_ctx<F>(f: F)
where
    F: FnOnce(&mut TxContext<'_>),
{
    with_ctx_signer([7u8; 32], f);
}

fn with_ctx_signer<F>(signer_account_id: [u8; 32], f: F)
where
    F: FnOnce(&mut TxContext<'_>),
{
    let services = ServiceDirectory::new(Vec::new());
    let mut ctx = TxContext {
        block_height: 42,
        block_timestamp: 1_750_000_000_000_000_000,
        chain_id: ChainId(1),
        signer_account_id: AccountId(signer_account_id),
        services: &services,
        simulation: false,
        is_internal: false,
    };
    f(&mut ctx);
}

fn run_async<F: std::future::Future<Output = T>, T>(future: F) -> T {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime")
        .block_on(future)
}

#[derive(Clone)]
struct HybridSigner {
    ed25519: Ed25519KeyPair,
    mldsa: MldsaKeyPair,
    signer_id: [u8; 32],
}

fn new_hybrid_signer() -> HybridSigner {
    let ed25519 = Ed25519KeyPair::generate().expect("ed25519 keypair");
    let mldsa = MldsaScheme::new(SecurityLevel::Level2)
        .generate_keypair()
        .expect("mldsa keypair");
    let mut hybrid_public_key = ed25519.public_key().to_bytes();
    hybrid_public_key.extend_from_slice(&mldsa.public_key().to_bytes());
    let signer_id =
        account_id_from_key_material(SignatureSuite::HYBRID_ED25519_ML_DSA_44, &hybrid_public_key)
            .expect("hybrid signer id");
    HybridSigner {
        ed25519,
        mldsa,
        signer_id,
    }
}

fn sign_hybrid_payload(signer: &HybridSigner, payload: &[u8]) -> Vec<u8> {
    let mut hybrid_public_key = signer.ed25519.public_key().to_bytes();
    hybrid_public_key.extend_from_slice(&signer.mldsa.public_key().to_bytes());

    let mut hybrid_signature = signer
        .ed25519
        .sign(payload)
        .expect("ed25519 sign")
        .to_bytes();
    hybrid_signature.extend_from_slice(&signer.mldsa.sign(payload).expect("mldsa sign").to_bytes());

    let proof = SignatureProof {
        suite: SignatureSuite::HYBRID_ED25519_ML_DSA_44,
        public_key: hybrid_public_key,
        signature: hybrid_signature,
    };
    codec::to_bytes_canonical(&proof).expect("encode hybrid signature proof")
}

#[derive(Clone)]
struct ApprovalSigner {
    keypair: Ed25519KeyPair,
    authority: ApprovalAuthority,
}

fn new_approval_signer() -> ApprovalSigner {
    let keypair = Ed25519KeyPair::generate().expect("approval ed25519 keypair");
    let public_key = keypair.public_key().to_bytes();
    let authority_id =
        account_id_from_key_material(SignatureSuite::ED25519, &public_key).expect("authority id");
    ApprovalSigner {
        keypair,
        authority: ApprovalAuthority {
            schema_version: 1,
            authority_id,
            public_key,
            signature_suite: SignatureSuite::ED25519,
            expires_at: 1_850_000_000_000,
            revoked: false,
            scope_allowlist: vec!["wallet_network.approval".to_string()],
        },
    }
}

fn signed_wallet_approval_grant(
    signer: &ApprovalSigner,
    request_hash: [u8; 32],
    policy_hash: [u8; 32],
    audience: [u8; 32],
    nonce: [u8; 32],
    counter: u64,
    max_usages: Option<u32>,
    expires_at: u64,
) -> ApprovalGrant {
    let mut grant = ApprovalGrant {
        schema_version: 1,
        authority_id: signer.authority.authority_id,
        request_hash,
        policy_hash,
        audience,
        nonce,
        counter,
        expires_at,
        max_usages,
        window_id: None,
        pii_action: None,
        scoped_exception: None,
        review_request_hash: None,
        approver_public_key: signer.authority.public_key.clone(),
        approver_sig: Vec::new(),
        approver_suite: SignatureSuite::ED25519,
    };
    let bytes = grant.signing_bytes().expect("grant signing bytes");
    grant.approver_sig = signer
        .keypair
        .sign(&bytes)
        .expect("sign grant")
        .to_bytes()
        .to_vec();
    grant
}

#[derive(Clone)]
struct StandingGrantFixture {
    grant: StandingApprovalGrant,
    standing_envelope_json: Vec<u8>,
    approval_ceremony_context_json: Vec<u8>,
    auth_factor_receipt_json: Vec<u8>,
}

impl StandingGrantFixture {
    fn record_params(&self) -> RecordStandingApprovalGrantParams {
        RecordStandingApprovalGrantParams {
            grant: self.grant.clone(),
            standing_envelope_json: self.standing_envelope_json.clone(),
            approval_ceremony_context_json: self.approval_ceremony_context_json.clone(),
            auth_factor_receipt_json: self.auth_factor_receipt_json.clone(),
        }
    }
}

fn test_digest(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes).expect("test sha256");
    let mut output = [0u8; 32];
    output.copy_from_slice(digest.as_ref());
    output
}

fn hash_ref(value: [u8; 32]) -> String {
    format!("sha256:{}", hex::encode(value))
}

fn test_rfc3339(timestamp_ms: u64) -> String {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(timestamp_ms) * 1_000_000)
        .expect("test timestamp")
        .format(&Rfc3339)
        .expect("test RFC3339")
}

fn signed_standing_approval_grant(
    signer: &ApprovalSigner,
    policy_hash: [u8; 32],
    audience: [u8; 32],
    nonce: [u8; 32],
    counter: u64,
    max_usages: u32,
    max_cumulative_deposit_microusd: u64,
    max_cumulative_spend_microusd: u64,
    marker: u8,
) -> StandingGrantFixture {
    const NOW_MS: u64 = 1_750_000_000_000;
    let marker = format!("{marker:02x}");
    let mut envelope = json!({
        "schema_version": "ioi.foundations.standing-authority-envelope.v1",
        "standing_envelope_ref": format!("standing-envelope://wallet-test/{marker}"),
        "owner_ref": "org://wallet-test",
        "bounded_system_ref": "system://wallet-test",
        "principal_ref": "org://wallet-network/effect-owner",
        "audience_ref": "wallet-client://hypervisor/provider-ops",
        "authority_scope": "scope:hypervisor.live-route.hypervisor-provider-op",
        "facet_template": {
            "provider_id": "pacc_18cd245812ad55b9",
            "operations": ["create", "delete", "reconcile"],
            "provider_selector": {
                "mode": "exact",
                "provider_addresses": ["akash1aaul837r7en7hpk9wv2svg8u78fdq0t2j2e82z"],
                "selection": "only_qualified_bid_from_exact_provider"
            },
            "per_operation_deposit_microusd": max_cumulative_deposit_microusd,
            "pricing_ceiling": { "amount": "1000", "denom": "uact" },
            "sdl_hashes": [hash_ref([0x41; 32])],
            "image_digests": [hash_ref([0x42; 32])],
            "registry_hosts": ["ghcr.io"],
            "result_destination_refs": ["connector://result/test"],
            "result_transport_certificate_hashes": [hash_ref([0x43; 32])],
            "auto_topup": false,
            "teardown_policy": "always_teardown_required",
            "max_duration_seconds": 7200
        },
        "aggregate_bounds": {
            "max_cumulative_deposit_microusd": max_cumulative_deposit_microusd,
            "max_cumulative_spend_microusd": max_cumulative_spend_microusd,
            "max_usages": max_usages,
            "max_concurrent_resources": 1,
            "max_provider_fanout": 1,
            "max_failures": max_usages
        },
        "not_before_ms": NOW_MS - 60_000,
        "expires_at_ms": 1_850_000_000_000u64,
        "revocation_epoch": 0,
        "trajectory_policy_ref": "policy://wallet-test/trajectory/v1",
        "trajectory_policy_hash": hash_ref(policy_hash),
        "approval_mode": "standing_envelope",
        "recovery_posture": "recovery_never_widens_or_resets_drawdown",
        "body_hash": hash_ref([1; 32])
    });
    let mut envelope_material = envelope.clone();
    envelope_material
        .as_object_mut()
        .expect("envelope object")
        .remove("body_hash");
    envelope_material
        .as_object_mut()
        .expect("envelope object")
        .insert(
            "domain".into(),
            json!("ioi.standing-authority-envelope-jcs-sha256.v1"),
        );
    let standing_envelope_hash =
        test_digest(&serde_jcs::to_vec(&envelope_material).expect("canonical envelope material"));
    envelope["body_hash"] = json!(hash_ref(standing_envelope_hash));

    let review_receipt_hash = [0x31; 32];
    let authorization_subject = json!({
        "kind": "standing_envelope",
        "subject_ref": envelope["standing_envelope_ref"],
        "subject_hash": hash_ref(standing_envelope_hash),
        "validation_profile_ref": "schema://ioi/foundations/standing-authority-envelope/v1"
    });
    let context = json!({
        "schema_version": "ioi.foundations.approval-ceremony-context.v1",
        "approval_ceremony_context_ref": format!("approval-ceremony-context://wallet-test/{marker}"),
        "authority_request_ref": format!("authority-request://wallet-test/{marker}"),
        "authority_request_body_hash": hash_ref([0x11; 32]),
        "authority_review_ref": format!("review://wallet-test/{marker}"),
        "authority_review_body_hash": hash_ref([0x12; 32]),
        "predecessor_authority_review_ref": null,
        "predecessor_authority_review_body_hash": null,
        "predecessor_authority_request_ref": null,
        "predecessor_authority_request_body_hash": null,
        "predecessor_authority_review_receipt_ref": null,
        "predecessor_authority_review_receipt_hash": null,
        "reviewed_representation_hash": hash_ref([0x13; 32]),
        "principal_ref": "org://wallet-network/effect-owner",
        "acting_subject_ref": "runtime://wallet-test/operator",
        "product_session_ref": "session://wallet-test/operator",
        "origin_binding_ref": "origin://wallet-test/local",
        "authorization_subject": authorization_subject,
        "presentation_surface_ref": "wallet-client://wallet-test/local",
        "presentation_evidence_profile_ref": "policy://wallet-test/presentation/v1",
        "principal_authority_resolution_ref": null,
        "principal_authority_resolution_hash": null,
        "required_auth_factor_posture_refs": ["auth_factor://passkey/operator/device"],
        "required_guardian_surface_refs": [],
        "posture_satisfaction_profile_ref": "policy://wallet-test/step-up/v1",
        "interaction_mode": "interactive",
        "authentication_posture": "step_up",
        "receipt_timing": "before_effect",
        "policy_decision_receipt_ref": format!("receipt://wallet-test/review/{marker}"),
        "policy_decision_receipt_hash": hash_ref(review_receipt_hash),
        "policy_hash": hash_ref(policy_hash),
        "risk_classes": ["external_spend", "standing_authority"],
        "revocation_epoch": 0,
        "nonce_b64url": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
        "issued_at": test_rfc3339(NOW_MS - 1_000),
        "expires_at": test_rfc3339(NOW_MS + 4 * 60_000),
        "single_use": true
    });
    let mut context_material = b"IOI-APPROVAL-CEREMONY-CONTEXT-V1\0".to_vec();
    context_material
        .extend_from_slice(&serde_jcs::to_vec(&context).expect("canonical approval context"));
    let approval_ceremony_context_hash = test_digest(&context_material);

    let mut factor = json!({
        "schema_version": "ioi.hypervisor.auth-factor-receipt.v1",
        "receipt_id": format!("afr_wallet{marker}"),
        "receipt_hash": hash_ref([1; 32]),
        "ceremony_id": format!("pkc_wallet{marker}"),
        "principal_id": "operator",
        "principal_ref": "org://wallet-network/effect-owner",
        "factor_kind": "passkey",
        "credential_id_hash": hash_ref([0x21; 32]),
        "user_verification": "required_and_verified",
        "purpose": "standing_effect_authority",
        "approval_ceremony_context_ref": context["approval_ceremony_context_ref"],
        "approval_ceremony_context_hash": hash_ref(approval_ceremony_context_hash),
        "authorization_subject": context["authorization_subject"],
        "policy_hash": hash_ref(policy_hash),
        "effect_authority_created": false,
        "created_at": test_rfc3339(NOW_MS)
    });
    let mut factor_material = factor.clone();
    factor_material
        .as_object_mut()
        .expect("factor object")
        .remove("receipt_hash");
    let auth_factor_receipt_hash =
        test_digest(&serde_jcs::to_vec(&factor_material).expect("canonical factor receipt"));
    factor["receipt_hash"] = json!(hash_ref(auth_factor_receipt_hash));

    let mut grant = StandingApprovalGrant {
        schema_version: 1,
        authority_id: signer.authority.authority_id,
        standing_envelope_hash,
        policy_hash,
        audience,
        nonce,
        counter,
        issued_at_ms: 1_749_999_999_999,
        expires_at_ms: 1_850_000_000_000,
        max_usages,
        max_cumulative_deposit_microusd,
        max_cumulative_spend_microusd,
        review_receipt_hash,
        approval_ceremony_context_hash,
        auth_factor_receipt_hash,
        approver_public_key: signer.authority.public_key.clone(),
        approver_sig: Vec::new(),
        approver_suite: SignatureSuite::ED25519,
    };
    grant.approver_sig = signer
        .keypair
        .sign(&grant.signing_bytes().expect("standing grant signing bytes"))
        .expect("sign standing grant")
        .to_bytes()
        .to_vec();
    StandingGrantFixture {
        grant,
        standing_envelope_json: serde_jcs::to_vec(&envelope).expect("canonical envelope"),
        approval_ceremony_context_json: serde_jcs::to_vec(&context)
            .expect("canonical approval context"),
        auth_factor_receipt_json: serde_jcs::to_vec(&factor).expect("canonical factor receipt"),
    }
}

fn make_session_grant(
    session_id: [u8; 32],
    actions: Vec<ActionTarget>,
    max_actions: Option<u32>,
    max_spend: Option<u64>,
    expires_at_ms: u64,
) -> SessionGrant {
    SessionGrant {
        session_id,
        vault_id: [9u8; 32],
        agent_id: "agent-a".to_string(),
        purpose: "autonomous execution".to_string(),
        scope: ioi_types::app::wallet_network::SessionScope {
            expires_at_ms,
            max_actions,
            max_spend_usd_micros: max_spend,
            action_allowlist: actions,
            domain_allowlist: vec!["status.vendor-a.com".to_string()],
        },
        guardian_ephemeral_public_key: vec![1, 2, 3],
        issued_at_ms: 1_750_000_000_000,
    }
}

fn make_channel_open_init(
    channel_id: [u8; 32],
    lc_signer: &HybridSigner,
    rc_signer: &HybridSigner,
    ordering: ioi_types::app::wallet_network::SessionChannelOrdering,
) -> SessionChannelOpenInit {
    SessionChannelOpenInit {
        envelope: ioi_types::app::wallet_network::SessionChannelEnvelope {
            channel_id,
            lc_id: lc_signer.signer_id,
            rc_id: rc_signer.signer_id,
            ordering,
            mode: ioi_types::app::wallet_network::SessionChannelMode::RemoteRequestLocalExecution,
            policy_hash: [23u8; 32],
            policy_version: 1,
            root_grant_id: [24u8; 32],
            capability_set: vec![
                "email:read".to_string(),
                "mail.write".to_string(),
                "openai.chat.completions".to_string(),
            ],
            constraints: BTreeMap::from([
                ("max_usd".to_string(), "50".to_string()),
                ("allow_domain".to_string(), "example.com".to_string()),
            ]),
            delegation_rules: ioi_types::app::wallet_network::SessionChannelDelegationRules {
                max_depth: 2,
                can_redelegate: true,
                issuance_budget: Some(10),
            },
            revocation_epoch: 0,
            expires_at_ms: 1_850_000_000_000,
        },
        lc_kem_ephemeral_pub_classical: vec![1, 2, 3],
        lc_kem_ephemeral_pub_pq: vec![4, 5, 6],
        nonce_lc: [25u8; 32],
        sig_hybrid_lc: Vec::new(),
    }
}

fn open_channel(
    service: &WalletNetworkService,
    state: &mut MockState,
    channel_id: [u8; 32],
    lc_signer: &HybridSigner,
    rc_signer: &HybridSigner,
) {
    open_channel_with_ordering(
        service,
        state,
        channel_id,
        lc_signer,
        rc_signer,
        ioi_types::app::wallet_network::SessionChannelOrdering::Ordered,
    );
}

fn open_channel_with_ordering(
    service: &WalletNetworkService,
    state: &mut MockState,
    channel_id: [u8; 32],
    lc_signer: &HybridSigner,
    rc_signer: &HybridSigner,
    ordering: ioi_types::app::wallet_network::SessionChannelOrdering,
) {
    with_ctx(|ctx| {
        let mut open_init = make_channel_open_init(channel_id, lc_signer, rc_signer, ordering);
        let mut open_init_unsigned = open_init.clone();
        open_init_unsigned.sig_hybrid_lc.clear();
        let open_init_sign_bytes = codec::to_bytes_canonical(&open_init_unsigned).expect("encode");
        open_init.sig_hybrid_lc = sign_hybrid_payload(lc_signer, &open_init_sign_bytes);
        let open_init_params = codec::to_bytes_canonical(&open_init).expect("encode");
        run_async(service.handle_service_call(
            state,
            "open_channel_init@v1",
            &open_init_params,
            ctx,
        ))
        .expect("open init");

        let envelope_hash = hash_channel_envelope(&open_init).expect("hash");
        let mut open_try = SessionChannelOpenTry {
            channel_id,
            envelope_hash,
            rc_attestation_evidence: vec![1, 2],
            rc_attestation_pub: vec![3, 4],
            rc_kem_ephemeral_pub_classical: vec![5, 6],
            rc_kem_ciphertext_pq: vec![7, 8],
            nonce_rc: [26u8; 32],
            sig_hybrid_rc: Vec::new(),
        };
        let mut open_try_unsigned = open_try.clone();
        open_try_unsigned.sig_hybrid_rc.clear();
        let open_try_sign_bytes = codec::to_bytes_canonical(&open_try_unsigned).expect("encode");
        open_try.sig_hybrid_rc = sign_hybrid_payload(rc_signer, &open_try_sign_bytes);
        let open_try_params = codec::to_bytes_canonical(&open_try).expect("encode");
        run_async(service.handle_service_call(state, "open_channel_try@v1", &open_try_params, ctx))
            .expect("open try");

        let mut open_ack = SessionChannelOpenAck {
            channel_id,
            envelope_hash,
            nonce_lc2: [27u8; 32],
            sig_hybrid_lc: Vec::new(),
        };
        let mut open_ack_unsigned = open_ack.clone();
        open_ack_unsigned.sig_hybrid_lc.clear();
        let open_ack_sign_bytes = codec::to_bytes_canonical(&open_ack_unsigned).expect("encode");
        open_ack.sig_hybrid_lc = sign_hybrid_payload(lc_signer, &open_ack_sign_bytes);
        let open_ack_params = codec::to_bytes_canonical(&open_ack).expect("encode");
        run_async(service.handle_service_call(state, "open_channel_ack@v1", &open_ack_params, ctx))
            .expect("open ack");

        let mut open_confirm = SessionChannelOpenConfirm {
            channel_id,
            envelope_hash,
            nonce_rc2: [28u8; 32],
            sig_hybrid_rc: Vec::new(),
        };
        let mut open_confirm_unsigned = open_confirm.clone();
        open_confirm_unsigned.sig_hybrid_rc.clear();
        let open_confirm_sign_bytes =
            codec::to_bytes_canonical(&open_confirm_unsigned).expect("encode");
        open_confirm.sig_hybrid_rc = sign_hybrid_payload(rc_signer, &open_confirm_sign_bytes);
        let open_confirm_params = codec::to_bytes_canonical(&open_confirm).expect("encode");
        run_async(service.handle_service_call(
            state,
            "open_channel_confirm@v1",
            &open_confirm_params,
            ctx,
        ))
        .expect("open confirm");

        provision_test_mail_connector(service, state, ctx);
    });
}

fn provision_test_mail_connector(
    service: &WalletNetworkService,
    state: &mut MockState,
    ctx: &mut TxContext<'_>,
) {
    let secret_specs = [
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
    ];

    for (secret_id, alias, value) in secret_specs {
        let secret = VaultSecretRecord {
            secret_id: secret_id.to_string(),
            alias: alias.to_string(),
            kind: ioi_types::app::wallet_network::SecretKind::AccessToken,
            ciphertext: value.as_bytes().to_vec(),
            metadata: BTreeMap::new(),
            created_at_ms: 1_750_000_000_000,
            rotated_at_ms: None,
        };
        let secret_params = codec::to_bytes_canonical(&secret).expect("encode secret");
        run_async(service.handle_service_call(
            state,
            "store_secret_record@v1",
            &secret_params,
            ctx,
        ))
        .expect("store mail connector secret");
    }

    for mailbox in ["primary", "spam"] {
        let connector_upsert = MailConnectorUpsertParams {
            mailbox: mailbox.to_string(),
            config: MailConnectorConfig {
                provider: MailConnectorProvider::ImapSmtp,
                auth_mode: MailConnectorAuthMode::Password,
                account_email: "agent@example.com".to_string(),
                sender_display_name: None,
                imap: MailConnectorEndpoint {
                    host: "imap.example.com".to_string(),
                    port: 993,
                    tls_mode: MailConnectorTlsMode::Tls,
                },
                smtp: MailConnectorEndpoint {
                    host: "smtp.example.com".to_string(),
                    port: 465,
                    tls_mode: MailConnectorTlsMode::Tls,
                },
                secret_aliases: MailConnectorSecretAliases {
                    imap_username_alias: "mail.imap.username".to_string(),
                    imap_password_alias: "mail.imap.password".to_string(),
                    smtp_username_alias: "mail.smtp.username".to_string(),
                    smtp_password_alias: "mail.smtp.password".to_string(),
                },
                metadata: BTreeMap::new(),
            },
        };
        let connector_params =
            codec::to_bytes_canonical(&connector_upsert).expect("encode connector");
        run_async(service.handle_service_call(
            state,
            "mail_connector_upsert@v1",
            &connector_params,
            ctx,
        ))
        .expect("upsert test mail connector");
    }
}

mod approvals_and_injection;
mod channel;
mod connector_auth;
mod connector_config;
mod delegation;
mod identity_owner_link;
mod mail_operations;
mod principal_authority;
mod replay_and_receipts;
