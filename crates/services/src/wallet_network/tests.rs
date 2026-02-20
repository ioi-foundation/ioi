use super::handlers::channel::hash_channel_envelope;
use super::keys::{
    approval_consumption_key, approval_key, channel_key, channel_key_state_key,
    injection_grant_key, lease_consumption_key, lease_counter_window_key, lease_key,
    lease_replay_key, mail_connector_get_receipt_key, mail_connector_key, mail_delete_receipt_key,
    mail_list_receipt_key, mail_read_receipt_key, mail_reply_receipt_key, receipt_window_key,
    session_delegation_key, session_key, PANIC_FLAG_KEY, REVOCATION_EPOCH_KEY,
};
use super::support::load_typed;
use super::*;
use ioi_api::crypto::{SerializableKey, SigningKeyPair};
use ioi_api::services::access::ServiceDirectory;
use ioi_api::state::StateScanIter;
use ioi_api::transaction::context::TxContext;
use ioi_crypto::security::SecurityLevel;
use ioi_crypto::sign::dilithium::{MldsaKeyPair, MldsaScheme};
use ioi_crypto::sign::eddsa::Ed25519KeyPair;
use ioi_types::app::action::{ApprovalScope, ApprovalToken};
use ioi_types::app::wallet_network::{
    GuardianAttestation, MailConnectorAuthMode, MailConnectorConfig, MailConnectorEndpoint,
    MailConnectorGetParams, MailConnectorGetReceipt, MailConnectorProvider, MailConnectorRecord,
    MailConnectorSecretAliases, MailConnectorTlsMode, MailConnectorUpsertParams,
    MailDeleteSpamParams, MailDeleteSpamReceipt, MailListRecentParams, MailListRecentReceipt,
    MailReadLatestParams, MailReadLatestReceipt, MailReplyParams, MailReplyReceipt,
    SecretInjectionGrant, SecretInjectionRequest, SecretInjectionRequestRecord,
    SessionChannelKeyState, SessionChannelOpenAck, SessionChannelOpenConfirm,
    SessionChannelOpenInit, SessionChannelOpenTry, SessionChannelRecord, SessionChannelState,
    SessionGrant, SessionLease, SessionLeaseMode, VaultSecretRecord, WalletApprovalDecision,
    WalletInterceptionContext,
};
use ioi_types::app::{
    account_id_from_key_material, AccountId, ActionTarget, ChainId, SignatureProof, SignatureSuite,
};
use ioi_types::error::StateError;
use std::collections::BTreeMap;
use std::sync::Arc;

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

fn sign_wallet_approval_decision(
    mut approval: WalletApprovalDecision,
    signer: &HybridSigner,
) -> WalletApprovalDecision {
    {
        let token = approval
            .approval_token
            .as_mut()
            .expect("approval decision requires approval_token");
        token.approver_suite = SignatureSuite::HYBRID_ED25519_ML_DSA_44;
        token.approver_sig.clear();
    }
    let sign_bytes = codec::to_bytes_canonical(&approval).expect("encode approval decision");
    let signature = sign_hybrid_payload(signer, &sign_bytes);
    approval
        .approval_token
        .as_mut()
        .expect("approval decision requires approval_token")
        .approver_sig = signature;
    approval
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

        provision_mock_mail_connector(service, state, ctx);
    });
}

fn provision_mock_mail_connector(
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
        };
        let connector_params =
            codec::to_bytes_canonical(&connector_upsert).expect("encode connector");
        run_async(service.handle_service_call(
            state,
            "mail_connector_upsert@v1",
            &connector_params,
            ctx,
        ))
        .expect("upsert mock mail connector");
    }
}

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
fn mail_delete_spam_rejects_non_spam_mailbox_target() {
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

        let delete_req = MailDeleteSpamParams {
            operation_id: [0x97u8; 32],
            channel_id,
            lease_id,
            op_seq: 1,
            op_nonce: Some([0x98u8; 32]),
            mailbox: "primary".to_string(),
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
        .expect_err("mail_delete_spam should reject non-spam mailbox");
        assert!(err
            .to_string()
            .to_ascii_lowercase()
            .contains("spam/junk mailbox target"));
    });

    assert!(state
        .get(&mail_delete_receipt_key(&[0x97u8; 32]))
        .expect("state")
        .is_none());
}

#[test]
fn mail_connector_upsert_and_get_round_trip() {
    let service = WalletNetworkService;
    let mut state = MockState::default();
    let request_id = [0x51u8; 32];

    with_ctx(|ctx| {
        for (secret_id, alias, value) in [
            ("mail-imap-user", "mail.imap.user", "agent@example.com"),
            ("mail-imap-pass", "mail.imap.pass", "imap-password"),
            ("mail-smtp-user", "mail.smtp.user", "agent@example.com"),
            ("mail-smtp-pass", "mail.smtp.pass", "smtp-password"),
        ] {
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
                &mut state,
                "store_secret_record@v1",
                &secret_params,
                ctx,
            ))
            .expect("store connector secret");
        }

        let upsert = MailConnectorUpsertParams {
            mailbox: " Primary ".to_string(),
            config: MailConnectorConfig {
                provider: MailConnectorProvider::ImapSmtp,
                auth_mode: MailConnectorAuthMode::Password,
                account_email: " Agent@Example.COM ".to_string(),
                imap: MailConnectorEndpoint {
                    host: " IMAP.EXAMPLE.COM ".to_string(),
                    port: 993,
                    tls_mode: MailConnectorTlsMode::Tls,
                },
                smtp: MailConnectorEndpoint {
                    host: " SMTP.EXAMPLE.COM ".to_string(),
                    port: 587,
                    tls_mode: MailConnectorTlsMode::StartTls,
                },
                secret_aliases: MailConnectorSecretAliases {
                    imap_username_alias: " Mail.Imap.User ".to_string(),
                    imap_password_alias: " Mail.Imap.Pass ".to_string(),
                    smtp_username_alias: " Mail.Smtp.User ".to_string(),
                    smtp_password_alias: " Mail.Smtp.Pass ".to_string(),
                },
                metadata: BTreeMap::from([
                    (" Region ".to_string(), " us-east-1 ".to_string()),
                    ("".to_string(), "drop-me".to_string()),
                ]),
            },
        };
        let upsert_params = codec::to_bytes_canonical(&upsert).expect("encode");
        run_async(service.handle_service_call(
            &mut state,
            "mail_connector_upsert@v1",
            &upsert_params,
            ctx,
        ))
        .expect("mail connector upsert");

        let get = MailConnectorGetParams {
            request_id,
            mailbox: "PRIMARY".to_string(),
        };
        let get_params = codec::to_bytes_canonical(&get).expect("encode");
        run_async(service.handle_service_call(
            &mut state,
            "mail_connector_get@v1",
            &get_params,
            ctx,
        ))
        .expect("mail connector get");

        let replay_err = run_async(service.handle_service_call(
            &mut state,
            "mail_connector_get@v1",
            &get_params,
            ctx,
        ))
        .expect_err("request_id replay must fail");
        assert!(replay_err
            .to_string()
            .to_ascii_lowercase()
            .contains("replay"));
    });

    let connector: MailConnectorRecord = codec::from_bytes_canonical(
        &state
            .get(&mail_connector_key("primary"))
            .expect("state")
            .expect("mail connector record"),
    )
    .expect("decode connector");
    assert_eq!(connector.mailbox, "primary");
    assert_eq!(connector.config.account_email, "agent@example.com");
    assert_eq!(connector.config.imap.host, "imap.example.com");
    assert_eq!(connector.config.smtp.host, "smtp.example.com");
    assert_eq!(
        connector.config.secret_aliases.imap_username_alias,
        "mail.imap.user"
    );
    assert_eq!(
        connector.config.secret_aliases.smtp_password_alias,
        "mail.smtp.pass"
    );
    assert_eq!(
        connector.config.metadata.get("region"),
        Some(&"us-east-1".to_string())
    );
    assert!(connector.config.metadata.get("").is_none());

    let receipt: MailConnectorGetReceipt = codec::from_bytes_canonical(
        &state
            .get(&mail_connector_get_receipt_key(&request_id))
            .expect("state")
            .expect("mail connector get receipt"),
    )
    .expect("decode receipt");
    assert_eq!(receipt.mailbox, "primary");
    assert_eq!(receipt.connector, connector);
}

#[test]
fn mail_connector_get_rejects_unknown_mailbox() {
    let service = WalletNetworkService;
    let mut state = MockState::default();

    with_ctx(|ctx| {
        let get = MailConnectorGetParams {
            request_id: [0x52u8; 32],
            mailbox: "primary".to_string(),
        };
        let get_params = codec::to_bytes_canonical(&get).expect("encode");
        let err = run_async(service.handle_service_call(
            &mut state,
            "mail_connector_get@v1",
            &get_params,
            ctx,
        ))
        .expect_err("missing mailbox config should fail");
        assert!(err
            .to_string()
            .to_ascii_lowercase()
            .contains("not configured"));
    });
}

#[test]
fn mail_connector_upsert_rejects_unregistered_secret_aliases() {
    let service = WalletNetworkService;
    let mut state = MockState::default();

    with_ctx(|ctx| {
        let upsert = MailConnectorUpsertParams {
            mailbox: "primary".to_string(),
            config: MailConnectorConfig {
                provider: MailConnectorProvider::ImapSmtp,
                auth_mode: MailConnectorAuthMode::Password,
                account_email: "agent@example.com".to_string(),
                imap: MailConnectorEndpoint {
                    host: "imap.example.com".to_string(),
                    port: 993,
                    tls_mode: MailConnectorTlsMode::Tls,
                },
                smtp: MailConnectorEndpoint {
                    host: "smtp.example.com".to_string(),
                    port: 587,
                    tls_mode: MailConnectorTlsMode::StartTls,
                },
                secret_aliases: MailConnectorSecretAliases {
                    imap_username_alias: "mail.imap.user".to_string(),
                    imap_password_alias: "mail.imap.pass".to_string(),
                    smtp_username_alias: "mail.smtp.user".to_string(),
                    smtp_password_alias: "mail.smtp.pass".to_string(),
                },
                metadata: BTreeMap::new(),
            },
        };
        let upsert_params = codec::to_bytes_canonical(&upsert).expect("encode");
        let err = run_async(service.handle_service_call(
            &mut state,
            "mail_connector_upsert@v1",
            &upsert_params,
            ctx,
        ))
        .expect_err("unregistered secret aliases should fail");
        assert!(err.to_string().contains("is not registered"));
    });
}

#[test]
fn mail_connector_upsert_rejects_sensitive_metadata_keys() {
    let service = WalletNetworkService;
    let mut state = MockState::default();

    with_ctx(|ctx| {
        let upsert = MailConnectorUpsertParams {
            mailbox: "primary".to_string(),
            config: MailConnectorConfig {
                provider: MailConnectorProvider::ImapSmtp,
                auth_mode: MailConnectorAuthMode::Password,
                account_email: "agent@example.com".to_string(),
                imap: MailConnectorEndpoint {
                    host: "imap.example.com".to_string(),
                    port: 993,
                    tls_mode: MailConnectorTlsMode::Tls,
                },
                smtp: MailConnectorEndpoint {
                    host: "smtp.example.com".to_string(),
                    port: 587,
                    tls_mode: MailConnectorTlsMode::StartTls,
                },
                secret_aliases: MailConnectorSecretAliases {
                    imap_username_alias: "mail.imap.user".to_string(),
                    imap_password_alias: "mail.imap.pass".to_string(),
                    smtp_username_alias: "mail.smtp.user".to_string(),
                    smtp_password_alias: "mail.smtp.pass".to_string(),
                },
                metadata: BTreeMap::from([("smtp_password".to_string(), "abc123".to_string())]),
            },
        };
        let upsert_params = codec::to_bytes_canonical(&upsert).expect("encode");
        let err = run_async(service.handle_service_call(
            &mut state,
            "mail_connector_upsert@v1",
            &upsert_params,
            ctx,
        ))
        .expect_err("sensitive metadata key should fail");
        assert!(err.to_string().contains("use secret aliases instead"));
    });
}

#[test]
fn session_subgrant_must_be_narrower_than_parent() {
    let service = WalletNetworkService;
    let mut state = MockState::default();
    let root = make_session_grant(
        [1u8; 32],
        vec![ActionTarget::WebRetrieve, ActionTarget::NetFetch],
        Some(10),
        Some(1_000),
        1_850_000_000_000,
    );
    let child = make_session_grant(
        [2u8; 32],
        vec![ActionTarget::WebRetrieve],
        Some(3),
        Some(400),
        1_800_000_000_000,
    );

    with_ctx(|ctx| {
        let root_params = codec::to_bytes_canonical(&IssueSessionGrantParams {
            grant: root,
            parent_session_id: None,
            delegation_rules: None,
        })
        .expect("encode");
        run_async(service.handle_service_call(
            &mut state,
            "issue_session_grant@v1",
            &root_params,
            ctx,
        ))
        .expect("root session grant");

        let child_params = codec::to_bytes_canonical(&IssueSessionGrantParams {
            grant: child.clone(),
            parent_session_id: Some([1u8; 32]),
            delegation_rules: None,
        })
        .expect("encode");
        run_async(service.handle_service_call(
            &mut state,
            "issue_session_grant@v1",
            &child_params,
            ctx,
        ))
        .expect("child session grant");
    });

    let stored: SessionGrant = codec::from_bytes_canonical(
        &state
            .get(&session_key(&[2u8; 32]))
            .expect("state")
            .expect("session present"),
    )
    .expect("decode");
    assert_eq!(stored.session_id, [2u8; 32]);
    assert_eq!(stored.scope.max_actions, Some(3));
}

#[test]
fn session_grant_delegation_enforces_depth_and_budget() {
    let service = WalletNetworkService;
    let mut state = MockState::default();
    let root = make_session_grant(
        [0x71u8; 32],
        vec![ActionTarget::WebRetrieve, ActionTarget::NetFetch],
        Some(10),
        Some(1_000),
        1_850_000_000_000,
    );
    let child_one = make_session_grant(
        [0x72u8; 32],
        vec![ActionTarget::WebRetrieve],
        Some(5),
        Some(500),
        1_840_000_000_000,
    );
    let child_two = make_session_grant(
        [0x73u8; 32],
        vec![ActionTarget::WebRetrieve],
        Some(4),
        Some(400),
        1_830_000_000_000,
    );
    let grandchild = make_session_grant(
        [0x74u8; 32],
        vec![ActionTarget::WebRetrieve],
        Some(2),
        Some(200),
        1_820_000_000_000,
    );

    with_ctx(|ctx| {
        let root_params = codec::to_bytes_canonical(&IssueSessionGrantParams {
            grant: root,
            parent_session_id: None,
            delegation_rules: Some(
                ioi_types::app::wallet_network::SessionChannelDelegationRules {
                    max_depth: 1,
                    can_redelegate: true,
                    issuance_budget: Some(1),
                },
            ),
        })
        .expect("encode");
        run_async(service.handle_service_call(
            &mut state,
            "issue_session_grant@v1",
            &root_params,
            ctx,
        ))
        .expect("root session grant");

        let child_one_params = codec::to_bytes_canonical(&IssueSessionGrantParams {
            grant: child_one,
            parent_session_id: Some([0x71u8; 32]),
            delegation_rules: None,
        })
        .expect("encode");
        run_async(service.handle_service_call(
            &mut state,
            "issue_session_grant@v1",
            &child_one_params,
            ctx,
        ))
        .expect("child one grant");

        let child_two_params = codec::to_bytes_canonical(&IssueSessionGrantParams {
            grant: child_two,
            parent_session_id: Some([0x71u8; 32]),
            delegation_rules: None,
        })
        .expect("encode");
        let budget_err = run_async(service.handle_service_call(
            &mut state,
            "issue_session_grant@v1",
            &child_two_params,
            ctx,
        ))
        .expect_err("root issuance budget should be exhausted");
        let budget_err_lc = budget_err.to_string().to_ascii_lowercase();
        assert!(budget_err_lc.contains("budget") || budget_err_lc.contains("re-delegation"));

        let depth_root = make_session_grant(
            [0x91u8; 32],
            vec![ActionTarget::WebRetrieve],
            Some(5),
            Some(500),
            1_850_000_000_000,
        );
        let depth_child = make_session_grant(
            [0x92u8; 32],
            vec![ActionTarget::WebRetrieve],
            Some(4),
            Some(400),
            1_840_000_000_000,
        );
        let depth_root_params = codec::to_bytes_canonical(&IssueSessionGrantParams {
            grant: depth_root,
            parent_session_id: None,
            delegation_rules: Some(
                ioi_types::app::wallet_network::SessionChannelDelegationRules {
                    max_depth: 1,
                    can_redelegate: true,
                    issuance_budget: None,
                },
            ),
        })
        .expect("encode");
        run_async(service.handle_service_call(
            &mut state,
            "issue_session_grant@v1",
            &depth_root_params,
            ctx,
        ))
        .expect("depth root");

        let depth_child_params = codec::to_bytes_canonical(&IssueSessionGrantParams {
            grant: depth_child,
            parent_session_id: Some([0x91u8; 32]),
            delegation_rules: None,
        })
        .expect("encode");
        run_async(service.handle_service_call(
            &mut state,
            "issue_session_grant@v1",
            &depth_child_params,
            ctx,
        ))
        .expect("depth child");

        let grandchild_params = codec::to_bytes_canonical(&IssueSessionGrantParams {
            grant: grandchild,
            parent_session_id: Some([0x92u8; 32]),
            delegation_rules: None,
        })
        .expect("encode");
        let depth_err = run_async(service.handle_service_call(
            &mut state,
            "issue_session_grant@v1",
            &grandchild_params,
            ctx,
        ))
        .expect_err("max depth=1 should reject grandchild");
        let depth_err_lc = depth_err.to_string().to_ascii_lowercase();
        assert!(depth_err_lc.contains("depth") || depth_err_lc.contains("re-delegation"));
    });

    let root_state: SessionDelegationState =
        load_typed(&state, &session_delegation_key(&[0x71u8; 32]))
            .expect("load")
            .expect("root state");
    assert_eq!(root_state.depth, 0);
    assert_eq!(root_state.max_depth, 1);
    assert_eq!(root_state.remaining_issuance_budget, Some(0));
    assert_eq!(root_state.children_issued, 1);
    assert!(!root_state.can_redelegate);

    let child_state: SessionDelegationState =
        load_typed(&state, &session_delegation_key(&[0x72u8; 32]))
            .expect("load")
            .expect("child state");
    assert_eq!(child_state.root_session_id, [0x71u8; 32]);
    assert_eq!(child_state.depth, 1);
}

#[test]
fn session_subgrant_requires_existing_parent_delegation_state() {
    let service = WalletNetworkService;
    let mut state = MockState::default();
    let root = make_session_grant(
        [0x61u8; 32],
        vec![ActionTarget::WebRetrieve, ActionTarget::NetFetch],
        Some(10),
        Some(1_000),
        1_850_000_000_000,
    );
    let child = make_session_grant(
        [0x62u8; 32],
        vec![ActionTarget::WebRetrieve],
        Some(5),
        Some(500),
        1_840_000_000_000,
    );

    with_ctx(|ctx| {
        let root_params = codec::to_bytes_canonical(&IssueSessionGrantParams {
            grant: root,
            parent_session_id: None,
            delegation_rules: None,
        })
        .expect("encode");
        run_async(service.handle_service_call(
            &mut state,
            "issue_session_grant@v1",
            &root_params,
            ctx,
        ))
        .expect("root session grant");
    });

    state
        .delete(&session_delegation_key(&[0x61u8; 32]))
        .expect("delete parent delegation state");

    with_ctx(|ctx| {
        let child_params = codec::to_bytes_canonical(&IssueSessionGrantParams {
            grant: child,
            parent_session_id: Some([0x61u8; 32]),
            delegation_rules: None,
        })
        .expect("encode");
        let err = run_async(service.handle_service_call(
            &mut state,
            "issue_session_grant@v1",
            &child_params,
            ctx,
        ))
        .expect_err("missing parent delegation state should fail");
        assert!(err.to_string().to_ascii_lowercase().contains("delegation"));
    });

    assert!(state
        .get(&session_key(&[0x62u8; 32]))
        .expect("state")
        .is_none());
}

#[test]
fn invalid_child_delegation_rules_do_not_consume_parent_budget() {
    let service = WalletNetworkService;
    let mut state = MockState::default();
    let root = make_session_grant(
        [0x63u8; 32],
        vec![ActionTarget::WebRetrieve, ActionTarget::NetFetch],
        Some(10),
        Some(1_000),
        1_850_000_000_000,
    );
    let child = make_session_grant(
        [0x64u8; 32],
        vec![ActionTarget::WebRetrieve],
        Some(5),
        Some(500),
        1_840_000_000_000,
    );

    with_ctx(|ctx| {
        let root_params = codec::to_bytes_canonical(&IssueSessionGrantParams {
            grant: root,
            parent_session_id: None,
            delegation_rules: Some(
                ioi_types::app::wallet_network::SessionChannelDelegationRules {
                    max_depth: 2,
                    can_redelegate: true,
                    issuance_budget: Some(1),
                },
            ),
        })
        .expect("encode");
        run_async(service.handle_service_call(
            &mut state,
            "issue_session_grant@v1",
            &root_params,
            ctx,
        ))
        .expect("root session grant");

        let invalid_child_params = codec::to_bytes_canonical(&IssueSessionGrantParams {
            grant: child,
            parent_session_id: Some([0x63u8; 32]),
            delegation_rules: Some(
                ioi_types::app::wallet_network::SessionChannelDelegationRules {
                    max_depth: 3,
                    can_redelegate: true,
                    issuance_budget: Some(1),
                },
            ),
        })
        .expect("encode");
        let err = run_async(service.handle_service_call(
            &mut state,
            "issue_session_grant@v1",
            &invalid_child_params,
            ctx,
        ))
        .expect_err("invalid child delegation rules should fail");
        assert!(err.to_string().to_ascii_lowercase().contains("max_depth"));
    });

    let root_state: SessionDelegationState =
        load_typed(&state, &session_delegation_key(&[0x63u8; 32]))
            .expect("load")
            .expect("root state");
    assert_eq!(root_state.remaining_issuance_budget, Some(1));
    assert_eq!(root_state.children_issued, 0);
    assert!(root_state.can_redelegate);
    assert!(state
        .get(&session_key(&[0x64u8; 32]))
        .expect("state")
        .is_none());
}

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
