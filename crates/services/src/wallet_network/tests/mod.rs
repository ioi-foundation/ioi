use super::handlers::channel::hash_channel_envelope;
use super::keys::{
    approval_consumption_key, approval_key, channel_key, channel_key_state_key,
    connector_auth_export_receipt_key, connector_auth_get_receipt_key,
    connector_auth_import_receipt_key, connector_auth_key, connector_auth_list_receipt_key,
    injection_grant_key, lease_consumption_key, lease_counter_window_key, lease_key,
    lease_replay_key, mail_connector_binding_receipt_key, mail_connector_get_receipt_key,
    mail_connector_key, mail_count_receipt_key, mail_delete_receipt_key, mail_list_receipt_key,
    mail_read_receipt_key, mail_reply_receipt_key, policy_key, receipt_window_key,
    secret_alias_key, secret_key, session_delegation_key, session_key, PANIC_FLAG_KEY,
    REVOCATION_EPOCH_KEY,
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
mod mail_operations;
mod replay_and_receipts;
