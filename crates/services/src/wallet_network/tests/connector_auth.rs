use super::super::support::{decrypt_secret_payload, is_encrypted_secret_payload};
use super::*;

#[test]
fn store_secret_record_encrypts_ciphertext_at_rest() {
    let service = WalletNetworkService;
    let mut state = MockState::default();

    with_ctx(|ctx| {
        let secret = VaultSecretRecord {
            secret_id: "secret-1".to_string(),
            alias: "mail.imap.password".to_string(),
            kind: ioi_types::app::wallet_network::SecretKind::Password,
            ciphertext: b"super-secret-password".to_vec(),
            metadata: BTreeMap::new(),
            created_at_ms: 1_750_000_000_000,
            rotated_at_ms: None,
        };
        let params = codec::to_bytes_canonical(&secret).expect("encode secret");
        run_async(service.handle_service_call(&mut state, "store_secret_record@v1", &params, ctx))
            .expect("store secret");
    });

    let stored: VaultSecretRecord = codec::from_bytes_canonical(
        &state
            .get(&secret_key("secret-1"))
            .expect("state")
            .expect("stored secret"),
    )
    .expect("decode secret");
    assert_ne!(stored.ciphertext, b"super-secret-password".to_vec());
    assert!(is_encrypted_secret_payload(&stored.ciphertext));
    let decrypted = decrypt_secret_payload(&stored.ciphertext).expect("decrypt secret payload");
    assert_eq!(decrypted, b"super-secret-password".to_vec());

    let alias_secret_id: String = load_typed(&state, &secret_alias_key("mail.imap.password"))
        .expect("load alias")
        .expect("alias secret id");
    assert_eq!(alias_secret_id, "secret-1");
}

#[test]
fn connector_auth_round_trip_exports_and_imports_wallet_state() {
    let service = WalletNetworkService;
    let mut state = MockState::default();
    let auth_record = ConnectorAuthRecord {
        connector_id: "mail.primary".to_string(),
        provider_family: "mail.wallet_network".to_string(),
        auth_protocol: ConnectorAuthProtocol::StaticPassword,
        state: ConnectorAuthState::Connected,
        account_label: Some("agent@example.com".to_string()),
        mailbox: Some("primary".to_string()),
        granted_scopes: vec![
            "mail.read.latest".to_string(),
            "mail.list.recent".to_string(),
            "mail.reply".to_string(),
        ],
        credential_aliases: BTreeMap::from([
            (
                "imap_username".to_string(),
                "mail.imap.username".to_string(),
            ),
            ("imap_secret".to_string(), "mail.imap.password".to_string()),
            (
                "smtp_username".to_string(),
                "mail.smtp.username".to_string(),
            ),
            ("smtp_secret".to_string(), "mail.smtp.password".to_string()),
        ]),
        metadata: BTreeMap::from([(
            "configured_by".to_string(),
            "wallet_network.tests".to_string(),
        )]),
        created_at_ms: 0,
        updated_at_ms: 0,
        expires_at_ms: None,
        last_validated_at_ms: None,
    };
    let policy_rule = VaultPolicyRule {
        rule_id: "shield-policy-mail-read".to_string(),
        label: "Mail reads auto-approved".to_string(),
        target: ActionTarget::Custom("connector::mail.primary::read".to_string()),
        auto_approve: true,
        max_value_usd_micros: None,
        max_ttl_secs: Some(600),
        domain_allowlist: vec!["mock.local".to_string()],
    };

    let export_receipt = with_ctx_return(|ctx| {
        provision_mock_mail_connector(&service, &mut state, ctx);

        let params = codec::to_bytes_canonical(&ConnectorAuthUpsertParams {
            record: auth_record.clone(),
        })
        .expect("encode auth record");
        run_async(service.handle_service_call(
            &mut state,
            "connector_auth_upsert@v1",
            &params,
            ctx,
        ))
        .expect("upsert auth record");

        let get_params = codec::to_bytes_canonical(&ConnectorAuthGetParams {
            request_id: [0x71u8; 32],
            connector_id: "MAIL.PRIMARY".to_string(),
        })
        .expect("encode get");
        run_async(service.handle_service_call(
            &mut state,
            "connector_auth_get@v1",
            &get_params,
            ctx,
        ))
        .expect("get auth record");

        let list_params = codec::to_bytes_canonical(&ConnectorAuthListParams {
            request_id: [0x72u8; 32],
            provider_family: Some("MAIL.WALLET_NETWORK".to_string()),
        })
        .expect("encode list");
        run_async(service.handle_service_call(
            &mut state,
            "connector_auth_list@v1",
            &list_params,
            ctx,
        ))
        .expect("list auth records");

        let policy_params = codec::to_bytes_canonical(&policy_rule).expect("encode policy");
        run_async(service.handle_service_call(
            &mut state,
            "upsert_policy_rule@v1",
            &policy_params,
            ctx,
        ))
        .expect("upsert policy");

        let export_params = codec::to_bytes_canonical(&ConnectorAuthExportParams {
            request_id: [0x73u8; 32],
            connector_ids: vec!["mail.primary".to_string()],
            passphrase: "backup-passphrase".to_string(),
        })
        .expect("encode export");
        run_async(service.handle_service_call(
            &mut state,
            "connector_auth_export@v1",
            &export_params,
            ctx,
        ))
        .expect("export wallet auth bundle");

        codec::from_bytes_canonical::<ConnectorAuthExportReceipt>(
            &state
                .get(&connector_auth_export_receipt_key(&[0x73u8; 32]))
                .expect("state")
                .expect("export receipt"),
        )
        .expect("decode export receipt")
    });

    let get_receipt: ConnectorAuthGetReceipt = codec::from_bytes_canonical(
        &state
            .get(&connector_auth_get_receipt_key(&[0x71u8; 32]))
            .expect("state")
            .expect("get receipt"),
    )
    .expect("decode get receipt");
    assert_eq!(get_receipt.record.connector_id, "mail.primary");
    assert_eq!(get_receipt.record.provider_family, "mail.wallet_network");

    let list_receipt: ConnectorAuthListReceipt = codec::from_bytes_canonical(
        &state
            .get(&connector_auth_list_receipt_key(&[0x72u8; 32]))
            .expect("state")
            .expect("list receipt"),
    )
    .expect("decode list receipt");
    assert_eq!(list_receipt.records.len(), 1);
    assert_eq!(list_receipt.records[0].connector_id, "mail.primary");

    assert_eq!(
        export_receipt.connector_ids,
        vec!["mail.primary".to_string()]
    );
    assert!(!export_receipt.encrypted_bundle.is_empty());

    let mut imported = MockState::default();
    with_ctx(|ctx| {
        let params = codec::to_bytes_canonical(&ConnectorAuthImportParams {
            request_id: [0x74u8; 32],
            encrypted_bundle: export_receipt.encrypted_bundle.clone(),
            passphrase: "backup-passphrase".to_string(),
            replace_existing: false,
        })
        .expect("encode import");
        run_async(service.handle_service_call(
            &mut imported,
            "connector_auth_import@v1",
            &params,
            ctx,
        ))
        .expect("import wallet auth bundle");
    });

    let imported_auth: ConnectorAuthRecord =
        load_typed(&imported, &connector_auth_key("mail.primary"))
            .expect("load imported auth")
            .expect("imported auth");
    assert_eq!(imported_auth.connector_id, "mail.primary");
    assert_eq!(imported_auth.provider_family, "mail.wallet_network");

    let imported_secret: VaultSecretRecord =
        load_typed(&imported, &secret_key("mail-imap-password"))
            .expect("load imported secret")
            .expect("imported secret");
    assert!(is_encrypted_secret_payload(&imported_secret.ciphertext));
    let decrypted_secret =
        decrypt_secret_payload(&imported_secret.ciphertext).expect("decrypt imported secret");
    assert_eq!(decrypted_secret, b"imap-password".to_vec());

    let imported_policy: VaultPolicyRule =
        load_typed(&imported, &policy_key("shield-policy-mail-read"))
            .expect("load imported policy")
            .expect("imported policy");
    assert_eq!(imported_policy.rule_id, "shield-policy-mail-read");

    let import_receipt: ConnectorAuthImportReceipt = codec::from_bytes_canonical(
        &imported
            .get(&connector_auth_import_receipt_key(&[0x74u8; 32]))
            .expect("state")
            .expect("import receipt"),
    )
    .expect("decode import receipt");
    assert_eq!(
        import_receipt.connector_ids,
        vec!["mail.primary".to_string()]
    );
    assert_eq!(import_receipt.mailboxes, vec!["primary".to_string()]);
    assert_eq!(
        import_receipt.policy_rule_ids,
        vec!["shield-policy-mail-read".to_string()]
    );
}

#[test]
fn mail_connector_binding_narrows_lease_to_requested_capability() {
    let service = WalletNetworkService;
    let mut state = MockState::default();

    with_ctx(|ctx| {
        provision_mock_mail_connector(&service, &mut state, ctx);
        let params = MailConnectorEnsureBindingParams {
            request_id: [0x75u8; 32],
            mailbox: "primary".to_string(),
            audience: None,
            lease_ttl_ms: None,
            requested_capability: Some("mail.read.latest".to_string()),
        };
        let payload = codec::to_bytes_canonical(&params).expect("encode ensure binding");
        run_async(service.handle_service_call(
            &mut state,
            "mail_connector_ensure_binding@v1",
            &payload,
            ctx,
        ))
        .expect("ensure narrow binding");
    });

    let receipt: MailConnectorEnsureBindingReceipt = codec::from_bytes_canonical(
        &state
            .get(&mail_connector_binding_receipt_key(&[0x75u8; 32]))
            .expect("state")
            .expect("binding receipt"),
    )
    .expect("decode binding receipt");
    let lease: SessionLease = codec::from_bytes_canonical(
        &state
            .get(&lease_key(&receipt.channel_id, &receipt.lease_id))
            .expect("state")
            .expect("lease"),
    )
    .expect("decode lease");
    assert!(lease
        .capability_subset
        .iter()
        .any(|capability| capability.eq_ignore_ascii_case("mail.read.latest")));
    assert!(!lease
        .capability_subset
        .iter()
        .any(|capability| capability.eq_ignore_ascii_case("mail.reply")));
    assert!(!lease
        .capability_subset
        .iter()
        .any(|capability| capability.eq_ignore_ascii_case("mail.delete.spam")));
    assert!(!lease
        .capability_subset
        .iter()
        .any(|capability| capability.eq_ignore_ascii_case("mail.list.recent")));
}

fn with_ctx_return<T, F>(f: F) -> T
where
    F: FnOnce(&mut TxContext<'_>) -> T,
{
    let services = ServiceDirectory::new(Vec::new());
    let mut ctx = TxContext {
        block_height: 42,
        block_timestamp: 1_750_000_000_000_000_000,
        chain_id: ChainId(1),
        signer_account_id: AccountId([7u8; 32]),
        services: &services,
        simulation: false,
        is_internal: false,
    };
    f(&mut ctx)
}
