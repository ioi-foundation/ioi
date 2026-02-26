use super::*;

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
