use super::*;
use ioi_state::primitives::hash::HashCommitmentScheme;
use ioi_state::tree::iavl::IAVLTree;
use ioi_types::app::wallet_network::{
    MailConnectorAuthMode, MailConnectorConfig, MailConnectorEndpoint, MailConnectorProvider,
    MailConnectorRecord, MailConnectorSecretAliases, MailConnectorTlsMode,
};
use std::collections::BTreeMap;

#[test]
fn discovers_mail_provider_candidates_from_connector_state() {
    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let record = MailConnectorRecord {
        mailbox: "primary".to_string(),
        config: MailConnectorConfig {
            provider: MailConnectorProvider::ImapSmtp,
            auth_mode: MailConnectorAuthMode::Password,
            account_email: "local-mail@example.com".to_string(),
            sender_display_name: Some("Local Mail".to_string()),
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
                imap_username_alias: "imap_username".to_string(),
                imap_password_alias: "imap_password".to_string(),
                smtp_username_alias: "smtp_username".to_string(),
                smtp_password_alias: "smtp_password".to_string(),
            },
            metadata: BTreeMap::new(),
        },
        created_at_ms: 0,
        updated_at_ms: 0,
    };
    state
        .insert(
            b"mail_connector::primary",
            &codec::to_bytes_canonical(&record).expect("encode mail connector"),
        )
        .expect("insert mail connector");

    let capabilities = BTreeSet::from([CapabilityId::from("mail.reply")]);
    let candidates = discover_mail_provider_candidates(
        Some(&state),
        MAIL_PROVIDER_FAMILY,
        MAIL_ROUTE_LABEL,
        &capabilities,
    );

    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].provider_family, MAIL_PROVIDER_FAMILY);
    assert_eq!(candidates[0].route_label, MAIL_ROUTE_LABEL);
    assert_eq!(
        candidates[0].provider_id.as_deref(),
        Some("mail://local-mail@example.com#primary")
    );
}
