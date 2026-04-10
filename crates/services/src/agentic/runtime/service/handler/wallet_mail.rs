use super::super::{RuntimeAgentService, ServiceCallContext};
use crate::agentic::pii_substrate;
use crate::wallet_network::mail_ontology::{
    parse_confidence_band, parse_volume_band, spam_confidence_band, MAIL_ONTOLOGY_SIGNAL_VERSION,
    SPAM_HIGH_CONFIDENCE_THRESHOLD_BPS,
};
use crate::wallet_network::LeaseActionReplayWindowState;
use ioi_api::state::{service_namespace_prefix, NamespacedStateAccess, StateAccess};
use ioi_api::transaction::context::TxContext;
use ioi_api::vm::inference::InferenceRuntime;
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::agentic::{InferenceOptions, PiiClass};
use ioi_types::app::wallet_network::{
    MailConnectorEnsureBindingParams, MailConnectorRecord, MailDeleteSpamParams,
    MailDeleteSpamReceipt, MailListRecentParams, MailListRecentReceipt, MailReadLatestParams,
    MailReadLatestReceipt, MailReplyParams, MailReplyReceipt, SessionChannelRecord,
    SessionChannelState, SessionLease,
};
use ioi_types::app::{ExecutionContractReceiptEvent, KernelEvent};
use ioi_types::codec;
use ioi_types::error::{TransactionError, VmError};
use ioi_types::keys::active_service_key;
use ioi_types::service_configs::ActiveServiceMeta;
use lettre::message::Mailbox;
use serde::Deserialize;
use serde_json::{json, Map as JsonMap, Value as JsonValue};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

include!("wallet_mail/mail_binding.rs");

const CHANNEL_PREFIX: &[u8] = b"channel::";
const LEASE_PREFIX: &[u8] = b"lease::";
const LEASE_ACTION_WINDOW_PREFIX: &[u8] = b"lease_action_window::";
const MAIL_CONNECTOR_PREFIX: &[u8] = b"mail_connector::";
const MAIL_READ_RECEIPT_PREFIX: &[u8] = b"mail_read_receipt::";
const MAIL_LIST_RECEIPT_PREFIX: &[u8] = b"mail_list_receipt::";
const MAIL_DELETE_RECEIPT_PREFIX: &[u8] = b"mail_delete_receipt::";
const MAIL_REPLY_RECEIPT_PREFIX: &[u8] = b"mail_reply_receipt::";
const WALLET_SERVICE_ID: &str = "wallet_network";
const MAIL_CONNECTOR_ENSURE_BINDING_METHOD: &str = "mail_connector_ensure_binding@v1";
const CEC_CONTRACT_VERSION: &str = "cec.v0.4";
const MAIL_REPLY_SYNTHESIS_MAX_ATTEMPTS: usize = 3;

const MAIL_READ_CAPABILITY_ALIASES: &[&str] =
    &["mail.read.latest", "mail:read", "mail.read", "email:read"];
const MAIL_LIST_CAPABILITY_ALIASES: &[&str] = &[
    "mail.list.recent",
    "mail:list",
    "mail.list",
    "email:list",
    "mail.read.latest",
    "mail:read",
    "mail.read",
    "email:read",
];
const MAIL_DELETE_CAPABILITY_ALIASES: &[&str] = &[
    "mail.delete.spam",
    "mail.delete",
    "mail.write",
    "mail:write",
    "email:write",
    "mail.modify",
    "email:modify",
];
const MAIL_REPLY_CAPABILITY_ALIASES: &[&str] = &[
    "mail.reply",
    "mail.send",
    "mail.write",
    "mail:write",
    "email:write",
    "mail.compose",
    "email:compose",
    "mail.modify",
    "email:modify",
];
const MAIL_REPLY_SYNTHESIS_MODEL_ID: &str = "mail_reply_synthesis.v1";

include!("wallet_mail/draft_synthesis.rs");

include!("wallet_mail/parsing.rs");

include!("wallet_mail/tool_dispatch.rs");

#[cfg(test)]
mod tests {
    use super::{
        assemble_mail_reply_body, build_mail_reply_synthesis_context, canonicalize_mail_recipient,
        is_wallet_mail_namespace_tool_name, mail_token_placeholder, rehydrate_mail_draft_text,
        resolve_explicit_mail_reply_draft, validate_mail_draft_text,
        wallet_mail_method_from_tool_name, ExplicitMailReplyDraftResolution, MailDraftToken,
        MailReplySignatureMode,
    };
    use serde_json::{json, Map as JsonMap, Value as JsonValue};

    #[test]
    fn wallet_mail_namespace_detection_includes_connector_tools() {
        assert!(is_wallet_mail_namespace_tool_name(
            "wallet_network__mail_connector_upsert"
        ));
        assert!(is_wallet_mail_namespace_tool_name("mail__read_latest"));
        assert!(!is_wallet_mail_namespace_tool_name("web__search"));
    }

    #[test]
    fn wallet_mail_method_mapping_excludes_connector_setup_tools() {
        assert!(wallet_mail_method_from_tool_name("wallet_network__mail_read_latest").is_some());
        assert!(
            wallet_mail_method_from_tool_name("wallet_network__mail_connector_upsert").is_none()
        );
    }

    #[test]
    fn explicit_mail_reply_draft_requires_canonical_to_subject_and_body() {
        let value = json!({
            "to": "team@ioi.network",
            "body": "Tomorrow's standup is moved to 2 PM."
        });
        let args: JsonMap<String, JsonValue> =
            value.as_object().expect("test args must be object").clone();

        let resolution = resolve_explicit_mail_reply_draft(&args)
            .expect("partial explicit draft should become synthesis candidate");
        assert!(matches!(
            resolution,
            ExplicitMailReplyDraftResolution::NeedsSynthesis { .. }
        ));
    }

    #[test]
    fn explicit_mail_reply_draft_accepts_canonical_fields() {
        let value = json!({
            "to": "team@ioi.network",
            "subject": "Standup moved",
            "body": "Tomorrow's standup is moved to 2 PM."
        });
        let args: JsonMap<String, JsonValue> =
            value.as_object().expect("test args must be object").clone();

        let resolution =
            resolve_explicit_mail_reply_draft(&args).expect("explicit fields should resolve");
        match resolution {
            ExplicitMailReplyDraftResolution::Accepted(draft) => {
                assert_eq!(draft.to, "team@ioi.network");
                assert_eq!(draft.subject, "Standup moved");
                assert_eq!(draft.body, "Tomorrow's standup is moved to 2 PM.");
            }
            other => panic!("expected accepted explicit draft, got {:?}", other),
        }
    }

    #[test]
    fn explicit_mail_reply_draft_accepts_mailto_recipient() {
        let value = json!({
            "to": "mailto:team@ioi.network?subject=Ignored",
            "subject": "Standup moved",
            "body": "Tomorrow's standup is moved to 2 PM."
        });
        let args: JsonMap<String, JsonValue> =
            value.as_object().expect("test args must be object").clone();

        let resolution =
            resolve_explicit_mail_reply_draft(&args).expect("mailto recipient should parse");
        match resolution {
            ExplicitMailReplyDraftResolution::Accepted(draft) => {
                assert_eq!(draft.to, "team@ioi.network");
            }
            other => panic!("expected accepted explicit draft, got {:?}", other),
        }
    }

    #[test]
    fn explicit_mail_reply_draft_ignores_redacted_recipient_and_defers_to_synthesis() {
        let value = json!({
            "to": "<REDACTED:email>",
            "subject": "Standup moved",
            "body": "Tomorrow's standup is moved to 2 PM."
        });
        let args: JsonMap<String, JsonValue> =
            value.as_object().expect("test args must be object").clone();

        let resolution =
            resolve_explicit_mail_reply_draft(&args).expect("redacted explicit draft should defer");
        assert!(matches!(
            resolution,
            ExplicitMailReplyDraftResolution::NeedsSynthesis { .. }
        ));
    }

    #[test]
    fn explicit_mail_reply_draft_defers_placeholder_body_to_synthesis() {
        let value = json!({
            "to": "team@ioi.network",
            "subject": "Standup moved",
            "body": "Hello,\n\nBest regards,\n[Your Name]"
        });
        let args: JsonMap<String, JsonValue> =
            value.as_object().expect("test args must be object").clone();

        let resolution = resolve_explicit_mail_reply_draft(&args)
            .expect("placeholder body should defer to synthesis");
        assert!(matches!(
            resolution,
            ExplicitMailReplyDraftResolution::NeedsSynthesis { .. }
        ));
    }

    #[test]
    fn assemble_mail_reply_body_appends_mailbox_sender_name_when_requested() {
        let body = assemble_mail_reply_body(
            "Tomorrow's standup is moved to 2 PM.".to_string(),
            Some("Best regards,".to_string()),
            MailReplySignatureMode::SenderName,
            Some("Levi Josman"),
        )
        .expect("sender-name signature should assemble");
        assert_eq!(
            body,
            "Tomorrow's standup is moved to 2 PM.\n\nBest regards,\nLevi Josman"
        );
    }

    #[test]
    fn assemble_mail_reply_body_rejects_sender_name_signature_when_unconfigured() {
        let error = assemble_mail_reply_body(
            "Tomorrow's standup is moved to 2 PM.".to_string(),
            Some("Best regards,".to_string()),
            MailReplySignatureMode::SenderName,
            None,
        )
        .expect_err("unconfigured sender-name signature must fail");
        assert!(error
            .to_string()
            .contains("requested sender-name signature"));
    }

    #[test]
    fn synthesis_context_tokenizes_email_entities_and_candidate_recipient() {
        let context = build_mail_reply_synthesis_context(
            "Draft an email to team@ioi.network saying tomorrow's standup is moved to 2 PM and cc team@ioi.network again.",
            Some("ops@ioi.network"),
        )
        .expect("context should build");

        assert_eq!(
            context.sanitized_request,
            "Draft an email to {{EMAIL_1}} saying tomorrow's standup is moved to 2 PM and cc {{EMAIL_1}} again."
        );
        assert_eq!(context.email_tokens.len(), 2);
        assert_eq!(context.email_tokens[0].id, "EMAIL_1");
        assert_eq!(context.email_tokens[0].raw_value, "team@ioi.network");
        assert_eq!(context.email_tokens[1].id, "EMAIL_2");
        assert_eq!(context.email_tokens[1].raw_value, "ops@ioi.network");
    }

    #[test]
    fn synthesis_context_requires_at_least_one_email_entity() {
        let error =
            build_mail_reply_synthesis_context("Send an email about tomorrow's standup.", None)
                .expect_err("context must require email token");
        assert!(error
            .to_string()
            .contains("could not derive any recipient email token"));
    }

    #[test]
    fn rehydrate_mail_draft_text_replaces_tokens_and_validates_result() {
        let value = rehydrate_mail_draft_text(
            "Hello {{EMAIL_1}}",
            &[MailDraftToken {
                id: "EMAIL_1".to_string(),
                placeholder: mail_token_placeholder("EMAIL_1"),
                raw_value: "team@ioi.network".to_string(),
            }],
        )
        .expect("email token should resolve");
        assert_eq!(value, "Hello team@ioi.network");
    }

    #[test]
    fn validate_mail_draft_text_rejects_legacy_placeholders() {
        let error = validate_mail_draft_text("body", "Best regards,\n[Your Name]".to_string())
            .expect_err("legacy placeholders must fail");
        assert!(error.to_string().contains("unresolved placeholders"));
    }

    #[test]
    fn canonicalize_mail_recipient_accepts_direct_mailbox_and_mailto() {
        assert_eq!(
            canonicalize_mail_recipient("team@ioi.network").as_deref(),
            Some("team@ioi.network")
        );
        assert_eq!(
            canonicalize_mail_recipient("mailto:team@ioi.network?subject=ignored").as_deref(),
            Some("team@ioi.network")
        );
    }
}
