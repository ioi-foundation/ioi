use super::{
    assemble_mail_reply_body, build_mail_reply_synthesis_context, canonicalize_mail_recipient,
    is_wallet_mail_namespace_tool_name, mail_token_placeholder, rehydrate_mail_draft_text,
    resolve_explicit_mail_reply_draft, validate_mail_draft_text, wallet_mail_method_from_tool_name,
    ExplicitMailReplyDraftResolution, MailDraftToken, MailReplySignatureMode,
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
    assert!(wallet_mail_method_from_tool_name("wallet_network__mail_connector_upsert").is_none());
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
    let error = build_mail_reply_synthesis_context("Send an email about tomorrow's standup.", None)
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
