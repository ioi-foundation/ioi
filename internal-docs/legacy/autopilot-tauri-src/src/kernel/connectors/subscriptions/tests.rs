use super::{
    calculate_gmail_renew_at, collect_placeholders, default_automation_template,
    google_project_from_resource_name, render_template, split_csv_field,
};
use serde_json::json;

#[test]
fn defaults_email_to_task_template() {
    let template = default_automation_template("workflow.email_to_task");
    assert_eq!(template["messageId"], "{{message.messageId}}");
}

#[test]
fn renders_string_and_scalar_placeholders() {
    let rendered = render_template(
        &json!({
            "messageId": "{{message.messageId}}",
            "text": "New event {{event.type}}"
        }),
        &json!({
            "message": { "messageId": "abc123" },
            "event": { "type": "created" }
        }),
    );
    assert_eq!(rendered["messageId"], "abc123");
    assert_eq!(rendered["text"], "New event created");
}

#[test]
fn extracts_placeholders_once() {
    let placeholders = collect_placeholders("{{message.id}} -> {{message.id}} -> {{event.type}}");
    assert_eq!(
        placeholders,
        vec!["message.id".to_string(), "event.type".to_string()]
    );
}

#[test]
fn derives_project_id_from_pubsub_resource_names() {
    let topic_project =
        google_project_from_resource_name("topics", "projects/demo-project/topics/demo-topic");
    let subscription_project = google_project_from_resource_name(
        "subscriptions",
        "projects/demo-project/subscriptions/demo-sub",
    );
    assert_eq!(topic_project.as_deref(), Some("demo-project"));
    assert_eq!(subscription_project.as_deref(), Some("demo-project"));
}

#[test]
fn splits_csv_fields() {
    let values = split_csv_field(Some("INBOX, Label_1\nLabel_2"));
    assert_eq!(values, vec!["INBOX", "Label_1", "Label_2"]);
}

#[test]
fn calculates_gmail_renewal_window() {
    let renew_at = calculate_gmail_renew_at("2026-03-08T12:00:00Z").expect("renew_at");
    assert_eq!(renew_at, "2026-03-08T11:00:00+00:00");
}
