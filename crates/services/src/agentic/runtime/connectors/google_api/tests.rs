use super::{
    build_gmail_raw_message, map_to_query_pairs, normalize_pubsub_topic_name, parse_google_command,
};
use base64::Engine as _;
use serde_json::json;

#[test]
fn parses_google_command_flags() {
    let command = parse_google_command(&[
        "gmail".to_string(),
        "+triage".to_string(),
        "--max".to_string(),
        "5".to_string(),
        "--query".to_string(),
        "is:unread".to_string(),
        "--labels".to_string(),
    ])
    .expect("command");
    assert_eq!(command.service, "gmail");
    assert_eq!(command.path, vec!["+triage".to_string()]);
    assert_eq!(
        command.options.get("query").cloned().unwrap_or_default(),
        vec!["is:unread".to_string()]
    );
    assert_eq!(
        command.options.get("labels").cloned().unwrap_or_default(),
        vec!["true".to_string()]
    );
}

#[test]
fn maps_query_pairs_with_arrays() {
    let pairs = map_to_query_pairs(
        json!({
            "fields": ["a", "b"],
            "maxResults": 10
        })
        .as_object()
        .cloned()
        .expect("object"),
    );
    assert!(pairs.contains(&("fields".to_string(), "a".to_string())));
    assert!(pairs.contains(&("fields".to_string(), "b".to_string())));
    assert!(pairs.contains(&("maxResults".to_string(), "10".to_string())));
}

#[test]
fn normalizes_pubsub_topic_names() {
    let full =
        normalize_pubsub_topic_name(Some("demo-project".to_string()), "demo-topic".to_string())
            .expect("topic");
    assert_eq!(full, "projects/demo-project/topics/demo-topic");
}

#[test]
fn gmail_raw_message_includes_reply_headers() {
    let raw = build_gmail_raw_message(
        "user@example.com",
        "Subject",
        "Body",
        Some("<message-1@example.com>"),
        Some("<message-0@example.com> <message-1@example.com>"),
    );
    let decoded = String::from_utf8(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(raw.as_bytes())
            .expect("raw message should decode"),
    )
    .expect("decoded raw should be valid utf-8");

    assert!(decoded.contains("In-Reply-To: <message-1@example.com>\r\n"));
    assert!(decoded.contains("References: <message-0@example.com> <message-1@example.com>\r\n"));
}
