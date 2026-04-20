use super::{
    expand_google_scope, missing_required_scopes, resolve_requested_google_oauth_scopes,
    split_scope_string,
};

#[test]
fn expands_google_scopes() {
    assert_eq!(
        expand_google_scope("gmail.modify"),
        vec!["https://www.googleapis.com/auth/gmail.modify".to_string()]
    );
    assert_eq!(
        expand_google_scope("https://www.googleapis.com/auth/drive"),
        vec!["https://www.googleapis.com/auth/drive".to_string()]
    );
}

#[test]
fn detects_missing_scopes_by_alias() {
    let granted = vec![
        "https://www.googleapis.com/auth/gmail.modify".to_string(),
        "https://www.googleapis.com/auth/calendar".to_string(),
    ];
    let missing = missing_required_scopes(&granted, &["gmail.modify", "spreadsheets"]);
    assert_eq!(missing, vec!["spreadsheets".to_string()]);
}

#[test]
fn broader_google_scopes_cover_readonly_requirements() {
    let granted = vec![
        "https://www.googleapis.com/auth/gmail.modify".to_string(),
        "https://www.googleapis.com/auth/calendar".to_string(),
        "https://www.googleapis.com/auth/tasks".to_string(),
        "https://www.googleapis.com/auth/drive".to_string(),
    ];
    let missing = missing_required_scopes(
        &granted,
        &[
            "gmail.readonly",
            "calendar.readonly",
            "tasks.readonly",
            "drive.readonly",
        ],
    );
    assert!(missing.is_empty());
}

#[test]
fn splits_scope_strings() {
    assert_eq!(
        split_scope_string("a b  c"),
        vec!["a".to_string(), "b".to_string(), "c".to_string()]
    );
}

#[test]
fn requested_google_scopes_include_identity_and_selected_bundles() {
    let scopes = resolve_requested_google_oauth_scopes(Some(vec![
        "gmail.modify".to_string(),
        "calendar".to_string(),
    ]))
    .expect("requested scopes should resolve");

    assert!(scopes.iter().any(|scope| scope == "openid"));
    assert!(scopes.iter().any(|scope| scope == "email"));
    assert!(scopes
        .iter()
        .any(|scope| scope == "https://www.googleapis.com/auth/gmail.modify"));
    assert!(scopes
        .iter()
        .any(|scope| scope == "https://www.googleapis.com/auth/calendar"));
}
