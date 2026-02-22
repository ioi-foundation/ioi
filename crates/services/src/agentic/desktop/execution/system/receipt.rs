use super::super::workload::{self, WORKLOAD_RECEIPT_REDACTED_PLACEHOLDER};
use super::ToolExecutor;

const WORKLOAD_RECEIPT_MAX_ARG_LEN: usize = 512;

fn is_sensitive_key_for_receipt(raw: &str) -> bool {
    let key = raw
        .trim_start_matches('-')
        .trim_matches(|c: char| c == '"' || c == '\'');
    let lower = key.to_ascii_lowercase();
    lower.contains("password")
        || lower.contains("passwd")
        || lower.contains("passphrase")
        || lower.contains("token")
        || lower.contains("secret")
        || lower.contains("api_key")
        || lower.contains("api-key")
        || lower.contains("apikey")
        || lower.contains("access_token")
        || lower.contains("access-token")
        || lower.contains("client_secret")
        || lower.contains("client-secret")
        || lower.contains("authorization")
        || lower.contains("bearer")
        || lower == "user"
        || lower == "username"
        || lower == "auth"
}

fn is_sensitive_flag_for_receipt(raw: &str) -> bool {
    matches!(
        raw,
        "--password"
            | "--passwd"
            | "--passphrase"
            | "--token"
            | "--access-token"
            | "--access_token"
            | "--api-key"
            | "--apikey"
            | "--client-secret"
            | "--client_secret"
            | "--secret"
            | "--authorization"
            | "--auth"
            | "--bearer"
            | "--private-key"
            | "--private_key"
            | "--user"
            | "-u"
            | "--data"
            | "--data-raw"
            | "--data-binary"
            | "--form"
            | "-d"
            | "-F"
    )
}

fn redact_authorization_header_value(raw: &str) -> String {
    let lower = raw.to_ascii_lowercase();
    let Some(bearer_start) = lower.find("bearer") else {
        return raw.to_string();
    };
    let after_bearer = &raw[bearer_start + "bearer".len()..];
    let mut iter = after_bearer.char_indices();
    let Some((space_idx, _)) = iter.find(|(_, ch)| !ch.is_whitespace()) else {
        return raw.to_string();
    };
    let token_start = bearer_start + "bearer".len() + space_idx;
    format!(
        "{}{}",
        &raw[..token_start],
        WORKLOAD_RECEIPT_REDACTED_PLACEHOLDER
    )
}

fn looks_like_jwt(arg: &str) -> bool {
    let mut parts = arg.split('.');
    let (Some(a), Some(b), Some(c), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let min_segment = 10;
    if a.len() < min_segment || b.len() < min_segment || c.len() < min_segment {
        return false;
    }
    let allowed = |ch: char| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '=';
    a.chars().all(allowed) && b.chars().all(allowed) && c.chars().all(allowed)
}

fn looks_like_known_secret_token(arg: &str) -> bool {
    let lower = arg.to_ascii_lowercase();
    lower.contains("sk_live_")
        || lower.contains("sk_test_")
        || lower.contains("sk-proj-")
        || (arg.starts_with("AKIA")
            && arg.len() == 20
            && arg.chars().all(|c| c.is_ascii_alphanumeric()))
}

fn looks_like_long_token(arg: &str) -> bool {
    if arg.len() < 48 || arg.len() > 256 {
        return false;
    }
    if arg.starts_with('-') {
        return false;
    }
    if arg.contains('/') || arg.contains('\\') {
        return false;
    }

    let allowed =
        |ch: char| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '=' | '+' | '/');
    arg.chars().all(allowed)
}

pub(super) fn redact_args_for_receipt(args: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(args.len());
    let mut redact_next = false;
    let mut header_next = false;

    for arg in args {
        if redact_next {
            out.push(WORKLOAD_RECEIPT_REDACTED_PLACEHOLDER.to_string());
            redact_next = false;
            continue;
        }
        if header_next {
            let lower = arg.to_ascii_lowercase();
            if lower.contains("authorization:") && lower.contains("bearer") {
                out.push(redact_authorization_header_value(arg));
            } else {
                out.push(arg.to_string());
            }
            header_next = false;
            continue;
        }

        let trimmed = arg.trim();
        if trimmed.is_empty() {
            out.push(String::new());
            continue;
        }

        if trimmed == "--header" || trimmed == "-H" {
            out.push(trimmed.to_string());
            header_next = true;
            continue;
        }

        if is_sensitive_flag_for_receipt(trimmed) {
            out.push(trimmed.to_string());
            redact_next = true;
            continue;
        }

        if trimmed.len() > WORKLOAD_RECEIPT_MAX_ARG_LEN {
            out.push(WORKLOAD_RECEIPT_REDACTED_PLACEHOLDER.to_string());
            continue;
        }

        if looks_like_known_secret_token(trimmed)
            || looks_like_jwt(trimmed)
            || looks_like_long_token(trimmed)
        {
            out.push(WORKLOAD_RECEIPT_REDACTED_PLACEHOLDER.to_string());
            continue;
        }

        if let Some((left, right)) = trimmed.split_once('=') {
            if !right.is_empty() && is_sensitive_key_for_receipt(left) {
                out.push(format!(
                    "{}={}",
                    left, WORKLOAD_RECEIPT_REDACTED_PLACEHOLDER
                ));
                continue;
            }
        }

        out.push(trimmed.to_string());
    }

    out
}

pub(super) async fn scrub_workload_text_field_for_receipt(
    exec: &ToolExecutor,
    input: &str,
) -> String {
    workload::scrub_workload_text_field_for_receipt(exec, input).await
}

pub(super) async fn scrub_workload_args_for_receipt(
    exec: &ToolExecutor,
    args: &[String],
) -> Vec<String> {
    let redacted = redact_args_for_receipt(args);
    let Some(scrubber) = exec.pii_scrubber.as_ref() else {
        return redacted;
    };

    let mut out = Vec::with_capacity(redacted.len());
    for arg in redacted {
        if arg.is_empty() {
            out.push(arg);
            continue;
        }
        match scrubber.scrub(arg.as_str()).await {
            Ok((scrubbed, _)) => out.push(scrubbed),
            Err(_) => out.push(WORKLOAD_RECEIPT_REDACTED_PLACEHOLDER.to_string()),
        }
    }
    out
}
