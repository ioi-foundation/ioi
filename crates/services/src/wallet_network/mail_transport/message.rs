use super::constants::{MAIL_FROM_MAX_LEN, MAIL_PREVIEW_MAX_LEN, MAIL_SUBJECT_MAX_LEN};
use super::model::MailProviderMessage;
use super::util::bound_text;
use ioi_types::error::TransactionError;

pub(super) fn mail_provider_message_from_fetch(
    fetch: &imap::types::Fetch,
    now_ms: u64,
) -> Result<MailProviderMessage, TransactionError> {
    let envelope = fetch.envelope();
    let from = envelope
        .and_then(|envelope| {
            envelope.from.as_ref().and_then(|addresses| {
                addresses
                    .iter()
                    .filter_map(|address| {
                        let mailbox = address
                            .mailbox
                            .as_ref()
                            .map(|value| decode_bytes(value.as_ref()));
                        let host = address
                            .host
                            .as_ref()
                            .map(|value| decode_bytes(value.as_ref()));
                        match (mailbox, host) {
                            (Some(mailbox), Some(host))
                                if !mailbox.is_empty() && !host.is_empty() =>
                            {
                                Some(format!("{}@{}", mailbox, host))
                            }
                            _ => address
                                .name
                                .as_ref()
                                .map(|value| decode_bytes(value.as_ref()))
                                .filter(|value| !value.is_empty()),
                        }
                    })
                    .next()
            })
        })
        .unwrap_or_else(|| "unknown@unknown".to_string());
    let subject = envelope
        .and_then(|value| value.subject.as_ref())
        .map(|value| decode_bytes(value.as_ref()))
        .unwrap_or_else(|| "(no subject)".to_string());
    let message_id = envelope
        .and_then(|value| value.message_id.as_ref())
        .map(|value| decode_bytes(value.as_ref()))
        .map(|value| value.trim_matches(['<', '>']).to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| match fetch.uid {
            Some(uid) => format!("uid-{}", uid),
            None => format!("seq-{}", fetch.message),
        });

    let preview = fetch
        .text()
        .map(decode_bytes)
        .filter(|value| !value.is_empty())
        .or_else(|| {
            fetch
                .body()
                .map(decode_bytes)
                .filter(|value| !value.is_empty())
        })
        .unwrap_or_else(|| subject.clone());

    let received_at_ms = fetch
        .internal_date()
        .map(|value| value.timestamp_millis())
        .filter(|value| *value > 0)
        .map(|value| value as u64)
        .unwrap_or(now_ms);

    Ok(MailProviderMessage {
        message_id: bound_text(&message_id, 256),
        from: bound_text(&from, MAIL_FROM_MAX_LEN),
        subject: bound_text(&subject, MAIL_SUBJECT_MAX_LEN),
        received_at_ms,
        preview: bound_text(&preview, MAIL_PREVIEW_MAX_LEN),
    })
}

fn decode_bytes(input: &[u8]) -> String {
    let lossy = String::from_utf8_lossy(input);
    lossy.split_whitespace().collect::<Vec<_>>().join(" ")
}
