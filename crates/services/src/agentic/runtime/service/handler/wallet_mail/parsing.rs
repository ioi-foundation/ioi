fn extract_dynamic_args_object(
    arguments: &JsonValue,
) -> Result<JsonMap<String, JsonValue>, TransactionError> {
    let to_object = |value: JsonValue| -> Result<JsonMap<String, JsonValue>, TransactionError> {
        value.as_object().cloned().ok_or_else(|| {
            TransactionError::Invalid(
                "wallet mail tool arguments must encode a JSON object".to_string(),
            )
        })
    };

    if let Some(params_value) = arguments.get("params") {
        match params_value {
            JsonValue::Null => Ok(JsonMap::new()),
            JsonValue::Object(map) => Ok(map.clone()),
            JsonValue::String(raw) => {
                let trimmed = raw.trim();
                if trimmed.is_empty() {
                    return Ok(JsonMap::new());
                }
                let decoded: JsonValue = serde_json::from_str(trimmed).map_err(|e| {
                    TransactionError::Invalid(format!(
                        "wallet mail tool arguments.params must be valid JSON: {}",
                        e
                    ))
                })?;
                to_object(decoded)
            }
            _ => Err(TransactionError::Invalid(
                "wallet mail tool arguments.params must be object|string|null".to_string(),
            )),
        }
    } else if let Some(map) = arguments.as_object() {
        Ok(map.clone())
    } else {
        Ok(JsonMap::new())
    }
}

fn pick_string<'a>(args: &'a JsonMap<String, JsonValue>, keys: &[&str]) -> Option<&'a str> {
    keys.iter().find_map(|key| args.get(*key)?.as_str())
}

fn pick_nonempty_string(args: &JsonMap<String, JsonValue>, keys: &[&str]) -> Option<String> {
    pick_string(args, keys)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn is_redacted_email_placeholder(value: &str) -> bool {
    let normalized = value.trim().to_ascii_lowercase();
    normalized.contains("<redacted:email>")
        || normalized == "redacted:email"
        || normalized == "redacted_email"
}

fn canonicalize_mail_recipient(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || is_redacted_email_placeholder(trimmed) {
        return None;
    }

    let mailto_stripped =
        if trimmed.len() >= "mailto:".len() && trimmed[..7].eq_ignore_ascii_case("mailto:") {
            trimmed[7..]
                .split(['?', '#'])
                .next()
                .map(str::trim)
                .unwrap_or("")
        } else {
            trimmed
        };
    if !mailto_stripped.is_empty() && mailto_stripped.parse::<Mailbox>().is_ok() {
        return Some(mailto_stripped.to_string());
    }
    trimmed
        .parse::<Mailbox>()
        .ok()
        .map(|mailbox| mailbox.to_string())
}

fn load_mailbox_sender_display_name(
    state: &dyn StateAccess,
    mailbox: &str,
) -> Result<Option<String>, TransactionError> {
    let Some(bytes) = state
        .get(&mail_connector_storage_key(mailbox))
        .map_err(TransactionError::State)?
    else {
        return Ok(None);
    };
    let connector: MailConnectorRecord = codec::from_bytes_canonical(&bytes)?;
    Ok(connector
        .config
        .sender_display_name
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty()))
}

fn pick_u64(args: &JsonMap<String, JsonValue>, keys: &[&str]) -> Option<u64> {
    keys.iter().find_map(|key| {
        let value = args.get(*key)?;
        if let Some(parsed) = value.as_u64() {
            return Some(parsed);
        }
        if let Some(text) = value.as_str() {
            return text.trim().parse::<u64>().ok();
        }
        None
    })
}

fn pick_u32(args: &JsonMap<String, JsonValue>, keys: &[&str]) -> Option<u32> {
    pick_u64(args, keys).and_then(|value| u32::try_from(value).ok())
}

fn decode_hex_32(label: &str, raw: &str) -> Result<[u8; 32], TransactionError> {
    let trimmed = raw.trim().trim_start_matches("0x");
    let decoded = hex::decode(trimmed)
        .map_err(|e| TransactionError::Invalid(format!("{} must be 32-byte hex: {}", label, e)))?;
    if decoded.len() != 32 {
        return Err(TransactionError::Invalid(format!(
            "{} must be exactly 32 bytes (hex len 64)",
            label
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded);
    Ok(out)
}

fn pick_hex_32(
    args: &JsonMap<String, JsonValue>,
    keys: &[&str],
) -> Result<Option<[u8; 32]>, TransactionError> {
    for key in keys {
        let Some(value) = args.get(*key) else {
            continue;
        };
        if let Some(text) = value.as_str() {
            return decode_hex_32(key, text).map(Some);
        }
    }
    Ok(None)
}

fn compute_sha256_id(seed: &str) -> [u8; 32] {
    if let Ok(hash) = ioi_crypto::algorithms::hash::sha256(seed.as_bytes()) {
        let mut out = [0u8; 32];
        out.copy_from_slice(hash.as_ref());
        if out != [0u8; 32] {
            return out;
        }
    }
    let mut fallback = [0u8; 32];
    fallback[0] = 1;
    fallback
}

fn infer_next_op_seq(state: &dyn StateAccess, channel_id: [u8; 32], lease_id: [u8; 32]) -> u64 {
    let key = lease_action_window_storage_key(&channel_id, &lease_id);
    state
        .get(&key)
        .ok()
        .flatten()
        .and_then(|bytes| codec::from_bytes_canonical::<LeaseActionReplayWindowState>(&bytes).ok())
        .map(|window| window.highest_seq.saturating_add(1).max(1))
        .unwrap_or(1)
}

fn op_nonce_from_operation(operation_id: [u8; 32], step_index: u32) -> [u8; 32] {
    let mut nonce = operation_id;
    nonce[0] ^= (step_index & 0xFF) as u8;
    nonce[1] ^= ((step_index >> 8) & 0xFF) as u8;
    if nonce == [0u8; 32] {
        nonce[0] = 1;
    }
    nonce
}

fn civil_date_from_days(days_since_epoch: i64) -> (i64, i64, i64) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if month <= 2 { 1 } else { 0 };
    (year, month, day)
}

fn iso_datetime_from_unix_ms(unix_ms: u64) -> String {
    let days_since_epoch = (unix_ms / 86_400_000) as i64;
    let (year, month, day) = civil_date_from_days(days_since_epoch);
    let ms_of_day = unix_ms % 86_400_000;
    let hour = ms_of_day / 3_600_000;
    let minute = (ms_of_day % 3_600_000) / 60_000;
    let second = (ms_of_day % 60_000) / 1_000;
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hour, minute, second
    )
}

fn truncate_chars(input: &str, max_chars: usize) -> String {
    if input.chars().count() <= max_chars {
        return input.to_string();
    }
    input.chars().take(max_chars).collect::<String>() + "..."
}
